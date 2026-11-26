"""Read a Rojo project directory into the same Place model the XML reader builds.

A Rojo project is a JSON tree plus a directory tree of Luau files. This module is the
only place that knows that convention: after ``load_rojo_project`` returns, rules,
coverage and the emulator see an ordinary ``Place`` and do not care where it came from.

The directory is untrusted input. It may contain symlinks, huge files, deep nesting,
thousands of entries and invalid encodings. Every bound exists because something below
would otherwise be recursive or superlinear.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .place import (
    MAX_DEPTH,
    MAX_SOURCE_BYTES,
    MAX_SOURCE_TOTAL,
    Instance,
    Place,
    PlaceParseError,
)

#: Project JSON is small; a huge one is not a project.
MAX_PROJECT_BYTES = 2 * 1024 * 1024
#: Files we will inspect in one project. A real game is far below this.
MAX_PROJECT_FILES = 20_000
#: Per-file source cap, matching the XML reader's per-script cap.
MAX_FILE_BYTES = MAX_SOURCE_BYTES
#: Total source cap, matching the XML reader's total.
MAX_TOTAL_SOURCE = MAX_SOURCE_TOTAL
#: Directory/project nesting bound. The XML reader's MAX_DEPTH is the same value.
MAX_PROJECT_DEPTH = MAX_DEPTH

#: Extensions Rojo treats as scripts. ``init.*`` files use the folder's name.
_SCRIPT_SUFFIXES = (".lua", ".luau")
_INIT_NAMES = (
    "init.lua",
    "init.luau",
    "init.server.lua",
    "init.server.luau",
    "init.client.lua",
    "init.client.luau",
)


class RojoError(PlaceParseError):
    """A project that cannot be read safely, or is not a Rojo project."""


@dataclass
class RojoCoverage:
    """What was read, what was skipped, and why.

    A partial read must never look like a clean scan. Every skipped file is counted and
    (up to a bound) named; ``scripts_read + scripts_skipped`` is not allowed to vanish.
    """

    project: str = ""
    files_seen: int = 0
    files_read: int = 0
    scripts_read: int = 0
    scripts_skipped: int = 0
    files_skipped: int = 0
    skipped: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    total_source_bytes: int = 0

    def skip(self, path: str, reason: str, *, script: bool = False) -> None:
        self.files_skipped += 1
        if script:
            self.scripts_skipped += 1
        if len(self.skipped) < 100:
            self.skipped.append(f"{path}: {reason}")

    def unsupported_item(self, path: str, reason: str) -> None:
        if len(self.unsupported) < 100:
            self.unsupported.append(f"{path}: {reason}")

    def as_dict(self) -> dict:
        return {
            "input": "rojo",
            "project": self.project,
            "files_seen": self.files_seen,
            "files_read": self.files_read,
            "scripts_read": self.scripts_read,
            "scripts_skipped": self.scripts_skipped,
            "files_skipped": self.files_skipped,
            "skipped": list(self.skipped),
            "unsupported": list(self.unsupported),
            "total_source_bytes": self.total_source_bytes,
        }


def _instance_name(path: Path) -> str:
    """The instance name Rojo derives from a source filename (without the suffix)."""
    name = path.name
    for suffix in (".server.lua", ".server.luau", ".client.lua", ".client.luau",
                   ".lua", ".luau"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _script_class(path: Path) -> str | None:
    """The instance class for a Rojo source file, or None when it is not a script."""
    name = path.name.lower()
    if name not in ("init.lua", "init.luau") and not name.endswith(_SCRIPT_SUFFIXES):
        return None
    if name.startswith("init.client."):
        return "LocalScript"
    if name.startswith("init.server."):
        return "Script"
    if name == "init.lua" or name == "init.luau":
        return "ModuleScript"
    if name.endswith(".client.lua") or name.endswith(".client.luau"):
        return "LocalScript"
    if name.endswith(".server.lua") or name.endswith(".server.luau"):
        return "Script"
    return "ModuleScript"


def _class_for_spec(name: str, path: Path | None, explicit: str | None,
                    coverage: RojoCoverage) -> str:
    if explicit:
        return explicit
    if path is not None:
        inferred = _script_class(path)
        if inferred:
            return inferred
    # A directory node without $className is a Folder. Services need $className in the
    # project file; guessing "ReplicatedStorage" from a folder name would be unsafe.
    return "Folder"


class _Builder:
    def __init__(self, project_file: Path, project_root: Path) -> None:
        self.project_file = project_file
        self.project_root = project_root
        self.root = Instance(class_name="DataModel", name="game", path="game")
        self.instances: list[Instance] = [self.root]
        self.coverage = RojoCoverage(project=str(project_file))
        self._seen_files: set[Path] = set()
        self._json_path_cache: dict[str, Path] = {}

    # -- path safety -----------------------------------------------------

    def _within(self, target: Path) -> bool:
        try:
            resolved = target.resolve()
        except OSError as exc:
            raise RojoError(f"cannot resolve {target}: {exc}") from exc
        try:
            resolved.relative_to(self.project_root)
        except ValueError:
            return False
        return True

    def _safe_path(self, raw: object, where: str) -> Path:
        if not isinstance(raw, str) or not raw.strip():
            raise RojoError(f"{where}: $path must be a non-empty string")
        # Absolute paths and traversal are refused before touching the filesystem.
        if os.path.isabs(raw):
            raise RojoError(f"{where}: $path {raw!r} is absolute; only project-relative paths are allowed")
        target = self.project_root / raw
        if not self._within(target):
            raise RojoError(f"{where}: $path {raw!r} escapes the project root {self.project_root}")
        if target.is_symlink():
            raise RojoError(f"{where}: $path {raw!r} is a symlink; symlinks are not followed")
        if not target.exists():
            raise RojoError(f"{where}: $path {raw!r} does not exist")
        return target

    def _rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.project_root))
        except ValueError:
            return str(path)

    # -- coverage/caps --------------------------------------------------

    def _count_file(self) -> None:
        self.coverage.files_seen += 1
        if self.coverage.files_seen > MAX_PROJECT_FILES:
            raise RojoError(
                f"the project contains more than {MAX_PROJECT_FILES:,} files; refusing to read it"
            )

    def _read_source(self, path: Path, where: str) -> str | None:
        self._count_file()
        try:
            st = path.stat()
        except OSError as exc:
            self.coverage.skip(self._rel(path), f"cannot stat: {exc}", script=True)
            return None
        if st.st_size == 0:
            return ""
        if st.st_size > MAX_FILE_BYTES:
            raise RojoError(
                f"{where}: {self._rel(path)} is {st.st_size / 1024 / 1024:.1f} MB; "
                f"the per-file limit is {MAX_FILE_BYTES / 1024 / 1024:.0f} MB"
            )
        if self.coverage.total_source_bytes + st.st_size > MAX_TOTAL_SOURCE:
            raise RojoError(
                f"the project's scripts total more than {MAX_TOTAL_SOURCE / 1024 / 1024:.0f} MB; "
                "refusing to scan"
            )
        try:
            data = path.read_bytes()
        except OSError as exc:
            self.coverage.skip(self._rel(path), f"cannot read: {exc}", script=True)
            return None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            self.coverage.skip(self._rel(path), f"not UTF-8: {exc}", script=True)
            return None
        self.coverage.files_read += 1
        self.coverage.scripts_read += 1
        self.coverage.total_source_bytes += len(data)
        return text

    # -- instance helpers ----------------------------------------------

    def _add(self, inst: Instance, parent: Instance) -> None:
        inst.parent = parent
        parent.children.append(inst)
        self.instances.append(inst)

    def _new(self, name: str, class_name: str, parent: Instance) -> Instance:
        if any(child.name == name for child in parent.children):
            raise RojoError(f"duplicate instance name {name!r} under {parent.path}")
        inst = Instance(class_name=class_name, name=name, path=f"{parent.path}.{name}", parent=parent)
        self._add(inst, parent)
        return inst

    def _meta_for(self, path: Path) -> dict | None:
        meta = path.with_name(path.name + ".meta.json")
        if not meta.is_file() or meta.is_symlink():
            return None
        try:
            raw = meta.read_text(encoding="utf-8")
            obj = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.coverage.unsupported_item(self._rel(meta), f"bad meta.json: {exc}")
            return None
        return obj if isinstance(obj, dict) else None

    def _file_instance(self, parent: Instance, name: str, path: Path,
                       explicit_class: str | None, where: str) -> None:
        inferred = _script_class(path)
        if inferred is None:
            self.coverage.unsupported_item(where, f"{self._rel(path)} is not a Luau script")
            return
        meta = self._meta_for(path)
        if explicit_class is None and meta and isinstance(meta.get("className"), str):
            explicit_class = meta["className"]
        cls = explicit_class or inferred
        if cls not in ("Script", "LocalScript", "ModuleScript"):
            raise RojoError(
                f"{where}: $path {self._rel(path)!r} names {path.name}, which is a {cls}; "
                "a source file must map to Script, LocalScript or ModuleScript"
            )
        source = self._read_source(path, where)
        if source is None:
            return
        inst = self._new(name, cls, parent)
        inst.source = source

    def _init_file(self, directory: Path) -> Path | None:
        for name in _INIT_NAMES:
            candidate = directory / name
            if candidate.is_file() and not candidate.is_symlink():
                return candidate
        return None

    # -- directory tree -------------------------------------------------

    def _fill_dir(self, inst: Instance, directory: Path, depth: int,
                  where: str, *, is_node: bool = False) -> None:
        if depth > MAX_PROJECT_DEPTH:
            raise RojoError(f"{where}: project nesting is deeper than {MAX_PROJECT_DEPTH} levels")
        init = self._init_file(directory) if is_node else None
        if init is not None:
            existing = inst.class_name
            inferred = _script_class(init)
            if inferred is None:
                raise RojoError(f"{where}: {self._rel(init)} is not a Luau script")
            if existing == "Folder":
                inst.class_name = inferred
            elif existing not in ("Script", "LocalScript", "ModuleScript"):
                # A service or Part with an init.lua would silently lose the source: its
                # class cannot be a script, so say so instead of pretending it was read.
                self.coverage.unsupported_item(
                    f"{where}/{init.name}", f"init source under a {existing}; not a script instance")
                inferred = None
            source = self._read_source(init, where) if inferred is not None else None
            if source is not None:
                inst.source = source
        # Deterministic order: sort names, not raw directory order.
        entries = list(os.scandir(directory))
        entries.sort(key=lambda e: e.name)
        for entry in entries:
            rel = self._rel(Path(entry.path))
            if entry.name in _INIT_NAMES or entry.name.endswith(".meta.json"):
                continue
            if entry.is_symlink():
                self.coverage.skip(rel, "symlink", script=bool(_script_class(Path(entry.path)))
                                  or entry.name in _INIT_NAMES)
                continue
            if entry.name == "default.project.json":
                # A nested project is not a child script; support it by recursion only
                # when $path points at it explicitly, not by treating it as source.
                self.coverage.unsupported_item(rel, "nested default.project.json ignored")
                continue
            if entry.is_dir(follow_symlinks=False):
                child = self._new(entry.name, "Folder", inst)
                self._fill_dir(child, Path(entry.path), depth + 1, f"{where}/{entry.name}")
            elif entry.is_file(follow_symlinks=False):
                cls = _script_class(Path(entry.path))
                if cls is None:
                    self.coverage.unsupported_item(rel, "not a Luau script")
                    continue
                self._file_instance(inst, _instance_name(Path(entry.path)), Path(entry.path),
                                    None, f"{where}/{entry.name}")
            else:
                self.coverage.skip(rel, "not a regular file or directory")

    # -- JSON tree ------------------------------------------------------

    def _json_children(self, spec: dict, parent: Instance, depth: int, where: str) -> None:
        if depth > MAX_PROJECT_DEPTH:
            raise RojoError(f"{where}: project nesting is deeper than {MAX_PROJECT_DEPTH} levels")
        for key, value in spec.items():
            if key.startswith("$"):
                continue
            if not isinstance(value, dict):
                raise RojoError(f"{where}.{key}: a project child must be a JSON object")
            self._json_node(key, value, parent, depth + 1, f"{where}.{key}")

    def _json_node(self, name: str, spec: dict, parent: Instance, depth: int, where: str) -> None:
        if depth > MAX_PROJECT_DEPTH:
            raise RojoError(f"{where}: project nesting is deeper than {MAX_PROJECT_DEPTH} levels")
        if "$properties" in spec and spec["$properties"]:
            self.coverage.unsupported_item(where, "$properties beyond class/name are not read")
        explicit = spec.get("$className")
        if explicit is not None and not isinstance(explicit, str):
            raise RojoError(f"{where}: $className must be a string")
        path_spec = spec.get("$path")
        if path_spec is None:
            cls = explicit or "Folder"
            inst = self._new(name, cls, parent)
            self._json_children(spec, inst, depth + 1, where)
            return
        target = self._safe_path(path_spec, where)
        if target.is_dir():
            cls = explicit or "Folder"
            inst = self._new(name, cls, parent)
            # Project JSON children are merged with directory children; duplicates are
            # an error, because two different instances under one path would break IDs.
            self._json_children(spec, inst, depth + 1, where)
            self._fill_dir(inst, target, depth + 1, where, is_node=True)
        elif target.is_file():
            if target.name.endswith(".project.json"):
                self._nested_project(name, target, parent, depth + 1, where, explicit)
            else:
                self._file_instance(parent, name, target, explicit, where)
        else:
            raise RojoError(f"{where}: $path {path_spec!r} is not a file or directory")

    # -- nested projects ------------------------------------------------

    def _nested_project(self, name: str, path: Path, parent: Instance, depth: int,
                        where: str, explicit: str | None) -> None:
        if depth > MAX_PROJECT_DEPTH:
            raise RojoError(f"{where}: nested project exceeds {MAX_PROJECT_DEPTH} levels")
        if path.stat().st_size > MAX_PROJECT_BYTES:
            raise RojoError(f"{where}: nested project file is too large")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RojoError(f"{where}: cannot read nested project: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("tree"), dict):
            raise RojoError(f"{where}: nested project has no tree")
        cls = explicit or "Folder"
        inst = self._new(name, cls, parent)
        # Paths inside a nested project are relative to that project file, not the
        # top-level project. Switch the resolver root only for this subtree.
        old_root = self.project_root
        try:
            self.project_root = path.parent.resolve()
            self._json_children(data["tree"], inst, depth + 1, where)
        finally:
            self.project_root = old_root

    # -- top-level ------------------------------------------------------

    def build(self, data: dict) -> Place:
        tree = data.get("tree")
        if not isinstance(tree, dict):
            raise RojoError(f"{self.project_file}: missing or invalid 'tree' object")
        root_spec = tree
        root_class = root_spec.get("$className")
        if root_class is not None and root_class != "DataModel":
            # A non-DataModel top-level tree is legal in Rojo for models. The scanner's
            # Place needs a DataModel root, so keep it and record the difference.
            self.coverage.unsupported_item("tree", f"top-level $className={root_class!r}; using DataModel")
        self._json_children(root_spec, self.root, 0, "tree")
        # Ensure no duplicate top-level service names? _json_node appends; a malformed
        # project with two identical keys cannot exist in JSON parsing.
        return Place(
            path=str(self.project_file),
            root=self.root,
            instances=self.instances,
            coverage=self.coverage.as_dict(),
        )


def load_rojo_project(path: str | Path) -> Place:
    """Load a Rojo project directory and return a Place.

    ``path`` may be the directory containing ``default.project.json`` or the project
    file itself. The project root is the directory containing that file.
    """
    p = Path(path)
    if p.is_dir():
        project = p / "default.project.json"
        root = p
    elif p.is_file() and p.name.endswith(".project.json"):
        project = p
        root = p.parent
    else:
        raise RojoError(
            f"{p} is not a Rojo directory or .project.json file. Pass a directory with "
            "default.project.json, or save the place as .rbxlx."
        )

    if project.is_symlink():
        raise RojoError(f"{project} is a symlink; refusing to follow it")
    if not project.is_file():
        raise RojoError(f"{p} does not contain default.project.json")
    if project.stat().st_size > MAX_PROJECT_BYTES:
        raise RojoError(
            f"{project.name} is {project.stat().st_size / 1024 / 1024:.1f} MB; "
            f"the project file limit is {MAX_PROJECT_BYTES / 1024 / 1024:.0f} MB"
        )
    try:
        raw = project.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RojoError(f"cannot read {project.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise RojoError(f"{project.name} is not a JSON object")

    builder = _Builder(project.resolve(), root.resolve())
    try:
        return builder.build(data)
    except RojoError:
        raise
    except OSError as exc:
        raise RojoError(f"cannot read the project tree: {exc}") from exc


def is_rojo_project(path: str | Path) -> bool:
    p = Path(path)
    if p.is_dir():
        return (p / "default.project.json").is_file()
    return p.is_file() and p.name.endswith(".project.json")
