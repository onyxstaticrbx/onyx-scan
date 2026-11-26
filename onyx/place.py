"""Parse Roblox place/model files (.rbxlx, .rbxmx — the XML formats).

A Studio-saved place is a tree of <Item class="..."> elements. Each carries a
<Properties> block; scripts carry their Luau source in
<ProtectedString name="Source">.

This is how we see an entire game's scripts in one pass, without the user
sending anything script-by-script.

Binary .rbxl/.rbxm are NOT supported — say so clearly and ask for an XML save.
A `.rbxl`/`.rbxm` file whose content is XML text is accepted: the extension is a
convention, not a format guarantee (confirmed on the 2026-11-19 archive sweep).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

#: Limits for a file we did not write. A place file is untrusted input: it arrives
#: from a third party, a forum, or an API request. Every one of these bounds exists
#: because something below is superlinear or recursive without it.
MAX_PLACE_BYTES = 64 * 1024 * 1024      # 64 MB of XML
MAX_INSTANCES = 200_000                 # nodes we will materialise
MAX_DEPTH = 120                         # nesting levels
MAX_SOURCE_TOTAL = 24 * 1024 * 1024     # total script source, all scripts
MAX_SOURCE_BYTES = 4 * 1024 * 1024      # one script

#: Refused outright. A Roblox XML file has no legitimate DOCTYPE or entity
#: declaration; both exist in this format only for entity-expansion attacks.
FORBIDDEN_XML = (b"<!DOCTYPE", b"<!ENTITY", b"<!doctype", b"<!entity")

SCRIPT_CLASSES = frozenset(
    {
        "Script",
        "LocalScript",
        "ModuleScript",
        # legacy / tool variants
        "CoreScript",
    }
)

CLIENT_SCRIPT_CLASSES = frozenset({"LocalScript"})
SERVER_SCRIPT_CLASSES = frozenset({"Script"})

REMOTE_CLASSES = frozenset(
    {
        "RemoteEvent",
        "UnreliableRemoteEvent",
        "RemoteFunction",
        "BindableEvent",
        "BindableFunction",
    }
)

# Services whose contents are replicated to (and readable by) every client.
CLIENT_REACHABLE_SERVICES = frozenset(
    {
        "ReplicatedStorage",
        "ReplicatedFirst",
        "Workspace",
        "StarterGui",
        "StarterPlayer",
        "StarterPack",
        "Lighting",
        "SoundService",
        "Chat",
        "StarterPlayerScripts",
    }
)


class PlaceParseError(Exception):
    pass


@dataclass
class Instance:
    class_name: str
    name: str
    path: str
    source: str | None = None
    parent: "Instance | None" = None
    children: list["Instance"] = field(default_factory=list)

    @property
    def is_script(self) -> bool:
        return self.class_name in SCRIPT_CLASSES

    @property
    def is_remote(self) -> bool:
        return self.class_name in REMOTE_CLASSES

    @property
    def is_client(self) -> bool:
        return self.class_name in CLIENT_SCRIPT_CLASSES

    def ancestors(self) -> list["Instance"]:
        out: list[Instance] = []
        node = self.parent
        while node is not None:
            out.append(node)
            node = node.parent
        return out

    def top_service(self) -> str | None:
        cur: Instance | None = self
        while cur is not None and cur.parent is not None:
            cur = cur.parent
        return cur.class_name if cur is not None else None

    def is_client_reachable(self) -> bool:
        """True if a client can read this instance's location."""
        node: Instance | None = self
        while node is not None:
            if node.class_name in CLIENT_REACHABLE_SERVICES or node.name in CLIENT_REACHABLE_SERVICES:
                return True
            node = node.parent
        return False


@dataclass
class Place:
    path: str
    root: Instance
    instances: list[Instance]
    #: Source-read coverage for an input that can be partial (Rojo directories). XML input
    #: leaves this empty; the scan report always carries a coverage block regardless.
    coverage: dict = field(default_factory=dict)
    #: Optional RequireAnalysis, installed by scan_place. Kept as object to avoid a
    #: place -> require_graph import cycle.
    analysis: object | None = None

    @property
    def scripts(self) -> list[Instance]:
        return [i for i in self.instances if i.is_script and (i.source or "").strip()]

    @property
    def remotes(self) -> list[Instance]:
        return [i for i in self.instances if i.is_remote]

    @property
    def client_reachable_remotes(self) -> list[Instance]:
        return [r for r in self.remotes if r.is_client_reachable()]

    @property
    def client_remotes(self) -> list[Instance]:
        """True client<->server remotes only (excludes bindables)."""
        return [
            r
            for r in self.remotes
            if r.class_name in ("RemoteEvent", "UnreliableRemoteEvent", "RemoteFunction")
            and r.is_client_reachable()
        ]

    def by_path(self, path: str) -> Instance | None:
        for i in self.instances:
            if i.path == path:
                return i
        return None

    def summary(self) -> dict:
        return {
            "path": self.path,
            "instances": len(self.instances),
            "scripts": len(self.scripts),
            "client_scripts": sum(1 for s in self.scripts if s.is_client),
            "server_scripts": sum(1 for s in self.scripts if s.class_name == "Script"),
            "modules": sum(1 for s in self.scripts if s.class_name == "ModuleScript"),
            "remotes": len(self.remotes),
            "client_reachable_remotes": len(self.client_remotes),
        }


def _prop(properties: ET.Element, name: str, tag: str = "string") -> str | None:
    for child in properties:
        if child.get("name") != name:
            continue
        if child.tag != tag:
            continue
        return child.text if child.text is not None else ""
    return None


def _walk(item: ET.Element, parent: Instance | None, depth: int = 0,
          budget: list[int] | None = None) -> Instance:
    if depth > MAX_DEPTH:
        raise PlaceParseError(
            f"the instance tree is nested deeper than {MAX_DEPTH} levels — refusing to walk it"
        )
    if budget is not None:
        budget[0] -= 1
        if budget[0] < 0:
            raise PlaceParseError(
                f"the file contains more than {MAX_INSTANCES:,} instances — refusing to read it"
            )
    class_name = item.get("class", "Unknown")
    props = item.find("Properties")
    name = "Unknown"
    source = None
    if props is not None:
        name = _prop(props, "Name", "string") or name
        # Studio writes Source as ProtectedString; rbx-dom's XML writer (used to convert
        # binary .rbxl places) writes it as string. Both are the same text.
        source = _prop(props, "Source", "ProtectedString")
        if source is None:
            source = _prop(props, "Source", "string")
    path = name if parent is None else f"{parent.path}.{name}"
    inst = Instance(class_name=class_name, name=name, path=path, source=source, parent=parent)
    for child in item.findall("Item"):
        inst.children.append(_walk(child, inst, depth + 1, budget))
    return inst


def load_place(path: str | Path) -> Place:
    p = Path(path)
    suffix = p.suffix.lower()
    if not p.exists():
        raise PlaceParseError(f"file not found: {p}")
    if not p.is_file():
        raise PlaceParseError(f"not a file: {p}")

    size = p.stat().st_size
    if size == 0:
        raise PlaceParseError(f"{p.name} is empty")
    if size > MAX_PLACE_BYTES:
        raise PlaceParseError(
            f"{p.name} is {size / 1024 / 1024:.1f} MB; the limit is "
            f"{MAX_PLACE_BYTES / 1024 / 1024:.0f} MB"
        )
    head = p.open("rb").read(4096)
    banner = head.lstrip(b"\xef\xbb\xbf \t\r\n")
    # A valid XML place may carry an `<?xml …?>` declaration before <roblox>.
    if banner.startswith(b"<?xml"):
        decl_end = banner.find(b"?>")
        if decl_end != -1:
            banner = banner[decl_end + 2:].lstrip()
    # `.rbxl`/`.rbxm` usually means the binary format, but Roblox and third-party
    # exporters also write XML text under those extensions. Sniff the content, not the
    # name: binary places start with the magic `<roblox!`, XML places with `<roblox `.
    # A file rejected as "binary" when it was plain XML is a false drop-off, so the
    # content decides.
    is_xml = banner.startswith(b"<roblox") and not banner.startswith(b"<roblox!")
    if suffix in {".rbxl", ".rbxm"} and not is_xml:
        raise PlaceParseError(
            f"{suffix} is the binary format and cannot be read. In Studio: File > Save to "
            "File As..., then pick 'Roblox XML Place Files (*.rbxlx)' under Save as type. "
            "(In Team Create, File > Download a Copy first, then save that copy as XML.)"
        )
    if suffix not in {".rbxlx", ".rbxmx", ".xml"} and not is_xml:
        raise PlaceParseError(f"unsupported file type: {suffix} (expected .rbxlx or .rbxmx)")
    for needle in FORBIDDEN_XML:
        if needle in head:
            raise PlaceParseError(
                f"{p.name} declares an XML DOCTYPE or ENTITY. A Roblox place file never "
                "needs one, and expanding entities is how a small file becomes a large one."
            )

    try:
        tree = ET.parse(p)
    except ET.ParseError as exc:
        raise PlaceParseError(f"invalid XML in {p.name}: {exc}") from exc

    root_el = tree.getroot()
    if root_el.tag != "roblox":
        raise PlaceParseError(f"not a Roblox XML file (root element is <{root_el.tag}>)")

    top_items = root_el.findall("Item")
    if not top_items:
        raise PlaceParseError("no items found in file")

    budget = [MAX_INSTANCES]

    # A place has multiple top-level services; a model has one top item.
    if len(top_items) == 1 and top_items[0].get("class") not in CLIENT_REACHABLE_SERVICES:
        root = _walk(top_items[0], None, 0, budget)
    else:
        root = Instance(class_name="DataModel", name="game", path="game")
        for el in top_items:
            root.children.append(_walk(el, root, 0, budget))

    flat: list[Instance] = []

    def collect(node: Instance) -> None:
        flat.append(node)
        for child in node.children:
            collect(child)

    collect(root)

    total_source = 0
    for inst in flat:
        if not inst.source:
            continue
        length = len(inst.source.encode("utf-8"))
        if length > MAX_SOURCE_BYTES:
            raise PlaceParseError(
                f"{inst.path} carries {length / 1024 / 1024:.1f} MB of script source; "
                f"the per-script limit is {MAX_SOURCE_BYTES / 1024 / 1024:.0f} MB"
            )
        total_source += length
        if total_source > MAX_SOURCE_TOTAL:
            raise PlaceParseError(
                f"the scripts in {p.name} total more than "
                f"{MAX_SOURCE_TOTAL / 1024 / 1024:.0f} MB; refusing to scan"
            )

    return Place(path=str(p), root=root, instances=flat)
