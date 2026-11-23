--!nocheck
-- Onyx mock of the Roblox runtime. Emulation, not simulation of production:
-- every claim it produces is "this code, against the documented API contract,
-- lets a client control server state." That is a real claim and it is bounded.

local Onyx = {}
Onyx.__version = "0.2.2"
Onyx.log = {}
Onyx.claims = {}
Onyx.remoteCalls = {}
Onyx.httpCalls = {}
Onyx.datastores = {}
Onyx.gamepassOwned = false
Onyx.failWrites = false
Onyx.writeAttempts = 0
-- Yield budget: `wait()`/`task.wait()` return instantly here,
-- so `while true do wait() end` progress loops spin forever and the place never finishes.
-- Counting them and failing once the budget is spent turns a hang into a script error, so
-- the rest of the place still runs and the card becomes measurable. This is execution-time
-- bounding, not dispatch instrumentation.
Onyx.yieldBudget = 5000
Onyx.yieldCount = 0
-- Slices get instance-shaped children and instance-level snapshots. Off for the
-- whole-place judge, so every frozen plate and sample keeps the same universe it had.
Onyx.sliceMode = false
-- Members a handler asked for on a *supplied shape* that the mock cannot honestly fake.
-- A write to such a member would otherwise become an invented field and could be judged as
-- a fact; recording it lets the judge refuse instead of guessing.
Onyx.shapeMisses = {}
Onyx.shapeWrites = {}

local function shapeNote(bucket, inst, key)
	local n = 0
	for _ in pairs(bucket) do n = n + 1 end
	if n >= 256 then return end
	local path = inst.GetFullName and inst:GetFullName() or "?"
	bucket[path .. "." .. tostring(key)] = true
end

local function awaitBudget()
	Onyx.yieldCount = Onyx.yieldCount + 1
	if Onyx.yieldCount > Onyx.yieldBudget then
		error("onyx yield budget exhausted: " .. Onyx.yieldBudget ..
			" awaits returned with no progress (a non-yielding loop in this place)", 2)
	end
	return 0
end

local function pushLog(kind, msg)
	table.insert(Onyx.log, kind .. ": " .. tostring(msg))
end
Onyx.pushLog = pushLog

-- ---------------------------------------------------------------- signals
local Signal = {}
Signal.__index = Signal
function Onyx.newSignal(name)
	return setmetatable({ _name = name, _handlers = {} }, Signal)
end
function Signal:Connect(fn)
	if type(fn) ~= "function" then
		error("Connect expects a function, got " .. typeof(fn), 2)
	end
	table.insert(self._handlers, fn)
	return { Disconnect = function() end }
end
function Signal:Once(fn) return self:Connect(fn) end

-- Legacy places call the lowercase Roblox form (`:connect`); RbxUtility shipped it as an
-- alias of Connect and the real Signal still accepts it. Without this alias old scripts
-- error out before registering a handler, so the remote fuzz has nothing to dispatch to.
function Signal:connect(fn) return self:Connect(fn) end
function Signal:wait() return nil end
function Signal:Fire(...)
	local results = {}
	for _, fn in ipairs(self._handlers) do
		local ok, res = pcall(fn, ...)
		table.insert(results, { ok = ok, value = res })
		if not ok then
			pushLog("handler-error", tostring(res))
		end
	end
	return results
end
function Signal:FireDeferred(...) return self:Fire(...) end
function Signal:DisconnectAll() self._handlers = {} end

-- ---------------------------------------------------------------- Instance
local Instance = {}
-- Roblox resolves a.b.c by child name, not only by property. Emulate that:
-- raw field first, then a child with that Name, then the method table.
Instance.__index = function(self, key)
	local direct = rawget(self, key)
	if direct ~= nil then
		return direct
	end
	local kids = rawget(self, "Children")
	if kids then
		for _, child in ipairs(kids) do
			if child.Name == key then
				return child
			end
		end
	end
	local method = Instance[key]
	if method ~= nil then
		return method
	end
	-- Structural fields legitimately read nil (a detached Tool has no Parent); they are not
	-- members the mock failed to shape, so they never become a refusal.
	if rawget(self, "_onyxShape") ~= nil and key ~= "Parent" and key ~= "Name"
		and key ~= "ClassName" and key ~= "Children" and key ~= "Attributes" then
		shapeNote(Onyx.shapeMisses, self, key)
	end
	return method
end

local VALUE_CLASSES = {
	IntValue = 0, NumberValue = 0, StringValue = "", BoolValue = false,
	ObjectValue = nil, Color3Value = nil, Vector3Value = nil,
}

local function newInstance(className, name)
	local inst = setmetatable({
		ClassName = className,
		Name = name or className,
		Parent = nil,
		Children = {},
		Attributes = {},
		_signals = {},
	}, Instance)
	if VALUE_CLASSES[className] ~= nil then
		inst.Value = VALUE_CLASSES[className]
	end
	return inst
end

-- Whitelisted properties per supplied shape. A handler writing one of these is real usage
-- (a Humanoid health write is out of scope for this order and is refused by the classifier,
-- not by pretending the write did not happen); anything else is a member the mock would be
-- inventing, so it is recorded for refusal.
local SHAPE_PROPS = {
	humanoid = { Health = true, MaxHealth = true, WalkSpeed = true, JumpPower = true,
		JumpHeight = true, HipHeight = true, UseJumpPower = true, WalkSpeed = true },
	character = { PrimaryPart = true },
	tool = { Handle = true },
	backpack = {},
	value = { Value = true },
}
Instance.__newindex = function(self, key, value)
	local shape = rawget(self, "_onyxShape")
	local structural = key == "_onyxShape" or key == "Parent" or key == "Name"
		or key == "ClassName" or key == "Children" or key == "Attributes"
		or key == "_signals"
	if shape ~= nil and not structural then
		local known = SHAPE_PROPS[shape]
		if not (known and known[key]) then
			shapeNote(Onyx.shapeWrites, self, key)
		end
	end
	rawset(self, key, value)
end

function Instance:Clone()
	local copy = newInstance(self.ClassName, self.Name)
	copy.Parent = nil
	copy.Attributes = {}
	for k, v in pairs(self.Attributes or {}) do copy.Attributes[k] = v end
	for _, c in ipairs(self.Children or {}) do
		local cc = c:Clone()
		cc.Parent = copy
		table.insert(copy.Children, cc)
	end
	return copy
end

function Instance:GetChildren()
	local out = {}
	for _, c in ipairs(self.Children) do
		table.insert(out, c)
	end
	return out
end

function Instance:GetDescendants()
	local out = {}
	local function walk(n)
		for _, c in ipairs(n.Children) do
			table.insert(out, c)
			walk(c)
		end
	end
	walk(self)
	return out
end

function Instance:FindFirstChild(name, recursive)
	for _, c in ipairs(self.Children) do
		if c.Name == name then return c end
	end
	if recursive then
		for _, c in ipairs(self:GetDescendants()) do
			if c.Name == name then return c end
		end
	end
	return nil
end

function Instance:WaitForChild(name, _timeout)
	return self:FindFirstChild(name) or newInstance("Folder", name)
end

function Instance:FindFirstChildOfClass(className)
	for _, c in ipairs(self.Children) do
		if c.ClassName == className then return c end
	end
	return nil
end

function Instance:FindFirstChildWhichIsA(className)
	for _, c in ipairs(self.Children) do
		if c.ClassName == className then return c end
	end
	return nil
end

function Instance:IsA(className)
	return self.ClassName == className
end

function Instance:GetFullName()
	local parts = {}
	local n = self
	while n and n ~= Onyx.game do
		table.insert(parts, 1, n.Name)
		n = n.Parent
	end
	return table.concat(parts, ".")
end

function Instance:Destroy()
	if self.Parent then
		for i, c in ipairs(self.Parent.Children) do
			if c == self then table.remove(self.Parent.Children, i) break end
		end
	end
	self.Parent = nil
	self.Destroyed = true
end

function Instance:SetAttribute(key, value)
	self.Attributes[key] = value
end

function Instance:GetAttribute(key)
	return self.Attributes[key]
end

function Instance:GetAttributes()
	return self.Attributes
end

function Instance:GetPropertyChangedSignal(prop)
	local key = "_sig_" .. tostring(prop)
	if not self._signals[key] then self._signals[key] = Onyx.newSignal(prop) end
	return self._signals[key]
end

local function addChild(parent, child)
	child.Parent = parent
	table.insert(parent.Children, child)
	return child
end

function Onyx.new(className, name)
	return newInstance(className, name)
end

Instance.new = function(className, parent)
	local inst = newInstance(className)
	if parent then addChild(parent, inst) end
	if Onyx.clientMode and type(className) == "string" and string.find(className, "Remote", 1, true) then
		table.insert(Onyx.clientRemotes, { class = className, name = inst.Name })
	end
	return inst
end

-- ---------------------------------------------------------------- remotes
local function makeRemote(className, name)
	local remote = newInstance(className, name)
	remote.OnServerEvent = Onyx.newSignal("OnServerEvent")
	remote.OnClientEvent = Onyx.newSignal("OnClientEvent")
	remote.OnServerInvoke = nil
	remote.OnClientInvoke = nil

	-- Firing from a "client": reach every OnServerEvent handler with the caller
	-- player as the first argument, exactly as the documented contract states.
	remote.FireServer = function(_self, ...)
		table.insert(Onyx.remoteCalls, { remote = _self:GetFullName(), via = "FireServer" })
		if not Onyx.clientMode then
			table.insert(Onyx.wrongDirection, { remote = _self:GetFullName(), via = "FireServer" })
		end
		return _self.OnServerEvent:Fire(Onyx.currentPlayer, ...)
	end
	remote.InvokeServer = function(_self, ...)
		table.insert(Onyx.remoteCalls, { remote = _self:GetFullName(), via = "InvokeServer" })
		if not Onyx.clientMode then
			table.insert(Onyx.wrongDirection, { remote = _self:GetFullName(), via = "InvokeServer" })
		end
		if _self.OnServerInvoke then
			local ok, res = pcall(_self.OnServerInvoke, Onyx.currentPlayer, ...)
			if not ok then pushLog("invoke-error", tostring(res)) end
			return res
		end
		return nil
	end
	remote.FireClient = function() end
	remote.FireAllClients = function() end
	remote.InvokeClient = function() return nil end
	-- Bindables are not client<->server remotes, but place scripts connect to them
	-- (`script.AddStat.Event:connect(...)`), and a script that dies on its bindable
	-- never registers anything after it. Give them the
	-- documented Event/Fire surface so server code loads.
	if className == "BindableEvent" then
		remote.Event = Onyx.newSignal("Event")
		remote.Fire = function(_self, ...)
			return _self.Event:Fire(...)
		end
	elseif className == "BindableFunction" then
		remote.Invoke = function(_self, ...)
			return nil
		end
	end
	return remote
end

-- lowercase/legacy aliases: pre-2016 code calls these names
Instance.findFirstChild = Instance.FindFirstChild
Instance.FindFirstchild = Instance.FindFirstChild
Instance.findFirstChildOfClass = Instance.FindFirstChildOfClass
Instance.findFirstChildWhichIsA = Instance.FindFirstChildWhichIsA
Instance.getChildren = Instance.GetChildren
Instance.Getchildren = Instance.GetChildren
Instance.getDescendants = Instance.GetDescendants
Instance.isA = Instance.IsA
Instance.waitForChild = Instance.WaitForChild
Instance.destroy = Instance.Destroy
Instance.clone = Instance.Clone
Instance.findFirstAncestor = function(self, name)
	local n = self.Parent
	while n and n ~= Onyx.game do
		if n.Name == name then return n end
		n = n.Parent
	end
	return nil
end

-- ---------------------------------------------------------------- services
local function makeService(name, className)
	local svc = newInstance(className or name, name)
	return svc
end

local DataStoreService = makeService("DataStoreService")
local stores = {}
DataStoreService.GetDataStore = function(_self, storeName)
	if not stores[storeName] then
		local store = {
			_data = {},
			GetAsync = function(_s, key)
				table.insert(Onyx.remoteCalls, { store = storeName, key = tostring(key), op = "GetAsync" })
				return _s._data[tostring(key)]
			end,
			SetAsync = function(_s, key, value)
				Onyx.writeAttempts = Onyx.writeAttempts + 1
				if Onyx.failWrites then error("emulated write failure", 2) end
				_s._data[tostring(key)] = value
				table.insert(Onyx.remoteCalls, { store = storeName, key = tostring(key), op = "SetAsync" })
			end,
			UpdateAsync = function(_s, key, fn)
				Onyx.writeAttempts = Onyx.writeAttempts + 1
				if Onyx.failWrites then error("emulated write failure", 2) end
				local new = fn(_s._data[tostring(key)])
				_s._data[tostring(key)] = new
			end,
			IncrementAsync = function(_s, key, delta)
				Onyx.writeAttempts = Onyx.writeAttempts + 1
				if Onyx.failWrites then error("emulated write failure", 2) end
				_s._data[tostring(key)] = (_s._data[tostring(key)] or 0) + (delta or 0)
				table.insert(Onyx.remoteCalls, { store = storeName, key = tostring(key), op = "IncrementAsync" })
			end,
			RemoveAsync = function(_s, key) _s._data[tostring(key)] = nil end,
			Get = function(_s, key) return _s._data[tostring(key)] end,
			Set = function(_s, key, v) _s._data[tostring(key)] = v end,
			Dump = function(_s)
				local out = {}
				for k, v in pairs(_s._data) do out[tostring(k)] = v end
				return out
			end,
			_storeName = storeName,
		}
		stores[storeName] = store
		Onyx.datastores[storeName] = store
	end
	return stores[storeName]
end
DataStoreService.GetGlobalDataStore = DataStoreService.GetDataStore

local Players = makeService("Players")
Players._list = {}
function Players:GetPlayers()
	local out = {}
	for _, p in ipairs(self._list) do table.insert(out, p) end
	return out
end
function Players:GetPlayerByUserId(id)
	for _, p in ipairs(self._list) do
		if p.UserId == id then return p end
	end
	return nil
end
function Players:GetPlayerFromCharacter(char)
	for _, p in ipairs(self._list) do
		if p.Character == char then return p end
	end
	return nil
end
Players.PlayerAdded = Onyx.newSignal("PlayerAdded")
Players.PlayerRemoving = Onyx.newSignal("PlayerRemoving")

local MarketplaceService = makeService("MarketplaceService")
MarketplaceService.ProcessReceipt = nil
MarketplaceService.PromptGamePassPurchase = function(_s, player, passId)
	pushLog("gamepass-prompt", tostring(passId))
end
MarketplaceService.PromptProductPurchase = function(_s, player, productId)
	pushLog("product-prompt", tostring(productId))
end
MarketplaceService.UserOwnsGamePassAsync = function(_s, userId, passId)
	return Onyx.gamepassOwned
end
MarketplaceService.PlayerOwnsAsset = function(_s, player, assetId)
	return Onyx.gamepassOwned
end
MarketplaceService.GetProductInfo = function(_s, id)
	return { Name = "MockProduct", PriceInRobux = 100 }
end

local HttpService = makeService("HttpService")
local function httpCall(op)
	return function(_s, url, ...)
		table.insert(Onyx.httpCalls, { op = op, url = tostring(url) })
		pushLog("http", op .. " " .. tostring(url))
		error("HttpService is disabled in the emulator (recorded: " .. tostring(url) .. ")", 2)
	end
end
HttpService.GetAsync = httpCall("GetAsync")
HttpService.PostAsync = httpCall("PostAsync")
HttpService.RequestAsync = httpCall("RequestAsync")
HttpService.JSONEncode = function(_s, t) return tostring(t) end
HttpService.JSONDecode = function(_s, s) return {} end
HttpService.GenerateGUID = function() return "mock-guid" end
HttpService.HttpEnabled = true

local CollectionService = makeService("CollectionService")
CollectionService._tags = {}
CollectionService.AddTag = function(_s, inst, tag)
	_s._tags[tag] = _s._tags[tag] or {}
	table.insert(_s._tags[tag], inst)
end
CollectionService.HasTag = function(_s, inst, tag)
	for _, i in ipairs(_s._tags[tag] or {}) do
		if i == inst then return true end
	end
	return false
end
CollectionService.GetTagged = function(_s, tag) return _s._tags[tag] or {} end

-- ---------------------------------------------------------------- game
local game = newInstance("DataModel", "game")
Onyx.game = game

local services = {
	Players = Players,
	DataStoreService = DataStoreService,
	MarketplaceService = MarketplaceService,
	HttpService = HttpService,
	CollectionService = CollectionService,
}
for name, svc in pairs(services) do
	addChild(game, svc)
	game[name] = svc
end

game.GetService = function(_self, name)
	if type(_self) == "string" and name == nil then
		name, _self = _self, game
	end
	if Onyx.clientMode and Onyx.SERVER_ONLY_SERVICES[name] then
		table.insert(Onyx.clientServices, name)
	end
	local svc = services[name]
	if not svc then
		svc = makeService(name)
		services[name] = svc
		addChild(_self, svc)
		_self[name] = svc
	end
	return svc
end
game.FindService = function(_self, name) return services[name] end
game.service = function(_self, name)
	if type(_self) == "string" and name == nil then
		name, _self = _self, game
	end
	return game.GetService(_self, name)
end
game.Service = game.service
game.IsLoaded = function() return true end
game.BindToClose = function(_self, fn) Onyx.onClose = fn end
local RunService = game:GetService("RunService")
-- Documented RunService surface that place code checks during load. Without IsStudio a
-- script aborts at its own guard (`if RunService:IsStudio() then ...`) and never registers
-- its handler.
RunService.IsStudio = function() return false end
RunService.IsServer = function() return not Onyx.clientMode end
RunService.IsClient = function() return Onyx.clientMode end
RunService.IsRunning = function() return true end
-- Pre-2018 code indexes services by their old display names (`game["Run Service"]`); the
-- real engine resolved those. Mirror them so a script's load-time guard does not die on nil.
game["Run Service"] = RunService
game["Data Store Service"] = game:GetService("DataStoreService")
game["Marketplace Service"] = game:GetService("MarketplaceService")
game["Players Service"] = game:GetService("Players")

-- ---------------------------------------------------------------- Enum / env
local Enum = {}
local function makeEnum(name, members)
	local e = {}
	for _, m in ipairs(members) do
		e[m] = { Name = m, Value = 0, EnumType = name }
	end
	Enum[name] = e
	return e
end
-- Members are a list of names. (They used to be passed as `{ Name = 1 }` maps, which
-- `ipairs` never visits, so every enum was empty and `Enum.X.Y` compared as nil — found
-- while wiring the L008 receipt scenario: a handler returning PurchaseGranted looked
-- identical to one returning nothing.)
makeEnum("ProductPurchaseDecision", { "PurchaseGranted", "NotProcessedYet" })
makeEnum("UserInputType", { "MouseButton1", "Touch", "Keyboard" })
makeEnum("KeyCode", { "E", "F" })
makeEnum("HumanoidStateType", { "Dead" })
makeEnum("EasingStyle", { "Linear" })
makeEnum("Font", { "Gotham" })
makeEnum("HttpContentType", { ApplicationJson = 1 })
makeEnum("RunContext", { Server = 1, Client = 2 })

local function noop() end
local task = {
	wait = function() return awaitBudget() end,
	spawn = function(fn) pcall(fn) end,
	defer = function(fn) pcall(fn) end,
	delay = function(_t, fn) pcall(fn) end,
}
Onyx.task = task

Onyx.makeRemote = makeRemote
Onyx.parent = addChild
Onyx.makeInstance = newInstance

-- ---------------------------------------------------------------- players
function Onyx.makePlayer(userId, name, currencyFields)
	local player = newInstance("Player", name or ("Player" .. tostring(userId)))
	player.UserId = userId
	-- Roblox exposes both spellings; old places use `player.userId` everywhere and a slice
	-- that errors on the missing alias would report a stub problem that is really ours
	-- (row 57 mock-fidelity fix; no judge kind is involved).
	player.userId = userId
	player.DisplayName = player.Name
	player.Character = nil
	player.Kicked = false
	player.Kick = function(self, reason)
		self.Kicked = true
		pushLog("kick", tostring(reason))
	end
	-- Badge/group lookups are server-side identity checks. They return false / 0 here: the
	-- point is that the call exists, so handler logic past it can execute; a badge check is
	-- never evidence a client controls anything.
	player.UserHasBadge = function(_self, _badgeId) return false end
	player.UserHasBadgeAsync = function(_self, _badgeId) return false end
	player.IsInGroup = function(_self, _groupId) return false end
	player.GetRankInGroup = function(_self, _groupId) return 0 end
	player.GetRoleInGroup = function(_self, _groupId) return "Guest" end
	-- Instance-shaped fuzz primitives. Handlers that gate on `player.Character` or walk
	-- the character/humanoid/backpack previously died on a nil index before their write, so the
	-- judge could never see the movement. These are supplied shapes with the same fake property
	-- surface the accessor-shaped stub path already fakes; anything they do not model is
	-- recorded (shapeMisses/shapeWrites) and refused, never invented.
	if Onyx.sliceMode then
		local character = newInstance("Model", player.Name)
		character._onyxShape = "character"
		local humanoid = newInstance("Humanoid", "Humanoid")
		humanoid._onyxShape = "humanoid"
		humanoid.Health = 100
		humanoid.MaxHealth = 100
		humanoid.WalkSpeed = 16
		humanoid.JumpPower = 50
		addChild(character, humanoid)
		addChild(character, newInstance("Part", "Head"))
		addChild(character, newInstance("Part", "HumanoidRootPart"))
		addChild(player, character)
		player.Character = character
		local backpack = newInstance("Backpack", "Backpack")
		backpack._onyxShape = "backpack"
		local tool = newInstance("Tool", "Tool")
		tool._onyxShape = "tool"
		addChild(tool, newInstance("Part", "Handle"))
		addChild(backpack, tool)
		addChild(player, backpack)
		player.Backpack = backpack
	end

	local leaderstats = newInstance("Folder", "leaderstats")
	addChild(player, leaderstats)
	for _, field in ipairs(currencyFields) do
		local v = Instance.new("IntValue")
		v.Name = field
		v.Value = 1000
		addChild(leaderstats, v)
	end
	return player
end

function Onyx.addPlayer(player)
	table.insert(Players._list, player)
	addChild(game, player)
	Players.PlayerAdded:Fire(player)
	return player
end

Onyx.currentPlayer = nil

-- Server scripts run after the player is created, so a handler bound in
-- Players.PlayerAdded:Connect never sees that first player. Replay the signal once the
-- server phase is done; Signal:Fire already wraps each handler in pcall, so a handler
-- that errors on the replay is logged, not fatal.
function Onyx.replayPlayerAdded()
	if Onyx.currentPlayer then
		Players.PlayerAdded:Fire(Onyx.currentPlayer)
	end
end

-- ---------------------------------------------------------------- snapshot
local function isScalar(v)
	local t = type(v)
	return t == "number" or t == "string" or t == "boolean"
end

-- DataStore values are often tables (`{args}`, a save record). Scalar-only snapshots made
-- every table write invisible to the judge; flatten up to 4 levels so a client value stored
-- inside a record still shows up as a delta.
local function flattenStore(prefix, value, out, depth)
	if isScalar(value) then
		out[prefix] = value
		return
	end
	if type(value) ~= "table" or depth >= 4 then return end
	for k, v in pairs(value) do
		local kt = type(k)
		if kt == "string" or kt == "number" then
			flattenStore(prefix .. "." .. tostring(k), v, out, depth + 1)
		end
	end
end

-- Instance-level state, slice mode only. Two grammar families:
--   `player:<name>.<child path>` / `player:<name>@<Attribute>`  (unchanged)
--   `inst:<full name>` for game-tree instances outside the player subtree, plus
--   `.<prop>`, `@<Attribute>` and `#class` suffixes for both.
-- Only scalars are captured (same rule the store flattening uses); refs, tables and
-- structural fields are skipped so the diff cannot be padded by object identity.
local SNAPSHOT_SKIP = {
	ClassName = true, Name = true, Parent = true, Children = true, Attributes = true,
	_signals = true, Destroyed = true, _onyxShape = true, _slots = true,
}

local function captureScalars(snap, inst, path, value_suffix)
	-- rawget: reading `.Value` on a supplied shape would otherwise record a shape miss for
	-- every instance the snapshot walks (the snapshot is observation, not place code).
	local value = rawget(inst, "Value")
	if isScalar(value) then snap[path .. value_suffix] = value end
	for k, v in pairs(inst) do
		if type(k) == "string" and not SNAPSHOT_SKIP[k] and string.sub(k, 1, 1) ~= "_"
			and k ~= "Value" and isScalar(v) then
			snap[path .. "." .. k] = v
		end
	end
	for k, v in pairs(inst.Attributes or {}) do
		if isScalar(v) then snap[path .. "@" .. k] = v end
	end
end

function Onyx.snapshot()
	local snap = {}
	local function walk(node, prefix)
		for _, c in ipairs(node.Children) do
			local path = prefix .. "." .. c.Name
			local value = rawget(c, "Value")
			if isScalar(value) then snap[path] = value end
			if Onyx.sliceMode then captureScalars(snap, c, path, "") end
			for k, v in pairs(c.Attributes or {}) do
				if isScalar(v) then snap[path .. "@" .. k] = v end
			end
			snap[path .. "#class"] = c.ClassName
			walk(c, path)
		end
	end
	for _, p in ipairs(Players._list) do
		walk(p, "player:" .. p.Name)
		for k, v in pairs(p.Attributes or {}) do
			if isScalar(v) then snap["player:" .. p.Name .. "@" .. k] = v end
		end
	end

	-- The rest of the instance tree (Workspace, storage services, world props a
	-- handler writes). Players are already captured above and are skipped here so one
	-- movement never appears twice.
	if Onyx.sliceMode then
		local function walkWorld(node, prefix, depth)
			if depth > 8 then return end
			for _, c in ipairs(node.Children) do
				if c.ClassName ~= "Player" then
					local path = prefix == nil and ("inst:" .. c.Name) or (prefix .. "." .. c.Name)
					captureScalars(snap, c, path, ".Value")
					snap[path .. "#class"] = c.ClassName
					walkWorld(c, path, depth + 1)
				end
			end
		end
		walkWorld(Onyx.game, nil, 0)
	end

	for storeName, store in pairs(Onyx.datastores) do
		for k, v in pairs(store:Dump()) do
			flattenStore("store:" .. storeName .. "/" .. k, v, snap, 0)
		end
	end
	return snap
end

function Onyx.diff(before, after)
	local changed = {}
	for k, v in pairs(after) do
		if before[k] ~= v and not k:match("#class$") then
			table.insert(changed, { key = k, before = before[k], after = v })
		end
	end
	table.sort(changed, function(a, b) return a.key < b.key end)
	return changed
end

-- Marker protocol must also survive a place that shadows a *primitive* the emit path uses
-- (`type(value)` can itself be shadowed when a place script assigns a string to the global
-- `type`, which would turn markers into "attempt to call a string value"). Capture the
-- primitives before any place script can shadow them.
local rawType = type
local rawTostring = tostring
local rawFormat = string.format

-- Marker protocol must survive a place that replaces the global `print` (real places do
-- this: one place script prefixes every line with a tag, which made every marker
-- unreadable). Capture the interpreter's print before any place script can shadow it.
local rawPrint = print

-- ---------------------------------------------------------------- emit
local function esc(s)
	s = rawTostring(s)
	s = s:gsub("\\", "\\\\")
	s = s:gsub("\n", "\\n")
	s = s:gsub("\r", "")
	s = s:gsub("=", "\\eq")
	s = s:gsub(":", "\\co")
	return s
end
local function unesc(s)
	s = s:gsub("\\n", "\n")
	s = s:gsub("\\eq", "=")
	s = s:gsub("\\co", ":")
	s = s:gsub("\\\\", "\\")
	return s
end

function Onyx.emit(key, value)
	if rawType(value) == "number" then
		value = rawFormat("%.10g", value)
	end
	rawPrint("@@ONYX|" .. key .. "|" .. esc(value))
end

function Onyx.emitChanged(changed)
	for _, c in ipairs(changed) do
		Onyx.emit("change", c.key .. "|" .. tostring(c.before) .. "|" .. tostring(c.after))
	end
end

-- ---------------------------------------------------------------- clientside
-- The harness runs in two phases: server scripts (clientMode = false), then the
-- client-side phase: LocalScripts, then the fuzz loop (clientMode = true). Facts
-- that can only happen on one side get their own channels so the judge can
-- confirm them instead of inferring them from source.
Onyx.clientMode = false
Onyx.clientServices = {}
Onyx.clientRemotes = {}
Onyx.dynCalls = {}
Onyx.wrongDirection = {}
Onyx.SERVER_ONLY_SERVICES = {
	DataStoreService = true,
	ServerStorage = true,
	ServerScriptService = true,
	HttpService = true,
	MarketplaceService = true,
	MemoryStoreService = true,
}

-- loadstring / getfenv are the runtime-code surface. Recording every call makes
-- "code was compiled at runtime" an observation rather than a source reading.
local rawLoadstring = loadstring
local loadstring = function(src)
	table.insert(Onyx.dynCalls, { via = "loadstring", src = tostring(src) })
	if rawLoadstring then
		local ok, fn = pcall(rawLoadstring, src)
		if ok then return fn end
		return nil, tostring(fn)
	end
	return nil, "loadstring unavailable"
end
if type(getfenv) == "function" then
	local rawGetfenv = getfenv
	local getfenv = function(level)
		table.insert(Onyx.dynCalls, { via = "getfenv", src = tostring(level) })
		return rawGetfenv(level)
	end
end

function Onyx.emitLog()
	for _, line in ipairs(Onyx.log) do
		Onyx.emit("log", line)
	end
	for _, call in ipairs(Onyx.remoteCalls) do
		if call.store then
			Onyx.emit("storecall", (call.store or "") .. "|" .. (call.key or "") .. "|" .. (call.op or ""))
		end
	end
	for _, call in ipairs(Onyx.httpCalls) do
		Onyx.emit("httpcall", (call.op or "") .. "|" .. (call.url or ""))
	end
	for _, call in ipairs(Onyx.dynCalls) do
		Onyx.emit("dyn_code", (call.via or "") .. "|" .. (call.src or ""))
	end
	for _, name in ipairs(Onyx.clientServices) do
		Onyx.emit("client_service", name)
	end
	for _, r in ipairs(Onyx.clientRemotes) do
		Onyx.emit("client_remote", (r.class or "") .. "|" .. (r.name or ""))
	end
	for _, w in ipairs(Onyx.wrongDirection) do
		Onyx.emit("wrong_direction", (w.remote or "") .. "|" .. (w.via or ""))
	end
end

-- ---------------------------------------------------------------- globals
-- _G is readonly in the Luau CLI, so these are chunk-scope locals. Because the
-- emulator, the world, and every script are concatenated into a single chunk,
-- scripts resolve `game`, `Instance`, `workspace`, `Enum` etc. to these.
local workspace = makeService("Workspace")
-- Legacy global some 2006-2016 places use (`Workspace.X`, capital W). Real Roblox had it;
-- places that use it died at load in the emulator, which made their claims unjudgeable
-- Alias it to the same service.
local Workspace = workspace
-- Luau rejects `require(<Instance>)` ("string expected, got table"); real places require
-- ModuleScript instances. Return a permissive stub so the requiring script can finish
-- loading and register its handler. Fields are plain functions returning nil: code that
-- calls a module function later still errors there, but the trust boundary is already
-- observable by then (the handler exists, DataStore calls happen before the stub is used).
local function requireStub(_target)
	return setmetatable({}, { __index = function() return function() return nil end end })
end
local require = requireStub
addChild(game, workspace)
game.Workspace = workspace
services.Workspace = workspace

local wait = function() return awaitBudget() end
local spawn = function(fn) pcall(fn) end
local delay = function(_t, fn) pcall(fn) end
local warn = function(...) pushLog("warn", table.concat({...}, " ")) end
local tick = function() return os.clock() end
local time = function() return os.time() end
local settings = function() return {} end
local getgenv = function() return Onyx end
local ypcall = function(fn, ...)
	local res = { pcall(fn, ...) }
	return table.unpack(res)
end
local Tick = tick
