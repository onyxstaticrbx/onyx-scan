--!nocheck
-- Differential fuzz driver. The claim it can support is narrow and real:
-- a client can cause server state to change to a value the client chose.
-- It emits raw evidence; Python does the judgement.

-- Onyx is a chunk-scope local from the mock
local function resolve(path)
	local parts = {}
	for seg in string.gmatch(path, "[^%.]+") do table.insert(parts, seg) end
	if parts[1] == "game" then table.remove(parts, 1) end
	local node = Onyx.game
	for _, seg in ipairs(parts) do
		if not node then return nil end
		node = node:FindFirstChild(seg)
	end
	return node
end

local PAYLOADS = {
	{ label = "no_args", args = {} },
	{ label = "one", args = { 1 } },
	{ label = "thousand", args = { 1000 } },
	{ label = "billion", args = { 1000000000 } },
	{ label = "negative_one", args = { -1 } },
	{ label = "negative_billion", args = { -1000000000 } },
	{ label = "zero", args = { 0 } },
	{ label = "string", args = { "client-controlled" } },
	{ label = "boolean", args = { true } },
	{ label = "table", args = { { amount = 1000000 } } },
	{ label = "two_args", args = { 1000000, 1000000 } },
}

local function fireRemote(remote, payload)
	if remote.ClassName == "RemoteFunction" then
		return pcall(function() return remote:InvokeServer(table.unpack(payload.args)) end)
	end
	return pcall(function() return remote:FireServer(table.unpack(payload.args)) end)
end

Onyx.emit("remotes_found", tostring(#(Onyx.remotePaths or {})))
Onyx.emit("player", Onyx.currentPlayer and Onyx.currentPlayer.Name or "none")

-- ==== receipt scenario ====
-- Deliver a receipt to the server's ProcessReceipt handler and record the decision it
-- returns. A handler that grants without returning PurchaseGranted is the retry-forever
-- bug; the Python judge turns "state changed + no acknowledgement" into a claim. The
-- handler runs with clientMode off so this phase cannot be mistaken for a client using a
-- server-only service.
--
-- The same phase feeds two L009 observations: how many persistent writes happened during
-- the delivery (an acknowledgement with zero writes is not a persisted grant), and what
-- the handler says when writes are forced to fail (a "granted" after a failed save is the
-- acknowledgement-before-persistence bug).
do
	local handler = MarketplaceService and MarketplaceService.ProcessReceipt
	if type(handler) == "function" then
		Onyx.clientMode = false
		local player = Onyx.currentPlayer
		local function deliver(pid, tag)
			local before = Onyx.snapshot()
			local writesBefore = #Onyx.remoteCalls
			local attemptsBefore = Onyx.writeAttempts
			local ok, decision = pcall(handler, {
				PlayerId = player.UserId,
				ProductId = pid,
				PurchaseId = "onyx-receipt-" .. tag .. tostring(pid),
			})
			local after = Onyx.snapshot()
			local changes = Onyx.diff(before, after)
			-- A DataStore write is persistence, not a grant: counting it as "state changed"
			-- would report a handler that saves-without-acknowledging as granting.
			local stateChanges = 0
			for _, c in ipairs(changes) do
				if not c.key:match("^store:") then stateChanges = stateChanges + 1 end
			end
			local granted = ok and decision == Enum.ProductPurchaseDecision.PurchaseGranted
			return granted, ok, stateChanges, #Onyx.remoteCalls - writesBefore,
				Onyx.writeAttempts - attemptsBefore
		end
		for _, pid in ipairs(Onyx.receiptProductIds or {}) do
			local granted, ok, changed, writes = deliver(pid, "")
			Onyx.emit(
				"receipt",
				tostring(pid) .. "|" .. (granted and "1" or "0")
					.. "|" .. (ok and "1" or "0") .. "|" .. tostring(changed)
			)
			if granted then
				Onyx.emit("receipt_store", tostring(pid) .. "|" .. tostring(writes))
				Onyx.failWrites = true
				local fGranted, fOk, _fChanged, _fWrites, fAttempts = deliver(pid, "fail-")
				Onyx.failWrites = false
				Onyx.emit(
					"receipt_fail",
					tostring(pid) .. "|" .. (fGranted and "1" or "0") .. "|" .. (fOk and "1" or "0")
						.. "|" .. tostring(fAttempts)
				)
			end
		end
		Onyx.clientMode = true
	end
end

local baseline = Onyx.snapshot()
Onyx.emitChanged(Onyx.diff(baseline, baseline))

for _, path in ipairs(Onyx.remotePaths or {}) do
	local remote = resolve(path)
	if remote then
		Onyx.emit("remote", path .. "|" .. remote.ClassName)
		for idx, payload in ipairs(PAYLOADS) do
			Onyx.emit("payload", path .. "|" .. tostring(idx) .. "|" .. payload.label)
			local before = Onyx.snapshot()
			local ok, err = fireRemote(remote, payload)
			local after = Onyx.snapshot()
			local changed = Onyx.diff(before, after)
			if not ok then
				Onyx.emit("fault", path .. "|" .. tostring(idx) .. "|" .. tostring(err))
			end
			for _, c in ipairs(changed) do
				Onyx.emit("delta", path .. "|" .. tostring(idx) .. "|" .. c.key .. "|" .. tostring(c.before) .. "|" .. tostring(c.after))
			end
		end
	end
end

-- Report members a handler asked for on a supplied instance shape. They are refusals,
-- not state: the judge must never build a fact on a member the mock invented.
local function emitSorted(bucket, marker)
	local keys = {}
	for k in pairs(bucket or {}) do table.insert(keys, k) end
	table.sort(keys)
	for _, k in ipairs(keys) do Onyx.emit(marker, k) end
end
emitSorted(Onyx.shapeMisses, "shape_miss")
emitSorted(Onyx.shapeWrites, "shape_write")

Onyx.emitLog()
Onyx.emit("done", "1")
