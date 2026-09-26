--!optimize 2
---!strict

--[[
	Using dot notations to prevent __namecall hooks
	ClientWatchdog LocalScript
	Consolidated onto a single remote ("Heartbeat") using a Nonce-based
	challenge/response protocol. Functionality is otherwise 1:1 with the
	original multi-remote version.

	Preserved caveats from the original author's notes (still true):
	  - CheckClosureSource relies on debug.info reporting "[C]" for native
	    functions. A hookfunction impl that fakes that source string will
	    slip past it. Kept as one signal among several, not standalone proof.
	  - Env-tamper checks fingerprint *current* engine error wording. If
	    Roblox changes error text, these need to be re-validated against
	    a clean client.

	New caveat from this pass:
	  - Detections (QueueExploit/QueueLog) no longer fire the instant they
	    happen. They're queued and only go out attached to the next Nonce
	    response, since a response can only be sent when answering a
	    server-issued challenge. Worst-case delay is HEARTBEAT_INTERVAL
	    seconds (server-side constant). Detection logic itself is unchanged.

	Sections:
		1. Self-obfuscation (hide script name/reference from explorers)
		2. Cached globals (frozen at T0 for identity-drift comparisons)
		3. Remote plumbing (hidden Heartbeat remote, queueing, challenge
		   response handler)
		4. Engine-service integrity checks (LogService / ScriptContext)
		5. Log history verification
		6. Environment / engine tamper checks
		7. World-state watchers (ESP props, GUI injection, camera FOV)
		8. Persistent LogService / ScriptContext listeners

		Credits to arkham ron20233 on dev forumns for crash client.
]]

--============================================================
-- 1. SELF-OBFUSCATION + EARLY CACHING TO PREVENT HOOKS.
--============================================================

const clientVersion1: string = Version()
const clientVersion2: string = version()

local selfRef = script
const toStringRef = tostring
const mathRandom = math.random

selfRef.Name = toStringRef(mathRandom(100000, 999999))
script = nil
selfRef:Destroy()

--============================================================
-- 2. CACHED GLOBALS (frozen as early as possible)
--============================================================

const getServiceRef = game.GetService
const findServiceRef = game.FindService
const MessageType = Enum.MessageType
const refGame = game

const UNPACK = unpack
const Vector2One = Vector2.one
const coroutineCreateRef = coroutine.create
const coroutineResumeRef = coroutine.resume
const coroutineWrapRef = coroutine.wrap
const MathPiRef = math.pi
const MathHugeRef = math.huge
const MathAtanRef = math.atan
const MathSqrtRef = math.sqrt
const stringRepRef = string.rep
const rawequalRef = rawequal
const rawgetRef = rawget
const rawsetRef = rawset
const getmetatableRef = getmetatable
const setmetatableRef = setmetatable
const newproxyRef = newproxy
const xpcallRef = xpcall
const selectRef = select
const nextRef = next
const debugInfoRef = debug.info
const taskWait = task.wait
const taskDelay = task.delay
const taskSpawn = task.spawn
const stringLower = string.lower
const stringFind = string.find
const stringLen = string.len
const tableFind = table.find
const pcallRef = pcall
const typeRef = type
const typeofRef = typeof
const pairsRef = pairs
const ipairsRef = ipairs
const warnRef = warn
const errorRef = error
const instanceNewRef = Instance.new
const tableFreezeRef = table.freeze
const tableInsertRef = table.insert
const printRef = print
const tableRemoveRef = table.remove
const stringByteRef = string.byte
const tableConcatRef = table.concat
const Bit32BXORRef = bit32.bxor
const Bit32BandRef = bit32.band
const Bit32rShiftRef = bit32.rshift
const CoroutineYieldRef = coroutine.yield
const TonumberRef = tonumber
const StringSubRef = string.sub
const StringMatchRef = string.match

local gcTracker = setmetatableRef({}, { __mode = "v" })

local ReplicatedStorage: ReplicatedStorage = getServiceRef(refGame, "ReplicatedStorage")
local LogService: LogService = getServiceRef(refGame, "LogService")
local ScriptContext: ScriptContext = getServiceRef(refGame, "ScriptContext")
local Players: Players = getServiceRef(refGame, "Players")
local Workspace: Workspace = getServiceRef(refGame, "Workspace")
local GuiService: GuiService = getServiceRef(refGame, "GuiService")
local UserInputService: UserInputService = getServiceRef(refGame, "UserInputService")
local TextService: TextService = getServiceRef(refGame, "TextService")

local LocalPlayer = Players.LocalPlayer
local IsClientCrashed = false

const MAX_FIELD_OF_VIEW = 70
const MAX_WAIT_TIME = 30
const ENABLE_CLIENT_VERSION_CHECK = false
const VERBOSE_LOGGING = false
const MAX_QUEUED_REASONS_PER_HEARTBEAT = 10
const MAX_QUEUED_LOGS_PER_HEARTBEAT = 20

local TextSetting = nil
local invalidSize = nil

if ENABLE_CLIENT_VERSION_CHECK then
TextSettings = {
	16,
	"SourceSans",
	Vector2One * 1000,
}

invalidSize = TextService:GetTextSize("\u{FFFF}", UNPACK(TextSettings))
end

local FNV_OFFSET_BASIS = 2166136261
local FNV_PRIME = 16777619
local MASK32 = 0xFFFFFFFF

--============================================================
-- 3. REMOTE PLUMBING
-- Single remote now: Heartbeat. Server issues a Nonce, we answer with
-- a hash of (nonce, status, reason) computed via the shared
-- HeartbeatHash module, plus any queued log entries.
--============================================================

local Remotes = ReplicatedStorage:WaitForChild("Remotes")
local Heartbeat = Remotes:WaitForChild("Heartbeat")

local fireHeartbeat = Heartbeat.FireServer
local heartbeatSignal = Heartbeat.OnClientEvent

Heartbeat.Parent = nil

local CORE_GUI_HONEYPOT = instanceNewRef("Folder")
CORE_GUI_HONEYPOT.Name = "CoreGui"
CORE_GUI_HONEYPOT.Parent = refGame

local function characterExists(character)
	if not ENABLE_CLIENT_VERSION_CHECK then return end
	local size = TextService:GetTextSize(character, UNPACK(TextSettings))
	return size.Magnitude ~= invalidSize.Magnitude
end

local function getArchitecture()
	if not ENABLE_CLIENT_VERSION_CHECK then return end
	local address = TonumberRef(StringSubRef(toStringRef{MathHugeRef}, 8))
	if stringLen(toStringRef(address)) <= 10 then
		return 32
	end
	return 64
end

local function getPlatformType()
	if not ENABLE_CLIENT_VERSION_CHECK then return end
	-- 1. Detect Console
	if GuiService:IsTenFootInterface() then
		return "Console"
	end

	-- 2. Check if Mobile using your version-matching logic
	local isMobile = StringMatchRef(clientVersion1, "^2%.") ~= nil

	if isMobile then
		if getArchitecture() == 32 or not characterExists("\u{F8FF}") then
			return "Android"
		else
			return "iOS"
		end
	end

	-- 3. Detect Desktop-class inputs (Keyboard + Mouse)
	local hasDesktopInputs = UserInputService.KeyboardEnabled and UserInputService.MouseEnabled

	if hasDesktopInputs then
		-- Use GuiService.IsWindows to check for Windows
		local success, isWindows = pcallRef(function()
			return GuiService.IsWindows
		end)

		if success and isWindows then
			return "Windows"
		else
			-- Process of elimination: Desktop inputs + Not Windows = Mac
			return "Mac"
		end
	end

	return "Unknown"
end

local CLIENT_PLATFORM = nil
if ENABLE_CLIENT_VERSION_CHECK then
	CLIENT_PLATFORM = getPlatformType() :: string
	print("Detected Platform: ", CLIENT_PLATFORM)
end

const function getExpectedVersion(platform: string, currentVersionData): string?
	if not ENABLE_CLIENT_VERSION_CHECK then return end
	if not currentVersionData then return nil end
	if typeofRef(currentVersionData) ~= "table" then return nil end

	if platform == "Windows" and currentVersionData.WindowsResponse then
		return currentVersionData.WindowsResponse.version
	elseif platform == "Mac" and currentVersionData.MacResponse then
		return currentVersionData.MacResponse.version
	elseif platform == "Android" then
		return currentVersionData.Android
	elseif platform == "iOS" then
		return currentVersionData.iOS
	end

	return nil
end

--[[
	Custom Implementation of FindService that helps against a new exploit method called oth.hook it basicallt tries to use findservice
	to find a servoce first if it finds the service it return it if it dosen't then it tries to lookf or it by using findfirstchild
	on the game and searching for the name.
]]
const function NewFindService(ServiceName: string): Instance?
	if typeRef(ServiceName) ~= "string" or ServiceName == "" then
		return nil
	end

	local service = findServiceRef(refGame, ServiceName):: Instance?

	if service then
		if service:IsA("Folder") and service.Name == "CoreGui" then
			return nil
		end

		return service
	end

	local exactChild = refGame:FindFirstChild(ServiceName)
	if exactChild then
		if exactChild:IsA("Folder") and exactChild.Name == "CoreGui" then
			return nil
		end

		return exactChild
	end	

	return nil
end

-- Standard FNV-1a over the payload string (nonce|status|reason).
const function FNV1a(str: string): number
	local hash = FNV_OFFSET_BASIS
	for i = 1, #str do
		hash = Bit32BXORRef(hash, stringByteRef(str, i))
		hash = Bit32BandRef(hash * FNV_PRIME, MASK32)
	end
	return hash
end

-- Extra avalanche/mixing pass so the result isn't just a plain FNV1a of a
-- predictable string layout — folds the raw numeric Nonce back in after
-- the string hash so the final value depends on the Nonce twice, in two
-- different ways (once as text, once as a mixed-in integer).
const function MixWithNonce(hash: number, nonce: number): number
	local mixed = Bit32BXORRef(hash, nonce)
	mixed = Bit32BandRef(mixed * 2654435761, MASK32) -- Knuth multiplicative hash
	mixed = Bit32BXORRef(mixed, Bit32rShiftRef(mixed, 15))
	mixed = Bit32BandRef(mixed * 2246822519, MASK32)
	mixed = Bit32BXORRef(mixed, Bit32rShiftRef(mixed, 13))
	return mixed
end

-- nonce: the one-time number issued by the server this cycle
-- status: "OK" | "FLAGGED"
-- reason: string if FLAGGED, nil/omitted if OK
const function Compute(nonce: number, status: string, reason: string?): number
	local payload = toStringRef(nonce) .. "|" .. status .. "|" .. (reason or "")
	local baseHash = FNV1a(payload)
	return MixWithNonce(baseHash, nonce)
end

-- removed crashing client code

--local crash1 = coroutineCreateRef(function()
--	local t = {}
--	while true do
--		for i = MathPiRef, MathHugeRef, MathPiRef do
--			tableInsertRef(t, i)
--		end
--	end
--end)

--local crash2 = coroutineCreateRef(function()
--	while true do
--		local desc = Workspace:GetDescendants()

--		for _, v in pairsRef(desc) do
--			local big = instanceNewRef("Fire", v)
--			local new = instanceNewRef("Part", Workspace)
--			local big2 = instanceNewRef("Fire", new)
--			big.Size = 9999999999
--			big.Heat = 9999999999
--			big.TimeScale = 1
--			big2.Size = 9999999999
--			big2.Heat = 9999999999
--			big2.TimeScale = 1
--		end
--	end
--end)

--const function CrashClient()
--	IsClientCrashed = true
--	coroutineResumeRef(crash1)
--	coroutineResumeRef(crash2)
--end

const function SafeFireHeartbeat(payload: any)
	Heartbeat.Parent = Remotes
	fireHeartbeat(Heartbeat, payload)
	Heartbeat.Parent = nil
end

const function vWarn(msg: string)
	if VERBOSE_LOGGING then
		warnRef("[AC:Client] " .. msg)
	end
end

const function CheckFunctionType(fn: any): "L" | "C" | nil
	-- debug.info with "s" returns the script name for Luau functions
	-- For many built-in C functions, it might return "[C]" or empty/nil depending on the environment
	if typeRef(fn) ~= "function" then
		return nil
	end

	local src = debugInfoRef(fn, "s")
	if src == "[C]" then
		return "c"
	else
		return "l"
	end
end

-- Pending reports queued since the last heartbeat response, flushed on
-- the next challenge.
local pendingReasons = {}
local pendingLogs = {}

const function QueueExploit(reason: string)
	vWarn("[Queued Exploit] " .. reason)
	tableInsertRef(pendingReasons, reason)
	if #pendingReasons > MAX_QUEUED_REASONS_PER_HEARTBEAT then
		tableRemoveRef(pendingReasons, 1)
	end

	if not IsClientCrashed then	
		--taskWait(60)
		--CrashClient()
	end
end

const function QueueLog(message: string, source: string)
	tableInsertRef(pendingLogs, { message = message, source = source })
	if #pendingLogs > MAX_QUEUED_LOGS_PER_HEARTBEAT then
		tableRemoveRef(pendingLogs, 1)
	end
end

if ENABLE_CLIENT_VERSION_CHECK then
	Remotes.LatestClientVersion.OnClientEvent:Connect(function(CurrentVersionData)
		if not ENABLE_CLIENT_VERSION_CHECK then return end
		warn("CLIENT RECIEVED")

		if typeofRef(CurrentVersionData) ~= "table" then
			LocalPlayer.Kick(LocalPlayer, "BAD BOIII!")
			return
		end

		-- means they forgot to hook the second one!
		if clientVersion1 ~= clientVersion2 then
			LocalPlayer.Kick(LocalPlayer, "BAD BOII")
		end

		local expectedVersion = getExpectedVersion(CLIENT_PLATFORM, CurrentVersionData)

		if expectedVersion ~= clientVersion1 then
			print("CLIENT VERSION MISMATCH! CLIENT VERSION: ".. toStringRef(clientVersion1).. " | VERSION EXPECTED: ".. toStringRef(expectedVersion) )
			LocalPlayer.Kick(LocalPlayer, "Client version mismatch")
		end

	end)
end

-- Answer a Nonce challenge from the server: build current status from
-- whatever's queued, hash it, send it, then clear the queues.
heartbeatSignal:Connect(function(challenge: any)
	if typeRef(challenge) ~= "table" or typeRef(challenge.nonce) ~= "number" then
		return
	end

	local nonce = challenge.nonce
	local status = "OK"
	local reason = nil

	if #pendingReasons > 0 then
		status = "FLAGGED"
		reason = tableConcatRef(pendingReasons, "; ")
	end

	local hash = Compute(nonce, status, reason)

	local logsToSend = pendingLogs
	pendingLogs = {}
	pendingReasons = {}

	SafeFireHeartbeat({
		nonce = nonce,
		status = status,
		reason = reason,
		hash = hash,
		logs = logsToSend,
	})
end)

--============================================================
-- DETECTION LISTS
--============================================================

const WHITELISTED_GUI = {
	"MainGui", "ShopGui", "InventoryGui",
	"TopbarCenteredClipped", "TopbarStandardClipped",
	"TopbarStandard", "TopbarCentered", "HDAdminInterface",
}

const BLACKLISTED_UI = {
	"dex", "cobalt", "mainmenu", "intro", "explorerselections", "properties", "ketamine",
}

const BLACKLISTED_TERMS = {
	"httpget", "loadstring", "getgenv", "getrawmetatable",
	"hookmetamethod", "hookfunction", "newcclosure", "replaceclosure",
	"synapse", "krnl", "fluxus", "xeno", "madium", "wave",
	"dex", "remotespy", "rayfield", "electron", "oxygen",
	"celery", "scriptware", "exploit", "executor",
	"cobalt", "syn", "explorerselections", "ketamine",
}

const INTERNAL_SCRIPT_PATH_MARKERS = {
	"starterplayer", "starterpack", "playergui",
	"replicatedstorage", "corescripts", "robloxgui",
}

tableFreezeRef(WHITELISTED_GUI)
tableFreezeRef(BLACKLISTED_UI)
tableFreezeRef(BLACKLISTED_TERMS)
tableFreezeRef(INTERNAL_SCRIPT_PATH_MARKERS)

const function IsSuspiciousMessage(msg: string): boolean
	local lower = stringLower(msg)
	for _, term in ipairsRef(BLACKLISTED_TERMS) do
		if stringFind(lower, term, 1, true) then
			return true
		end
	end
	return false
end

--============================================================
-- 4. ENGINE-SERVICE INTEGRITY CHECKS
--============================================================

local logServiceIntact = true
local scriptContextIntact = true

const function VerifyLogServiceTypes()
	if typeofRef(LogService.MessageOut) ~= "RBXScriptSignal" or typeRef(LogService.MessageOut) ~= "userdata" then
		logServiceIntact = false
		QueueExploit("LogService.MessageOut hook detected (type check)")
	end
end

const function VerifyScriptContextTypes()
	if typeofRef(ScriptContext.Error) ~= "RBXScriptSignal" or typeRef(ScriptContext.Error) ~= "userdata" then
		scriptContextIntact = false
		QueueExploit("ScriptContext.Error hook detected (type check)")
	end
end

--============================================================
-- 5. LOG HISTORY VERIFICATION
--============================================================

local checkedHistory = {}

const function CheckLogHistory()
	local testKey = "__actest_history_" .. toStringRef(mathRandom(10000, 99999))
	warnRef(testKey)
	taskWait(0.5) -- let the engine flush the log

	local ok, history = pcallRef(function()
		return LogService:GetLogHistory()
	end)

	if typeRef(history) ~= "table" then
		QueueExploit("LogService:GetLogHistory tampered (did not return a table)")
		return
	end

	local foundTestKey = false
	for _, entry in ipairsRef(history) do
		if typeRef(entry) == "table" and typeRef(entry.message) == "string" then
			local msg = entry.message
			if stringFind(msg, testKey, 1, true) then
				foundTestKey = true
			end
			if not checkedHistory[msg] and not stringFind(msg, "__actest", 1, true) then
				checkedHistory[msg] = true
				if IsSuspiciousMessage(msg) then
					QueueLog(msg, "LogHistory")
				end
			end
		end
	end

	if not foundTestKey then
		QueueExploit("LogService:GetLogHistory tampered (logs suppressed)")
	end
end

--============================================================
-- 6. ENVIRONMENT / ENGINE TAMPER CHECKS
--============================================================

local function isNativeIndexError(err) return err and stringFind(err, "is not a valid member of", 1, true) end
local function isNativeGetServiceError(err) return err and stringFind(err, "is not a valid Service name", 1, true) end
local function isNativeInstanceNewError(err) return err and stringFind(err, "Unable to create an Instance of type", 1, true) end
local function isNativeDebugInfoError(err)
	return err and (
		stringFind(err, "missing argument #2 to 'info'", 1, true)
			or stringFind(err, "invalid argument #1 to 'info'", 1, true)
	)
end

const function testFunctionCall(description: string, func, errorCheck): boolean
	local ok, err = pcallRef(func)
	if not ok then
		if errorCheck(err) then
			vWarn(description .. ": PASS (native error confirmed)")
			return false
		end
		QueueExploit("[EnvTamper] " .. description .. " - error text doesn't match native engine wording: " .. toStringRef(err))
		return true
	end
	QueueExploit("[EnvTamper] " .. description .. " - call succeeded / error was swallowed (expected a native error)")
	return true
end

-- mkake child added to coregui honeypot folder.

-- rawequal against the T0-cached ref catches hookfunction/replaceclosure
-- swapping the function object even when behavior looks identical.
local IDENTITY_CHECK_TARGETS = {
	{ rawequalRef, rawequal, "rawequal" },
	{ rawgetRef, rawget, "rawget" },
	{ rawsetRef, rawset, "rawset" },
	{ typeRef, type, "type" },
	{ typeofRef, typeof, "typeof" },
	{ getmetatableRef, getmetatable, "getmetatable" },
	{ setmetatableRef, setmetatable, "setmetatable" },
	{ newproxyRef, newproxy, "newproxy" },
	{ pcallRef, pcall, "pcall" },
	{ xpcallRef, xpcall, "xpcall" },
	{ selectRef, select, "select" },
	{ nextRef, next, "next" },
	{ toStringRef, tostring, "tostring" },
	{ taskWait, task.wait, "task.wait" },
	{ stringLower, string.lower, "string.lower" },
}

local function CheckGlobalIdentityTamper(): boolean
	local drift = {}
	for _, entry in IDENTITY_CHECK_TARGETS do
		local cached, live, name = entry[1], entry[2], entry[3]
		if not rawequalRef(cached, live) then
			tableInsertRef(drift, name)
		end
	end

	if #drift > 0 then
		QueueExploit("[EnvTamper] global identity drift on: " .. tableConcatRef(drift, ", "))
		return true
	end
	vWarn(("global identity check: PASS (%d symbols)"):format(#IDENTITY_CHECK_TARGETS))
	return false
end

const function CheckMetatableGuard(): boolean
	local probe = setmetatableRef({}, { __metatable = "locked" })
	local ok, result = pcallRef(getmetatableRef, probe)
	if not ok then
		QueueExploit("[EnvTamper] getmetatable threw unexpectedly on a locked table")
		return true
	end
	if result ~= "locked" then
		QueueExploit("[EnvTamper] getmetatable bypassed __metatable lock (result: " .. toStringRef(result) .. ")")
		return true
	end
	if pcallRef(setmetatableRef, probe, {}) then
		QueueExploit("[EnvTamper] setmetatable bypassed __metatable lock")
		return true
	end
	vWarn("metatable guard check: PASS")
	return false
end

-- On a clean client getmetatable(game) returns the locked-string sentinel,
-- not a table. A table means Instance metatable protection was bypassed.
const function CheckInstanceMetatableLock(): boolean
	local ok, mt = pcallRef(getmetatableRef, refGame)
	if ok and typeRef(mt) == "table" then
		QueueExploit("[EnvTamper] game's metatable is unlocked/tampered (expected a locked string, got a table)")
		return true
	end
	vWarn("instance metatable lock check: PASS")
	return false
end

-- to do add this check to loop to make it actually do it
-- Checks if the tables is still a readonly table if its not then someone used setreadonly to unfreeze it.
const function CheckTableFreezeIntegrity(): boolean
	local ok = pcallRef(function()
		WHITELISTED_GUI[1] = "Tampered"
		BLACKLISTED_UI[1] = "Tampered"
		BLACKLISTED_TERMS[1] = "Tampered"
		INTERNAL_SCRIPT_PATH_MARKERS[1] = "Tampered"
	end)

	if ok then
		QueueExploit("[EnvTamper] table is unfrozen. Frozen detection table was mutated")
	end

end

const function CheckClosureSource(func, name: string): boolean
	if typeRef(func) ~= "function" then
		return false
	end
	local ok, info = pcallRef(debugInfoRef, func, "s")
	if not ok then
		vWarn(name .. " closure-source check skipped (debug.info unavailable)")
		return false
	end
	if info ~= "[C]" then
		QueueExploit("[EnvTamper] hookfunction suspected on " .. name .. " (reported source: " .. toStringRef(info) .. ")")
		return true
	end
	vWarn(name .. " closure-source check: PASS")
	return false
end

local function GetCallerFromXpcall(BaseFunction)
	return selectRef(2, xpcallRef(BaseFunction, function()
		return debugInfoRef(2, "f")
	end))
end

local __namecall = GetCallerFromXpcall(function() return refGame:____() end)
--local __newindex = GetCallerFromXpcall(function()
--	local var = refGame.____ == nil
--	return var
--end)

--local __newindex = GetCallerFromXpcall(function() return refGame.____ = nil end) -- was erroring
local __index = GetCallerFromXpcall(function() return refGame.____ end)

local C_REF_CHECKS = {
	{ "tostring", toStringRef },
	{ "math.random", mathRandom },
	{ "coroutine.create", coroutineCreateRef },
	{ "coroutine.resume", coroutineResumeRef },
	{ "math.atan", MathAtanRef },
	{ "math.sqrt", MathSqrtRef },
	{ "string.rep", stringRepRef },
	{ "rawequal", rawequalRef },
	{ "rawget", rawgetRef },
	{ "rawset", rawsetRef },
	{ "getmetatable", getmetatableRef },
	{ "setmetatable", setmetatableRef },
	{ "newproxy", newproxyRef },
	{ "xpcall", xpcallRef },
	{ "select", selectRef },
	{ "next", nextRef },
	{ "debug.info", debugInfoRef },
	{ "task.wait", taskWait },
	{ "task.delay", taskDelay },
	{ "task.spawn", taskSpawn },
	{ "string.lower", stringLower },
	{ "string.find", stringFind },
	{ "string.len", stringLen },
	{ "table.find", tableFind },
	{ "pcall", pcallRef },
	{ "type", typeRef },
	{ "typeof", typeofRef },
	{ "pairs", pairsRef },
	{ "ipairs", ipairsRef },
	{ "warn", warnRef },
	{ "error", errorRef },
	{ "Instance.new", instanceNewRef },
	{ "table.freeze", tableFreezeRef },
	{ "table.insert", tableInsertRef },
	{ "print", printRef },
	{ "game.GetService", refGame.GetService },
	{ "game.IsA", refGame.IsA },
	{ "game.FindFirstChild", refGame.FindFirstChild },
	{ "game.WaitForChild", refGame.WaitForChild },
	{ "Workspace.GetChildren", Workspace.GetChildren },
	{ "Players.GetPlayers", Players.GetPlayers },
	{ "LogService.GetLogHistory", LogService.GetLogHistory },
}

local function CheckAllCachedCRefs(): boolean
	local hits = 0
	for _, entry in ipairsRef(C_REF_CHECKS) do
		local name, fn = entry[1], entry[2]
		if typeRef(fn) == "function" then
			if CheckClosureSource(fn, name) then
				hits += 1
			end
		end
	end

	if hits == 0 then
		vWarn(("C-ref check: PASS (%d functions)"):format(#C_REF_CHECKS))
	end

	return hits > 0
end

local function CheckRawMetaMethodHooks(): boolean
	local nc = GetCallerFromXpcall(function() return refGame:____() end)
	local ix = GetCallerFromXpcall(function() return refGame.____ end)

	-- If the probe failed (returned nil / non-function), don't accuse anyone.
	if typeRef(nc) ~= "function" or typeRef(ix) ~= "function" then
		vWarn("raw metamethod hook check: SKIPPED (probe returned non-function)")
		return false
	end

	if nc ~= __namecall or ix ~= __index then
		QueueExploit("[MetaHook] Raw __namecall/__index hook detected on game metatable")
		return true
	end

	vWarn("raw metamethod hook check: PASS")
	return false
end


local function IsReferenced(Object): boolean
	local Table = {}
	local WeakMT = setmetatableRef({
		Table, 1, "String", Object,
	}, {
		__mode = "kv"
	})

	Table = nil
	Object = nil

	local waited = 0
	repeat
		taskWait()
		waited += 1
	until not WeakMT[1] or waited > 100

	taskWait(0.2)

	if #WeakMT ~= 3 then
		return true
	end

	return false
end

local function CheckCoreGuiReference(): boolean
	local ok, detected = pcallRef(function()
		return IsReferenced(refGame:GetService("CoreGui"))
	end)

	if ok and detected then
		QueueExploit("[GUI] CoreGui referenced without cloneref (Dex/Infinite Yield/Rayfield/etc.)")
		return true
	end

	vWarn("CoreGui reference check: PASS")
	return false
end

--local function CheckInsertServiceReference(): boolean
--	local ok, detected = pcallRef(function()
--		return IsReferenced(refGame:GetService("InsertService"))
--	end)

--	if ok and detected then
--		QueueExploit("[Executor] InsertService referenced (Electron-style executor)")
--		return true
--	end

--	vWarn("InsertService reference check: PASS")
--	return false
--end

--============================================================
-- Basic hook detection via C-stack overflow
-- Throttle this. It is old and can false-positive.
--============================================================

local function IsHooked(Closure): boolean
	for _ = 1, 198 do
		Closure = coroutineWrapRef(Closure)
	end

	local Success, Out = pcallRef(Closure)
	if (not Success) and stringFind(Out, "C stack overflow", 1, true) then
		return true
	end

	return false
end

local HOOK_CHECK_TARGETS = {
	{ "game.GetService", refGame.GetService },
	{ "Instance.new", instanceNewRef },
	{ "task.wait", taskWait },
	{ "debug.info", debugInfoRef },
	{ "pcall", pcallRef },
	{ "xpcall", xpcallRef },
}

local function CheckBasicHooks(): boolean
	local hit = false

	for _, entry in ipairsRef(HOOK_CHECK_TARGETS) do
		if IsHooked(entry[2]) then
			QueueExploit("[Hook] C-stack overflow on " .. entry[1] .. " (hookfunction/detour)")
			hit = true
		end
	end

	return hit
end

--============================================================
-- tostring(self/args) detection
-- Catches bad hooks that call tostring(self) or tostring(arg)
--============================================================

local function IsTostringDetected(Func): boolean
	local Called = false
	local Bait = setmetatableRef({}, {
		__tostring = function(self)
			Called = true
			return ""
		end
	})

	if Func == __namecall then
		refGame:GetFullName()
	end

	pcallRef(Func, Bait, Bait, Bait)
	return Called
end

local function CheckTostringOnMetamethods(): boolean
	local hit = false

	if typeRef(__namecall) == "function" and IsTostringDetected(__namecall) then
		QueueExploit("[Hook] tostring called on self/args in game __namecall")
		hit = true
	end

	if typeRef(__index) == "function" and IsTostringDetected(__index) then
		QueueExploit("[Hook] tostring called on self/args in game __index")
		hit = true
	end

	return hit
end

--============================================================
-- Runner
--============================================================

local function RunLegacyChecks()
	CheckAllCachedCRefs()
	CheckRawMetaMethodHooks()
	CheckCoreGuiReference()
	--CheckInsertServiceReference()
	CheckBasicHooks()
	CheckTostringOnMetamethods()
end

const function CheckCoreClosures(): boolean
	local targets = {
		{ refGame.GetService, "game.GetService" },
		{ instanceNewRef, "Instance.new" },
		{ refGame.IsA, "Instance.IsA" },
		{ taskWait, "task.wait" },
		{ taskSpawn, "task.spawn" },
	}
	local hit = false
	for _, t in targets do
		if CheckClosureSource(t[1], t[2]) then
			hit = true
		end
	end
	return hit
end

local frozenCoreRefs
const function FreezeCoreRefs()
	frozenCoreRefs = {
		GetService = refGame.GetService,
		InstanceNew = Instance.new,
		IsA = refGame.IsA,
		FindFirstChild = refGame.FindFirstChild,
		WaitForChild = refGame.WaitForChild,
	}
end

const function CheckRefDrift(): boolean
	if not frozenCoreRefs then return false end

	local drift = {}
	if frozenCoreRefs.GetService ~= refGame.GetService then tableInsertRef(drift, "game.GetService") end
	if frozenCoreRefs.InstanceNew ~= Instance.new then tableInsertRef(drift, "Instance.new") end
	if frozenCoreRefs.IsA ~= refGame.IsA then tableInsertRef(drift, "Instance.IsA") end
	if frozenCoreRefs.FindFirstChild ~= refGame.FindFirstChild then tableInsertRef(drift, "Instance.FindFirstChild") end
	if frozenCoreRefs.WaitForChild ~= refGame.WaitForChild then tableInsertRef(drift, "Instance.WaitForChild") end

	if #drift > 0 then
		QueueExploit("[EnvTamper] mid-session reference drift on: " .. tableConcatRef(drift, ", "))
		return true
	end
	vWarn("reference drift check: PASS")
	return false
end

-- Behavioral probe: for each cached ref, call it and compare the result
-- against a value the real implementation is guaranteed to produce.
-- Catches hooks that return constant garbage (nil/false/true) regardless
-- of input — which neither identity drift nor closure-source checks see.
const function CheckFunctionBehaviors(): boolean
	local failures: {string} = {}

	local function expect(cond: boolean, label: string)
		if not cond then
			tableInsertRef(failures, label)
		end
	end

	-- type / typeof
	expect(typeRef(1) == "number", "type(number)")
	expect(typeRef("x") == "string", "type(string)")
	expect(typeRef(nil) == "nil", "type(nil)")
	expect(typeRef(true) == "boolean", "type(boolean)")
	expect(typeRef({}) == "table", "type(table)")
	expect(typeRef(typeRef) == "function", "type(function)")
	expect(typeofRef(1) == "number", "typeof(number)")
	expect(typeofRef({}) == "table", "typeof(table)")

	-- rawequal
	local selfTable = {}
	expect(rawequalRef(selfTable, selfTable) == true, "rawequal(same)")
	expect(rawequalRef({}, {}) == false, "rawequal(diff)")

	-- rawget / rawset
	local rt = {}
	rawsetRef(rt, "k", "v")
	expect(rawgetRef(rt, "k") == "v", "rawget/rawset roundtrip")
	expect(rawgetRef(rt, "missing") == nil, "rawget(missing)")

	-- getmetatable / setmetatable
	local mt = { __index = function() return 42 end }
	local obj = setmetatableRef({}, mt)
	expect(rawequalRef(getmetatableRef(obj), mt), "getmetatable(setmetatable)")
	expect(obj.missing == 42, "setmetatable __index honored")

	-- pcall
	local ok1, val1 = pcallRef(function() return 5 end)
	expect(ok1 == true and val1 == 5, "pcall(success)")
	local ok2 = pcallRef(function() errorRef("probe") end)
	expect(ok2 == false, "pcall(error)")

	-- xpcall
	local ok3, val3 = xpcallRef(function() return 7 end, function(e) return e end)
	expect(ok3 == true and val3 == 7, "xpcall(success)")
	local ok4 = xpcallRef(function() errorRef("probe") end, function(e) return e end)
	expect(ok4 == false, "xpcall(error)")

	-- select
	expect(selectRef("#", 1, 2, 3) == 3, "select('#')")
	local s1, s2 = selectRef(2, "a", "b", "c")
	expect(s1 == "b" and s2 == "c", "select(index)")

	-- next
	local nt = { a = 1 }
	local nk, nv = nextRef(nt)
	expect(nk == "a" and nv == 1, "next(populated)")
	expect(nextRef({}) == nil, "next(empty)")

	-- tostring
	expect(toStringRef(123) == "123", "tostring(123)")
	expect(toStringRef(nil) == "nil", "tostring(nil)")
	expect(toStringRef(true) == "true", "tostring(true)")

	-- string
	expect(stringLower("ABC") == "abc", "string.lower")
	expect(stringFind("hello", "ell") == 2, "string.find(hit)")
	expect(stringFind("hello", "zzz") == nil, "string.find(miss)")
	expect(stringLen("abc") == 3, "string.len")
	expect(stringRepRef("ab", 2) == "abab", "string.rep")

	-- math
	expect(MathSqrtRef(4) == 2, "math.sqrt")
	expect(MathAtanRef(0) == 0, "math.atan")
	expect(MathPiRef > 3.14 and MathPiRef < 3.15, "math.pi")
	expect(MathHugeRef > 0, "math.huge")
	expect(mathRandom(1, 1) == 1, "math.random(1,1)")

	-- table
	expect(tableFind({1, 2, 3}, 2) == 2, "table.find(hit)")
	expect(tableFind({1, 2, 3}, 99) == nil, "table.find(miss)")
	local ft = tableFreezeRef({ a = 1 })
	expect(not pcallRef(function() ft.a = 2 end), "table.freeze")
	local it = {}
	tableInsertRef(it, "x")
	expect(it[1] == "x", "table.insert")

	-- newproxy
	expect(typeRef(newproxyRef(true)) == "userdata", "newproxy")

	-- debug.info on a native C function
	expect(debugInfoRef(printRef, "s") == "[C]", "debug.info on print")

	-- Instance.new
	local inst = instanceNewRef("Folder")
	expect(typeofRef(inst) == "Instance" and inst.ClassName == "Folder", "Instance.new(Folder)")
	if typeofRef(inst) == "Instance" then inst:Destroy() end

	-- game:GetService
	local ok5, svc = pcallRef(function() return refGame:GetService("Players") end)
	expect(ok5 == true and svc == Players, "game:GetService('Players')")

	-- game:IsA
	expect(refGame:IsA("DataModel") == true, "game:IsA(DataModel)")
	expect(refGame:IsA("Part") == false, "game:IsA(Part)")

	-- FindFirstChild on a guaranteed-missing child
	expect(refGame:FindFirstChild("__nonexistent_probe_child__") == nil, "FindFirstChild(missing)")

	-- coroutine
	local co = coroutineCreateRef(function() CoroutineYieldRef(1); return 2 end)
	local okc, valc = coroutineResumeRef(co)
	expect(okc == true and valc == 1, "coroutine.create+resume")

	if #failures > 0 then
		QueueExploit("[Behavior] function behavior mismatch on: " .. tableConcatRef(failures, ", "))
		return true
	end
	vWarn("function behavior check: PASS")
	return false
end

--============================================================
-- Internal AC function integrity
-- An exploiter who can silently neutralize our own detection
-- functions (hookfunction CheckCoreGuiReference to always
-- return false) makes every other check in this file a no-op.
-- We fingerprint each detection function at T0 and re-verify
-- identity + closure-source + line number on every run.
--
-- Note on "checking the result": calling the function and
-- looking at its return value alone can't distinguish
-- "working, no exploit present" from "hooked to always
-- return false" — both produce `false` on a clean client.
-- The identity + source + line fingerprint is what actually
-- catches the hook. We DO additionally re-call the cheap,
-- side-effect-free checks for behavioral sanity.
--============================================================

local INTERNAL_AC_FUNCTIONS = {}
local INTERNAL_AC_FINGERPRINTS = {}

const function FingerprintInternalAC()
	INTERNAL_AC_FUNCTIONS = {
		{ "CheckMetatableGuard", CheckMetatableGuard },
		{ "CheckInstanceMetatableLock", CheckInstanceMetatableLock },
		{ "CheckGlobalIdentityTamper", CheckGlobalIdentityTamper },
		{ "CheckRefDrift", CheckRefDrift },
		{ "CheckFunctionBehaviors", CheckFunctionBehaviors },
		{ "CheckCoreGuiReference", CheckCoreGuiReference },
		{ "CheckRawMetaMethodHooks", CheckRawMetaMethodHooks },
		{ "CheckBasicHooks", CheckBasicHooks },
		{ "CheckTostringOnMetamethods", CheckTostringOnMetamethods },
		{ "CheckAllCachedCRefs", CheckAllCachedCRefs },
	}

	for _, entry in ipairsRef(INTERNAL_AC_FUNCTIONS) do
		local name, fn = entry[1], entry[2]
		if typeRef(fn) == "function" then
			local okSrc, src = pcallRef(debugInfoRef, fn, "s")
			local okLine, line = pcallRef(debugInfoRef, fn, "l")
			INTERNAL_AC_FINGERPRINTS[name] = {
				ref = fn,
				source = okSrc and src or nil,
				line = okLine and line or nil,
			}
		end
	end
end

const function CheckInternalACIntegrity(): boolean
	local bad = {}

	for _, entry in ipairsRef(INTERNAL_AC_FUNCTIONS) do
		local name, fn = entry[1], entry[2]
		local fp = INTERNAL_AC_FINGERPRINTS[name]
		if not fp then continue end

		-- 1. Identity: must be the exact object we captured at T0.
		--    Catches hookfunction and replaceclosure swaps.
		if not rawequalRef(fn, fp.ref) then
			tableInsertRef(bad, name .. ":identity")
			continue
		end

		-- 2. Closure source: native closures (C-hook stubs) report
		--    "[C]" or a different script path than our own script.
		local okSrc, src = pcallRef(debugInfoRef, fn, "s")
		if not okSrc or src ~= fp.source or src == "[C]" or src == nil or src == "" then
			tableInsertRef(bad, name .. ":source")
			continue
		end

		-- 3. Line number: catches a replaceclosure that swaps in a
		--    different Luau closure with the same debug name. Very
		--    rare, but cheap to check.
		local okLine, line = pcallRef(debugInfoRef, fn, "l")
		if okLine and fp.line and line ~= fp.line then
			tableInsertRef(bad, name .. ":line")
		end
	end

	-- Behavioral sanity for the cheap, side-effect-free checks.
	-- On a clean client these all return false. We don't flag
	-- `result == true` here because on a genuinely compromised
	-- client they SHOULD return true, and the periodic runs
	-- will already have queued an exploit for that.
	local cheapChecks = {
		{ "CheckMetatableGuard", CheckMetatableGuard },
		{ "CheckInstanceMetatableLock", CheckInstanceMetatableLock },
		{ "CheckGlobalIdentityTamper", CheckGlobalIdentityTamper },
		{ "CheckRefDrift", CheckRefDrift },
	}
	for _, entry in ipairsRef(cheapChecks) do
		local name, fn = entry[1], entry[2]
		local okCall, result = pcallRef(fn)
		if not okCall then
			tableInsertRef(bad, name .. ":throws")
		elseif typeRef(result) ~= "boolean" then
			tableInsertRef(bad, name .. ":nonbool")
		end
	end

	if #bad > 0 then
		QueueExploit("[InternalAC] tampered detection functions: " .. tableConcatRef(bad, ", "))
		return true
	end
	vWarn(("internal AC integrity: PASS (%d functions)"):format(#INTERNAL_AC_FUNCTIONS))
	return false
end

const function RunEnvironmentTamperChecks()
	local indexKey = "___CHECK_" .. toStringRef(mathRandom(100000, 999999))
	testFunctionCall("game.__index", function() return refGame[indexKey] end, isNativeIndexError)
	testFunctionCall("workspace.__index", function() return Workspace[indexKey] end, isNativeIndexError)
	testFunctionCall("players.__index", function() return Players[indexKey] end, isNativeIndexError)

	local fakeService = "__FAKE_SERVICE__" .. toStringRef(mathRandom(100000, 999999))
	testFunctionCall("game:GetService", function() return refGame:GetService(fakeService) end, isNativeGetServiceError)

	local fakeClass = "__FAKE_CLASS__" .. toStringRef(mathRandom(100000, 999999))
	testFunctionCall("Instance.new", function() return instanceNewRef(fakeClass) end, isNativeInstanceNewError)

	testFunctionCall("debug.info", function() return debugInfoRef(123) end, isNativeDebugInfoError)

	CheckMetatableGuard()
	CheckInstanceMetatableLock()
	CheckGlobalIdentityTamper()
	CheckFunctionBehaviors()
	CheckCoreClosures()
	CheckRefDrift()
	CheckInternalACIntegrity()
end

FreezeCoreRefs() -- synchronous, before first yield
FingerprintInternalAC()

taskSpawn(VerifyLogServiceTypes)
taskSpawn(VerifyScriptContextTypes)
taskSpawn(CheckLogHistory)
taskSpawn(RunEnvironmentTamperChecks)
taskSpawn(RunLegacyChecks)

const function CheckExploitArtifactServices()
	if refGame:FindFirstChild("MessagingService") then
		QueueExploit("Found Executor injection successful notification!")
	end

	if NewFindService("RbxAnalyticsService") then
		QueueExploit("Found Service that exploiters use. RbxAnalyticsService")
	end

	game:GetService("VirtualInputManager")
	if not refGame:FindService("VirtualInputManager") then
		--[[
			this means they did oth.hook and made findservice always return nil for this service and it should be created as we did getsevrice
			oth.hook(game.FindService, function(self, service)
    if service == "VirtualInputManager" then
        return nil
    end

    return oth.get_root_callback()(self, service)
end)
		]]
		QueueExploit("Used Oth.Hook to hook FindService!")
	end

end

const function CheckExploitReferences()
	local control = instanceNewRef("Folder")
	control.Name = "GCCheck_Control"

	local honeypot = instanceNewRef("Folder")
	honeypot.Name = "GCCheck_Honeypot_" .. toStringRef(mathRandom(10000, 99999))

	gcTracker.Control = control
	gcTracker.Honeypot = honeypot

	honeypot.Parent = ReplicatedStorage

	taskWait(0.5)

	control:Destroy()
	honeypot:Destroy()

	control = nil
	honeypot = nil

	local TimePassed = 0

	while TimePassed < MAX_WAIT_TIME do
		taskWait(1)
		TimePassed += 1

		if not gcTracker.Control then
			if gcTracker.Honeypot then
				QueueExploit("Unexpected client behavior detected. (Code: K-DETECT)")
				return true
			else
				return false
			end
		end

	end

end

taskSpawn(CheckExploitArtifactServices)

taskSpawn(function()
	while true do
		taskWait(30)
		taskSpawn(VerifyLogServiceTypes)
		taskSpawn(VerifyScriptContextTypes)
		taskSpawn(CheckLogHistory)
		taskSpawn(RunEnvironmentTamperChecks)
		taskSpawn(CheckExploitArtifactServices)
		taskSpawn(CheckExploitReferences)
		taskSpawn(RunLegacyChecks)
	end
end)

--============================================================
-- 7. WORLD-STATE WATCHERS
--============================================================

const function MonitorOtherCharacter(character: Model)
	character.ChildAdded:Connect(function(child: Instance)
		if child:IsA("Highlight") or child:IsA("BillboardGui") or child:IsA("BoxHandleAdornment") then
			QueueExploit("ESP injected into character: " .. toStringRef(child.ClassName))
		end
	end)
end

const function HookPlayer(targetPlayer: Player)
	if targetPlayer == LocalPlayer then return end
	if targetPlayer.Character then
		MonitorOtherCharacter(targetPlayer.Character)
	end
	targetPlayer.CharacterAdded:Connect(MonitorOtherCharacter)
end

for _, player in pairsRef(Players:GetPlayers()) do
	HookPlayer(player)
end

Players.PlayerAdded:Connect(HookPlayer)

LocalPlayer.PlayerGui.ChildAdded:Connect(function(child: Instance)
	taskWait()
	if not child:IsA("ScreenGui") then return end

	local lowerName = stringLower(child.Name)
	for _, badName in ipairsRef(BLACKLISTED_UI) do
		if stringFind(lowerName, badName) then
			QueueExploit("Dex/Cobalt GUI Fallback Detected: " .. child.Name)
			return
		end
	end

	if not tableFind(WHITELISTED_GUI, child.Name) then
		QueueExploit("Unauthorized ScreenGui injected: " .. toStringRef(child.Name))
	end
end)

-- Camera FOV tamper detection (catches some ESP/zoom exploits).
Workspace.CurrentCamera:GetPropertyChangedSignal("FieldOfView"):Connect(function()
	local fov = Workspace.CurrentCamera.FieldOfView
	if fov > MAX_FIELD_OF_VIEW then
		QueueExploit("Camera FieldOfView tampered: " .. toStringRef(fov))
	end
end)

CORE_GUI_HONEYPOT.ChildAdded:Connect(function(child: Instance)
	QueueExploit("Core gui honeypot child added. Child Name: ".. toStringRef(child.Name))
end)

--============================================================
-- 8. PERSISTENT LOGSERVICE / SCRIPTCONTEXT LISTENERS
--============================================================

local lastLogCanarySeen = false
local LOG_CANARY_TAG = "__actest_live__"

const function OnMessageOut(message: string, messageType: Enum.MessageType)
	if stringFind(message, LOG_CANARY_TAG, 1, true) then
		lastLogCanarySeen = true
		return
	end
	-- Fallback ignore for legacy actest logs to prevent history flagging
	if stringFind(message, "__actest", 1, true) then return end

	if not logServiceIntact then return end
	if messageType == MessageType.MessageError then return end

	checkedHistory[message] = true -- so CheckLogHistory doesn't re-report it
	if IsSuspiciousMessage(message) then
		QueueLog(message, "LogService")
	end
end

local logMessageConn = LogService.MessageOut:Connect(OnMessageOut)
local logDisconnectCount = 0

const function VerifyPersistentLogListener()
	lastLogCanarySeen = false
	warnRef(LOG_CANARY_TAG)
	taskWait()
	taskWait()

	if not lastLogCanarySeen then
		QueueExploit("LogService listener disabled/silenced (persistent connection did not observe canary)")
	end
end

taskSpawn(function()
	while taskWait(5) do
		if not (logMessageConn and logMessageConn.Connected) then
			logDisconnectCount += 1
			if logDisconnectCount >= 3 then
				QueueExploit("LogService.MessageOut connection repeatedly killed (3 strikes).")
				break
			end
			logMessageConn = LogService.MessageOut:Connect(OnMessageOut)
		end

		VerifyPersistentLogListener()
	end
end)

local lastScriptCanarySeen = false
local SCRIPT_CANARY_TAG = "__actest_script_live__"

const function OnScriptError(message: string, stackTrace: string, errorScript)
	if stringFind(message, SCRIPT_CANARY_TAG, 1, true) then
		lastScriptCanarySeen = true
		return
	end

	if not scriptContextIntact then return end

	if errorScript == nil or errorScript == "" or errorScript == " " then
		QueueLog("[GhostScript]", "NilScript")
		return
	end

	local ok, scriptPath = pcallRef(function() return errorScript:GetFullName() end)
	if not (ok and scriptPath) then
		QueueLog("[MaskedScript Environment Exception]", "NilScript")
		return
	end

	local lowerPath = stringLower(scriptPath)
	local isInternalScript = false
	for _, marker in INTERNAL_SCRIPT_PATH_MARKERS do
		if stringFind(lowerPath, marker) then
			isInternalScript = true
			break
		end
	end

	if not isInternalScript or stringFind(lowerPath, "workspace") then
		QueueLog(message .. " | Path: " .. scriptPath, "ScriptContext.UnauthorizedOrigin")
		if typeRef(stackTrace) == "string" and stringLen(stackTrace) > 0 then
			QueueLog(stackTrace, "ScriptContext.StackTrace")
		end
	end
end

local scriptErrorConn = ScriptContext.Error:Connect(OnScriptError)
local scriptErrorDisconnectCount = 0

const function VerifyPersistentScriptListener()
	lastScriptCanarySeen = false
	taskSpawn(function()
		errorRef(SCRIPT_CANARY_TAG)
	end)
	taskWait()
	taskWait()

	if not lastScriptCanarySeen then
		QueueExploit("ScriptContext.Error listener disabled/silenced (persistent connection did not observe canary)")
	end
end

taskSpawn(function()
	while taskWait(5) do
		if not (scriptErrorConn and scriptErrorConn.Connected) then
			scriptErrorDisconnectCount += 1
			if scriptErrorDisconnectCount >= 3 then
				QueueExploit("ScriptContext.Error connection repeatedly killed (3 strikes).")
				break
			end
			scriptErrorConn = ScriptContext.Error:Connect(OnScriptError)
		end

		VerifyPersistentScriptListener()
	end
end)
