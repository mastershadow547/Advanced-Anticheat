--[[
	AntiCheat Server Script
	Consolidated onto a single remote ("Heartbeat") using a Nonce-based
	challenge/response protocol. Functionality is otherwise 1:1 with the
	original multi-remote version.

	Sections:
		1. Config / constants
		2. Utility helpers
		3. Profile-load queue (RunWhenDataLoads)
		4. Remote spam throttle
		5. Movement anticheat (speed / fly / rubberband)
		6. Service name obfuscation
		7. Blacklist scanning (log messages)
		8. Heartbeat protocol (Nonce challenge, response validation,
		   FLAGGED handling, batched log ingestion, honeypot-equivalent
		   payload validation)
		9. Player lifecycle wiring

		REMEMBER TO KEEP THIS AS A MDOULE SCRIPT WITH return Anticheat

	--------------------------------------------------------------------
	PROTOCOL NOTES (read this before touching section 8):

	Every remote (ExploitDetected, LogReport, GiveItem honeypot,
	Handshake) has been merged into one bidirectional RemoteEvent,
	"Heartbeat". The flow per player:

	  1. On join, the server waits HEARTBEAT_INITIAL_GRACE seconds before
	     enforcing anything, so the client watchdog has time to load.
	  2. The server fires a Nonce (a random number) to the client and
	     starts a HEARTBEAT_RESPONSE_TIMEOUT countdown.
	  3. The client must fire back { nonce, status, reason?, hash, logs? }
	     where hash = HeartbeatHash.Compute(nonce, status, reason) — the
	     exact same function the server runs. Because the Nonce changes
	     every cycle, a captured/replayed old response will never match
	     the new Nonce, so simple replay doesn't work.
	  4. If the response never arrives in time -> kick + log only, no
	     flag/ban (this is a "missed ping", not proof of tampering).
	  5. If a response arrives but the hash doesn't match -> kick + log
	     only (per spec: "drops the player", no flag/ban distinction
	     requested for a bad answer vs. a missed one).
	  6. If the payload is malformed (wrong shape / wrong types) -> this
	     is what the old GiveItem honeypot caught: no legitimate client
	     build ever produces a malformed payload, so seeing one is on its
	     own strong enough evidence to flag+ban+kick immediately.
	  7. status = "FLAGGED" reports route through the same
	     PenalizeForMessage path the old ExploitDetected remote used.
	     status = "OK" with a `logs` array batches what LogReport used to
	     send individually; each entry still goes through the same
	     blacklist-term/pattern scan as before.

	Tradeoff vs. the old design: exploit/log reports can only go out
	attached to a Nonce response, so they're delayed by at most
	HEARTBEAT_INTERVAL seconds instead of firing the instant they're
	detected client-side. Everything else — what gets penalized and how
	— is unchanged.
	--------------------------------------------------------------------
]]

local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local HttpService = game:GetService("HttpService")
local Workspace = game:GetService("Workspace")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local Scripts = script.Parent
local Config = require(Scripts.Configurations)
local AntiCheatData = require(Scripts.AntiCheatData)
local AntiCheatDataTemplate = require(Scripts.AntiCheatData.AntiCheatTemplate)

local Remotes = ReplicatedStorage:FindFirstChild("Remotes")

type DataCallback = (AntiCheatDataTemplate.AntiCheatData) -> ()

--============================================================
-- 1. CONFIG / CONSTANTS
--============================================================
const PROXY_ENDPOINT = "https://workers-playground-sweet-mode-e797.warzone1071.workers.dev/"

const MAX_REMOTES_PER_SECOND = 20
const MAX_ERROR_LOGS = 100

const SERVICE_OBFUSCATION_INTERVAL = 360
const FETCH_LIVE_VERSION_INTERVAL = 900
const PROFILE_LOAD_TIMEOUT = 10 -- seconds before kicking if profile never loads

const SAVE_INTERVAL = 1.5
const RUBBERBAND_COOLDOWN = 1
const POST_RUBBERBAND_IMMUNITY = 2.5
const SPAWN_IMMUNITY = 3

const SPEED_BUFFER = 10
const SPEED_VIOLATION_THRESHOLD = 5
const SPEED_SAMPLE_COUNT = 6
const EXTREME_SPEED_MULTIPLIER = 4
const SAVE_SPEED_TOLERANCE = 15

const FLY_HOVER_GRACE = 1.8
const FLY_HOVER_THRESHOLD = 0.4
const FLY_SUSTAINED_UP = 5
const FLY_VIOLATION_THRESHOLD = 6
const FLY_MIN_AIRTIME_FOR_SUSTAINED = 0.3

const JUMP_IMMUNITY_DURATION = 1.4
const JUMP_VELOCITY_TRIGGER = 15
const MAX_WALKSPEED = 16
const ALLOWED_SPEED = MAX_WALKSPEED + SPEED_BUFFER -- precomputed, was recomputed per-call

const CHECK_INTERVAL = 0.1

-- Heartbeat protocol timing. "Every few seconds" per spec.
const HEARTBEAT_INITIAL_GRACE = 10   -- seconds of slack after join before enforcement starts
const HEARTBEAT_INTERVAL = 3        -- seconds between successive Nonce challenges
const HEARTBEAT_RESPONSE_TIMEOUT = 2 -- seconds the client has to answer a given Nonce
const HEARTBEAT_CHECK_STEP = 0.5     -- poll granularity while waiting on a response

local FNV_OFFSET_BASIS = 2166136261
local FNV_PRIME = 16777619
local MASK32 = 0xFFFFFFFF

local BLACKLISTED_TERMS = {
	"httpget", "loadstring", "getgenv", "getrawmetatable",
	"hookmetamethod", "hookfunction", "newcclosure", "replaceclosure",
	"synapse", "krnl", "fluxus", "xeno", "madium", "wave",
	"dex", "remotespy", "rayfield", "electron", "oxygen",
	"celery", "scriptware", "exploit", "executor", "injector",
}

local BLACKLISTED_PATTERNS = {
	"get.*env", "hook.*method", "hook.*function", "load.*string",
	"http.*get", "raw.*equal", "set.*readonly", "make.*writeable",
}

local FLAG_TERM_COOLDOWN = 5 -- seconds before the same term can re-flag a player

--============================================================
-- STATE
--============================================================

local RemoteThrottles = {}
local RecentlyFlagged = {}
local PlayerMovementData = {}
local MovementConnections = {}
local EarlyDetectionQueue = {}
local ServiceMap = {}
local HeartbeatState = {} -- [UserId] = { expectedNonce, responded }

local RNG = Random.new()
local currentVersionData = nil

local AntiCheat = {}

--============================================================
-- 				CLIENT VERSION FETCHER
--============================================================

const function fetchLatestVersion()
	if not Config.ENABLE_CLIENT_VERSION_CHECK then return end
	-- 1. Execute HTTP Request via Proxy
	local httpSuccess, response = pcall(function()
		return HttpService:RequestAsync({
			Url = PROXY_ENDPOINT,
			Method = "GET",
		})
	end)

	if not httpSuccess then
		warn("[VersionCheck] HTTP request failed:", response)
		return
	end

	-- 2. Validate Response Code
	if not response.Success then
		warn(string.format("[VersionCheck] Server error HTTP %d: %s", response.StatusCode, response.StatusMessage))
		return
	end

	-- 3. Safely Parse JSON
	local jsonSuccess, data = pcall(function()
		return HttpService:JSONDecode(response.Body)
	end)

	if not jsonSuccess then
		warn("[VersionCheck] Failed to parse JSON response:", data)
		return
	end

	-- 4. Validate Structural Integrity
	if type(data) ~= "table" or not data.WindowsResponse or not data.MacResponse then
		warn("[VersionCheck] Invalid payload structure received from Worker")
		return
	end

	currentVersionData = data
	print("Data is: ", data)
	--print("[VersionCheck] Successfully fetched target Windows version:", data.WindowsResponse.version)
end

--============================================================
-- 				HEARTBEAT COMPUTE FUNCTIONS
--============================================================

-- Standard FNV-1a over the payload string (nonce|status|reason).
const function FNV1a(str: string): number
	local hash = FNV_OFFSET_BASIS
	for i = 1, #str do
		hash = bit32.bxor(hash, string.byte(str, i))
		hash = bit32.band(hash * FNV_PRIME, MASK32)
	end
	return hash
end

-- Extra avalanche/mixing pass so the result isn't just a plain FNV1a of a
-- predictable string layout — folds the raw numeric Nonce back in after
-- the string hash so the final value depends on the Nonce twice, in two
-- different ways (once as text, once as a mixed-in integer).
const function MixWithNonce(hash: number, nonce: number): number
	local mixed = bit32.bxor(hash, nonce)
	mixed = bit32.band(mixed * 2654435761, MASK32) -- Knuth multiplicative hash
	mixed = bit32.bxor(mixed, bit32.rshift(mixed, 15))
	mixed = bit32.band(mixed * 2246822519, MASK32)
	mixed = bit32.bxor(mixed, bit32.rshift(mixed, 13))
	return mixed
end

-- nonce: the one-time number issued by the server this cycle
-- status: "OK" | "FLAGGED"
-- reason: string if FLAGGED, nil/omitted if OK
const function Compute(nonce: number, status: string, reason: string?): number
	local payload = tostring(nonce) .. "|" .. status .. "|" .. (reason or "")
	local baseHash = FNV1a(payload)
	return MixWithNonce(baseHash, nonce)
end

--============================================================
-- 2. UTILITY HELPERS
--============================================================

local function vPrint(...)
	if Config.VERBOSE then print(...) end
end

local function vWarn(...)
	if Config.VERBOSE then warn(...) end
end

local function GetAverage(samples: { number }): number
	if #samples == 0 then return 0 end
	local sum = 0
	for _, v in samples do
		sum += v
	end
	return sum / #samples
end

local function IsGrounded(character: Model): boolean
	local hrp = character:FindFirstChild("HumanoidRootPart")
	local humanoid = character:FindFirstChildOfClass("Humanoid")
	if not hrp or not humanoid then return false end

	local params = RaycastParams.new()
	params.FilterDescendantsInstances = { character }
	params.FilterType = Enum.RaycastFilterType.Exclude

	local origin = hrp.Position - Vector3.new(0, hrp.Size.Y / 2, 0)
	local direction = Vector3.new(0, -(humanoid.HipHeight + 1.2), 0)
	return Workspace:Raycast(origin, direction, params) ~= nil
end

local function GenerateNonce(): number
	return RNG:NextInteger(1, 2147483646)
end

--============================================================
-- 3. PROFILE-LOAD QUEUE
-- Defers any penalty/log action until ProfileStore data exists,
-- so an early exploit signal can never race a nil profile.
--============================================================

local function RunWhenDataLoads(player: Player, callback: DataCallback)
	local data = AntiCheatData.GetData(player)
	if data then
		callback(data)
		return
	end

	if EarlyDetectionQueue[player.UserId] then
		table.insert(EarlyDetectionQueue[player.UserId], callback)
		return
	end

	local queue = { callback }
	EarlyDetectionQueue[player.UserId] = queue

	task.spawn(function()
		local elapsed = 0
		while elapsed < PROFILE_LOAD_TIMEOUT do
			task.wait(1)
			elapsed += 1

			if not player.Parent then
				EarlyDetectionQueue[player.UserId] = nil
				return
			end

			local loadedData = AntiCheatData.GetData(player)
			if loadedData then
				for _, queuedCallback in queue do
					queuedCallback(loadedData)
				end
				EarlyDetectionQueue[player.UserId] = nil
				return
			end
		end

		if player.Parent then
			player:Kick("Anti-Cheat Timeout: Profile data failed to load.")
		end
		EarlyDetectionQueue[player.UserId] = nil
	end)
end

local function AppendErrorLog(player: Player, logType: string, message: string, source: string)
	local data = AntiCheatData.GetData(player)
	if not data then return end

	data.ErrorLogs = data.ErrorLogs or {}
	if #data.ErrorLogs >= MAX_ERROR_LOGS then
		table.remove(data.ErrorLogs, 1)
	end
	table.insert(data.ErrorLogs, {
		Type = logType,
		Message = message,
		Source = source,
		Timestamp = os.time(),
	})
end

--============================================================
-- 4. REMOTE SPAM THROTTLE
--============================================================

local function IsSpamming(player: Player): boolean
	local now = os.clock()
	local throttle = RemoteThrottles[player.UserId]
	if not throttle then
		throttle = { lastReset = now, count = 0 }
		RemoteThrottles[player.UserId] = throttle
	end

	if now - throttle.lastReset >= 1 then
		throttle.count = 1
		throttle.lastReset = now
		return false
	end

	throttle.count += 1
	return throttle.count > MAX_REMOTES_PER_SECOND
end

--============================================================
-- 5. MOVEMENT ANTICHEAT
--============================================================

local function ResetMovementData(player: Player)
	PlayerMovementData[player.UserId] = {
		lastGoodPosition = nil,
		immuneUntil = tick() + SPAWN_IMMUNITY,
		jumpImmunityUntil = 0,
		lastCheckPos = nil,
		lastCheckTime = nil,
		airTime = 0,
		flyViolations = 0,
		speedViolations = 0,
		speedSamples = {},
		wasGrounded = false,
		lastRubberbandTime = nil,
	}
end

local function TeleportToSavedPosition(player: Player)
	local data = PlayerMovementData[player.UserId]
	if not data or not data.lastGoodPosition then
		vWarn("[AC:Rubberband] No lastGoodPosition for", player.Name, "- cannot rubberband")
		return
	end

	local character = player.Character
	if not character then return end
	local hrp = character:FindFirstChild("HumanoidRootPart")
	local humanoid = character:FindFirstChildOfClass("Humanoid")
	if not hrp or not humanoid or humanoid.Health <= 0 then return end

	hrp.Anchored = true
	hrp.CFrame = CFrame.new(data.lastGoodPosition + Vector3.new(0, 3, 0))
	hrp.AssemblyLinearVelocity = Vector3.zero
	hrp.AssemblyAngularVelocity = Vector3.zero

	task.defer(function()
		if hrp.Parent then
			hrp.Anchored = false
		end
	end)

	data.immuneUntil = tick() + POST_RUBBERBAND_IMMUNITY
	data.jumpImmunityUntil = 0
	data.airTime = 0
	data.flyViolations = 0
	data.speedViolations = 0
	data.speedSamples = {}
	data.lastCheckPos = nil
	data.lastCheckTime = nil
end

local function FlagOrKick(player: Player, reason: string)
	local data = PlayerMovementData[player.UserId]
	if not data then return end

	local now = tick()
	if data.lastRubberbandTime and (now - data.lastRubberbandTime) < RUBBERBAND_COOLDOWN then
		return
	end
	data.lastRubberbandTime = now

	local acData = AntiCheatData.GetData(player)
	if not acData then return end

	vWarn("[AC:Violation]", player.Name, "-", reason)
	AppendErrorLog(player, "MovementViolation", reason, "ServerMovementCheck")
	TeleportToSavedPosition(player)

	if Config.USE_FLAG_SYSTEM then
		acData.Flagged = true
	end
	if Config.USE_IMMEDIATE_ACTION_SYSTEM then
		acData.Banned = true
		player:Kick(reason)
	end
end

local function EvaluateSpeed(player: Player, data, horizontalSpeed: number)
	if horizontalSpeed > ALLOWED_SPEED * EXTREME_SPEED_MULTIPLIER then
		FlagOrKick(player, ("Extreme Speed Detected (%d studs/s)"):format(math.round(horizontalSpeed)))
		return true -- short-circuit: caller should refresh check timestamps and bail
	end

	if horizontalSpeed <= ALLOWED_SPEED then
		table.clear(data.speedSamples)
		if data.speedViolations > 0 then
			data.speedViolations -= 1
		end
		return false
	end

	table.insert(data.speedSamples, horizontalSpeed)
	if #data.speedSamples > SPEED_SAMPLE_COUNT then
		table.remove(data.speedSamples, 1)
	end

	if #data.speedSamples < SPEED_SAMPLE_COUNT then
		return false
	end

	local avg = GetAverage(data.speedSamples)
	if avg > ALLOWED_SPEED then
		data.speedViolations += 1
		if data.speedViolations >= SPEED_VIOLATION_THRESHOLD then
			data.speedViolations = 0
			table.clear(data.speedSamples)
			FlagOrKick(player, ("Speed Hack Detected (avg %d studs/s)"):format(math.round(avg)))
		end
	end

	return false
end

local function EvaluateFly(data, grounded: boolean, jumpImmune: boolean, verticalSpeed: number)
	if grounded then
		return
	end

	if jumpImmune then
		data.flyViolations = math.max(0, data.flyViolations - 1)
		return
	end

	local absVertical = math.abs(verticalSpeed)
	local isSustainedUp = verticalSpeed > FLY_SUSTAINED_UP and data.airTime > FLY_MIN_AIRTIME_FOR_SUSTAINED
	local isHovering = data.airTime > FLY_HOVER_GRACE and absVertical < FLY_HOVER_THRESHOLD

	if isSustainedUp or isHovering then
		data.flyViolations += 1
	else
		data.flyViolations = math.max(0, data.flyViolations - 1)
	end

	return data.flyViolations >= FLY_VIOLATION_THRESHOLD
end

local function StartMovementChecks(player: Player)
	local existing = MovementConnections[player.UserId]
	if existing then
		existing:Disconnect()
	end

	local saveTimer, checkTimer = 0, 0

	local connection
	connection = RunService.Heartbeat:Connect(function(dt: number)
		if not player.Parent then
			connection:Disconnect()
			MovementConnections[player.UserId] = nil
			return
		end

		local data = PlayerMovementData[player.UserId]
		if not data then
			connection:Disconnect()
			MovementConnections[player.UserId] = nil
			return
		end

		local character = player.Character
		if not character then return end

		local hrp = character:FindFirstChild("HumanoidRootPart")
		local humanoid = character:FindFirstChildOfClass("Humanoid")
		if not hrp or not humanoid or humanoid.Health <= 0 or hrp.Anchored then return end

		local now = tick()

		if data.immuneUntil > now then
			if IsGrounded(character) then
				data.lastGoodPosition = hrp.Position
			end
			return
		end

		local velocity = hrp.AssemblyLinearVelocity
		local grounded = IsGrounded(character)
		local jumpImmune = data.jumpImmunityUntil > now

		if velocity.Y >= JUMP_VELOCITY_TRIGGER and not grounded and not jumpImmune then
			data.jumpImmunityUntil = now + JUMP_IMMUNITY_DURATION
			jumpImmune = true
		end

		if grounded then
			data.wasGrounded = true
			data.airTime = 0
			data.flyViolations = math.max(0, data.flyViolations - 2)
			if #data.speedSamples == 0 then
				data.speedViolations = math.max(0, data.speedViolations - 1)
			end
			data.jumpImmunityUntil = 0
		else
			data.wasGrounded = false
			data.airTime += dt
		end

		checkTimer += dt
		saveTimer += dt

		if checkTimer >= CHECK_INTERVAL then
			local elapsed = checkTimer
			checkTimer = 0

			if data.lastCheckPos and data.lastCheckTime then
				local delta = hrp.Position - data.lastCheckPos
				local horizontalSpeed = Vector3.new(delta.X, 0, delta.Z).Magnitude / elapsed
				local verticalSpeed = delta.Y / elapsed

				local bailedOnExtremeSpeed = EvaluateSpeed(player, data, horizontalSpeed)
				if not bailedOnExtremeSpeed then
					local flyTripped = EvaluateFly(data, grounded, jumpImmune, verticalSpeed)
					if flyTripped then
						data.flyViolations = 0
						FlagOrKick(player, "Fly Hack Detected")
					end
				end
			end

			data.lastCheckPos = hrp.Position
			data.lastCheckTime = now
		end

		if saveTimer >= SAVE_INTERVAL then
			saveTimer = 0
			if grounded and hrp.AssemblyLinearVelocity.Magnitude < (ALLOWED_SPEED + SAVE_SPEED_TOLERANCE) then
				data.lastGoodPosition = hrp.Position
			end
		end

		if data.lastGoodPosition == nil and grounded then
			data.lastGoodPosition = hrp.Position
		end
	end)

	MovementConnections[player.UserId] = connection
end

--============================================================
-- 6. SERVICE NAME OBFUSCATION
--============================================================

local function ObfuscateServices()
	local targets = {
		Workspace, game:GetService("Lighting"),
		game:GetService("MaterialService"), game:GetService("ReplicatedFirst"),
		ReplicatedStorage, game:GetService("StarterGui"),
		game:GetService("StarterPack"), game:GetService("StarterPlayer"),
		game:GetService("Teams"), game:GetService("SoundService"),
		game:GetService("TextChatService"),
	}

	for _, svc in targets do
		local newName = HttpService:GenerateGUID(false)
		local ok, err = pcall(function()
			ServiceMap[svc] = { originalName = svc.Name, obfuscatedName = newName }
			svc.Name = newName
		end)
		if not ok then
			vWarn("[AntiCheat] Could not rename service:", err)
		end
	end
end

--============================================================
-- 7. BLACKLIST SCANNING (log messages reported by client)
--============================================================

local function IsTermRecentlyFlagged(player: Player, key: string): boolean
	local flags = RecentlyFlagged[player.UserId]
	if flags[key] then return true end
	flags[key] = true
	task.delay(FLAG_TERM_COOLDOWN, function()
		if RecentlyFlagged[player.UserId] then
			RecentlyFlagged[player.UserId][key] = nil
		end
	end)
	return false
end

local function PenalizeForMessage(player: Player, logType: string, message: string, source: string, kickReason: string)
	RunWhenDataLoads(player, function(data)
		AppendErrorLog(player, logType, message, source)
		if Config.USE_FLAG_SYSTEM then data.Flagged = true end
		if Config.USE_IMMEDIATE_ACTION_SYSTEM then player:Kick(kickReason) end
	end)
end

local function CheckMessageForExploits(player: Player, message: string, source: string): boolean
	if type(message) ~= "string" then return false end
	local lower = string.lower(message)
	RecentlyFlagged[player.UserId] = RecentlyFlagged[player.UserId] or {}

	for _, term in BLACKLISTED_TERMS do
		if string.find(lower, term, 1, true) then
			if IsTermRecentlyFlagged(player, term) then return false end
			PenalizeForMessage(player, "BlacklistedTerm", message, source, "Blacklisted term detected (" .. term .. ")")
			return true
		end
	end

	for _, pattern in BLACKLISTED_PATTERNS do
		if string.find(lower, pattern) then
			local key = "pattern_" .. pattern
			if IsTermRecentlyFlagged(player, key) then return false end
			PenalizeForMessage(player, "SuspiciousPattern", message, source, "Suspicious pattern detected")
			return true
		end
	end

	return false
end

local function HandleGhostScript(player: Player)
	RecentlyFlagged[player.UserId] = RecentlyFlagged[player.UserId] or {}
	if IsTermRecentlyFlagged(player, "GhostScript") then return end
	PenalizeForMessage(player, "GhostScript", "[GhostScript]", "NilScript", "Error fired from a nil/external script environment.")
end

--============================================================
-- 8. HEARTBEAT PROTOCOL
-- One remote, bidirectional: server issues a Nonce challenge, client
-- must answer with a hash of (nonce, status, reason) computed via the
-- shared HeartbeatHash module. See the top-of-file protocol notes.
--============================================================

local function StartHeartbeatWatcher(player: Player)
	task.spawn(function()
		-- Let the client watchdog finish loading before enforcing anything.
		task.wait(HEARTBEAT_INITIAL_GRACE)

		while player.Parent do
			local state = HeartbeatState[player.UserId]
			if not state then return end -- player left mid-wait

			local nonce = GenerateNonce()
			state.expectedNonce = nonce
			state.responded = false

			Remotes.Heartbeat:FireClient(player, { nonce = nonce })

			local waited = 0
			while waited < HEARTBEAT_RESPONSE_TIMEOUT do
				if state.responded then break end
				if not player.Parent then return end
				task.wait(HEARTBEAT_CHECK_STEP)
				waited += HEARTBEAT_CHECK_STEP
			end

			if not state.responded then
				if player.Parent then
					AppendErrorLog(player, "HeartbeatTimeout", "Client failed to respond to heartbeat challenge in time.", "Heartbeat")
					vWarn("[AC:Heartbeat] Kicking", player.Name, "- missed heartbeat")
					player:Kick("Anti-Cheat: Heartbeat timeout. Rejoin You aren't banned!")
				end
				return
			end

			task.wait(HEARTBEAT_INTERVAL)
		end
	end)
end

Remotes.Heartbeat.OnServerEvent:Connect(function(player: Player, payload: any)
	if IsSpamming(player) then
		player:Kick("Remote Spam")
		return
	end

	local state = HeartbeatState[player.UserId]
	if not state then return end

	-- Honeypot-equivalent: no legitimate client build ever produces a
	-- payload outside this exact shape, so a malformed one is itself the
	-- signal (this is what the old GiveItem honeypot remote caught).
	if type(payload) ~= "table"
		or type(payload.nonce) ~= "number"
		or type(payload.status) ~= "string"
		or type(payload.hash) ~= "number"
		or (payload.status ~= "OK" and payload.status ~= "FLAGGED")
	then
		vWarn("[AC:Honeypot] Malformed Heartbeat payload from", player.Name)
		RunWhenDataLoads(player, function(data)
			AppendErrorLog(player, "MalformedHeartbeat", "Invalid heartbeat payload shape", "Heartbeat")
			if Config.USE_FLAG_SYSTEM then data.Flagged = true end
			if Config.USE_IMMEDIATE_ACTION_SYSTEM then
				data.Banned = true
				player:Kick("Anti-Cheat: invalid heartbeat payload.")
			end
		end)
		return
	end

	-- Stale/replayed response for a Nonce we've already moved past — ignore.
	if payload.nonce ~= state.expectedNonce then
		return
	end

	local reasonField = type(payload.reason) == "string" and payload.reason or nil
	local expectedHash = Compute(payload.nonce, payload.status, reasonField)

	if expectedHash ~= payload.hash then
		vWarn("[AC:Heartbeat] Hash mismatch from", player.Name)

		RunWhenDataLoads(player, function(data)
			AppendErrorLog(player, "HeartbeatMismatch", "Challenge/response hash did not match.", "Heartbeat")
			if Config.USE_FLAG_SYSTEM then
				data.Flagged = true
			end
			if Config.USE_IMMEDIATE_ACTION_SYSTEM then
				data.Banned = true
			end
		end)
		player:Kick("Anti-Cheat: heartbeat verification failed.")
		return
	end

	state.responded = true

	if payload.status == "FLAGGED" then
		local reason = reasonField or "Unknown"
		vPrint("[AC:Client] Heartbeat FLAGGED from", player.Name, "—", reason)
		PenalizeForMessage(player, "ExploitDetected", reason, "ClientWatchdog", reason)
	end

	if type(payload.logs) == "table" then
		for _, logEntry in payload.logs do
			if type(logEntry) == "table" and type(logEntry.message) == "string" and type(logEntry.source) == "string" then
				--warn("ENTRIES ARE: ".. tostring(logEntry.message).. " AND ".. tostring(logEntry.source))
				if logEntry.message == "[GhostScript]" and logEntry.source == "NilScript" then
					HandleGhostScript(player)
				else
					--vPrint("[AC:Log]", player.Name, "|", logEntry.source, "|", logEntry.message)
					RunWhenDataLoads(player, function(data)
						AppendErrorLog(player, "LogReport", logEntry.message, logEntry.source)
					end)
					CheckMessageForExploits(player, logEntry.message, logEntry.source)
				end
			end
		end
	end
end)

Remotes.GiveItem.OnServerEvent:Connect(function(Player: Player, ITEM_TO_GIVE: any)
	if IsSpamming(Player) then return end
	vWarn("[AC:Honeypot] GiveItem fired by", Player.Name, "item:", tostring(ITEM_TO_GIVE))

	RunWhenDataLoads(Player, function(data)
		if Config.USE_FLAG_SYSTEM then data.Flagged = true end
		if Config.USE_IMMEDIATE_ACTION_SYSTEM then
			data.Banned = true
			Player:Kick("Exploiting fired honeypot!")
		end
	end)
end)



--============================================================
-- 9. PLAYER LIFECYCLE
--============================================================

Players.PlayerAdded:Connect(function(player: Player)
	ResetMovementData(player)
	RecentlyFlagged[player.UserId] = {}
	HeartbeatState[player.UserId] = { expectedNonce = nil, responded = false }
	StartHeartbeatWatcher(player)

	if player.Character then
		task.wait(2)
		StartMovementChecks(player)
	end

	player.CharacterAdded:Connect(function()
		ResetMovementData(player)
		task.wait(2)
		StartMovementChecks(player)
	end)
	
	task.wait(0.5)
	
	if Config.ENABLE_CLIENT_VERSION_CHECK and currentVersionData then
		warn("SERVER SENT")
		Remotes.LatestClientVersion:FireClient(player, currentVersionData)
	else
		warn("NO DATA SENT")
		--print(Config.ENABLE_CLIENT_VERSION_CHECK)
	end
	
end)

Players.PlayerRemoving:Connect(function(player: Player)
	local connection = MovementConnections[player.UserId]
	if connection then
		connection:Disconnect()
	end
	MovementConnections[player.UserId] = nil
	PlayerMovementData[player.UserId] = nil
	HeartbeatState[player.UserId] = nil
	RecentlyFlagged[player.UserId] = nil
	RemoteThrottles[player.UserId] = nil
	EarlyDetectionQueue[player.UserId] = nil
end)

--============================================================
-- BACKGROUND LOOPS
--============================================================

if Config.ENABLE_SERVICE_OBFUSCATION then
	task.spawn(function()
		ObfuscateServices()
		while true do
			task.wait(SERVICE_OBFUSCATION_INTERVAL)
			ObfuscateServices()
		end
	end)
end

if Config.ENABLE_CLIENT_VERSION_CHECK then
	task.spawn(function()
		while true do
			fetchLatestVersion()
			task.wait(FETCH_LIVE_VERSION_INTERVAL)
		end
	end)
end

return AntiCheat
