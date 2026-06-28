local Scripts = script.Parent
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Remotes = ReplicatedStorage:FindFirstChild("Remotes")
local Config = require(Scripts.Configurations)
local AntiCheatData = require(Scripts.AntiCheatData)
local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local HttpService = game:GetService("HttpService")

local function vPrint(...)
	if Config.VERBOSE then print(...) end
end

local function vWarn(...)
	if Config.VERBOSE then warn(...) end
end

local ExpectedHandshakes = {}
local RemoteThrottles = {}
local AntiCheat = {}
local ServiceMap = {}

local MovementConnections = {}

local MAX_REMOTES_PER_SECOND = 10
local MAX_ERROR_LOGS = 100

local SAVE_INTERVAL = 1.5
local RUBBERBAND_COOLDOWN = 1
local POST_RUBBERBAND_IMMUNITY = 2.5

local SPEED_BUFFER = 10
local SPEED_VIOLATION_THRESHOLD = 5
local SPEED_SAMPLE_COUNT = 6

local FLY_HOVER_GRACE = 1.8
local FLY_HOVER_THRESHOLD = 0.4
local FLY_SUSTAINED_UP = 5
local FLY_VIOLATION_THRESHOLD = 6
local JUMP_IMMUNITY_DURATION = 1.4
local JUMP_VELOCITY_TRIGGER = 15
local MAX_WALKSPEED = 16

local CHECK_INTERVAL = 0.1

local BlacklistedTerms = {
	"httpget", "loadstring", "getgenv", "getrawmetatable",
	"hookmetamethod", "hookfunction", "newcclosure", "replaceclosure",
	"synapse", "krnl", "fluxus", "xeno", "madium", "wave",
	"dex", "remotespy", "rayfield", "electron", "oxygen",
	"celery", "scriptware", "exploit", "executor", "Injector"
}

local BlacklistedPatterns = {
	"get.*env", "hook.*method", "hook.*function", "load.*string",
	"http.*get", "raw.*equal", "set.*readonly", "make.*writeable",
}

local RecentlyFlagged = {}
local PlayerMovementData = {}

local function AppendErrorLog(player, logType, message, source)
	local Data = AntiCheatData.GetData(player)
	if not Data then return end
	if not Data.ErrorLogs then Data.ErrorLogs = {} end
	if #Data.ErrorLogs >= MAX_ERROR_LOGS then table.remove(Data.ErrorLogs, 1) end
	table.insert(Data.ErrorLogs, {
		Type = logType,
		Message = message,
		Source = source,
		Timestamp = os.time(),
	})
end

local function IsSpamming(player)
	local now = os.clock()
	if not RemoteThrottles[player.UserId] then
		RemoteThrottles[player.UserId] = { lastReset = now, count = 0 }
	end
	local d = RemoteThrottles[player.UserId]
	if now - d.lastReset >= 1 then
		d.count = 1
		d.lastReset = now
		return false
	end
	d.count += 1
	return d.count > MAX_REMOTES_PER_SECOND
end

local function IsGrounded(character)
	local hrp = character:FindFirstChild("HumanoidRootPart")
	local humanoid = character:FindFirstChildOfClass("Humanoid")
	if not hrp or not humanoid then return false end

	local params = RaycastParams.new()
	params.FilterDescendantsInstances = { character }
	params.FilterType = Enum.RaycastFilterType.Exclude

	local origin = hrp.Position - Vector3.new(0, hrp.Size.Y / 2, 0)
	local direction = Vector3.new(0, -(humanoid.HipHeight + 1.2), 0)
	return game:GetService("Workspace"):Raycast(origin, direction, params) ~= nil
end

local function GetAllowedSpeed(humanoid)
	return MAX_WALKSPEED + SPEED_BUFFER
end

local function GetAverage(t)
	if #t == 0 then return 0 end
	local s = 0
	for _, v in ipairs(t) do
		s += v
	end
	return s / #t
end

local function TeleportToSavedPosition(player)
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

	vPrint(string.format("[AC:Rubberband] Teleporting %s back to (%.1f, %.1f, %.1f)",
		player.Name, data.lastGoodPosition.X, data.lastGoodPosition.Y, data.lastGoodPosition.Z))

	hrp.Anchored = true
	hrp.CFrame = CFrame.new(data.lastGoodPosition + Vector3.new(0, 3, 0))
	hrp.AssemblyLinearVelocity = Vector3.zero
	hrp.AssemblyAngularVelocity = Vector3.zero

	task.defer(function()
		if hrp and hrp.Parent then
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

local function FlagOrKick(player, reason)
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

local function StartMovementChecks(player)
	if MovementConnections[player.UserId] then
		MovementConnections[player.UserId]:Disconnect()
		MovementConnections[player.UserId] = nil
	end

	local saveTimer = 0
	local checkTimer = 0
	local connection

	vPrint("[AC:Loop] Starting movement checks for", player.Name)

	connection = RunService.Heartbeat:Connect(function(dt)
		if not player or not player.Parent then
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
		if not hrp or not humanoid or humanoid.Health <= 0 then return end
		if hrp.Anchored then return end

		local now = tick()

		if data.immuneUntil and now < data.immuneUntil then
			if IsGrounded(character) then
				data.lastGoodPosition = hrp.Position
			end
			return
		end

		local vel = hrp.AssemblyLinearVelocity
		local grounded = IsGrounded(character)
		local jumpImmune = data.jumpImmunityUntil and now < data.jumpImmunityUntil

		if vel.Y >= JUMP_VELOCITY_TRIGGER and not grounded and not jumpImmune then
			data.jumpImmunityUntil = now + JUMP_IMMUNITY_DURATION
			jumpImmune = true
			vPrint(string.format("[AC:Jump] %s jump detected (velY=%.1f), immunity granted", player.Name, vel.Y))
		end

		if grounded then
			if not data.wasGrounded then
				vPrint(string.format("[AC:Ground] %s landed (airTime=%.2fs)", player.Name, data.airTime or 0))
			end

			data.wasGrounded = true
			data.airTime = 0

			data.flyViolations = math.max(0, (data.flyViolations or 0) - 2)

			if #data.speedSamples == 0 then
				data.speedViolations = math.max(0, (data.speedViolations or 0) - 1)
			end

			data.jumpImmunityUntil = 0
		else
			data.wasGrounded = false
			data.airTime = (data.airTime or 0) + dt
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
				local absVertical = math.abs(verticalSpeed)
				local allowedSpeed = GetAllowedSpeed(humanoid)
				
				if horizontalSpeed > allowedSpeed * 4 then
					vWarn(string.format(
						"[AC:Speed] %s extreme speed %.1f > %.1f",
						player.Name,
						horizontalSpeed,
						allowedSpeed * 4
						))

					FlagOrKick(player,
						"Extreme Speed Detected (" ..
							math.round(horizontalSpeed) ..
							" studs/s)"
					)

					data.lastCheckPos = hrp.Position
					data.lastCheckTime = now

					return
				end

				vPrint(string.format("[AC:Check] %s | hSpeed=%.1f (max=%.1f) | vSpeed=%.1f | air=%.2fs | jumpImm=%s | grounded=%s",
					player.Name,
					horizontalSpeed, allowedSpeed,
					verticalSpeed,
					data.airTime or 0,
					tostring(jumpImmune),
					tostring(grounded)))

				if horizontalSpeed > allowedSpeed then
					table.insert(data.speedSamples, horizontalSpeed)
					if #data.speedSamples > SPEED_SAMPLE_COUNT then
						table.remove(data.speedSamples, 1)
					end

					if #data.speedSamples >= SPEED_SAMPLE_COUNT then
						local avg = GetAverage(data.speedSamples)
						vWarn(string.format("[AC:Speed] %s avg=%.1f (violations=%d/%d)",
							player.Name, avg, data.speedViolations or 0, SPEED_VIOLATION_THRESHOLD))
						if avg > allowedSpeed then
							data.speedViolations = (data.speedViolations or 0) + 1

							vWarn(string.format(
								"[AC:Speed] %s violation %d/%d (avg %.1f)",
								player.Name,
								data.speedViolations,
								SPEED_VIOLATION_THRESHOLD,
								avg
								))

							if data.speedViolations >= SPEED_VIOLATION_THRESHOLD then
								data.speedViolations = 0
								data.speedSamples = {}
								FlagOrKick(player, "Speed Hack Detected (avg " .. math.round(avg) .. " studs/s)")
							end
						end
					end
				else
					data.speedSamples = {}

					if data.speedViolations > 0 then
						data.speedViolations = math.max(0, data.speedViolations - 1)
					end
				end

				if not grounded and not jumpImmune then
					local isSustainedUp = verticalSpeed > FLY_SUSTAINED_UP and (data.airTime or 0) > 0.3
					local isHovering = (data.airTime or 0) > FLY_HOVER_GRACE and absVertical < FLY_HOVER_THRESHOLD

					if isSustainedUp or isHovering then
						data.flyViolations = (data.flyViolations or 0) + 1
						vWarn(string.format("[AC:Fly] %s violation %d/%d | sustained=%s hover=%s",
							player.Name, data.flyViolations, FLY_VIOLATION_THRESHOLD,
							tostring(isSustainedUp), tostring(isHovering)))
					else
						data.flyViolations = math.max(0, (data.flyViolations or 0) - 1)
					end

					if (data.flyViolations or 0) >= FLY_VIOLATION_THRESHOLD then
						data.flyViolations = 0
						FlagOrKick(player, "Fly Hack Detected")
					end
				elseif not grounded and jumpImmune then
					data.flyViolations = math.max(0, (data.flyViolations or 0) - 1)
				end
			end

			data.lastCheckPos = hrp.Position
			data.lastCheckTime = now
		end

		if saveTimer >= SAVE_INTERVAL then
			saveTimer = 0

			if grounded then
				local currentSpeed = hrp.AssemblyLinearVelocity.Magnitude

				if currentSpeed < (GetAllowedSpeed(humanoid) + 15) then
					data.lastGoodPosition = hrp.Position
					vPrint(string.format("[AC:Save] %s good pos saved (%.1f, %.1f, %.1f)",
						player.Name, hrp.Position.X, hrp.Position.Y, hrp.Position.Z))
				else
					vWarn("[AC:Save] Rejected save due to high speed:", currentSpeed)
				end
			else
				saveTimer = 0
			end
		end

		if data.lastGoodPosition == nil and grounded then
			data.lastGoodPosition = hrp.Position
			vPrint("[AC:Save] Initial goo pos seeded for", player.Name)
		end
	end)

	MovementConnections[player.UserId] = connection
end

local function ObfuscateServices()
	local targets = {
		game:GetService("Workspace"), game:GetService("Lighting"),
		game:GetService("MaterialService"), game:GetService("ReplicatedFirst"),
		game:GetService("ReplicatedStorage"), game:GetService("StarterGui"),
		game:GetService("StarterPack"), game:GetService("StarterPlayer"),
		game:GetService("Teams"), game:GetService("SoundService"),
		game:GetService("TextChatService"),
	}
	for _, svc in ipairs(targets) do
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

local function CheckMessageForExploits(player, message, source)
	if type(message) ~= "string" then return false end
	local lower = string.lower(message)
	RecentlyFlagged[player.UserId] = RecentlyFlagged[player.UserId] or {}
	local flags = RecentlyFlagged[player.UserId]

	for _, term in ipairs(BlacklistedTerms) do
		if string.find(lower, term, 1, true) then
			if flags[term] then return false end
			flags[term] = true
			task.delay(5, function()
				if flags then flags[term] = nil end
			end)
			AppendErrorLog(player, "BlacklistedTerm", message, source)
			if Config.USE_FLAG_SYSTEM then AntiCheatData.GetData(player).Flagged = true end
			if Config.USE_IMMEDIATE_ACTION_SYSTEM then
				player:Kick("Blacklisted term detected (" .. term .. ")")
			end
			return true
		end
	end

	for _, pattern in ipairs(BlacklistedPatterns) do
		if string.find(lower, pattern) then
			local key = "pattern_" .. pattern
			if flags[key] then return false end
			flags[key] = true
			task.delay(5, function()
				if flags then flags[key] = nil end
			end)
			AppendErrorLog(player, "SuspiciousPattern", message, source)
			if Config.USE_FLAG_SYSTEM then AntiCheatData.GetData(player).Flagged = true end
			if Config.USE_IMMEDIATE_ACTION_SYSTEM then
				player:Kick("Suspicious pattern detected")
			end
			return true
		end
	end

	return false
end

local function HandleGhostScript(player)
	RecentlyFlagged[player.UserId] = RecentlyFlagged[player.UserId] or {}
	local flags = RecentlyFlagged[player.UserId]
	if flags["GhostScript"] then return end
	flags["GhostScript"] = true
	task.delay(5, function()
		if flags then flags["GhostScript"] = nil end
	end)

	AppendErrorLog(player, "GhostScript", "[GhostScript]", "NilScript")
	if Config.USE_FLAG_SYSTEM then AntiCheatData.GetData(player).Flagged = true end
	if Config.USE_IMMEDIATE_ACTION_SYSTEM then
		player:Kick("Error fired from a nil/external script environment.")
	end
end

local function ResetMovementData(player)
	PlayerMovementData[player.UserId] = {
		lastGoodPosition = nil,
		immuneUntil = tick() + 3,
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

Players.PlayerAdded:Connect(function(player)
	ResetMovementData(player)
	RecentlyFlagged[player.UserId] = {}

	task.wait(1)
	local gui = player:WaitForChild("PlayerGui", 10)
	if gui then
		local watchdog = script:FindFirstChild("LocalScript")
		if watchdog then
			local clone = watchdog:Clone()
			clone.Name = "ClientWatchdog"
			clone.Parent = gui
		end
	end

	if player.Character then
		vPrint("[AC:Init] Character already exists for", player.Name, "— starting checks immediately")
		task.wait(2)
		StartMovementChecks(player)
	end

	player.CharacterAdded:Connect(function()
		vPrint("[AC:Spawn] Character added for", player.Name)
		ResetMovementData(player)
		task.wait(2)
		StartMovementChecks(player)
	end)
end)

Players.PlayerRemoving:Connect(function(player)
	if MovementConnections[player.UserId] then
		MovementConnections[player.UserId]:Disconnect()
		MovementConnections[player.UserId] = nil
	end
	PlayerMovementData[player.UserId] = nil
	ExpectedHandshakes[player.UserId] = nil
	RecentlyFlagged[player.UserId] = nil
	RemoteThrottles[player.UserId] = nil
end)

Remotes.ExploitDetected.OnServerEvent:Connect(function(player, reason)
	if IsSpamming(player) then player:Kick("Remote Spam") return end
	if type(reason) ~= "string" then return end
	vPrint("[AC:Client] ExploitDetected from", player.Name, "—", reason)
	local data = AntiCheatData.GetData(player)
	if not data then return end
	AppendErrorLog(player, "ExploitDetected", reason, "ClientWatchdog")
	if Config.USE_FLAG_SYSTEM then data.Flagged = true end
	if Config.USE_IMMEDIATE_ACTION_SYSTEM then player:Kick(reason) end
end)

Remotes.LogReport.OnServerEvent:Connect(function(player, message, source)
	if IsSpamming(player) then return end
	if type(message) ~= "string" or type(source) ~= "string" then return end
	if message == "__actest__" then return end

	if message == "[GhostScript]" and source == "NilScript" then
		HandleGhostScript(player)
		return
	end

	vPrint("[AC:Log]", player.Name, "|", source, "|", message)
	AppendErrorLog(player, "LogReport", message, source)
	CheckMessageForExploits(player, message, source)
end)

Remotes.GiveItem.OnServerEvent:Connect(function(player, item)
	if IsSpamming(player) then return end
	vWarn("[AC:Honeypot] GiveItem fired by", player.Name, "item:", tostring(item))
	local data = AntiCheatData.GetData(player)
	if not data then return end
	if Config.USE_FLAG_SYSTEM then data.Flagged = true end
	if Config.USE_IMMEDIATE_ACTION_SYSTEM then
		data.Banned = true
		player:Kick("Exploiting fired honeypot!")
	end
end)

Remotes.Handshake.OnServerEvent:Connect(function(player, token)
	if ExpectedHandshakes[player.UserId] == token then
		ExpectedHandshakes[player.UserId] = nil
	else
		AppendErrorLog(player, "InvalidHandshake", "Token mismatch", "Handshake")
		player:Kick("Invalid Handshake")
	end
end)

task.spawn(function()
	while true do
		task.wait(20)
		for _, player in pairs(Players:GetPlayers()) do
			local token = HttpService:GenerateGUID(false)
			ExpectedHandshakes[player.UserId] = token
			Remotes.Handshake:FireClient(player, token)
		end
	end
end)

if Config.ENABLE_SERVICE_OBFUSCATION then
	task.spawn(function()
		ObfuscateServices()
		while true do
			task.wait(360)
			ObfuscateServices()
		end
	end)
end

return AntiCheat
