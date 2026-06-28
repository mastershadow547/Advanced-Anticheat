local selfRef = script
selfRef.Name = tostring(math.random(100000, 999999))
script = nil
selfRef:Destroy()

local refGame = game
local taskWait = task.wait
local taskDelay = task.delay
local taskSpawn = task.spawn
local stringLower = string.lower
local stringFind = string.find
local stringLen = string.len
local tableFind = table.find
local mathRandom = math.random
local pcallRef = pcall
local typeRef = type
local toStringRef = tostring

local ReplicatedStorage = refGame:GetService("ReplicatedStorage")
local LogService = refGame:GetService("LogService")
local ScriptContext = refGame:GetService("ScriptContext")
local Players = refGame:GetService("Players")
local RunService = refGame:GetService("RunService")

local Remotes = ReplicatedStorage:WaitForChild("Remotes")
local ExploitDetected = Remotes:WaitForChild("ExploitDetected")
local HandshakeRemote = Remotes:WaitForChild("Handshake")
local LogReport = Remotes:WaitForChild("LogReport")

local fireExploit = ExploitDetected.FireServer
local fireLog = LogReport.FireServer
local fireHandshake = HandshakeRemote.FireServer
local handshakeSignal = HandshakeRemote.OnClientEvent

local MAX_FIELD_OF_VIEW = 70
local LocalPlayer = Players.LocalPlayer

local WhiteListedGui = {
	"MainGui",
	"ShopGui",
	"InventoryGui",
	"TopbarCenteredClipped",
	"TopbarStandardClipped",
	"TopbarStandard",
	"TopbarCentered",
	"HDAdminInterface"
}

local BlacklistedUI = {
	"dex", "cobalt", "mainmenu", "intro", "explorerselections", "properties", "ketamine",
}

local BlacklistedTerms = {
	"httpget", "loadstring", "getgenv", "getrawmetatable",
	"hookmetamethod", "hookfunction", "newcclosure", "replaceclosure",
	"synapse", "krnl", "fluxus", "xeno", "madium", "wave",
	"dex", "remotespy", "rayfield", "electron", "oxygen",
	"celery", "scriptware", "exploit", "executor",
	"cobalt", "Cobalt", "syn", "Dex", "ExplorerSelections",
	"Ketamine", "ketamine",
}

ExploitDetected.Parent = nil
LogReport.Parent = nil
HandshakeRemote.Parent = nil

local function SafeFireExploit(reason: string)
	ExploitDetected.Parent = Remotes
	fireExploit(ExploitDetected, reason)
	ExploitDetected.Parent = nil
end

local function SafeFireLog(message: string, source: string)
	LogReport.Parent = Remotes
	fireLog(LogReport, message, source)
	LogReport.Parent = nil
end

local function SafeFireHandshake(token: string)
	HandshakeRemote.Parent = Remotes
	fireHandshake(HandshakeRemote, token)
	HandshakeRemote.Parent = nil
end

handshakeSignal:Connect(function(Token: string)
	SafeFireHandshake(Token)
end)

local logServiceIntact = true
local scriptContextIntact = true

local function VerifyLogService()
	local fired = false
	local conn

	local ok = pcallRef(function()
		conn = LogService.MessageOut:Connect(function()
			fired = true
		end)
	end)

	if not ok or not conn then
		logServiceIntact = false
		SafeFireExploit("LogService.MessageOut hook detected (connect failed)")
		return
	end

	warn("__actest__")
	taskWait()
	taskWait()

	pcallRef(function() conn:Disconnect() end)

	if not fired then
		logServiceIntact = false
		SafeFireExploit("LogService.MessageOut hook detected (suppressed)")
	end
end

local function VerifyScriptContext()
	local conn

	local ok, err = pcallRef(function()
		conn = ScriptContext.Error:Connect(function() end)
	end)

	if not ok or not conn then
		scriptContextIntact = false
		SafeFireExploit("ScriptContext.Error hook detected (connect failed): " .. toStringRef(err))
		return
	end

	local disconnectOk = pcallRef(function()
		conn:Disconnect()
	end)

	if not disconnectOk then
		scriptContextIntact = false
		SafeFireExploit("ScriptContext.Error hook detected (disconnect failed)")
	end
end

taskSpawn(VerifyLogService)
taskSpawn(VerifyScriptContext)

taskSpawn(function()
	if refGame:FindFirstChild("MessagingService") then
		SafeFireExploit("Found Executor injection successful notification!")
	end
end)

taskSpawn(function()
	while true do
		taskWait(30)
		taskSpawn(VerifyLogService)	
		taskSpawn(VerifyScriptContext)

		if refGame:FindFirstChild("MessagingService") then
			SafeFireExploit("Found Executor injection successful notification!")
		end

	end
end)

local function MonitorOtherCharacter(character: Model)
	character.ChildAdded:Connect(function(child: Instance)
		if child:IsA("Highlight") or child:IsA("BillboardGui") or child:IsA("BoxHandleAdornment") then
			SafeFireExploit("ESP injected into character: " .. toStringRef(child.ClassName))
		end
	end)
end

local function HookPlayer(targetPlayer: Player)
	if targetPlayer == LocalPlayer then return end
	if targetPlayer.Character then
		MonitorOtherCharacter(targetPlayer.Character)
	end
	targetPlayer.CharacterAdded:Connect(MonitorOtherCharacter)
end

for _, player in pairs(Players:GetPlayers()) do
	HookPlayer(player)
end
Players.PlayerAdded:Connect(HookPlayer)

LocalPlayer.PlayerGui.ChildAdded:Connect(function(child: Instance)
	taskWait()
	if child:IsA("ScreenGui") then
		local lowerName = stringLower(child.Name)

		for _, badName in ipairs(BlacklistedUI) do
			if stringFind(lowerName, badName) then
				SafeFireExploit("Dex/Cobalt GUI Fallback Detected: " .. child.Name)
				return
			end
		end

		if not tableFind(WhiteListedGui, child.Name) then
			SafeFireExploit("Unauthorized ScreenGui injected: " .. toStringRef(child.Name))
		end
	end
end)

refGame:GetService("Workspace").CurrentCamera:GetPropertyChangedSignal("FieldOfView"):Connect(function()
	if refGame:GetService("Workspace").CurrentCamera.FieldOfView > MAX_FIELD_OF_VIEW then
		SafeFireExploit("Camera FieldOfView tampered: " .. toStringRef(refGame:GetService("Workspace").CurrentCamera.FieldOfView))
	end
end)

local function IsSuspiciousMessage(msg: string): boolean
	local lower = stringLower(msg)
	for _, term in ipairs(BlacklistedTerms) do
		if stringFind(lower, term, 1, true) then
			return true
		end
	end
	return false
end

LogService.MessageOut:Connect(function(message: string, messageType: Enum.MessageType)
	if not logServiceIntact then return end
	if stringFind(message, "__actest__", 1, true) then return end
	if messageType == Enum.MessageType.MessageError then return end
	if IsSuspiciousMessage(message) then
		SafeFireLog(message, "LogService")
	end
end)

ScriptContext.Error:Connect(function(message: string, stackTrace: string, errorScript: Instance)
	if not scriptContextIntact then return end

	if errorScript == nil then
		SafeFireLog("[GhostScript]", "NilScript")
		return
	end

	local pcallOk, scriptPath = pcallRef(function()
		return errorScript:GetFullName()
	end)

	if pcallOk and scriptPath then
		local lowerPath = stringLower(scriptPath)

		local isInternalScript = stringFind(lowerPath, "starterplayer")
			or stringFind(lowerPath, "starterpack")
			or stringFind(lowerPath, "playergui")
			or stringFind(lowerPath, "replicatedstorage")
			or stringFind(lowerPath, "corescripts")
			or stringFind(lowerPath, "robloxgui")

		if not isInternalScript or stringFind(lowerPath, "workspace") then
			SafeFireLog(message .. " | Path: " .. scriptPath, "ScriptContext.UnauthorizedOrigin")
			if typeRef(stackTrace) == "string" and stringLen(stackTrace) > 0 then
				SafeFireLog(stackTrace, "ScriptContext.StackTrace")
			end
		end
	else
		SafeFireLog("[MaskedScript Environment Exception]", "NilScript")
	end
end)

_G.AntiCheatEnabled = "ON"

taskSpawn(function()
	while true do
		taskWait(3)
		if _G.AntiCheatEnabled ~= "ON" then
			SafeFireExploit("_G.AntiCheatEnabled tampered")
			_G.AntiCheatEnabled = "ON"
		end
	end
end)

taskSpawn(function()
	while true do
		taskWait(15)

		if typeRef(task.wait) ~= "function" then
			SafeFireExploit("task.wait replaced in environment")
		end

		if typeRef(pcall) ~= "function" then
			SafeFireExploit("pcall replaced in environment")
		end

		if typeRef(string.lower) ~= "function" then
			SafeFireExploit("string.lower replaced in environment")
		end
	end
end)
