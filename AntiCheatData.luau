local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("RunService")
local RunService = game:GetService("RunService")
local ServerScriptService = game:GetService("ServerScriptService")

local AntiCheatDataTemplate = require(script.AntiCheatTemplate)
local Config = require(script.Parent.Configurations)
local ProfileStore = require(ServerScriptService.Libraries.ProfileStore)

local DATA_STORE_KEY = RunService:IsStudio() and "TEST_ANTICHEAT7" or "OFFICIAL_ANTICHEAT"
local AntiCheatStore = ProfileStore.New(DATA_STORE_KEY, AntiCheatDataTemplate.DEFAULT_ANTI_CHEAT_DATA)
local Profiles: {[Player]: typeof(AntiCheatStore:StartSessionAsync())} = {}

local Local = {}
local Shared = {}

function Local.OnStart()
	for _, Player in Players:GetPlayers() do
		task.spawn(Local.LoadProfile, Player)
	end
	
	Players.PlayerAdded:Connect(Local.LoadProfile)
	Players.PlayerRemoving:Connect(Local.RemoveProfile)
end

function Local.LoadProfile(Player: Player)
	if Player.AccountAge < Config.MINIMUM_ACCOUNT_AGE then
		Player:Kick("Your account must be at least "..Config.MINIMUM_ACCOUNT_AGE.." days old to play this game.")
	end
	
	local Profile = AntiCheatStore:StartSessionAsync(`{Player.UserId}`, {
		Cancel = function()
			return Player.Parent ~= Players
		end,
	})
	
	if Profile == nil then
		return Player:Kick("Profile load fail! Please rejoin or contact devs.")
	end
	
	Profile:AddUserId(Player.UserId)
	Profile:Reconcile()
	
	Profile.OnSessionEnd:Connect(function()
		Profiles[Player] = nil
		Player:Kick("Profile session ended! Please rejoin.")
	end)
	
	local IsIngame = Player.Parent == Players
	if IsIngame then
		Profiles[Player] = Profile
	else
		Profile:EndSession()
	end
	
	local HasBeenKicked = false
	
	if RunService:IsServer() then
		print(`Loaded AntiCheat profile for {Player.Name}`, Profile.Data)
	end

	if Profile.Data.Banned == true then
		Player:Kick("You have been banned from this game.")
		HasBeenKicked = true
	end
	
	if Config.USE_FLAG_SYSTEM == true then
		if Config.ACTIVATE_BANWAVE == true then
			if HasBeenKicked == false then
				Profile.Data.Banned = true
				Player:Kick("You have been banned from this game.")
			end
		end
	end
	
end

function Local.RemoveProfile(Player: Player)
	local Profile = Profiles[Player]
	if Profile ~= nil then
		Profile:EndSession()
	end
end

function Shared.GetData(Player: Player): AntiCheatDataTemplate.AntiCheatData?
	local Profile = Profiles[Player]
	if not Profile then return end
	
	return Profile.Data
end

Local.OnStart()

return Shared
