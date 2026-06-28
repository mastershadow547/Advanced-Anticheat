-- Showcase https://drive.google.com/file/d/15AiSCMoJgrgyQgWNhKH2uqJQCnLPmnCe/view?usp=sharing

local RunService = game:GetService("RunService")

local Configurations = {}

Configurations.USE_FLAG_SYSTEM = true
Configurations.USE_IMMEDIATE_ACTION_SYSTEM = false
Configurations.ACTIVATE_BANWAVE = false
Configurations.ENABLE_SERVICE_OBFUSCATION = true
Configurations.VERBOSE = true
Configurations.MINIMUM_ACCOUNT_AGE = 7

local function ValidateConfig()
	local function AssertType(key, expectedType)
		local val = Configurations[key]
		if val == nil then
			error("AntiCheat Configuration Error: " .. key .. " cannot be nil.")
		end
		if typeof(val) ~= expectedType then
			error("AntiCheat Configuration Error: " .. key .. " must be " .. expectedType .. ", got " .. typeof(val))
		end
	end

	AssertType("USE_FLAG_SYSTEM", "boolean")
	AssertType("USE_IMMEDIATE_ACTION_SYSTEM", "boolean")
	AssertType("ACTIVATE_BANWAVE", "boolean")
	AssertType("ENABLE_SERVICE_OBFUSCATION", "boolean")
	AssertType("VERBOSE", "boolean")
	AssertType("MINIMUM_ACCOUNT_AGE", "number")

	if Configurations.USE_FLAG_SYSTEM and Configurations.USE_IMMEDIATE_ACTION_SYSTEM then
		warn("AntiCheat Error: Both systems enabled. Defaulting to Flag System only.")
		Configurations.USE_IMMEDIATE_ACTION_SYSTEM = false
	elseif not Configurations.USE_FLAG_SYSTEM and not Configurations.USE_IMMEDIATE_ACTION_SYSTEM then
		error("AntiCheat Configuration Error: No system selected! Enable either Flag or Immediate Action.")
	end

	if Configurations.VERBOSE and not RunService:IsStudio() then
		warn("AntiCheat Warning: Verbose mode enabled in production environment. Turning off!")
		Configurations.VERBOSE = false
	end
end

ValidateConfig()

return Configurations
