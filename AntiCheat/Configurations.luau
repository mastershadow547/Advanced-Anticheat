local Configurations = {}

Configurations.USE_FLAG_SYSTEM = true
Configurations.USE_IMMEDIATE_ACTION_SYSTEM = false
Configurations.ACTIVATE_BANWAVE = false
Configurations.VERBOSE = false

Configurations.MINIMUM_ACCOUNT_AGE = 7 -- in days

if Configurations.USE_FLAG_SYSTEM and Configurations.USE_IMMEDIATE_ACTION_SYSTEM then
	if Configurations.VERBOSE then
		warn("AntiCheat Error: Both systems enabled. Defaulting to Flag System only.")
	end
	Configurations.USE_IMMEDIATE_ACTION_SYSTEM = false
elseif not Configurations.USE_FLAG_SYSTEM and not Configurations.USE_IMMEDIATE_ACTION_SYSTEM then
	error("AntiCheat Configuration Error: No system selected! Enable either Flag or Immediate Action.")
end

return Configurations
