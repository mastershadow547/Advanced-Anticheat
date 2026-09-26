local Shared = {}

Shared.DEFAULT_ANTI_CHEAT_DATA = {
	Flagged = false,
	Banned = false,
	ErrorLogs = {},
}

export type AntiCheatData = typeof(Shared.DEFAULT_ANTI_CHEAT_DATA)

return Shared
