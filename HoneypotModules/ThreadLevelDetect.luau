local module = {}
-- as soon as a exploiter requires this module script it will detect their thread level if it is higher then 2 it will detect it.
-- ============================================================
-- CHECK 1: Thread identity probing
--   2 = GameScript (normal)
--   4 = CommandBar (exploit / elevated)
--   5 = StudioPlugin (elevated)
--   Anything > 2 is suspicious for a runtime module
-- ============================================================

local Module = Instance.new("ModuleScript")

local hasLocalUser = pcall(function() return game.DataCost end)
local hasPlugin    = pcall(function() return game:GetService("CoreGui").Name end)
local hasOpenCloud = pcall(function() return Module.Source end)

local identity
if hasLocalUser and hasPlugin and hasOpenCloud then
	identity = 4 -- CommandBar
elseif hasPlugin and hasOpenCloud then
	identity = 5 -- StudioPlugin
elseif hasPlugin then
	identity = 0 -- legacy Plugin identity
elseif hasLocalUser then
	identity = 1 -- LocalUser
else
	identity = 2 -- GameScript
end

print(identity)

if identity > 2 then
	print(("Exploit detected! (identity %d > 2)"):format(identity))
end

Module:Destroy()

return module
