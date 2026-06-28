-- Showcase https://drive.google.com/file/d/15AiSCMoJgrgyQgWNhKH2uqJQCnLPmnCe/view?usp=sharing

local Scripts = script.Parent:FindFirstChild("Scripts")

if Scripts then
	for _, module in ipairs(Scripts:GetChildren()) do
		if module:IsA("ModuleScript") then
			task.spawn(function()
				require(module)
				--print("Module loaded: " .. module.Name)
			end)
		end
	end
else
	warn("Scripts folder not found in ModuleScript")
end
