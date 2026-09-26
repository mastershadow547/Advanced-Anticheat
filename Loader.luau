local Scripts = script.Parent:FindFirstChild("Scripts")

local LoadedModules = {}

if Scripts then
	for _, module in ipairs(Scripts:GetChildren()) do
		if module:IsA("ModuleScript") then
			task.spawn(function()
				require(module)
				LoadedModules[module.Name] = true
			end)
		end
	end
	
	print(LoadedModules)
	
else
	warn("Scripts folder not found in ModuleScript")
end
