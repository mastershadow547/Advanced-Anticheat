-- found this on youtube video by https://www.youtube.com/@taze92 on youtube. not mines. 
local DEBUG_INFO = debug.info
local GET_FENV = getfenv

return {
	Output = function(...)
		local stack = DEBUG_INFO(2, "f")
		
		if stack then
			local env = GET_FENV(stack)
			
			if env then
				if env.getgc then
					print("Exploit Stack Detected! GetGC")
				end
				if env.rconsolewarn then
					print("Exploit stack detected! rconsoleWarn")
				end
			end
		end
		
		print(...)
	end,
}
