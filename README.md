# Advanced-Anticheat
A robust anti-cheat system for Roblox designed to detect movement exploits, unauthorized remote execution, and environment tampering.

# 🛠️ How to Setup
Follow these steps to integrate the system into your project.

# 1. Dependencies
1. Inside ServerScriptService, create a folder named Libraries.

2. Place the ProfileStore ModuleScript inside this folder.

- Note: If you already use ProfileStore elsewhere, simply update the ProfileStore variable in your AntiCheatData script to point to your existing location.

# 2. Core Structure
1. Create a folder inside ServerScriptService named AntiCheatLoader.

2. Inside AntiCheatLoader, create a folder named Scripts.

# 3. File Hierarchy
Organize your scripts exactly as shown below:

# Plaintext
```text
ServerScriptService
 ├── Libraries
 │    └── ProfileStore (ModuleScript)
 └── AntiCheatLoader (Folder)
      ├── Loader (Script)
      └── Scripts (Folder)
           ├── Configurations (ModuleScript)
           ├── AntiCheatData (ModuleScript)
           │    └── AntiCheatTemplate (ModuleScript)
           └── ServerCore (ModuleScript)
                └── ClientCore (LocalScript)
```
# Important Configuration Notes
- Script Types:

- Loader must be a standard Server Script.
- ClientCore must be a LocalScript.
- All other files mentioned should be ModuleScripts.

- Parenting: Ensure ClientCore is parented directly under ServerCore, and AntiCheatTemplate is parented directly under AntiCheatData as indicated in the hierarchy above.

<img width="331" height="537" alt="image" src="https://github.com/user-attachments/assets/e6d0606e-041c-4db0-8762-02f286118118" />

# Now What Does It Detect and Do?
- Speed hacks
- Fly Hacks
- Unauthorized gui's (in PlayerGui as CoreGui requires higher level permissions)
- Unauthorized instances
- Highlight detection
- Honeypot (GiveItem)
- _G variable tampering
- Errors/Log detection
- Field Of View tampering detection
- Esp Detection (basic)
- Changes the names of common services so some scripts get errors and don't work.
- Method tampering detection
- Handshake
- Logs up to 100 errors or flags to a player.
- Makes it harder to find the client core.
- Flag system where it flags the player and when banwave is active it bans them.
- Enforces a minimum account age preventing some alt accounts.
- Verbose mode that shows everything in console.
- Immediate action system where it dosen't flag and waits for banwave it instantly bans.
- Remote rate limiting to prevent spam.
- Checks args sent by client.
- Saves everything to DataStore using ProfileStore

  Thats pretty much all I'm going to make this use Roblox's ban api later but also still save the logs.
  Im currently reading and trying to understand some scripts like Dark Dex and Ketamine Remote Spy, so I can find a way to detect them.
