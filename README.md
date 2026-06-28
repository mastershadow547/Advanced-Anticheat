# Advanced-Anticheat
A anti-cheat system for Roblox made to detect movement exploits, unauthorized remote execution, and environment tampering.

# How to Setup?
1. Dependency Setup
Inside ServerScriptService, create a folder named Libraries.

Place the ProfileStore ModuleScript inside this folder.

Note: If you already use ProfileStore elsewhere, ensure you update the ProfileStore variable in your AntiCheatData script to point to your existing location.

2. Main Folder Structure
Create a folder inside ServerScriptService named AntiCheatLoader.

3. Organizing Components
Inside the AntiCheatLoader folder, set up the following items:

Folder: Scripts

Place these scripts inside the Scripts folder:

Configurations.luau (ModuleScript)

AntiCheatData.luau (ModuleScript)

AntiCheatTemplate.luau (ModuleScript)

ServerCore.luau (ModuleScript)

LocalScript: ClientCore (Parented directly under ServerCore)

AntiCheatData.luau (ModuleScript)

ModuleScript: AntiCheatTemplate (Parented directly under AntiCheatData)

Script: Loader.luau (This must be a normal Server Script at the root of the AntiCheatLoader folder).

in the end the structure should look like this:
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

<img width="336" height="540" alt="image" src="https://github.com/user-attachments/assets/4ccbff1b-cafc-4ae3-9720-15a3d03f0edc" />
