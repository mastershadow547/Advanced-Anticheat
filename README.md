# Advanced-Anticheat
A robust anti-cheat system for Roblox designed to detect movement exploits, unauthorized remote execution, and environment tampering.

# 🛠️ How to Setup
Follow these steps to integrate the system into your project.

1. Dependencies
Inside ServerScriptService, create a folder named Libraries.

Place the ProfileStore ModuleScript inside this folder.

Note: If you already use ProfileStore elsewhere, simply update the ProfileStore variable in your AntiCheatData script to point to your existing location.

2. Core Structure
Create a folder inside ServerScriptService named AntiCheatLoader.

Inside AntiCheatLoader, create a folder named Scripts.

3. File Hierarchy
Organize your scripts exactly as shown below:

# Plaintext
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
Important Configuration Notes
Script Types:

Loader must be a standard Server Script.

ClientCore must be a LocalScript.

All other files mentioned should be ModuleScripts.

Parenting: Ensure ClientCore is parented directly under ServerCore, and AntiCheatTemplate is parented directly under AntiCheatData as indicated in the hierarchy above.

<img width="331" height="537" alt="image" src="https://github.com/user-attachments/assets/e6d0606e-041c-4db0-8762-02f286118118" />
