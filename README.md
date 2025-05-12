A simple Rust-based console tool to help migrate personal data and installed applications between Windows systems.

WinMigrator is a lightweight and interactive CLI utility designed to make setting up a new Windows machine easier. It allows you to:

    ✅ Export and import installed apps using winget

    📁 Back up personal folders (Documents, Downloads, etc.)

    🎯 Select individual files/folders for advanced export

    💾 Organize exports under a username and PC name

    🔁 Import backed-up files interactively

    📦 Track progress with clear progress bars

    🛠 Upgrade all installed apps in one go

Exports are saved in structured directories, and app lists are stored as .json for easy reuse.

🧰 Note: WinMigrator is intended to be run from a USB stick for easy portability between systems.

🧰 If you get errors, while installing packages, try to run winmigrator.exe as a normal user (not as Administrator)
