# PsBlackwakeMonitor
Powershell script to update, start and monitor Blackwake Server

# Requirements
Powershell (v3.0+ required)  
Blackwake v0.1.16 Server  (tested)

# Installation
* Put script in server folder, for example "C:\SteamCMD\blackwake_server"
* Edit script settings
* Put ```start /D %~dp0 Powershell.exe -ExecutionPolicy Bypass -NoLogo -File %~dp0\PsBlackwakeMonitor.ps1 && exit``` into  
```server update.bat``` for server daily autorestart
* Finally execute ```server update.bat``` as administrator



![PsBlackwakeMonitor Screenshot](https://raw.githubusercontent.com/man4red/PsBlackwakeMonitor/screenshots/PsBlackwakeMonitor_1.png?raw=true)

Feel free to contact me in any needs
