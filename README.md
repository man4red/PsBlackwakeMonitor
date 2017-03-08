# PsBlackwakeMonitor
Powershell script to update, start and monitor Blackwake Server

# Requirements
Powershell (v3.0+ required)  
Blackwake v0.1.15e Server  (tested)

# Installation
* Put script to server folder, for example "C:\SteamCMD\blackwake_server"
* Run powershell as administrator and execute ```Set-ExecutionPolicy Bypass -Force``` to allow scripts
* Edit settings
* Finally execute ```start powershell .\PsBlackwakeMonitor.ps1```
* Put ```start /D %~dp0 Powershell.exe -ExecutionPolicy Bypass -NoLogo -File %~dp0\PsBlackwakeMonitor.ps1``` into  
```server update.bat``` for autorestart


![PsBlackwakeMonitor Screenshot](https://raw.githubusercontent.com/man4red/PsBlackwakeMonitor/screenshots/PsBlackwakeMonitor_1.png?raw=true)

Feel free to contact me in any needs
