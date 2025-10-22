@echo off
set "_PSf=%~dp0Windows_10_ESU_Catalog_Monthly_Updates.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%_PSf%" %*
pause