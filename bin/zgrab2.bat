@echo off
cd /d "%~dp0"
wsl --cd "%cd%" ./zgrab2 %*
