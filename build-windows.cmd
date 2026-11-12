@echo off
rem Compila o app do Windows. Opcoes: -Test -Run -Dev  (veja scripts\build-windows.ps1)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build-windows.ps1" %*
echo %cmdcmdline% | find /i "%~0" >nul && pause
