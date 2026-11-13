@echo off
rem Compila o APK do Android. Opcoes: -Install -Release -SkipTests  (veja scripts\build-android.ps1)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build-android.ps1" %*
echo %cmdcmdline% | find /i "%~0" >nul && pause
