@echo off
REM nexus-request — Wrapper to invoke the PowerShell CLI from any shell (cmd, PowerShell, Windows Terminal)
REM Place this file and nexus-request.ps1 in a directory on your PATH.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0nexus-request.ps1" %*
