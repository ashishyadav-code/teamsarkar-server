@echo off
cd /d "%~dp0"
git init
git branch -M main
git remote remove origin 2>nul
git remote add origin https://github.com/ashishyadav-code/teamsarkar-server.git
git add .
git commit -m "initial server setup"
git push -u origin main
pause
