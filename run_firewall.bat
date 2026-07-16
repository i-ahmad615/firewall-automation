@echo off
title Firewall Automation

cd /d "%~dp0"

call .venv\Scripts\activate.bat

python main.py

pause