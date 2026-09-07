@echo off
python scripts\validate_contracts.py
if errorlevel 1 pause & exit /b 1
pytest -q
pause
