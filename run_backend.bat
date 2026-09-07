@echo off
python -m uvicorn backend.main:app --reload
pause
