@echo off
REM Быстрый запуск GUI приложения Bochka на Windows

setlocal enabledelayedexpansion

if exist .venv\Scripts\python.exe (
    echo ✅ Активирую виртуальное окружение...
    .venv\Scripts\python.exe apps\gui_scanner.py
) else (
    echo ❌ Виртуальное окружение не найдено
    echo.
    echo Установи зависимости:
    echo   python -m pip install -r requirements.txt
    pause
    exit /b 1
)
