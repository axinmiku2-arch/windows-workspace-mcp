@echo off
setlocal
cd /d "%~dp0" || exit /b 1
where py >nul 2>nul
if not errorlevel 1 (
    py -3 -c "import sys, tkinter; raise SystemExit(sys.version_info < (3, 11))" >nul 2>nul
    if not errorlevel 1 (
        py -3 -B -X utf8 "%~dp0runtime\manager.py" --gui
        if errorlevel 1 pause
        exit /b
    )
)
where python >nul 2>nul
if not errorlevel 1 (
    python -c "import sys, tkinter; raise SystemExit(sys.version_info < (3, 11))" >nul 2>nul
    if not errorlevel 1 (
        python -B -X utf8 "%~dp0runtime\manager.py" --gui
        if errorlevel 1 pause
        exit /b
    )
)
echo Install Python 3.11 or newer for Windows with Tcl/Tk enabled.
pause
exit /b 1
