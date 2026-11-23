@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "VENV_DIR=%~dp0.venv"
set "VENV_PY=%VENV_DIR%\Scripts\python.exe"
if exist "%VENV_PY%" goto verify_venv

python.exe -E -s -c "import sys; raise SystemExit(not (sys.platform == 'win32' and sys.version_info >= (3, 11)))" >nul 2>&1
if errorlevel 1 goto bad_python
python.exe -E -s -m venv "%VENV_DIR%"
if errorlevel 1 goto bad_venv

:verify_venv
"%VENV_PY%" -E -s -c "import sys; raise SystemExit(not (sys.platform == 'win32' and sys.version_info >= (3, 11) and sys.prefix != sys.base_prefix))" >nul 2>&1
if errorlevel 1 goto bad_venv
"%VENV_PY%" -E -s -m pip --isolated --disable-pip-version-check --require-virtualenv install --requirement "%~dp0requirements.txt"
if errorlevel 1 exit /b 1
echo Setup complete. See docs\quickstart.zh-CN.md before starting the helper.
exit /b 0

:bad_python
>&2 echo Python 3.11 or newer for Windows is required. Install it and make python.exe available on PATH, then run setup.cmd again.
exit /b 2

:bad_venv
>&2 echo Could not create or use the local .venv directory. If it contains an old or moved virtual environment, move it aside and run setup.cmd again.
exit /b 3
