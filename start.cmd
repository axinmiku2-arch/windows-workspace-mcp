@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "VENV_PY=%~dp0.venv\Scripts\python.exe"
if not exist "%VENV_PY%" (
    >&2 echo Local Python environment missing. Run setup.cmd first.
    exit /b 2
)
"%VENV_PY%" -E -s -B -X utf8 "%~dp0helper.py" %*
exit /b %ERRORLEVEL%
