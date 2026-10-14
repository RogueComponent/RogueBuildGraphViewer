@echo off
rem ---------------------------------------------------------------------------
rem  serve.bat -- start the bgview live picker and open it in the browser.
rem
rem  Double-click it, or run it from a prompt. Extra arguments are passed
rem  straight through, so `serve.bat --port 8765` pins the port instead of
rem  letting the OS choose a free one.
rem
rem  The server itself opens the browser and prints the URL it opened: the URL
rem  carries a per-run random token that every request must present (V36), so
rem  it is not interchangeable between runs and cannot be bookmarked. It binds
rem  127.0.0.1 only (V35) and is read-only (V37).
rem
rem  Ctrl-C stops it. cmd.exe will ask "Terminate batch job (Y/N)?" -- either
rem  answer is fine, the server has already shut down by then.
rem ---------------------------------------------------------------------------

setlocal EnableExtensions

rem Run from THIS file's directory, so `python -m bgview` finds the package no
rem matter where the shortcut was invoked from. %~dp0 keeps its trailing slash.
pushd "%~dp0" || (
  echo [bgview] could not enter "%~dp0".
  pause
  exit /b 2
)

if not exist "bgview\__main__.py" (
  echo [bgview] this script must sit next to the 'bgview' package directory.
  echo          Looked in: "%CD%"
  goto :fail
)

rem --- find a Python that meets the floor in SPEC.md -C: 3.10+, stdlib only ---
rem The launcher is tried first on purpose. Bare `python` on a stock Windows
rem install can resolve to the Microsoft Store stub, which is not an
rem interpreter and opens the Store instead of running anything; the version
rem probe below rejects it either way, but `py -3` avoids the detour.
set "PY="

py -3 -c "import sys; raise SystemExit(0 if sys.version_info>=(3,10) else 1)" >nul 2>&1
if not errorlevel 1 set "PY=py -3"
if defined PY goto :found

python -c "import sys; raise SystemExit(0 if sys.version_info>=(3,10) else 1)" >nul 2>&1
if not errorlevel 1 set "PY=python"
if defined PY goto :found

echo [bgview] no Python 3.10+ found on PATH.
echo.
echo          bgview is stdlib-only -- there is nothing to pip install, it just
echo          needs an interpreter. Install Python 3.10 or newer from
echo          https://www.python.org/downloads/ and tick "Add python.exe to PATH".
goto :fail

:found
echo [bgview] using: %PY%
echo [bgview] starting the live picker; the browser should open by itself.
echo.

rem -u (unbuffered) so the tokened URL appears the moment the server binds.
rem Python line-buffers to a console but BLOCK-buffers to a pipe, so without
rem this `serve.bat > log.txt` would sit there looking hung with the one line
rem the user actually needs still stuck in a buffer.
%PY% -u -m bgview --serve %*
set "RC=%ERRORLEVEL%"

popd
rem Only hold the window open when something went wrong -- a clean Ctrl-C exit
rem should not make the user press a key to dismiss a window they just closed.
if not "%RC%"=="0" (
  echo.
  echo [bgview] exited with code %RC%.
  pause
)
exit /b %RC%

:fail
popd
echo.
pause
exit /b 2
