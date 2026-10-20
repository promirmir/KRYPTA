@echo off
cd /d "%~dp0"
py -3 -m krypta gui
if errorlevel 1 (
  echo.
  echo Nie udalo sie uruchomic KRYPTA.
  echo Zainstaluj Python i zaleznosci: py -m pip install -e .
  pause
)