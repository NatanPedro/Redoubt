@echo off
rem ============================================================
rem  Gera o instalador Windows  (dist\Redoubt-Setup-<versao>.exe)
rem  via Inno Setup, a partir de installer\redoubt.iss.
rem
rem  Pre-requisitos:
rem    1) dist\Redoubt.exe ja buildado  ->  build.bat
rem    2) Inno Setup 6 instalado        ->  winget install JRSoftware.InnoSetup
rem ============================================================
setlocal
set DIR=%~dp0
set ISCC="%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not exist %ISCC% set ISCC="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist %ISCC% (
  echo [ERRO] Inno Setup nao encontrado.
  echo        Instale com:  winget install JRSoftware.InnoSetup
  exit /b 1
)
if not exist "%DIR%dist\Redoubt.exe" (
  echo [ERRO] dist\Redoubt.exe nao existe. Rode build.bat primeiro.
  exit /b 1
)
%ISCC% "%DIR%installer\redoubt.iss"
endlocal
