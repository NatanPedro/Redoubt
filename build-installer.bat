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
rem  Da raiz: ler APP_VERSION (notepy) e, depois, assinar o manifesto exigem o pacote no path.
pushd "%DIR%"
rem  Versao unica fonte da verdade: notepy/__init__.py (APP_VERSION).
for /f "usebackq delims=" %%v in (`python -c "from notepy import APP_VERSION; print(APP_VERSION)"`) do set APPVER=%%v
if not defined APPVER (
  echo [ERRO] nao consegui ler APP_VERSION de notepy/__init__.py.
  popd
  exit /b 1
)
echo Versao do release: %APPVER%
%ISCC% /DAppVersion=%APPVER% "%DIR%installer\redoubt.iss"
if errorlevel 1 (
  popd
  exit /b 1
)

echo.
echo === Gerando manifesto de release assinado (RELEASE.json + SHA256SUMS) ===
rem  Assina os binarios com a identidade Ed25519 do Redoubt (custody) e gera os
rem  artefatos de verificacao. Tudo LOCAL. Verifique depois com:  verify_release.py
python -m notepy.release make --dist "%DIR%dist"

echo.
echo === Atualizando o manifesto Scoop (scoop\redoubt.json) ===
rem  Sincroniza versao + hash do Redoubt.exe com o release (nunca fica stale).
python "%DIR%tools\make_scoop_manifest.py"
popd
endlocal
