@echo off
rem ============================================================
rem  Instala o hook git pre-push do Redoubt (roda a suite antes
rem  de empurrar e bloqueia se algo quebrar). Local, sem servidor.
rem  Coexiste com o pre-commit anti-segredo (arquivos distintos).
rem ============================================================
setlocal
set DIR=%~dp0
set SRC=%DIR%tools\hooks\pre-push
set HOOKS=%DIR%.git\hooks

if not exist "%SRC%" (
  echo [ERRO] nao achei %SRC%
  exit /b 1
)
if not exist "%HOOKS%" (
  echo [ERRO] %HOOKS% nao existe — isto e um repositorio git?
  exit /b 1
)
copy /Y "%SRC%" "%HOOKS%\pre-push" >nul
if errorlevel 1 (
  echo [ERRO] nao consegui copiar o hook.
  exit /b 1
)
echo Hook pre-push instalado em: %HOOKS%\pre-push
echo.
echo Agora "git push" roda a suite de testes antes (bloqueia se quebrar).
echo Para pular numa emergencia:  git push --no-verify
endlocal
