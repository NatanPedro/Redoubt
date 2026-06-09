@echo off
rem ============================================================
rem  Empacota o Redoubt num executavel standalone (dist\Redoubt.exe).
rem  Pre-requisitos:  pip install pyinstaller pillow
rem  Os intermediarios vao para %TEMP% (fora do OneDrive); o .exe
rem  final fica em dist\ (ignorado pelo git).
rem ============================================================
setlocal
set DIR=%~dp0
set BUILD=%TEMP%\redoubt-build

python -m PyInstaller --noconfirm --noconsole --onefile --name Redoubt ^
  --icon "%DIR%assets\redoubt.ico" ^
  --add-data "%DIR%assets;assets" ^
  --hidden-import PyQt6.Qsci ^
  --workpath "%BUILD%\work" --distpath "%DIR%dist" --specpath "%BUILD%" ^
  "%DIR%main.py"

echo.
echo Pronto:  %DIR%dist\Redoubt.exe
endlocal
