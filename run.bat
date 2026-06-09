@echo off
rem Inicia o Notepy sem janela de console (pythonw).
rem %~dp0 = pasta deste .bat   |   %* = arquivos passados (ex.: arrastar pro .bat)
start "" pythonw "%~dp0main.py" %*
