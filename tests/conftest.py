"""Configuracao comum dos testes.

Roda o Qt em modo headless (offscreen) e oferece fixtures para uma janela
de teste com os dialogos (QMessageBox/QInputDialog/QFileDialog) neutralizados,
para nada bloquear a suite.
"""

import os
import tempfile

# DEVE vir antes de qualquer import de Qt.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Isola o diretorio de dados do app (identidade Ed25519, chave de destinatario X25519 e trilha de
# auditoria, que `custody._data_dir()` deriva de %APPDATA%) num temporario. Sem isto, qualquer teste
# que toque `custody` sem fazer o monkeypatch por conta propria grava no perfil REAL do usuario — foi
# assim que a suite inflou o audit.log real e chegou a gerar uma `recipient.x25519` acidental.
# Feito por ENV no import (nao como fixture autouse): acrescentar uma fixture muda a ordem/timing de
# setup e isso destrava o crash conhecido do Qt offscreen em theme.apply_app.
os.environ["APPDATA"] = tempfile.mkdtemp(prefix="redoubt-tests-appdata-")

import pytest
from PyQt6.QtWidgets import QApplication, QFileDialog, QInputDialog, QMessageBox


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def win(qapp, monkeypatch):
    """MainWindow pronta, com dialogos mockados. Use win._inbox para respostas
    de QInputDialog (ex.: senhas): win._inbox.append(("senha", True))."""
    from notepy import theme
    from notepy.mainwindow import MainWindow

    SB = QMessageBox.StandardButton
    for name in ("information", "warning", "critical"):
        monkeypatch.setattr(QMessageBox, name, staticmethod(lambda *a, **k: SB.Ok))
    monkeypatch.setattr(QMessageBox, "about", staticmethod(lambda *a, **k: None))

    inbox: list = []
    monkeypatch.setattr(QInputDialog, "getText",
                        staticmethod(lambda *a, **k: inbox.pop(0) if inbox else ("", False)))
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: ("", "")))
    monkeypatch.setattr(QFileDialog, "getOpenFileNames", staticmethod(lambda *a, **k: ([], "")))

    theme.apply_app(qapp)
    w = MainWindow()
    w._inbox = inbox
    yield w
    w.close()
