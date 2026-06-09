"""Configuracao comum dos testes.

Roda o Qt em modo headless (offscreen) e oferece fixtures para uma janela
de teste com os dialogos (QMessageBox/QInputDialog/QFileDialog) neutralizados,
para nada bloquear a suite.
"""

import os

# DEVE vir antes de qualquer import de Qt.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

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
