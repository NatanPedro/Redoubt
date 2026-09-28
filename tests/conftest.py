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
# No Linux/BSD a mesma pasta vem do XDG: `_data_dir()` usa $XDG_DATA_HOME, e o QSettings grava as
# preferencias em $XDG_CONFIG_HOME/Redoubt/Redoubt.conf. Sem isolar os dois, rodar a suite (ex.: o
# check() do PKGBUILD, na maquina de quem instala) mexeria nas chaves e preferencias REAIS.
os.environ["XDG_DATA_HOME"] = tempfile.mkdtemp(prefix="redoubt-tests-xdgdata-")
os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="redoubt-tests-xdgconfig-")
# O tema grava as setas dos campos (PNG) no cache do usuario: nos testes, num cache temporario.
os.environ["XDG_CACHE_HOME"] = tempfile.mkdtemp(prefix="redoubt-tests-xdgcache-")
os.environ["LOCALAPPDATA"] = tempfile.mkdtemp(prefix="redoubt-tests-localappdata-")

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

    # Dialogos proprios do redesign: selar le as DUAS senhas da mesma fila (como os dois
    # QInputDialog de antes) e a custodia nao abre janela modal.
    from notepy import widgets

    def _seal_ask(_parent, _name):
        first = inbox.pop(0) if inbox else ("", False)
        if not first[1]:
            return None
        second = inbox.pop(0) if inbox else ("", False)
        if not second[1]:
            return None
        return first[0], second[0]

    monkeypatch.setattr(widgets.SealDialog, "ask", staticmethod(_seal_ask))
    monkeypatch.setattr(widgets.CustodyDialog, "exec", lambda self: 0)

    theme.apply_app(qapp)
    w = MainWindow()
    w._inbox = inbox
    yield w
    w.close()
