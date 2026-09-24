"""Ponto de entrada do Redoubt.

Uso:
    python main.py [arquivo1 arquivo2 ...]
"""

from __future__ import annotations

import os
import sys

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

from notepy import APP_NAME, config, theme
from notepy.mainwindow import MainWindow


def asset_path(name: str) -> str:
    """Resolve um arquivo de assets/ tanto rodando do codigo quanto do .exe (PyInstaller)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "assets", name)


def main() -> int:
    # No Windows, declara um AppUserModelID proprio para a taskbar usar NOSSO icone
    # (e nao o do python/pythonw) e agrupar como app independente.
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Redoubt.Editor")
        except Exception:
            pass

    # argv[0] vira o nome da INSTANCIA no WM_CLASS do X11 ("main.py" por padrao): com "redoubt" a
    # janela casa com o redoubt.desktop e a dock/barra agrupa no icone certo (GNOME/KDE em X11).
    app = QApplication(["redoubt", *sys.argv[1:]])
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)
    # Linux: liga a janela ao redoubt.desktop instalado. No Wayland e isso que da o icone e o
    # agrupamento certos na barra de tarefas (o compositor ignora o icone definido pela janela).
    app.setDesktopFileName("redoubt")

    icon = QIcon(asset_path("redoubt.ico" if sys.platform == "win32" else "redoubt.png"))
    if not icon.isNull():
        app.setWindowIcon(icon)

    theme.set_theme(config.get("theme"))   # tema salvo nas preferencias
    theme.apply_app(app)          # estilo Fusion + paleta + QSS

    window = MainWindow()
    if not icon.isNull():
        window.setWindowIcon(icon)

    # Abre os arquivos passados na linha de comando (e via "Abrir com…").
    # Argumentos de CLI tem prioridade; sem eles, restaura a ultima sessao.
    opened_any = False
    for arg in sys.argv[1:]:
        window.open_path(arg)
        opened_any = True
    if opened_any:
        window._maybe_close_initial_empty()
    else:
        window.restore_session()

    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
