"""Tema "Redoubt" — carbono + ambar. A cor e SEMANTICA.

  ambar  = atencao / marca       verde = selado / limpo
  vermelho = exposto / segredo

Concentra a paleta, a folha de estilo (QSS) do chrome e as funcoes que pintam
o editor e os lexers do QScintilla — para o app NAO herdar as cores default do
Scintilla (que sao a cara do Notepad++).

Dois temas: 'dark' (carbono, padrao) e 'light' (claro), com a MESMA semantica de
cor. `set_theme(nome)` troca a paleta ativa em tempo de execucao reescrevendo as
constantes de modulo (BG, AMBER, ...) — por isso o resto do app deve ler
`theme.AMBER` (acesso por atributo), nunca `from theme import AMBER`.

As pecas da interface (barra superior, trilho lateral, painel da Sentinela, faixas de
alerta, cartoes) sao estilizadas por `objectName` no QSS abaixo: o codigo das telas so diz
O QUE cada peca e, a aparencia mora aqui.
"""

from __future__ import annotations

from string import Template

from PyQt6.QtGui import QColor, QFont, QPalette

# --------------------------------------------------------------------------- #
# Paletas (a cor e SEMANTICA, identica entre os temas)
# --------------------------------------------------------------------------- #
_PALETTES = {
    "dark": {
        "APP": "#07090C", "BG": "#0D1117", "SURFACE": "#11151C", "PANEL": "#151A22",
        "RAISED": "#1B212B", "BORDER": "#232A35", "BORDER2": "#2E3744",
        "TEXT": "#D5DCE5", "TEXT2": "#A3AEBB", "DIM": "#7C8898",
        "AMBER": "#E8A33D", "AMBER_INK": "#1A1206", "AMBER_BG": "rgba(232,163,61,12%)",
        "GREEN": "#4CC38A", "GREEN_BG": "rgba(76,195,138,12%)",
        "RED": "#FF6B61", "RED_INK": "#1A0604", "RED_BG": "rgba(255,107,97,12%)",
        "CYAN": "#6BD0FF", "VIOLET": "#B69CFF", "TERRACOTA": "#E08A6A",
        "KEYWORD": "#8FB4FF", "STRING": "#A6D189", "NUMBER": "#F2B880",
        "CARET_LN": "#141A23", "SELECTION": "#1F2D3D",
    },
    "light": {
        "APP": "#E6E9EE", "BG": "#FFFFFF", "SURFACE": "#F6F8FA", "PANEL": "#F0F2F5",
        "RAISED": "#E6EAEF", "BORDER": "#D8DEE4", "BORDER2": "#C4CCD5",
        "TEXT": "#1F2328", "TEXT2": "#4B5563", "DIM": "#5F6B78",
        "AMBER": "#A85C00", "AMBER_INK": "#FFFFFF", "AMBER_BG": "rgba(168,92,0,10%)",
        "GREEN": "#1A7F37", "GREEN_BG": "rgba(26,127,55,10%)",
        "RED": "#CF222E", "RED_INK": "#FFFFFF", "RED_BG": "rgba(207,34,46,8%)",
        "CYAN": "#0550AE", "VIOLET": "#8250DF", "TERRACOTA": "#A04100",
        "KEYWORD": "#0550AE", "STRING": "#116329", "NUMBER": "#953800",
        "CARET_LN": "#F2F4F8", "SELECTION": "#CCE5FF",
    },
}

# Constantes de modulo (inicializadas mais abaixo por _apply_palette).
APP = BG = SURFACE = PANEL = RAISED = BORDER = BORDER2 = ""
TEXT = TEXT2 = DIM = AMBER = AMBER_INK = AMBER_BG = GREEN = GREEN_BG = ""
RED = RED_INK = RED_BG = CYAN = VIOLET = TERRACOTA = ""
KEYWORD = STRING = NUMBER = CARET_LN = SELECTION = ""
_ACTIVE = "dark"

# Fonte da INTERFACE (o editor usa a monoespacada das preferencias, a parte).
UI_FONTS = ["IBM Plex Sans", "Segoe UI", "Noto Sans", "Cantarell", "Ubuntu", "Helvetica Neue", "Arial"]
MONO_FONTS = ["JetBrains Mono", "Cascadia Mono", "Consolas", "Noto Sans Mono", "DejaVu Sans Mono",
              "Liberation Mono", "Menlo", "monospace"]
_MONO_CSS = ", ".join(f'"{f}"' for f in MONO_FONTS[:-1]) + ", monospace"


# --------------------------------------------------------------------------- #
# QSS do chrome (Template: trata { } como literal, so substitui $VAR)
# --------------------------------------------------------------------------- #
_QSS_TEMPLATE = Template("""
QMainWindow, QWidget { background: $BG; color: $TEXT; }
QToolTip { background: $RAISED; color: $TEXT; border: 1px solid $BORDER2; padding: 5px 8px; }

/* ---------- barra superior: menus + busca + acoes ---------- */
#TopBar { background: $SURFACE; border-bottom: 1px solid $BORDER; }
#TopBar QMenuBar { background: transparent; border: none; }
QMenuBar { background: $SURFACE; color: $TEXT2; }
QMenuBar::item { background: transparent; padding: 6px 10px; border-radius: 6px; }
QMenuBar::item:selected { background: $RAISED; color: $TEXT; }
QMenu { background: $PANEL; color: $TEXT; border: 1px solid $BORDER2; padding: 6px; }
QMenu::item { padding: 6px 28px 6px 12px; border-radius: 6px; }
QMenu::item:selected { background: $RAISED; color: $AMBER; }
QMenu::item:disabled { color: $DIM; }
QMenu::separator { height: 1px; background: $BORDER; margin: 5px 8px; }

QPushButton#SearchPill {
    background: $BG; color: $DIM; border: 1px solid $BORDER2; border-radius: 8px;
    padding: 5px 12px; text-align: left; min-width: 360px;
}
QPushButton#SearchPill:hover { border-color: $DIM; color: $TEXT2; }

/* ---------- botoes ---------- */
QPushButton {
    background: transparent; color: $TEXT; border: 1px solid $BORDER2; border-radius: 8px;
    padding: 6px 14px;
}
QPushButton:hover { border-color: $DIM; background: $RAISED; }
QPushButton:pressed { background: $BORDER; }
QPushButton:disabled { color: $DIM; border-color: $BORDER; }
QPushButton:checked { background: $AMBER_BG; border-color: $AMBER; color: $AMBER; }
QPushButton#Primary {
    background: $AMBER; color: $AMBER_INK; border: 1px solid $AMBER; font-weight: 600;
}
QPushButton#Primary:hover { background: $AMBER; border-color: $TEXT; }
QPushButton#Primary:disabled { background: $RAISED; color: $DIM; border-color: $BORDER; }
QPushButton#Danger { background: $RED; color: $RED_INK; border: 1px solid $RED; font-weight: 600; }
QPushButton#Link { border: none; background: transparent; color: $CYAN; padding: 4px 0; text-align: left; }
QPushButton#Link:hover { text-decoration: underline; }
QPushButton#Chip { border-radius: 13px; padding: 3px 11px; color: $TEXT2; }
QPushButton#Chip:checked { background: $AMBER_BG; border-color: $AMBER; color: $AMBER; }
QPushButton#Ghost { border: none; color: $TEXT2; padding: 4px 8px; }
QPushButton#Ghost:hover { color: $TEXT; background: $RAISED; }

/* ---------- trilho lateral ---------- */
#Rail { background: $APP; border-right: 1px solid $BORDER; }
QToolButton#RailButton { background: transparent; border: none; border-radius: 8px; padding: 10px; }
QToolButton#RailButton:hover { background: $RAISED; }
QToolButton#RailButton:checked { background: $RAISED; }

/* ---------- painel da Sentinela ---------- */
#SidePanel { background: $PANEL; border-right: 1px solid $BORDER; }
#SidePanel QLabel { background: transparent; }
#PanelHeader { border-bottom: 1px solid $BORDER; background: transparent; }
#PanelFooter { border-top: 1px solid $BORDER; background: transparent; }
QListWidget#Findings { background: transparent; border: none; outline: none; }
QListWidget#Findings::item { border: 1px solid transparent; border-radius: 8px; margin: 1px 0; }
QListWidget#Findings::item:selected { background: $RAISED; border-color: $BORDER2; }
QListWidget#Findings::item:hover:!selected { background: $SURFACE; }
#FindingRow, #FindingRow QLabel { background: transparent; }

/* ---------- abas ---------- */
QTabWidget::pane { border: none; }
QTabBar { background: $SURFACE; }
QTabBar::tab {
    background: $SURFACE; color: $DIM; padding: 9px 12px 9px 12px;
    border: none; border-right: 1px solid $BORDER; border-bottom: 1px solid $BORDER;
}
QTabBar::tab:selected { background: $BG; color: $TEXT; border-top: 2px solid $AMBER; border-bottom: 1px solid $BG; }
QTabBar::tab:hover:!selected { color: $TEXT2; background: $PANEL; }
QToolButton#TabClose { background: transparent; border: none; border-radius: 4px; padding: 2px; }
QToolButton#TabClose:hover { background: $RAISED; }

/* ---------- faixa de alerta (dentro do editor) ---------- */
#Banner { border-bottom: 1px solid $BORDER; }
#Banner[level="danger"] { background: $RED_BG; }
#Banner[level="warn"] { background: $AMBER_BG; }
#Banner QLabel { background: transparent; }

/* ---------- barra de status ---------- */
QStatusBar { background: $APP; color: $TEXT2; border-top: 1px solid $BORDER; }
QStatusBar::item { border: none; }
QStatusBar QLabel { color: $TEXT2; padding: 0 7px; font-size: 12px; background: transparent; }
QStatusBar QLabel#Mono { font-family: $MONO; }

/* ---------- cartoes, dialogos, campos ---------- */
QDialog, QMessageBox { background: $PANEL; color: $TEXT; }
QDialog QLabel, QMessageBox QLabel { background: transparent; }
#Card { background: $BG; border: 1px solid $BORDER; border-radius: 10px; }
#Card QLabel { background: transparent; }
#LockCard { background: $PANEL; border: 1px solid $BORDER2; border-radius: 14px; }
#LockCard QLabel { background: transparent; }
#Toast { background: $RAISED; border: 1px solid $BORDER2; border-radius: 10px; }
#Toast QLabel { background: transparent; }
#Chip2 { background: $BG; border: 1px solid $BORDER; border-radius: 8px; }
#Chip2 QLabel { background: transparent; }
QLabel#Muted { color: $DIM; }
QLabel#Secondary { color: $TEXT2; }
QLabel#Mono { font-family: $MONO; }
QLabel#SectionTitle { color: $DIM; font-size: 11px; font-weight: 700; }
QLabel#DialogTitle { font-size: 17px; font-weight: 600; }

QLineEdit, QSpinBox, QComboBox, QFontComboBox {
    background: $BG; color: $TEXT; border: 1px solid $BORDER2; border-radius: 8px;
    padding: 7px 10px; selection-background-color: $AMBER; selection-color: $AMBER_INK;
}
QSpinBox { padding-right: 24px; }
QSpinBox::up-button, QSpinBox::down-button {
    subcontrol-origin: border; width: 22px; border: none; background: transparent;
}
QSpinBox::up-button { subcontrol-position: top right; margin-top: 3px; }
QSpinBox::down-button { subcontrol-position: bottom right; margin-bottom: 3px; }
QSpinBox::up-button:hover, QSpinBox::down-button:hover { background: $RAISED; border-radius: 4px; }

QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border: 1px solid $AMBER; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView { background: $PANEL; border: 1px solid $BORDER2; selection-background-color: $RAISED; }
QCheckBox { spacing: 8px; background: transparent; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid $BORDER2; border-radius: 4px; background: $BG; }
QCheckBox::indicator:checked { background: $AMBER; border-color: $AMBER; }

QListWidget, QTreeWidget, QTextEdit { background: $BG; border: 1px solid $BORDER; border-radius: 8px; }
QListWidget::item { padding: 6px 8px; border-radius: 6px; }
QListWidget::item:selected, QTreeWidget::item:selected { background: $RAISED; color: $TEXT; }
#Palette QListWidget { border: none; background: transparent; }
#Palette QLineEdit { border: none; background: transparent; font-size: 16px; padding: 10px 4px; }

QScrollBar:vertical { background: transparent; width: 11px; margin: 0; }
QScrollBar::handle:vertical { background: $BORDER2; min-height: 28px; border-radius: 5px; margin: 2px; }
QScrollBar::handle:vertical:hover { background: $DIM; }
QScrollBar:horizontal { background: transparent; height: 11px; margin: 0; }
QScrollBar::handle:horizontal { background: $BORDER2; min-width: 28px; border-radius: 5px; margin: 2px; }
QScrollBar::handle:horizontal:hover { background: $DIM; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
""")

# QSS ativo (reconstruido por _apply_palette conforme o tema).
QSS = ""


def _apply_palette(name: str) -> None:
    """Reescreve as constantes de modulo e o QSS para o tema `name`."""
    # guarda contra tipo nao-hashavel (list/dict vindos de um QSettings adulterado):
    # 'name in _PALETTES' / _PALETTES.get(name) levantariam TypeError.
    if not (isinstance(name, str) and name in _PALETTES):
        name = "dark"
    pal = _PALETTES[name]
    g = globals()
    g.update(pal)
    g["_ACTIVE"] = name
    g["QSS"] = _QSS_TEMPLATE.substitute(MONO=_MONO_CSS, **pal)


def set_theme(name: str) -> None:
    """Troca o tema ativo ('dark' | 'light'). Use antes de apply_app/apply_editor_theme."""
    _apply_palette(name)        # _apply_palette ja sanitiza tipo/valor invalido


def current_theme() -> str:
    return _ACTIVE


_apply_palette("dark")     # inicializa as constantes no import


def ui_font(size: int = 10) -> QFont:
    """Fonte da interface: a primeira da lista que existir (Qt cai para a proxima)."""
    f = QFont()
    f.setFamilies(UI_FONTS)
    f.setPointSize(size)
    return f


def mono_font(size: int = 9) -> QFont:
    f = QFont()
    f.setFamilies(MONO_FONTS)
    f.setStyleHint(QFont.StyleHint.Monospace)
    f.setPointSize(size)
    return f


def _arrow_qss() -> str:
    """Setas dos campos numericos e das caixas de selecao. O QSS so aceita imagem por ARQUIVO,
    entao os icones do app (icons.py) viram PNGs no cache DO USUARIO (nunca num /tmp compartilhado:
    la outro usuario poderia plantar um symlink no nome do arquivo e o app sobrescreveria o alvo)."""
    import os

    from PyQt6.QtCore import QStandardPaths

    from . import icons
    try:
        base = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.CacheLocation)
        if not base:
            return ""
        d = os.path.join(base, "ui")
        os.makedirs(d, mode=0o700, exist_ok=True)
        paths = {}
        for name in ("chevup", "chev"):
            p = os.path.join(d, f"{name}-{TEXT2.lstrip('#')}.png")
            if not os.path.exists(p):
                icons.pixmap(name, TEXT2, 12, 2.2).save(p, "PNG")
            paths[name] = p.replace("\\", "/")
    except Exception:
        return ""                         # sem as setas, os campos seguem funcionando (roda/teclas)
    up, down = paths["chevup"], paths["chev"]
    rules = [
        f'QSpinBox::up-arrow {{ image: url("{up}"); width: 10px; height: 10px; }}',
        f'QSpinBox::down-arrow {{ image: url("{down}"); width: 10px; height: 10px; }}',
        f'QComboBox::down-arrow, QFontComboBox::down-arrow {{ image: url("{down}"); '
        'width: 10px; height: 10px; }',
    ]
    return "\n".join(rules) + "\n"


def apply_app(app) -> None:
    """Aplica estilo Fusion + paleta + QSS + fonte de interface na aplicacao inteira."""
    app.setStyle("Fusion")
    app.setFont(ui_font())
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(BG))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Base, QColor(BG))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor(SURFACE))
    pal.setColor(QPalette.ColorRole.Text, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Button, QColor(PANEL))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(AMBER))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(AMBER_INK))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(RAISED))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(DIM))
    app.setPalette(pal)
    app.setStyleSheet(QSS + _arrow_qss())


def apply_editor_theme(ed) -> None:
    """Pinta o canvas do editor na paleta (cores que o lexer nao mexe)."""
    ed.setPaper(QColor(BG))
    ed.setColor(QColor(TEXT))
    ed.setMarginsBackgroundColor(QColor(BG))
    ed.setMarginsForegroundColor(QColor(DIM))
    ed.setFoldMarginColors(QColor(BG), QColor(BG))
    ed.setCaretLineBackgroundColor(QColor(CARET_LN))
    ed.setCaretForegroundColor(QColor(AMBER))
    ed.setCaretWidth(2)
    ed.setSelectionBackgroundColor(QColor(SELECTION))
    ed.setSelectionForegroundColor(QColor(TEXT))
    ed.setMatchedBraceBackgroundColor(QColor(RAISED))
    ed.setMatchedBraceForegroundColor(QColor(AMBER))
    ed.setUnmatchedBraceForegroundColor(QColor(RED))
    ed.setIndentationGuidesForegroundColor(QColor(BORDER))
    ed.setIndentationGuidesBackgroundColor(QColor(BG))


def retheme_lexer(lexer) -> None:
    """Repinta TODOS os estilos do lexer na paleta Redoubt.

    Em vez de mapear ids de estilo (que mudam de lexer pra lexer), usamos a
    descricao textual de cada estilo (Comment/Keyword/String/Number/...), o
    que funciona de forma generica para qualquer QsciLexer*.
    """
    if lexer is None:
        return
    for style in range(128):
        desc = lexer.description(style).lower()
        lexer.setPaper(QColor(BG), style)
        if not desc:
            lexer.setColor(QColor(TEXT), style)
            continue
        color = TEXT
        if "comment" in desc:
            color = DIM
        elif "keyword" in desc or "key word" in desc:
            color = KEYWORD
        elif "string" in desc or "char" in desc or "heredoc" in desc:
            color = STRING
        elif "number" in desc or "numeric" in desc:
            color = NUMBER
        elif "preprocessor" in desc or "directive" in desc or "decorator" in desc:
            color = TERRACOTA
        elif "class" in desc or "type" in desc or "tag" in desc:
            color = VIOLET
        elif "function" in desc or "method" in desc or "identifier" in desc:
            color = TEXT
        lexer.setColor(QColor(color), style)
    lexer.setDefaultPaper(QColor(BG))
    lexer.setDefaultColor(QColor(TEXT))
