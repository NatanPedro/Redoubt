"""Tema "Redoubt" — HUD carbono + ambar. A cor e SEMANTICA.

  ambar  = atencao / marca       verde = selado / limpo
  vermelho = exposto / segredo

Concentra a paleta, a folha de estilo (QSS) do chrome e as funcoes que pintam
o editor e os lexers do QScintilla — para o app NAO herdar as cores default do
Scintilla (que sao a cara do Notepad++).

Dois temas: 'dark' (carbono, padrao) e 'light' (claro), com a MESMA semantica de
cor. `set_theme(nome)` troca a paleta ativa em tempo de execucao reescrevendo as
constantes de modulo (BG, AMBER, ...) — por isso o resto do app deve ler
`theme.AMBER` (acesso por atributo), nunca `from theme import AMBER`.
"""

from __future__ import annotations

from string import Template

from PyQt6.QtGui import QColor, QPalette

# --------------------------------------------------------------------------- #
# Paletas (a cor e SEMANTICA, identica entre os temas)
# --------------------------------------------------------------------------- #
_PALETTES = {
    "dark": {
        "BG": "#0E1116", "PANEL": "#161B22", "BORDER": "#21262D",
        "TEXT": "#C9D1D9", "DIM": "#5B6673", "AMBER": "#E8A33D",
        "GREEN": "#3FB950", "RED": "#F85149", "CYAN": "#6BD0FF",
        "VIOLET": "#9B5DE5", "TERRACOTA": "#C45A3B",
        "CARET_LN": "#11161D", "SELECTION": "#1F2D3D",
    },
    "light": {
        "BG": "#FFFFFF", "PANEL": "#F0F2F5", "BORDER": "#D0D7DE",
        "TEXT": "#1F2328", "DIM": "#6E7781", "AMBER": "#BF6A00",
        "GREEN": "#1A7F37", "RED": "#CF222E", "CYAN": "#0550AE",
        "VIOLET": "#8250DF", "TERRACOTA": "#A04100",
        "CARET_LN": "#F2F4F8", "SELECTION": "#CCE5FF",
    },
}

# Constantes de modulo (inicializadas mais abaixo por _apply_palette).
BG = PANEL = BORDER = TEXT = DIM = AMBER = GREEN = RED = ""
CYAN = VIOLET = TERRACOTA = CARET_LN = SELECTION = ""
_ACTIVE = "dark"


# --------------------------------------------------------------------------- #
# QSS do chrome (Template: trata { } como literal, so substitui $VAR)
# --------------------------------------------------------------------------- #
_QSS_TEMPLATE = Template("""
QMainWindow, QWidget { background: $BG; color: $TEXT; }

QMenuBar { background: $PANEL; color: $TEXT; border-bottom: 1px solid $BORDER; }
QMenuBar::item { background: transparent; padding: 5px 12px; }
QMenuBar::item:selected { background: $BORDER; color: $AMBER; }

QMenu { background: $PANEL; color: $TEXT; border: 1px solid $BORDER; padding: 4px; }
QMenu::item { padding: 5px 24px 5px 20px; border-radius: 4px; }
QMenu::item:selected { background: $BORDER; color: $AMBER; }
QMenu::separator { height: 1px; background: $BORDER; margin: 4px 8px; }

QToolBar { background: $PANEL; border: none; border-bottom: 1px solid $BORDER;
           spacing: 4px; padding: 3px; }
QToolBar QToolButton { background: transparent; padding: 5px; border-radius: 5px; }
QToolBar QToolButton:hover { background: $BORDER; }
QToolBar QToolButton:checked { background: $BORDER; color: $AMBER; }
QToolBar::separator { width: 1px; background: $BORDER; margin: 4px 4px; }

QTabWidget::pane { border: none; border-top: 1px solid $BORDER; }
QTabBar { background: $BG; }
QTabBar::tab {
    background: $BG; color: $DIM;
    padding: 6px 14px; margin-right: 1px;
    border: 1px solid transparent; border-bottom: 2px solid transparent;
    font-family: "JetBrains Mono", "Cascadia Code", Consolas, monospace;
}
QTabBar::tab:selected { color: $TEXT; background: $PANEL; border-bottom: 2px solid $AMBER; }
QTabBar::tab:hover:!selected { color: $TEXT; }
QTabBar::close-button { subcontrol-position: right; }

QStatusBar { background: $PANEL; color: $DIM; border-top: 1px solid $BORDER; }
QStatusBar::item { border: none; }
QStatusBar QLabel {
    color: $DIM; padding: 0 8px;
    font-family: "JetBrains Mono", "Cascadia Code", Consolas, monospace;
    font-size: 12px;
}

QToolTip { background: $PANEL; color: $TEXT; border: 1px solid $AMBER; padding: 4px; }

QScrollBar:vertical { background: $BG; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: $BORDER; min-height: 28px; border-radius: 6px; }
QScrollBar::handle:vertical:hover { background: $DIM; }
QScrollBar:horizontal { background: $BG; height: 12px; margin: 0; }
QScrollBar::handle:horizontal { background: $BORDER; min-width: 28px; border-radius: 6px; }
QScrollBar::handle:horizontal:hover { background: $DIM; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

QDialog, QMessageBox { background: $PANEL; color: $TEXT; }
QLineEdit { background: $BG; color: $TEXT; border: 1px solid $BORDER;
            border-radius: 6px; padding: 6px 8px;
            selection-background-color: $AMBER; selection-color: $BG; }
QLineEdit:focus { border: 1px solid $AMBER; }
QPushButton { background: $BORDER; color: $TEXT; border: 1px solid $BORDER;
              border-radius: 6px; padding: 6px 14px; }
QPushButton:hover { border: 1px solid $AMBER; color: $AMBER; }
QPushButton:default { background: $AMBER; color: $BG; font-weight: 600; }
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
    g["_ACTIVE"] = name if name in _PALETTES else "dark"
    g["QSS"] = _QSS_TEMPLATE.substitute(
        BG=BG, PANEL=PANEL, BORDER=BORDER, TEXT=TEXT, DIM=DIM, AMBER=AMBER)


def set_theme(name: str) -> None:
    """Troca o tema ativo ('dark' | 'light'). Use antes de apply_app/apply_editor_theme."""
    _apply_palette(name)        # _apply_palette ja sanitiza tipo/valor invalido


def current_theme() -> str:
    return _ACTIVE


_apply_palette("dark")     # inicializa as constantes no import


def apply_app(app) -> None:
    """Aplica estilo Fusion + paleta escura + QSS na aplicacao inteira."""
    app.setStyle("Fusion")
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor(BG))
    pal.setColor(QPalette.ColorRole.WindowText, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Base, QColor(PANEL))
    pal.setColor(QPalette.ColorRole.AlternateBase, QColor(BG))
    pal.setColor(QPalette.ColorRole.Text, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Button, QColor(PANEL))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.Highlight, QColor(AMBER))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(BG))
    pal.setColor(QPalette.ColorRole.ToolTipBase, QColor(PANEL))
    pal.setColor(QPalette.ColorRole.ToolTipText, QColor(TEXT))
    pal.setColor(QPalette.ColorRole.PlaceholderText, QColor(DIM))
    app.setPalette(pal)
    app.setStyleSheet(QSS)


def apply_editor_theme(ed) -> None:
    """Pinta o canvas do editor na paleta carbono (cores que o lexer nao mexe)."""
    ed.setPaper(QColor(BG))
    ed.setColor(QColor(TEXT))
    ed.setMarginsBackgroundColor(QColor(BG))
    ed.setMarginsForegroundColor(QColor(DIM))
    ed.setFoldMarginColors(QColor(PANEL), QColor(PANEL))
    ed.setCaretLineBackgroundColor(QColor(CARET_LN))
    ed.setCaretForegroundColor(QColor(AMBER))
    ed.setCaretWidth(2)
    ed.setSelectionBackgroundColor(QColor(SELECTION))
    ed.setSelectionForegroundColor(QColor(TEXT))
    ed.setMatchedBraceBackgroundColor(QColor(PANEL))
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
            color = AMBER
        elif "string" in desc or "char" in desc or "heredoc" in desc:
            color = GREEN
        elif "number" in desc or "numeric" in desc:
            color = CYAN
        elif "preprocessor" in desc or "directive" in desc or "decorator" in desc:
            color = TERRACOTA
        elif "class" in desc or "type" in desc or "tag" in desc:
            color = VIOLET
        elif "function" in desc or "method" in desc or "identifier" in desc:
            color = TEXT
        lexer.setColor(QColor(color), style)
    lexer.setDefaultPaper(QColor(BG))
    lexer.setDefaultColor(QColor(TEXT))
