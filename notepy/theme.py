"""Tema "Redoubt" — HUD carbono + ambar. A cor e SEMANTICA.

  ambar  = atencao / marca       verde = selado / limpo
  vermelho = exposto / segredo

Concentra a paleta, a folha de estilo (QSS) do chrome e as funcoes que pintam
o editor e os lexers do QScintilla — para o app NAO herdar as cores default do
Scintilla (que sao a cara do Notepad++).
"""

from __future__ import annotations

from string import Template

from PyQt6.QtGui import QColor, QPalette

# --------------------------------------------------------------------------- #
# Paleta
# --------------------------------------------------------------------------- #
BG = "#0E1116"          # fundo carbono (quase preto, leve verde)
PANEL = "#161B22"       # paineis / chrome
BORDER = "#21262D"      # bordas / divisores
TEXT = "#C9D1D9"        # texto base
DIM = "#5B6673"         # texto apagado / numeros de linha
AMBER = "#E8A33D"       # ATENCAO / cor da marca
GREEN = "#3FB950"       # SELADO / LIMPO / seguro
RED = "#F85149"         # EXPOSTO / segredo
CYAN = "#6BD0FF"        # numeros / literais
VIOLET = "#9B5DE5"      # tipos / classes
TERRACOTA = "#C45A3B"   # preprocessador / diretiva
CARET_LN = "#11161D"    # fundo da linha atual
SELECTION = "#1F2D3D"   # selecao


# --------------------------------------------------------------------------- #
# QSS do chrome (Template: trata { } como literal, so substitui $VAR)
# --------------------------------------------------------------------------- #
QSS = Template("""
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
""").substitute(
    BG=BG, PANEL=PANEL, BORDER=BORDER, TEXT=TEXT, DIM=DIM, AMBER=AMBER,
)


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
