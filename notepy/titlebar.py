"""Barra de titulo unificada do Redoubt (40 px): icone + menus + paleta + acoes + controles.

Substitui as duas faixas de antes (titulo nativo do Windows + barra de acoes). A logica de
Tarjar, Selar cofre e da paleta NAO mora aqui: a barra so mostra estado e emite intencoes.

Posicionamento a mao (resizeEvent), nao por layout: a paleta fica centrada em relacao a JANELA,
e nao ao espaco livre entre os grupos, e encolhe/vira icone conforme a largura:

  > 1280 px     tudo;
  960-1280      Tarjar e Selar cofre so com icone (tooltip);
  720-960       paleta ate 240 px, impressao digital so com icone;
  < 720         menus num botao so e a paleta vira um botao de icone.

No Windows, as regioes vazias viram HTCAPTION e o maximizar vira HTMAXBUTTON (winframe.py).
Fora dele, a janela mantem a moldura nativa (respeita a ordem de botoes de cada desktop) e a
barra esconde icone e controles de janela.
"""

from __future__ import annotations

from itertools import pairwise

from PyQt6.QtCore import QEvent, QObject, QPoint, QPointF, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QPen
from PyQt6.QtWidgets import (
    QAbstractButton,
    QApplication,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPushButton,
    QToolButton,
    QToolTip,
    QWidget,
)

from . import icons, theme

HEIGHT = 40
ACTION_H = 28
GAP = 6
CLOSE_HOVER = "#C42B1C"                 # vermelho de fechar do Windows

MODE_FULL, MODE_MID, MODE_SMALL, MODE_TINY = "full", "mid", "small", "tiny"


def mode_for(width: int) -> str:
    """Faixa de largura da janela (px logicos) -> modo da barra."""
    if width > 1280:
        return MODE_FULL
    if width >= 960:
        return MODE_MID
    if width >= 720:
        return MODE_SMALL
    return MODE_TINY


def place_centered(total: int, want: int, lo: int, hi: int, minimum: int) -> tuple[int, int]:
    """(x, largura) de um bloco centrado em `total`, preso entre `lo` e `hi` (bordas livres).
    Encolhe ate `minimum` antes de sair do centro; largura 0 = nao cabe."""
    avail = hi - lo
    if avail <= 0:
        return lo, 0
    w = min(want, avail)
    if w < minimum:
        return lo, 0
    x = total // 2 - w // 2
    x = max(lo, min(x, hi - w))
    return x, w


# --------------------------------------------------------------------------- #
# Botoes de janela (46x40): minimizar, maximizar/restaurar, fechar
# --------------------------------------------------------------------------- #
class WindowButton(QAbstractButton):
    def __init__(self, kind: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.kind = kind                        # 'min' | 'max' | 'close'
        self.maximized = False
        self._hover = False
        self.setFixedSize(46, HEIGHT)
        self.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.setCursor(Qt.CursorShape.ArrowCursor)
        self._sync_label()

    def _sync_label(self) -> None:
        name = {"min": "Minimizar", "close": "Fechar",
                "max": "Restaurar" if self.maximized else "Maximizar"}[self.kind]
        self.setAccessibleName(name)
        self.setToolTip(name)

    def set_maximized(self, on: bool) -> None:
        self.maximized = on
        self._sync_label()
        self.update()

    def set_hover(self, on: bool) -> None:
        """O maximizar e nao-cliente no Windows (Snap Layouts): o hover chega pelo winframe."""
        if on != self._hover:
            self._hover = on
            self.update()

    def enterEvent(self, ev) -> None:
        self.set_hover(True)
        super().enterEvent(ev)

    def leaveEvent(self, ev) -> None:
        self.set_hover(False)
        super().leaveEvent(ev)

    def colors(self) -> tuple[str | None, str]:
        """(fundo, icone) no estado atual — separado do paint para ser testavel."""
        hot = self._hover or self.isDown()
        if self.kind == "close" and hot:
            if theme.HIGH_CONTRAST:
                return theme.AMBER, theme.AMBER_INK
            return CLOSE_HOVER, "#FFFFFF"
        if hot:
            return (theme.BORDER if self.isDown() else theme.RAISED), theme.TEXT
        return None, theme.TEXT2

    def paintEvent(self, ev) -> None:
        p = QPainter(self)
        bg, fg = self.colors()
        if bg:
            p.fillRect(self.rect(), QColor(bg))
        pen = QPen(QColor(fg), 1.0)
        pen.setCosmetic(True)
        p.setPen(pen)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, self.kind == "close")
        cx, cy = self.width() / 2, self.height() / 2
        s = 5.0                                 # glifos de 10 px, como os do Windows
        if self.kind == "min":
            p.drawLine(QPointF(cx - s, cy), QPointF(cx + s, cy))
        elif self.kind == "max" and not self.maximized:
            p.drawRect(QRectF(cx - s, cy - s, 2 * s, 2 * s))
        elif self.kind == "max":                # restaurar: dois quadrados sobrepostos
            p.drawRect(QRectF(cx - s, cy - s + 2, 2 * s - 2, 2 * s - 2))
            p.drawPolyline([QPointF(cx - s + 2, cy - s), QPointF(cx + s, cy - s), QPointF(cx + s, cy + s - 2)])
        else:
            p.drawLine(QPointF(cx - s, cy - s), QPointF(cx + s, cy + s))
            p.drawLine(QPointF(cx + s, cy - s), QPointF(cx - s, cy + s))
        if self.hasFocus():                     # anel de foco (so via teclado: TabFocus)
            ring = QPen(QColor(theme.AMBER), 2)
            p.setPen(ring)
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRect(QRectF(self.rect()).adjusted(1, 1, -1, -1))
        p.end()


# --------------------------------------------------------------------------- #
# Paleta: um campo continuo, com o atalho dentro (mesmo fundo e borda do campo)
# --------------------------------------------------------------------------- #
class PalettePill(QPushButton):
    TEXT_LONG = "Comandos, arquivos, segredos…"
    TEXT_SHORT = "Comandos…"

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("SearchPill")
        self.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAccessibleName("Paleta de comandos (Ctrl+Shift+P)")
        self.setToolTip("Paleta de comandos (Ctrl+Shift+P)")
        self.setFixedHeight(ACTION_H)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 0, 5, 0)
        lay.setSpacing(8)
        self.icon = QLabel()
        self.icon.setFixedSize(14, 14)
        self.placeholder = QLabel(self.TEXT_LONG)
        self.placeholder.setObjectName("PillText")
        self.kbd = QLabel("Ctrl+Shift+P")
        self.kbd.setObjectName("Kbd")
        self.kbd.setFont(theme.mono_font(8))
        lay.addWidget(self.icon)
        lay.addWidget(self.placeholder, 1)
        lay.addWidget(self.kbd)
        self.compact = False
        self.retheme()

    def set_compact(self, on: bool) -> None:
        """So o icone (janelas estreitas): abre a paleta do mesmo jeito."""
        self.compact = on
        self.placeholder.setVisible(not on)
        self.kbd.setVisible(not on)
        self.layout().setContentsMargins(7 if on else 10, 0, 7 if on else 5, 0)

    def fit(self, width: int) -> None:
        """Campo estreito: primeiro sai o atalho (fica no tooltip), depois o texto encurta."""
        base = 10 + 14 + 8 + 5                  # margens + icone + espaco
        fm = self.placeholder.fontMetrics()
        long_w = fm.horizontalAdvance(self.TEXT_LONG) + 4
        kbd_w = self.kbd.sizeHint().width() + 8
        self.kbd.setVisible(width >= base + long_w + kbd_w)
        self.placeholder.setText(self.TEXT_LONG if width >= base + long_w else self.TEXT_SHORT)

    def retheme(self) -> None:
        self.icon.setPixmap(icons.pixmap("search", theme.DIM, 14, 1.9))


# --------------------------------------------------------------------------- #
# A barra
# --------------------------------------------------------------------------- #
class TitleBar(QWidget):
    palette_requested = pyqtSignal()
    redaction_toggled = pyqtSignal(bool)
    seal_requested = pyqtSignal()
    minimize_requested = pyqtSignal()
    maximize_requested = pyqtSignal()
    close_requested = pyqtSignal()

    def __init__(self, menubar: QWidget, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("TitleBar")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedHeight(HEIGHT)
        self.native_frame = False
        self.mode = MODE_FULL
        self.vault_state = "none"               # 'none' | 'locked' | 'open'
        self._fingerprint = ""
        self._protected = False

        self.sys_icon = QLabel(self)
        self.sys_icon.setFixedSize(18, 18)
        self.sys_icon.setToolTip("Menu da janela")

        self._menubar = menubar
        menubar.setParent(self)
        f = menubar.font()
        f.setPixelSize(13)
        menubar.setFont(f)

        self.hamburger = QToolButton(self)
        self.hamburger.setObjectName("BarButton")
        self.hamburger.setAccessibleName("Menus")
        self.hamburger.setToolTip("Menus")
        self.hamburger.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.hamburger.setFixedSize(ACTION_H + 4, ACTION_H)
        self.hamburger.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self._ham_menu = QMenu(self.hamburger)
        self.hamburger.setMenu(self._ham_menu)

        self.search = PalettePill(self)
        self.search.clicked.connect(self.palette_requested.emit)

        self.redact = self._action_button("Tarjar", checkable=True)
        self.redact.setToolTip("Modo Redação: tarja os segredos na tela e no clipboard (Ctrl+Shift+R)")
        self.redact.toggled.connect(self._on_redact)
        self.seal = self._action_button("Selar cofre")
        self.seal.clicked.connect(self.seal_requested.emit)
        self.identity = self._action_button("—")
        self.identity.setObjectName("Fingerprint")
        self.identity.setFont(theme.mono_font(9))
        self.identity.clicked.connect(self.copy_fingerprint)

        self.sep = QFrame(self)
        self.sep.setObjectName("BarSeparator")
        self.sep.setFixedSize(1, 20)

        self.btn_min = WindowButton("min", self)
        self.btn_max = WindowButton("max", self)
        self.btn_close = WindowButton("close", self)
        self.btn_min.clicked.connect(self.minimize_requested.emit)
        self.btn_max.clicked.connect(self.maximize_requested.emit)
        self.btn_close.clicked.connect(self.close_requested.emit)

        self._effects: list[QGraphicsOpacityEffect] = []
        for w in self._content_widgets():
            eff = QGraphicsOpacityEffect(w)
            eff.setOpacity(1.0)
            w.setGraphicsEffect(eff)
            self._effects.append(eff)

        # Ordem de Tab = ordem visual.
        chain = [self.hamburger, self.search, self.redact, self.seal, self.identity,
                 self.btn_min, self.btn_max, self.btn_close]
        for a, b in pairwise(chain):
            QWidget.setTabOrder(a, b)

        self._copied_timer = QTimer(self)
        self._copied_timer.setSingleShot(True)
        self._copied_timer.timeout.connect(self._render_identity)
        self.retheme()

    # ------------------------------------------------------------ construcao
    def _action_button(self, text: str, checkable: bool = False) -> QPushButton:
        b = QPushButton(text, self)
        b.setObjectName("BarButton")
        b.setCheckable(checkable)
        b.setFocusPolicy(Qt.FocusPolicy.TabFocus)      # anel de foco so via teclado
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.setFixedHeight(ACTION_H)
        b.setIconSize(QSize(15, 15))
        return b

    def _content_widgets(self) -> list[QWidget]:
        return [self.sys_icon, self._menubar, self.hamburger, self.search, self.redact,
                self.seal, self.identity, self.sep, self.btn_min, self.btn_max, self.btn_close]

    def rebuild_hamburger(self) -> None:
        """O botao de menus (janela estreita) mostra os MESMOS menus da barra."""
        self._ham_menu.clear()
        for act in self._menubar.actions():
            self._ham_menu.addAction(act)

    # ------------------------------------------------------------ estado
    def set_native_frame(self, on: bool) -> None:
        """Fora do Windows a moldura e a do sistema: sem icone nem controles de janela aqui."""
        self.native_frame = on
        for w in (self.sys_icon, self.sep, self.btn_min, self.btn_max, self.btn_close):
            w.setVisible(not on)
        self._relayout()

    def _on_redact(self, on: bool) -> None:
        self._render_redact()
        self.redaction_toggled.emit(on)

    def set_redaction(self, on: bool) -> None:
        """Reflete o estado sem reemitir o sinal (a fonte da verdade e o editor)."""
        self.redact.blockSignals(True)
        self.redact.setChecked(on)
        self.redact.blockSignals(False)
        self._render_redact()

    def set_vault_state(self, state: str) -> None:
        """'none' (aba comum: Selar cofre) | 'locked' (Abrir cofre) | 'open' (Travar cofre)."""
        if state != self.vault_state:
            self.vault_state = state
            self._render_seal()
            self._relayout()

    def set_identity(self, fingerprint: str, protected: bool) -> None:
        self._fingerprint = fingerprint
        self._protected = protected
        self._render_identity()
        self._relayout()

    def set_maximized(self, on: bool) -> None:
        self.btn_max.set_maximized(on)

    def set_max_hover(self, on: bool) -> None:
        self.btn_max.set_hover(on)

    def set_active(self, on: bool) -> None:
        """Janela inativa: texto e icones da barra a ~60%."""
        for eff in self._effects:
            eff.setOpacity(1.0 if on else 0.6)

    # ------------------------------------------------------------ desenho dos botoes
    def _render_redact(self) -> None:
        on = self.redact.isChecked()
        self.redact.setIcon(icons.icon("eyeoff", theme.AMBER if on else theme.TEXT, 15, 1.9, fill=on))
        full = "Redação ligada" if on else "Tarjar"
        self.redact.setText("" if self._icon_only_actions() else full)
        self.redact.setAccessibleName(full)
        self.redact.setAccessibleDescription("pressionado" if on else "solto")

    def _render_seal(self) -> None:
        label, ic, color = {
            "none": ("Selar cofre", "unlock", theme.TEXT),
            "locked": ("Abrir cofre", "lock", theme.AMBER),
            "open": ("Travar cofre", "lock", theme.AMBER),
        }[self.vault_state]
        self.seal.setIcon(icons.icon(ic, color, 15, 1.9))
        self.seal.setText("" if self._icon_only_actions() else label)
        self.seal.setAccessibleName(label)
        self.seal.setProperty("sealed", self.vault_state != "none")
        self.seal.style().unpolish(self.seal)
        self.seal.style().polish(self.seal)
        tips = {"none": "Cifra a aba num cofre .rdbt (Ctrl+Shift+L)",
                "locked": "Destrava este cofre (Ctrl+Shift+U)",
                "open": "Trava este cofre agora: o conteúdo sai da memória"}
        self.seal.setToolTip(f"{label} — {tips[self.vault_state]}")

    def _render_identity(self) -> None:
        fp = self._fingerprint
        short = f"{fp[:4]}…{fp[-4:]}" if len(fp) >= 12 else (fp or "—")
        color = theme.TEXT2 if self._protected else theme.AMBER
        self.identity.setIcon(icons.icon("finger", color, 15, 1.9))
        self.identity.setText("" if self.mode in (MODE_SMALL, MODE_TINY) else short)
        state = "protegida por senha" if self._protected else "SEM senha: proteja em Segurança"
        self.identity.setToolTip(f"{fp or '(nenhuma identidade ainda)'} — {state}\nClique para copiar")
        self.identity.setAccessibleName(f"Impressão digital {fp or 'ausente'}")
        self.identity.setEnabled(bool(fp))

    def copy_fingerprint(self) -> None:
        if not self._fingerprint:
            return
        QApplication.clipboard().setText(self._fingerprint)
        self.identity.setText("Copiado")
        QToolTip.showText(self.identity.mapToGlobal(QPoint(0, self.identity.height() + 4)), "Copiado", self.identity)
        self._copied_timer.start(1500)
        self._relayout()

    def _icon_only_actions(self) -> bool:
        return self.mode != MODE_FULL

    def retheme(self) -> None:
        self.search.retheme()
        self.hamburger.setIcon(icons.icon("menu", theme.TEXT, 16, 1.9))
        px = self.window().windowIcon().pixmap(18, 18) if self.window() is not None else None
        if px is None or px.isNull():
            px = icons.pixmap("shield", theme.AMBER, 18, 2.0)
        self.sys_icon.setPixmap(px)
        self._render_redact()
        self._render_seal()
        self._render_identity()
        for b in (self.btn_min, self.btn_max, self.btn_close):
            b.update()

    # ------------------------------------------------------------ layout
    def resizeEvent(self, ev) -> None:
        super().resizeEvent(ev)
        self._relayout()

    def _relayout(self) -> None:
        width = self.width()
        mode = mode_for(width)
        if mode != self.mode:
            self.mode = mode
            self._render_redact()
            self._render_seal()
            self._render_identity()
        tiny = mode == MODE_TINY
        cy = (HEIGHT - ACTION_H) // 2

        x = 10
        if not self.native_frame:
            self.sys_icon.move(x, (HEIGHT - 18) // 2)
            x += 18 + 8
        self._menubar.setVisible(not tiny)
        self.hamburger.setVisible(tiny)
        if tiny:
            self.hamburger.move(x, cy)
            x += self.hamburger.width() + 8
        else:
            # o QMenuBar desenha os itens no topo: centraliza a faixa dele na barra
            hint = self._menubar.sizeHint()
            mw, mh = hint.width(), min(hint.height(), HEIGHT)
            self._menubar.setGeometry(x, (HEIGHT - mh) // 2, mw, mh)
            x += mw + 8
        left_end = x

        right = width
        if not self.native_frame:
            for b in (self.btn_close, self.btn_max, self.btn_min):
                right -= b.width()
                b.move(right, 0)
            right -= 8
            self.sep.move(right, (HEIGHT - self.sep.height()) // 2)
            right -= 8
        else:
            right -= 8
        for b in (self.identity, self.seal, self.redact):
            bw = b.sizeHint().width() if b.text() else ACTION_H + 4
            b.setFixedWidth(max(bw, ACTION_H + 4))
            right -= b.width()
            b.setGeometry(right, cy, b.width(), ACTION_H)
            right -= GAP
        right_start = right + GAP

        want = {MODE_FULL: 560, MODE_MID: 440, MODE_SMALL: 240}.get(mode, 0)
        minimum = {MODE_FULL: 320, MODE_MID: 240, MODE_SMALL: 100}.get(mode, 0)
        px, pw = (0, 0)
        if want:
            px, pw = place_centered(width, want, left_end + 8, right_start - 8, minimum)
        if pw:
            self.search.set_compact(False)
            self.search.fit(pw)
            self.search.setGeometry(px, cy, pw, ACTION_H)
        else:                                       # nao cabe (ou janela estreita): so o icone
            self.search.set_compact(True)
            px, _ = place_centered(width, ACTION_H + 4, left_end + 4, right_start - 4, ACTION_H + 4)
            self.search.setGeometry(px, cy, ACTION_H + 4, ACTION_H)

    # ------------------------------------------------------------ regioes (winframe)
    def regions(self) -> dict:
        """Retangulos em px logicos relativos a JANELA: o que NAO e area de arrasto."""
        top = self.window()

        def rel(w: QWidget) -> tuple[int, int, int, int]:
            p = w.mapTo(top, QPoint(0, 0))
            return (p.x(), p.y(), w.width(), w.height())

        interactive = [rel(w) for w in (self._menubar, self.hamburger, self.search, self.redact,
                                        self.seal, self.identity, self.btn_min, self.btn_close)
                       if w.isVisible()]
        return {"caption_height": HEIGHT,
                "max_button": rel(self.btn_max) if self.btn_max.isVisible() else None,
                "sys_icon": rel(self.sys_icon) if self.sys_icon.isVisible() else None,
                "interactive": interactive}


# --------------------------------------------------------------------------- #
# Mnemonicos: sublinhado so ao pressionar Alt (padrao do Windows)
# --------------------------------------------------------------------------- #
class MnemonicFilter(QObject):
    """Liga o sublinhado dos atalhos de menu enquanto Alt esta pressionado ou a barra de menus
    esta em modo teclado (Alt/F10); desliga com o mouse ou quando os menus fecham."""

    def __init__(self, menubar: QWidget, parent: QObject | None = None):
        super().__init__(parent)
        self.menubar = menubar
        for act in menubar.actions():
            m = act.menu()
            if m is not None:
                m.aboutToHide.connect(lambda: QTimer.singleShot(0, self._maybe_off))

    def show(self, on: bool) -> None:
        if theme.set_mnemonics_visible(on):
            self.menubar.update()
            for act in self.menubar.actions():
                m = act.menu()
                if m is not None and m.isVisible():
                    m.update()

    def _maybe_off(self) -> None:
        if self.menubar.activeAction() is None:
            self.show(False)

    def eventFilter(self, obj, ev) -> bool:
        t = ev.type()
        if t == QEvent.Type.KeyPress and ev.key() == Qt.Key.Key_Alt and not ev.isAutoRepeat():
            self.show(True)
        elif t == QEvent.Type.KeyRelease and ev.key() == Qt.Key.Key_Alt:
            QTimer.singleShot(0, self._maybe_off)
        elif t == QEvent.Type.MouseButtonPress:
            self.show(False)
        elif t == QEvent.Type.KeyPress and ev.key() == Qt.Key.Key_Escape:
            QTimer.singleShot(0, self._maybe_off)
        return False

