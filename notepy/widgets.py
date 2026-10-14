"""Pecas da interface do Redoubt (redesign "carbono"): barra superior, trilho lateral,
painel da Sentinela, faixa de alerta do editor, cartao de cofre travado, aviso flutuante e
os dialogos de selar cofre e de custodia.

Regra da casa: estas pecas MOSTRAM estado e EMITEM intencoes (sinais). A logica de seguranca
(selar, destravar, verificar) continua no MainWindow e nos nucleos puros — assim os testes
seguem exercitando o mesmo caminho, e a interface pode mudar sem mexer nas garantias.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import ClassVar

from PyQt6.QtCore import QEvent, QObject, QPoint, QRect, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QKeySequence, QPainter, QShortcut
from PyQt6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSizePolicy,
    QStatusBar,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from . import icons, sentinel_view, theme


# --------------------------------------------------------------------------- #
# Utilitarios
# --------------------------------------------------------------------------- #
def _label(text: str = "", name: str = "", wrap: bool = False, rich: bool = False) -> QLabel:
    lbl = QLabel(text)
    if name:
        lbl.setObjectName(name)
    if wrap:
        lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.TextFormat.RichText if rich else Qt.TextFormat.PlainText)
    return lbl


def _icon_label(name: str, color: str, size: int = 16, stroke: float = 2.0) -> QLabel:
    lbl = QLabel()
    lbl.setPixmap(icons.pixmap(name, color, size, stroke))
    lbl.setFixedSize(size, size)
    return lbl


def section_title(text: str) -> QLabel:
    lbl = _label(text.upper(), "SectionTitle")
    f = lbl.font()
    f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.0)
    lbl.setFont(f)
    return lbl


def _button(text: str, name: str = "", icon: str = "", icon_color: str | None = None,
            checkable: bool = False) -> QPushButton:
    b = QPushButton(text)
    if name:
        b.setObjectName(name)
    if icon:
        b.setIcon(icons.icon(icon, icon_color or theme.TEXT, 16, 1.9))
        b.setIconSize(QSize(16, 16))
    b.setCheckable(checkable)
    b.setCursor(Qt.CursorShape.PointingHandCursor)
    return b


# --------------------------------------------------------------------------- #
# Trilho lateral
# --------------------------------------------------------------------------- #
class RailButton(QToolButton):
    def __init__(self, key: str, icon_name: str, tip: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.key = key
        self.icon_name = icon_name
        self.tip = tip
        self.badge = 0
        self.setObjectName("RailButton")
        self.setToolTip(tip)
        self.setAccessibleName(tip)
        self.setFixedSize(44, 44)
        self.setIconSize(QSize(20, 20))
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_icon()

    def refresh_icon(self) -> None:
        color = theme.TEXT if self.isChecked() else theme.DIM
        self.setIcon(icons.icon(self.icon_name, color, 20, 1.8))

    def paintEvent(self, ev) -> None:
        super().paintEvent(ev)
        if not self.badge:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        txt = str(self.badge) if self.badge < 100 else "99+"
        f = theme.mono_font(7)
        f.setBold(True)
        p.setFont(f)
        w = max(16, p.fontMetrics().horizontalAdvance(txt) + 8)
        r = QRectF(self.width() - w - 2, 3, w, 16)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(theme.RED))
        p.drawRoundedRect(r, 8, 8)
        p.setPen(QColor(theme.RED_INK))
        p.drawText(r, Qt.AlignmentFlag.AlignCenter, txt)
        p.end()


class Rail(QWidget):
    """Trilho de 56 px: Sentinela (alterna o painel), Buscar em arquivos, Comparar, Custodia,
    e Preferencias embaixo. Emite `triggered(chave)`."""

    triggered = pyqtSignal(str)
    ITEMS = (("sentinela", "shield", "Sentinela: painel de segredos (Ctrl+B)"),
             ("busca", "search", "Buscar em arquivos (Ctrl+Shift+F)"),
             ("diff", "diff", "Comparar arquivos (Ctrl+Shift+D)"),
             ("custodia", "finger", "Custódia (Ctrl+Shift+H)"))

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Rail")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedWidth(56)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 8, 6, 8)
        lay.setSpacing(4)
        self.buttons: dict[str, RailButton] = {}
        for key, ic, tip in self.ITEMS:
            b = RailButton(key, ic, tip)
            if key == "sentinela":
                b.setCheckable(True)
                b.toggled.connect(lambda _on, bb=b: bb.refresh_icon())
            b.clicked.connect(lambda _c=False, k=key: self.triggered.emit(k))
            self.buttons[key] = b
            lay.addWidget(b)
        lay.addStretch(1)
        prefs = RailButton("prefs", "sliders", "Preferências (Ctrl+,)")
        prefs.clicked.connect(lambda: self.triggered.emit("prefs"))
        self.buttons["prefs"] = prefs
        lay.addWidget(prefs)

    def set_badge(self, n: int) -> None:
        b = self.buttons["sentinela"]
        if b.badge != n:
            b.badge = n
            b.update()
            # o numero e so desenhado: o leitor de tela o recebe pelo nome acessivel
            b.setAccessibleName(f"{b.tip} — {n} achado(s)" if n else b.tip)

    def set_sentinel_open(self, on: bool) -> None:
        b = self.buttons["sentinela"]
        b.blockSignals(True)
        b.setChecked(on)
        b.blockSignals(False)
        b.refresh_icon()

    def paintEvent(self, ev) -> None:
        super().paintEvent(ev)
        b = self.buttons["sentinela"]
        if b.isChecked():                      # marca ambar a esquerda do item ativo
            p = QPainter(self)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(theme.AMBER))
            y = b.geometry().center().y()
            p.drawRoundedRect(QRectF(0, y - 12, 2.5, 24), 1, 1)
            p.end()

    def retheme(self) -> None:
        for b in self.buttons.values():
            b.refresh_icon()


# --------------------------------------------------------------------------- #
# Painel da Sentinela
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    kind: str
    line: int              # 1-based
    offset: int            # offset em caracteres (para ir ate o segredo)
    snippet: str = field(repr=False)


class FindingRow(QWidget):
    def __init__(self, f: Finding, redacted: bool, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("FindingRow")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(10)
        dot = QLabel()
        dot.setFixedSize(8, 8)
        dot.setStyleSheet(f"background:{theme.AMBER if redacted else theme.RED}; border-radius:4px;")
        col = QVBoxLayout()
        col.setSpacing(3)
        top = QHBoxLayout()
        top.setSpacing(8)
        title = _label(sentinel_view.display(f.kind))
        tf = title.font()
        tf.setWeight(QFont.Weight.DemiBold)
        title.setFont(tf)
        top.addWidget(title, 1)
        ln = _label(f"L{f.line}", "Muted")
        ln.setFont(theme.mono_font(8))
        top.addWidget(ln)
        bot = QHBoxLayout()
        bot.setSpacing(8)
        masked = "••••••••" if redacted else sentinel_view.mask(f.snippet, f.kind)
        mk = _label(masked, "Secondary")
        mk.setFont(theme.mono_font(9))
        bot.addWidget(mk, 1)
        bot.addWidget(_label(sentinel_view.layer(f.kind), "Muted"))
        col.addLayout(top)
        col.addLayout(bot)
        lay.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)
        lay.addLayout(col, 1)


class SentinelPanel(QWidget):
    """Lista ao vivo dos segredos do arquivo atual, sempre mascarados (a tela e o que se
    compartilha). Clique leva ao segredo; os filtros separam credenciais de PII.

    O painel so diz "nenhum segredo" quando a varredura TERMINOU: verificando, nao verificado,
    conteudo oculto e cofre tem cada um a sua mensagem (ver `set_state`)."""

    finding_activated = pyqtSignal(int)      # offset em caracteres
    redact_all = pyqtSignal()
    report_requested = pyqtSignal()
    dismissed = pyqtSignal()                 # Esc dentro do painel: o foco volta ao editor

    # estado -> (icone, cor do tema, titulo, texto). {d} = detalhe (percentual, contagem).
    STATES: ClassVar[dict[str, tuple[str, str, str, str]]] = {
        "pending": ("clock", "AMBER", "Verificando… {d}%",
                    "Arquivo grande: a varredura roda em partes, sem travar a janela."),
        "skipped": ("alert", "AMBER", "Não verificado",
                    "Grande demais para varrer ao vivo, ou a varredura falhou. Não o trate como "
                    "limpo."),
        "hidden": ("eyeoff", "AMBER", "Conteúdo oculto",
                   "{d} credencial(is) detectada(s). Revele para ver onde estão, ou sele como "
                   "cofre."),
        "hidden_big": ("eyeoff", "AMBER", "Conteúdo oculto",
                       "Grande demais para verificar: fica oculto por precaução."),
        "vault": ("lock", "GREEN", "Cofre",
                  "Cofres não são varridos: no disco, o conteúdo é cifrado."),
        "locked": ("lock", "AMBER", "Cofre travado",
                   "O conteúdo saiu da memória. Destrave para ver e editar."),
    }

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("SidePanel")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedWidth(320)
        self._findings: list[Finding] = []
        self._total = 0
        self._redacted = False
        self._filter = "todos"
        self._state = "done"
        self._detail = ""

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        head = QWidget()
        head.setObjectName("PanelHeader")
        head.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        hl = QVBoxLayout(head)
        hl.setContentsMargins(14, 14, 14, 10)
        hl.setSpacing(10)
        row = QHBoxLayout()
        row.setSpacing(8)
        self._shield = _icon_label("shield", theme.AMBER, 16)
        row.addWidget(self._shield)
        t = section_title("Sentinela")
        t.setStyleSheet(f"color:{theme.TEXT};")
        row.addWidget(t)
        row.addStretch(1)
        row.addWidget(_label("5 camadas · ao vivo", "Muted"))
        hl.addLayout(row)
        chips = QHBoxLayout()
        chips.setSpacing(6)
        self._chip_group = QButtonGroup(self)
        self._chip_group.setExclusive(True)
        self.chips: dict[str, QPushButton] = {}
        for key in ("todos", "credencial", "pii"):
            b = _button("", "Chip", checkable=True)
            b.clicked.connect(lambda _c=False, k=key: self._set_filter(k))
            self._chip_group.addButton(b)
            self.chips[key] = b
            chips.addWidget(b)
        chips.addStretch(1)
        self.chips["todos"].setChecked(True)
        hl.addLayout(chips)
        outer.addWidget(head)

        # Linha de aviso sobre a lista: varredura em andamento (lista da anterior) ou teto atingido.
        self.note = _label("", "Muted", wrap=True)
        self.note.setContentsMargins(14, 8, 14, 0)
        self.note.hide()
        outer.addWidget(self.note)

        self.list = QListWidget()
        self.list.setObjectName("Findings")
        self.list.setAccessibleName("Achados da Sentinela")
        self.list.setSpacing(1)
        self.list.setVerticalScrollMode(QListWidget.ScrollMode.ScrollPerPixel)
        self.list.itemClicked.connect(self._activate)
        self.list.itemActivated.connect(self._activate)
        wrap = QWidget()
        wl = QVBoxLayout(wrap)
        wl.setContentsMargins(8, 8, 8, 8)
        wl.addWidget(self.list)
        outer.addWidget(wrap, 1)

        self.empty = QWidget()
        el = QVBoxLayout(self.empty)
        el.setContentsMargins(24, 40, 24, 40)
        el.setSpacing(10)
        self._empty_icon = _icon_label("shieldcheck", theme.GREEN, 28)
        el.addWidget(self._empty_icon, 0, Qt.AlignmentFlag.AlignHCenter)
        self._empty_title = _label("Nenhum segredo neste arquivo")
        self._empty_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        el.addWidget(self._empty_title)
        self._empty_text = _label("A Sentinela varre enquanto você digita.", "Muted", wrap=True)
        self._empty_text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        el.addWidget(self._empty_text)
        el.addStretch(1)
        outer.addWidget(self.empty, 1)
        self._empty_key: tuple = ()

        foot = QWidget()
        foot.setObjectName("PanelFooter")
        foot.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        fl = QHBoxLayout(foot)
        fl.setContentsMargins(14, 10, 14, 12)
        fl.setSpacing(8)
        self.btn_redact = _button("Tarjar todos", "Primary", "eyeoff", theme.AMBER_INK)
        self.btn_redact.clicked.connect(self.redact_all.emit)
        self.btn_report = _button("Relatório")
        self.btn_report.clicked.connect(self.report_requested.emit)
        fl.addWidget(self.btn_redact, 1)
        fl.addWidget(self.btn_report)
        outer.addWidget(foot)
        esc = QShortcut(QKeySequence("Escape"), self)
        esc.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        esc.activated.connect(self.dismissed.emit)
        self._render()

    def set_findings(self, findings: list[Finding], redacted: bool, total: int | None = None) -> None:
        """`findings` pode vir cortada (teto de exibicao); `total` e quantos ha de verdade."""
        self._findings = list(findings)
        self._total = len(self._findings) if total is None else max(total, len(self._findings))
        self._redacted = redacted
        self._render()

    def set_state(self, state: str, detail: str = "") -> None:
        """O que o painel pode afirmar sobre a aba: 'done' (varredura completa), 'pending',
        'skipped', 'hidden', 'hidden_big', 'vault' ou 'locked'. Barato: nao refaz a lista."""
        if state not in self.STATES:
            state = "done"
        if (state, detail) != (self._state, self._detail):
            self._state, self._detail = state, detail
            self._sync_view()

    def state(self) -> str:
        return self._state

    def _set_filter(self, key: str) -> None:
        self._filter = key
        self._render()

    def _render(self) -> None:
        cats = [sentinel_view.category(f.kind) for f in self._findings]
        counts = {"todos": len(cats), "credencial": cats.count("credencial"), "pii": cats.count("pii")}
        names = {"todos": "Todos", "credencial": "Credenciais", "pii": "PII"}
        for k, b in self.chips.items():
            b.setText(f"{names[k]} · {counts[k]}")
        # Desanexa as linhas antigas JA: o clear() so agenda a exclusao, e ate la a linha antiga
        # (talvez com o prefixo do provedor, sem a Redacao) continuaria viva entre os filhos.
        for i in range(self.list.count()):
            old = self.list.itemWidget(self.list.item(i))
            if old is not None:
                old.hide()
                old.setParent(None)
                old.deleteLater()
        self.list.clear()
        shown = [f for f, c in zip(self._findings, cats, strict=True)
                 if self._filter == "todos" or c == self._filter]
        for f in shown[:500]:                   # teto: lista de redacao com literal comum
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, f.offset)
            # a linha e um widget desenhado: o leitor de tela le este texto (nunca o segredo)
            item.setData(Qt.ItemDataRole.AccessibleTextRole,
                         f"{sentinel_view.display(f.kind)}, linha {f.line}")
            row = FindingRow(f, self._redacted)
            item.setSizeHint(QSize(0, row.sizeHint().height() + 12))   # borda+margem do item
            self.list.addItem(item)
            self.list.setItemWidget(item, row)
        has = bool(self._findings)
        self.btn_redact.setEnabled(has and not self._redacted)
        self.btn_redact.setText("Tarjados" if self._redacted else "Tarjar todos")
        self._sync_view()

    def _sync_view(self) -> None:
        """Lista ou mensagem, conforme o estado da varredura e o filtro."""
        st, d = self._state, self._detail
        listing = st in ("done", "pending") and self.list.count() > 0
        self.list.parentWidget().setVisible(listing)
        self.empty.setVisible(not listing)
        notes = []
        if listing and st == "pending":
            notes.append(f"Verificando… {d}% · a lista é da varredura anterior.")
        if listing and self._total > len(self._findings):
            notes.append(f"Mostrando {len(self._findings)} de {self._total}. F8 percorre todos.")
        self.note.setText("  ".join(notes))
        self.note.setVisible(bool(notes))
        if listing:
            return
        if st in self.STATES:
            ic, color, title, text = self.STATES[st]
            title, text = title.format(d=d), text.format(d=d)
        elif self._findings:                   # ha achados, mas nenhum deste filtro
            ic, color = "shield", "DIM"
            title = "Nenhuma credencial" if self._filter == "credencial" else "Nenhum dado pessoal (PII)"
            text = "Os outros achados estão em Todos."
        else:
            ic, color = "shieldcheck", "GREEN"
            title, text = "Nenhum segredo neste arquivo", "A Sentinela varre enquanto você digita."
        key = (ic, getattr(theme, color), title, text)
        if key != self._empty_key:
            self._empty_key = key
            self._empty_icon.setPixmap(icons.pixmap(ic, key[1], 28, 2.0))
            self._empty_title.setText(title)
            self._empty_text.setText(text)

    def _activate(self, item: QListWidgetItem) -> None:
        off = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(off, int):
            self.finding_activated.emit(off)

    def retheme(self) -> None:
        self._shield.setPixmap(icons.pixmap("shield", theme.AMBER, 16, 2.0))
        self._empty_key = ()                   # redesenha o icone da mensagem nas cores novas
        self.btn_redact.setIcon(icons.icon("eyeoff", theme.AMBER_INK, 16, 1.9))
        self._render()


# --------------------------------------------------------------------------- #
# Faixa de alerta DENTRO do editor (logo abaixo das abas)
# --------------------------------------------------------------------------- #
class Banner(QWidget):
    HEIGHT = 36

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Banner")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedHeight(self.HEIGHT)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 0, 10, 0)
        lay.setSpacing(10)
        self.icon = QLabel()
        self.icon.setFixedSize(16, 16)
        self.text = _label("", rich=True)
        # o texto encolhe (corta) em vez de empurrar os botoes para fora da faixa
        self.text.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.text.setMinimumWidth(0)
        lay.addWidget(self.icon)
        lay.addWidget(self.text, 1)
        self._buttons: list[QPushButton] = []
        self._lay = lay
        self.level = ""

    def set_state(self, level: str, icon_name: str, html: str,
                  buttons: list[tuple[str, object, bool]]) -> None:
        """level 'danger' | 'warn'; buttons = [(texto, callback, primario)]."""
        self.level = level
        self.setProperty("level", level)
        self.style().unpolish(self)
        self.style().polish(self)
        color = theme.RED if level == "danger" else theme.AMBER
        self.icon.setPixmap(icons.pixmap(icon_name, color, 16, 2.0))
        self.text.setText(html)
        for b in self._buttons:
            self._lay.removeWidget(b)
            b.hide()
            b.deleteLater()
        self._buttons = []
        for text, cb, primary in buttons:
            b = _button(text, "Danger" if (primary and level == "danger") else ("Primary" if primary else ""))
            b.setMinimumHeight(26)
            b.setStyleSheet("padding: 2px 10px;")
            b.clicked.connect(cb)
            self._lay.addWidget(b)
            self._buttons.append(b)


# --------------------------------------------------------------------------- #
# Cofre travado: cartao de destravar sobre o editor
# --------------------------------------------------------------------------- #
class LockedOverlay(QWidget):
    unlock_requested = pyqtSignal(str)
    keyfile_requested = pyqtSignal()
    recipient_requested = pyqtSignal()       # cofre selado PARA VOCE: destrava com a sua chave

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setObjectName("LockOverlay")
        outer = QVBoxLayout(self)
        outer.addStretch(1)
        card = QFrame()
        card.setObjectName("LockCard")
        card.setFixedWidth(460)
        cl = QVBoxLayout(card)
        cl.setContentsMargins(28, 26, 28, 24)
        cl.setSpacing(16)
        head = QHBoxLayout()
        head.setSpacing(14)
        self.badge = QLabel()
        self.badge.setFixedSize(48, 48)
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        head.addWidget(self.badge)
        tcol = QVBoxLayout()
        tcol.setSpacing(2)
        self.title = _label("", "DialogTitle", wrap=True)
        self.subtitle = _label("", "Secondary", wrap=True)
        tcol.addWidget(self.title)
        tcol.addWidget(self.subtitle)
        head.addLayout(tcol, 1)
        cl.addLayout(head)
        chips = QHBoxLayout()
        chips.setSpacing(8)
        self._chip_values: list[QLabel] = []
        for name in ("Formato", "Cifra", "Destravadores"):
            c = QFrame()
            c.setObjectName("Chip2")
            v = QVBoxLayout(c)
            v.setContentsMargins(10, 8, 10, 8)
            v.setSpacing(2)
            v.addWidget(_label(name, "Muted"))
            val = _label("", "Mono")
            val.setFont(theme.mono_font(9))
            v.addWidget(val)
            self._chip_values.append(val)
            chips.addWidget(c, 1)
        cl.addLayout(chips)
        pw_label = _label("Senha do cofre")
        cl.addWidget(pw_label)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Digite a senha")
        self.password.setAccessibleName("Senha do cofre")
        self.password.returnPressed.connect(self._submit)
        pw_label.setBuddy(self.password)
        cl.addWidget(self.password)
        self.error = _label("", wrap=True)
        self.error.setStyleSheet(f"color:{theme.RED};")
        self.error.hide()
        cl.addWidget(self.error)
        row = QHBoxLayout()
        self.btn_keyfile = _button("Usar arquivo-chave", "Link", "key", theme.CYAN)
        self.btn_keyfile.clicked.connect(self.keyfile_requested.emit)
        self.btn_recipient = _button("Usar minha chave", "Link", "user", theme.CYAN)
        self.btn_recipient.setToolTip("Este cofre foi selado para a sua chave de destinatário (X25519)")
        self.btn_recipient.clicked.connect(self.recipient_requested.emit)
        self.btn_recipient.hide()
        self.btn_unlock = _button("Destravar", "Primary")
        self.btn_unlock.setMinimumHeight(36)
        self.btn_unlock.clicked.connect(self._submit)
        row.addWidget(self.btn_keyfile)
        row.addWidget(self.btn_recipient)
        row.addStretch(1)
        row.addWidget(self.btn_unlock)
        cl.addLayout(row)
        cl.addWidget(_label("Zero-knowledge: a senha nunca é gravada. Esquecer todos os "
                            "destravadores é perder o cofre.", "Muted", wrap=True))
        h = QHBoxLayout()
        h.addStretch(1)
        h.addWidget(card)
        h.addStretch(1)
        outer.addLayout(h)
        outer.addStretch(1)
        self.retheme()

    def set_info(self, name: str, reason: str, formato: str, destravadores: str,
                 recipient: bool = False) -> None:
        self.title.setText(f"{name} está travado")
        self.subtitle.setText(reason)
        for lbl, val in zip(self._chip_values, (formato, "AES-256-GCM", destravadores), strict=True):
            lbl.setText(val)
        self.btn_recipient.setVisible(recipient)

    def reset(self) -> None:
        self.password.clear()
        self.error.hide()

    def show_error(self, msg: str) -> None:
        self.error.setText(msg)
        self.error.show()
        self.password.selectAll()
        self.password.setFocus()

    def set_busy(self, on: bool) -> None:
        """Enquanto o Argon2id deriva a chave (~1 s): botao inerte e o motivo na tela."""
        self.btn_unlock.setEnabled(not on)
        self.btn_unlock.setText("Destravando…" if on else "Destravar")
        self.password.setEnabled(not on)
        if on:
            self.setCursor(Qt.CursorShape.WaitCursor)
            self.btn_unlock.repaint()          # o trabalho e sincrono: pinta antes de comecar
        else:
            self.unsetCursor()

    def _submit(self) -> None:
        pw = self.password.text()
        if pw:
            self.unlock_requested.emit(pw)
        else:
            self.show_error("Digite a senha do cofre.")

    def paintEvent(self, ev) -> None:
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(theme.BG))
        dot = QColor(theme.TEXT)
        dot.setAlphaF(0.05)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(dot)
        for x in range(9, self.width(), 18):
            for y in range(9, self.height(), 18):
                p.drawEllipse(QPoint(x, y), 1, 1)
        p.end()

    def retheme(self) -> None:
        self.badge.setPixmap(icons.pixmap("lock", theme.AMBER, 24, 2.0))
        self.badge.setStyleSheet(f"background:{theme.AMBER_BG}; border-radius:12px;")
        self.btn_keyfile.setIcon(icons.icon("key", theme.CYAN, 16, 1.9))
        self.btn_recipient.setIcon(icons.icon("user", theme.CYAN, 16, 1.9))
        self.error.setStyleSheet(f"color:{theme.RED};")


# --------------------------------------------------------------------------- #
# Posiciona a faixa e o cartao de cofre travado sobre o editor
# --------------------------------------------------------------------------- #
class EditorChrome(QObject):
    """Faixa de alerta no topo e cartao de cofre travado, filhos do PROPRIO editor.

    As abas continuam guardando o CodeEditor direto (o resto do app e os testes dependem
    disso); a faixa ocupa uma margem do viewport e o cartao cobre o editor inteiro."""

    def __init__(self, editor):
        super().__init__(editor)
        self.editor = editor
        self.banner = Banner(editor)
        self.banner.hide()
        self.overlay = LockedOverlay(editor)
        self.overlay.hide()
        editor.installEventFilter(self)

    def eventFilter(self, obj, ev) -> bool:
        if obj is self.editor and ev.type() in (QEvent.Type.Resize, QEvent.Type.Show):
            self._layout()
        return False

    def _layout(self) -> None:
        r = self.editor.rect()
        self.banner.setGeometry(QRect(0, 0, r.width(), Banner.HEIGHT))
        self.overlay.setGeometry(r)
        if not self.overlay.isHidden():
            self.overlay.raise_()            # acima das barras de rolagem do editor

    def show_banner(self, on: bool) -> None:
        # isHidden (estado do PROPRIO widget), nao isVisible: com a janela minimizada ou fora da
        # tela, isVisible e sempre False e a faixa nunca sumiria.
        if on == (not self.banner.isHidden()):
            return
        self.banner.setVisible(on)
        self.editor.setViewportMargins(0, Banner.HEIGHT if on else 0, 0, 0)
        self._layout()
        self.banner.raise_()

    def show_overlay(self, on: bool) -> None:
        if on and self.overlay.isHidden():
            self.overlay.reset()
        self.overlay.setVisible(on)
        if on:
            self._layout()
            self.overlay.raise_()
            self.overlay.password.setFocus()


# --------------------------------------------------------------------------- #
# Barra de status: selo + informacoes + mensagens NO MEIO (sem cobrir nada)
# --------------------------------------------------------------------------- #
class StatusBar(QStatusBar):
    """O QStatusBar padrao desenha a mensagem temporaria POR CIMA dos widgets da esquerda (o
    selo e a posicao sumiam atras de "10 segredo(s) detectado(s)…"). Aqui tudo mora num unico
    widget permanente, e a mensagem ganha um espaco proprio entre a esquerda e a direita."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setSizeGripEnabled(False)
        box = QWidget()
        self._lay = QHBoxLayout(box)
        self._lay.setContentsMargins(6, 0, 8, 0)
        self._lay.setSpacing(2)
        self.msg = QLabel("")
        self.msg.setObjectName("Muted")
        self.msg.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.msg.setMinimumWidth(0)
        self._lay.addWidget(self.msg, 1)
        self._left = 0
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.clearMessage)
        super().addPermanentWidget(box, 1)

    def add_left(self, w: QWidget) -> None:
        self._lay.insertWidget(self._left, w)
        self._left += 1

    def add_right(self, w: QWidget) -> None:
        self._lay.addWidget(w)

    def showMessage(self, text: str, timeout: int = 0) -> None:
        self.msg.setText(" ".join(str(text).split()))
        self.msg.setToolTip(str(text))
        if timeout > 0:
            self._timer.start(timeout)
        else:
            self._timer.stop()

    def clearMessage(self) -> None:
        self.msg.setText("")
        self.msg.setToolTip("")

    def currentMessage(self) -> str:
        return self.msg.text()


# --------------------------------------------------------------------------- #
# Aviso flutuante (canto inferior direito)
# --------------------------------------------------------------------------- #
class Toast(QFrame):
    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setObjectName("Toast")
        self.setFixedWidth(400)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(12)
        self.icon = QLabel()
        self.icon.setFixedSize(18, 18)
        lay.addWidget(self.icon, 0, Qt.AlignmentFlag.AlignTop)
        col = QVBoxLayout()
        col.setSpacing(4)
        self.title = _label("")
        tf = self.title.font()
        tf.setWeight(QFont.Weight.DemiBold)
        self.title.setFont(tf)
        self.detail = _label("", "Secondary")
        self.detail.setFont(theme.mono_font(9))
        self.note = _label("", "Muted", wrap=True)
        col.addWidget(self.title)
        col.addWidget(self.detail)
        col.addWidget(self.note)
        lay.addLayout(col, 1)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)
        self.hide()

    def show_message(self, title: str, detail: str = "", note: str = "", icon_name: str = "copy",
                     msec: int = 4000) -> None:
        self.icon.setPixmap(icons.pixmap(icon_name, theme.AMBER, 18, 1.9))
        self.title.setText(title)
        fm = self.detail.fontMetrics()
        self.detail.setText(fm.elidedText(detail, Qt.TextElideMode.ElideRight, 330))
        self.detail.setVisible(bool(detail))
        self.note.setText(note)
        self.note.setVisible(bool(note))
        self.adjustSize()
        par = self.parentWidget()
        if par is not None:
            self.move(par.width() - self.width() - 28, par.height() - self.height() - 44)
        self.show()
        self.raise_()
        self._timer.start(msec)


# --------------------------------------------------------------------------- #
# Dialogos: cabecalho padrao
# --------------------------------------------------------------------------- #
def dialog_header(icon_name: str, color: str, title: str, subtitle: str) -> QWidget:
    w = QWidget()
    w.setObjectName("PanelHeader")
    w.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
    lay = QHBoxLayout(w)
    lay.setContentsMargins(24, 18, 24, 16)
    lay.setSpacing(14)
    badge = QLabel()
    badge.setFixedSize(40, 40)
    badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
    badge.setPixmap(icons.pixmap(icon_name, color, 20, 2.0))
    badge.setStyleSheet(f"background:{theme.RAISED}; border-radius:10px;")
    lay.addWidget(badge)
    col = QVBoxLayout()
    col.setSpacing(2)
    col.addWidget(_label(title, "DialogTitle"))
    col.addWidget(_label(subtitle, "Secondary"))
    lay.addLayout(col, 1)
    return w


def dialog_footer(*widgets: QWidget, left: QWidget | None = None) -> QWidget:
    w = QWidget()
    w.setObjectName("PanelFooter")
    w.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
    lay = QHBoxLayout(w)
    lay.setContentsMargins(24, 14, 24, 16)
    lay.setSpacing(10)
    if left is not None:
        lay.addWidget(left, 1)
    else:
        lay.addStretch(1)
    for x in widgets:
        lay.addWidget(x)
    return w


class StrengthMeter(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)
        bars = QHBoxLayout()
        bars.setSpacing(4)
        self._bars: list[QFrame] = []
        for _ in range(4):
            b = QFrame()
            b.setFixedHeight(4)
            bars.addWidget(b, 1)
            self._bars.append(b)
        lay.addLayout(bars)
        self.label = _label("", "Muted")
        lay.addWidget(self.label)
        self.set_password("")

    def set_password(self, pw: str) -> None:
        s = sentinel_view.password_strength(pw)
        color = {0: theme.BORDER2, 1: theme.RED, 2: theme.AMBER, 3: theme.GREEN, 4: theme.GREEN}[s.level]
        for i, b in enumerate(self._bars):
            b.setStyleSheet(f"background:{color if i < s.level else theme.BORDER2}; border-radius:2px;")
        if s.level == 0:
            self.label.setText("Mínimo de 4 caracteres. Frases longas são as mais fortes.")
            self.label.setStyleSheet("")
        else:
            self.label.setText(f"{s.label} · até ~{s.bits} bits "
                               "(estimativa otimista: não conhece palavras de dicionário)")
            self.label.setStyleSheet(f"color:{color};")


class SealDialog(QDialog):
    """Selar como cofre: senha + confirmacao + medidor de forca. Devolve as DUAS senhas
    digitadas; quem valida (tamanho minimo, iguais) e o MainWindow, como antes."""

    def __init__(self, source_name: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Selar como cofre")
        self.setMinimumWidth(560)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        base = os.path.splitext(source_name)[0] or source_name
        outer.addWidget(dialog_header("lock", theme.AMBER, "Selar como cofre", f"{source_name} → {base}.rdbt"))
        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(24, 20, 24, 20)
        bl.setSpacing(12)
        bl.addWidget(section_title("Senha principal"))
        l1 = _label("Senha")
        bl.addWidget(l1)
        self.pw1 = QLineEdit()
        self.pw1.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw1.setPlaceholderText("Senha forte ou frase longa")
        self.pw1.setAccessibleName("Senha")
        l1.setBuddy(self.pw1)
        bl.addWidget(self.pw1)
        self.meter = StrengthMeter()
        bl.addWidget(self.meter)
        l2 = _label("Confirmar senha")
        bl.addWidget(l2)
        self.pw2 = QLineEdit()
        self.pw2.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw2.setPlaceholderText("Repita a senha")
        self.pw2.setAccessibleName("Confirmar senha")
        l2.setBuddy(self.pw2)
        bl.addWidget(self.pw2)
        self.mismatch = _label("As senhas não conferem.")
        self.mismatch.setStyleSheet(f"color:{theme.RED};")
        self.mismatch.hide()
        bl.addWidget(self.mismatch)
        bl.addSpacing(6)
        bl.addWidget(section_title("Outros destravadores"))
        bl.addWidget(_label("Depois de selar, adicione uma senha de backup, um arquivo-chave ou "
                            "sele para um destinatário X25519 em Segurança. Qualquer destravador "
                            "abre o cofre.", "Secondary", wrap=True))
        warn = QFrame()
        warn.setObjectName("Card")
        warn.setStyleSheet(f"#Card {{ background:{theme.AMBER_BG}; border:1px solid {theme.AMBER}; }}")
        wl = QHBoxLayout(warn)
        wl.setContentsMargins(12, 10, 12, 10)
        wl.setSpacing(10)
        wl.addWidget(_icon_label("alert", theme.AMBER, 16), 0, Qt.AlignmentFlag.AlignTop)
        wl.addWidget(_label("Zero-knowledge: a senha não é guardada em lugar nenhum. Esquecê-la "
                            "torna o conteúdo irrecuperável — não há recuperação nem backdoor.",
                            wrap=True), 1)
        bl.addWidget(warn)
        outer.addWidget(body, 1)
        spec = _label("RDBT4 · AES-256-GCM · Argon2id (64 MiB, t=3)", "Muted")
        spec.setFont(theme.mono_font(8))
        cancel = _button("Cancelar")
        cancel.clicked.connect(self.reject)
        self.ok = _button("Selar cofre", "Primary", "lock", theme.AMBER_INK)
        self.ok.setDefault(True)
        self.ok.clicked.connect(self._accept)
        outer.addWidget(dialog_footer(cancel, self.ok, left=spec))
        self.pw1.textChanged.connect(self._changed)
        self.pw2.textChanged.connect(self._changed)
        self._changed()

    def _changed(self) -> None:
        self.meter.set_password(self.pw1.text())
        self.ok.setEnabled(bool(self.pw1.text()) and bool(self.pw2.text()))
        self.mismatch.setVisible(bool(self.pw2.text()) and self.pw1.text() != self.pw2.text())

    def _accept(self) -> None:
        if self.pw1.text() and self.pw2.text():
            self.accept()

    def values(self) -> tuple[str, str]:
        return self.pw1.text(), self.pw2.text()

    @staticmethod
    def ask(parent: QWidget | None, source_name: str) -> tuple[str, str] | None:
        """(senha, confirmacao) digitadas, ou None se cancelou. Mockavel nos testes."""
        dlg = SealDialog(source_name, parent)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return None
        return dlg.values()


# --------------------------------------------------------------------------- #
# Custodia
# --------------------------------------------------------------------------- #
@dataclass
class CustodyReport:
    name: str
    sha256: str
    content_state: str             # 'ok' | 'changed' | 'unsaved'
    signature_state: str           # 'ok' | 'bad' | 'none'
    signature_file: str
    fingerprint: str
    public_key: str
    identity_protected: bool
    warnings: list[str]
    chain_ok: bool
    chain_break_at: int
    events_total: int
    events_signed: int
    recent: list[tuple[str, str, str, str]]   # (seq, evento, arquivo, quando)
    identity_dpapi: bool = False               # abre sem senha nesta conta do Windows


def _state(ok: bool | None, text: str) -> QWidget:
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(6)
    if ok is True:
        color, ic = theme.GREEN, "check"
    elif ok is False:
        color, ic = theme.AMBER, "alert"
    else:
        color, ic = theme.DIM, "clock"
    lay.addWidget(_icon_label(ic, color, 14, 2.3))
    lbl = _label(text)
    lbl.setStyleSheet(f"color:{color}; font-weight:600;")
    lay.addWidget(lbl)
    return w


def _card(title: str, state: QWidget, rows: list[QWidget]) -> QFrame:
    c = QFrame()
    c.setObjectName("Card")
    lay = QVBoxLayout(c)
    lay.setContentsMargins(16, 12, 16, 14)
    lay.setSpacing(8)
    head = QHBoxLayout()
    head.addWidget(section_title(title))
    head.addStretch(1)
    head.addWidget(state)
    lay.addLayout(head)
    for r in rows:
        lay.addWidget(r)
    return c


def _kv(key: str, value: str, mono: bool = True) -> QWidget:
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(12)
    k = _label(key, "Muted")
    k.setFixedWidth(140)
    v = _label(value)
    v.setWordWrap(True)
    v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    if mono:
        v.setFont(theme.mono_font(9))
    lay.addWidget(k, 0, Qt.AlignmentFlag.AlignTop)
    lay.addWidget(v, 1)
    return w


class CustodyDialog(QDialog):
    """Custodia do arquivo atual num painel so: conteudo, assinatura, identidade, trilha e
    ancora. Os botoes chamam as mesmas acoes dos menus (passadas pelo MainWindow)."""

    def __init__(self, r: CustodyReport, actions: dict, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Custódia")
        self.setMinimumWidth(720)
        self._actions = actions
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(dialog_header("finger", theme.GREEN, "Custódia", f"{r.name} · Ctrl+Shift+H"))
        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(24, 18, 24, 18)
        bl.setSpacing(12)

        st = {"ok": (True, "confere com o último salvamento"),
              "changed": (False, "alterado desde o último salvamento"),
              "unsaved": (None, "ainda não salvo (sem linha de base)")}[r.content_state]
        bl.addWidget(_card("Conteúdo", _state(*st), [_kv("SHA-256", r.sha256)]))

        if r.signature_state == "none":
            sig = _card("Assinatura (.sig)", _state(None, "não assinado"),
                        [_label("Assine e exporte para provar que o arquivo não mudou: quem tiver "
                                "sua chave pública verifica.", "Secondary", wrap=True)])
        else:
            ok = r.signature_state == "ok"
            sig = _card("Assinatura (.sig)", _state(ok, "confere" if ok else "NÃO confere"),
                        [_kv("Arquivo", r.signature_file, False),
                         _label("Não mudou desde que você assinou." if ok else
                                "O conteúdo mudou, ou o .sig é de outro arquivo/chave.",
                                "Secondary", wrap=True)])
        bl.addWidget(sig)

        id_rows: list[QWidget] = [_kv("Fingerprint", r.fingerprint or "—"),
                                  _kv("Chave pública", r.public_key or "—")]
        if not r.identity_protected:
            row = QWidget()
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 4, 0, 0)
            rl.setSpacing(12)
            rl.addWidget(_label("Quem tiver esta máquina assina como você. Proteja a chave e faça "
                                "um backup cifrado.", "Secondary", wrap=True), 1)
            b = _button("Proteger com senha", "Primary")
            b.clicked.connect(lambda: self._run("protect_identity"))
            rl.addWidget(b)
            id_rows.append(row)
        if r.fingerprint:
            # Backup cifrado, protegida ou nao: sem ele, perder a senha (ou a maquina) perde a chave.
            row = QWidget()
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 4, 0, 0)
            rl.setSpacing(12)
            rl.addWidget(_label("Guarde um backup cifrado fora desta máquina (num pendrive): "
                                "perder a senha ou o disco sem ele perde a identidade.",
                                "Secondary", wrap=True), 1)
            bb = _button("Fazer backup")
            bb.setObjectName("CustodyBackup")
            bb.clicked.connect(lambda: self._run("backup_identity"))
            rl.addWidget(bb)
            id_rows.append(row)
        for wmsg in r.warnings:
            wl = _label(wmsg, wrap=True)
            wl.setStyleSheet(f"color:{theme.AMBER};")
            id_rows.append(wl)
        bl.addWidget(_card("Identidade Ed25519",
                           _state(True, "protegida · abre nesta conta do Windows"
                                  if r.identity_dpapi else "protegida por senha")
                           if r.identity_protected
                           else _state(False, "sem senha"), id_rows))

        ev_rows: list[QWidget] = []
        for seq, ev, name, when in r.recent:
            w = QWidget()
            wl2 = QHBoxLayout(w)
            wl2.setContentsMargins(0, 0, 0, 0)
            wl2.setSpacing(10)
            dot = QLabel()
            dot.setFixedSize(8, 8)
            dot.setStyleSheet(f"background:{theme.GREEN if r.chain_ok else theme.AMBER}; border-radius:4px;")
            wl2.addWidget(dot)
            s = _label(f"#{seq}", "Muted")
            s.setFont(theme.mono_font(8))
            s.setFixedWidth(44)
            wl2.addWidget(s)
            e = _label(ev)
            e.setFixedWidth(110)
            ef = e.font()
            ef.setWeight(QFont.Weight.DemiBold)
            e.setFont(ef)
            wl2.addWidget(e)
            wl2.addWidget(_label(name, "Secondary"), 1)
            wl2.addWidget(_label(when, "Muted"))
            ev_rows.append(w)
        if not ev_rows:
            ev_rows.append(_label("Nenhum evento registrado ainda.", "Muted"))
        chain_txt = (f"cadeia íntegra · {r.events_total} eventos" if r.chain_ok
                     else f"cadeia QUEBRADA na entrada {r.chain_break_at}")
        bl.addWidget(_card("Trilha de auditoria", _state(r.chain_ok, chain_txt), ev_rows))

        bl.addWidget(_card("Âncora anti-reset", _state(None, f"{r.events_signed} evento(s) assinado(s)"),
                           [_label("Exporte uma âncora e guarde fora da máquina: ela detecta se a "
                                   "trilha for apagada e recomeçada.", "Secondary", wrap=True)]))
        outer.addWidget(body, 1)

        b_anchor = _button("Exportar âncora", icon="anchor")
        b_anchor.clicked.connect(lambda: self._run("export_anchor"))
        b_check = _button("Verificar âncora", icon="shieldcheck")
        b_check.clicked.connect(lambda: self._run("check_anchor"))
        b_sign = _button("Assinar e exportar", icon="seal")
        b_sign.clicked.connect(lambda: self._run("sign"))
        close = _button("Fechar", "Primary")
        close.clicked.connect(self.accept)
        left = QWidget()
        ll = QHBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(10)
        for b in (b_anchor, b_check, b_sign):
            ll.addWidget(b)
        ll.addStretch(1)
        outer.addWidget(dialog_footer(close, left=left))

    def _run(self, key: str) -> None:
        fn = self._actions.get(key)
        if callable(fn):
            self.accept()
            fn()

