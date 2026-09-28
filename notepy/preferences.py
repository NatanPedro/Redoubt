"""Diálogo de Preferências (Configurações) do Redoubt."""

from __future__ import annotations

from PyQt6.QtCore import QRectF, QSize, Qt
from PyQt6.QtGui import QColor, QFont, QPainter
from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QFontComboBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from . import config, theme
from .widgets import dialog_footer, dialog_header, section_title


class ThemeCard(QPushButton):
    """Cartao de tema com uma miniatura desenhada nas cores DAQUELE tema."""

    def __init__(self, key: str, title: str, subtitle: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.key = key
        self.title = title
        self.subtitle = subtitle
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAccessibleName(f"Tema {title}")
        self.setMinimumSize(QSize(260, 150))

    def paintEvent(self, ev) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pal = theme._PALETTES[self.key]
        r = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        p.setPen(QColor(theme.AMBER if self.isChecked() else theme.BORDER2))
        p.setBrush(QColor(theme.BG))
        p.drawRoundedRect(r, 10, 10)
        prev = QRectF(r.left() + 10, r.top() + 10, r.width() - 20, 88)
        p.setPen(QColor(pal["BORDER"]))
        p.setBrush(QColor(pal["BG"]))
        p.drawRoundedRect(prev, 6, 6)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(pal["APP"]))
        p.drawRoundedRect(QRectF(prev.left() + 1, prev.top() + 1, 26, prev.height() - 2), 5, 5)
        x0 = prev.left() + 38
        for i, (w, color, alpha) in enumerate(((0.62, pal["TEXT"], 0.7), (0.42, pal["AMBER"], 1.0),
                                               (0.52, pal["TEXT"], 0.4), (0.30, pal["RED"], 0.9))):
            c = QColor(color)
            c.setAlphaF(alpha)
            p.setBrush(c)
            p.drawRoundedRect(QRectF(x0, prev.top() + 14 + i * 17, (prev.width() - 50) * w, 6), 3, 3)
        p.setPen(QColor(theme.TEXT))
        f = QFont(self.font())
        f.setWeight(QFont.Weight.DemiBold)
        p.setFont(f)
        p.drawText(QRectF(r.left() + 12, prev.bottom() + 8, r.width() - 24, 18),
                   int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter), self.title)
        p.setPen(QColor(theme.DIM))
        p.setFont(self.font())
        p.drawText(QRectF(r.left() + 12, prev.bottom() + 26, r.width() - 24, 18),
                   int(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter), self.subtitle)
        p.end()


class PreferencesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Preferências — Redoubt")
        self.setMinimumWidth(720)

        self.sp_lock = QSpinBox()
        self.sp_lock.setRange(0, 120)
        self.sp_lock.setSuffix(" min")
        self.sp_lock.setSpecialValueText("desativado")   # 0 aparece como "desativado"
        self.sp_lock.setValue(config.get("auto_lock_min"))

        self.cb_font = QFontComboBox()
        self.cb_font.setFontFilters(QFontComboBox.FontFilter.MonospacedFonts)
        fam = config.get("font_family") or config.monospace_family() or "Consolas"
        self.cb_font.setCurrentFont(QFont(fam))

        self.sp_size = QSpinBox()
        self.sp_size.setRange(8, 32)
        self.sp_size.setSuffix(" pt")
        self.sp_size.setValue(config.get("font_size"))

        self.sp_tab = QSpinBox()
        self.sp_tab.setRange(1, 8)
        self.sp_tab.setSuffix(" espaços")
        self.sp_tab.setValue(config.get("tab_width"))

        self.cb_restore = QCheckBox("Reabrir os arquivos ao iniciar")
        self.cb_restore.setToolTip(
            "Lembra apenas os CAMINHOS abertos — nunca o conteudo. Cofres reaparecem "
            "travados (sem pedir senha). Notas de queima e abas sem titulo nunca sao salvas.")
        self.cb_restore.setChecked(config.get("restore_session"))

        # O combo continua sendo a fonte do valor salvo; os cartoes so o escolhem.
        self.cb_theme = QComboBox()
        self.cb_theme.addItem("Escuro (carbono)", "dark")
        self.cb_theme.addItem("Claro", "light")
        idx = self.cb_theme.findData(config.get("theme"))
        self.cb_theme.setCurrentIndex(idx if idx >= 0 else 0)
        self.cb_theme.hide()

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(dialog_header("sliders", theme.TEXT2, "Preferências", "Ctrl+,"))

        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(28, 20, 28, 12)
        bl.setSpacing(4)
        bl.addWidget(section_title("Aparência"))
        cards = QHBoxLayout()
        cards.setSpacing(12)
        self._cards = QButtonGroup(self)
        self._cards.setExclusive(True)
        for key, title, sub in (("dark", "Carbono", "escuro · padrão"),
                                ("light", "Claro", "para ambientes iluminados")):
            c = ThemeCard(key, title, sub)
            c.setChecked(self.cb_theme.currentData() == key)
            c.clicked.connect(lambda _c=False, k=key: self._pick_theme(k))
            self._cards.addButton(c)
            cards.addWidget(c, 1)
        bl.addSpacing(8)
        bl.addLayout(cards)
        bl.addSpacing(8)
        bl.addWidget(self._row("Fonte do editor", "Monoespaçadas instaladas nesta máquina", self.cb_font))
        bl.addWidget(self._row("Tamanho da fonte", "Pontos", self.sp_size))
        bl.addWidget(self._row("Largura do tab", "Espaços por nível de indentação", self.sp_tab))
        bl.addSpacing(18)
        bl.addWidget(section_title("Sessão e segurança"))
        bl.addWidget(self._row("Restaurar sessão", "Só os caminhos; cofres voltam travados", self.cb_restore))
        bl.addWidget(self._row("Auto-lock do cofre", "Trava cofres após inatividade · 0 desativa", self.sp_lock))
        outer.addWidget(body, 1)

        cancel = QPushButton("Cancelar")
        cancel.clicked.connect(self.reject)
        ok = QPushButton("Salvar")
        ok.setObjectName("Primary")
        ok.setDefault(True)
        ok.clicked.connect(self.accept)
        outer.addWidget(dialog_footer(cancel, ok))

    @staticmethod
    def _row(title: str, subtitle: str, control: QWidget) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 10, 0, 10)
        lay.setSpacing(16)
        col = QVBoxLayout()
        col.setSpacing(2)
        t = QLabel(title)
        f = t.font()
        f.setWeight(QFont.Weight.Medium)
        t.setFont(f)
        s = QLabel(subtitle)
        s.setObjectName("Muted")
        col.addWidget(t)
        col.addWidget(s)
        lay.addLayout(col, 1)
        control.setMinimumWidth(220 if isinstance(control, (QFontComboBox, QComboBox)) else 140)
        lay.addWidget(control)
        return w

    def _pick_theme(self, key: str) -> None:
        idx = self.cb_theme.findData(key)
        if idx >= 0:
            self.cb_theme.setCurrentIndex(idx)
        for c in self._cards.buttons():
            c.update()

    def save(self) -> None:
        """Persiste os valores escolhidos no QSettings."""
        config.set_("auto_lock_min", self.sp_lock.value())
        config.set_("font_family", self.cb_font.currentFont().family())
        config.set_("font_size", self.sp_size.value())
        config.set_("tab_width", self.sp_tab.value())
        config.set_("restore_session", self.cb_restore.isChecked())
        config.set_("theme", self.cb_theme.currentData())
