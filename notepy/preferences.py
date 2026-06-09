"""Diálogo de Preferências (Configurações) do Redoubt."""

from __future__ import annotations

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QDialogButtonBox,
    QDialog,
    QFontComboBox,
    QFormLayout,
    QSpinBox,
)

from . import config


class PreferencesDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Preferências — Redoubt")
        self.setMinimumWidth(360)
        form = QFormLayout(self)

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
        self.sp_size.setValue(config.get("font_size"))

        self.sp_tab = QSpinBox()
        self.sp_tab.setRange(1, 8)
        self.sp_tab.setValue(config.get("tab_width"))

        form.addRow("Auto-lock do cofre:", self.sp_lock)
        form.addRow("Fonte:", self.cb_font)
        form.addRow("Tamanho da fonte:", self.sp_size)
        form.addRow("Largura do tab:", self.sp_tab)

        bb = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        form.addRow(bb)

    def save(self) -> None:
        """Persiste os valores escolhidos no QSettings."""
        config.set_("auto_lock_min", self.sp_lock.value())
        config.set_("font_family", self.cb_font.currentFont().family())
        config.set_("font_size", self.sp_size.value())
        config.set_("tab_width", self.sp_tab.value())
