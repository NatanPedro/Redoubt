"""Barra de Localizar/Substituir (Ctrl+F / Ctrl+H).

Opera sobre o editor atual via callback `get_editor`. Usa as primitivas do
QScintilla (findFirst/findNext/replace), com opcoes de regex, maiusc./minusc.
e palavra inteira.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QToolButton,
    QWidget,
)


class FindBar(QWidget):
    def __init__(self, get_editor, parent=None):
        super().__init__(parent)
        self._get_editor = get_editor
        self._active = False          # ha uma busca em andamento (usar findNext)
        self._expr = None
        self._forward = True

        lay = QHBoxLayout(self)
        lay.setContentsMargins(6, 3, 6, 3)
        lay.setSpacing(4)

        self.find_edit = QLineEdit()
        self.find_edit.setPlaceholderText("Localizar")
        self.find_edit.setMaximumWidth(240)
        self.replace_edit = QLineEdit()
        self.replace_edit.setPlaceholderText("Substituir por")
        self.replace_edit.setMaximumWidth(240)

        btn_prev = QToolButton(); btn_prev.setText("▲"); btn_prev.setToolTip("Anterior (Shift+F3)")
        btn_next = QToolButton(); btn_next.setText("▼"); btn_next.setToolTip("Proxima (F3)")
        self.btn_rep = QToolButton(); self.btn_rep.setText("Substituir")
        self.btn_repall = QToolButton(); self.btn_repall.setText("Tudo")

        self.cb_case = QCheckBox("Aa"); self.cb_case.setToolTip("Diferenciar maiusculas/minusculas")
        self.cb_word = QCheckBox("\\b"); self.cb_word.setToolTip("Palavra inteira")
        self.cb_regex = QCheckBox(".*"); self.cb_regex.setToolTip("Expressao regular")

        self.status = QLabel("")
        btn_close = QToolButton(); btn_close.setText("✕"); btn_close.setToolTip("Fechar (Esc)")

        for w in (self.find_edit, btn_prev, btn_next, self.replace_edit, self.btn_rep,
                  self.btn_repall, self.cb_case, self.cb_word, self.cb_regex, self.status):
            lay.addWidget(w)
        lay.addStretch(1)
        lay.addWidget(btn_close)

        self.find_edit.returnPressed.connect(self.find_next)
        self.replace_edit.returnPressed.connect(self.replace_one)
        self.find_edit.textChanged.connect(self._invalidate)
        self.cb_case.toggled.connect(self._invalidate)
        self.cb_word.toggled.connect(self._invalidate)
        self.cb_regex.toggled.connect(self._invalidate)
        btn_next.clicked.connect(self.find_next)
        btn_prev.clicked.connect(self.find_prev)
        self.btn_rep.clicked.connect(self.replace_one)
        self.btn_repall.clicked.connect(self.replace_all)
        btn_close.clicked.connect(self.hide_bar)

        esc = QShortcut(QKeySequence("Escape"), self)
        esc.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        esc.activated.connect(self.hide_bar)

        self.hide()

    # ------------------------------------------------------------------ #
    def open_find(self, replace: bool = False) -> None:
        ed = self._get_editor()
        if ed is not None and ed.hasSelectedText():
            sel = ed.selectedText()
            if "\n" not in sel and " " not in sel and sel:
                self.find_edit.setText(sel)
        show_rep = replace
        for w in (self.replace_edit, self.btn_rep, self.btn_repall):
            w.setVisible(show_rep)
        self.show()
        self._active = False
        self.find_edit.setFocus()
        self.find_edit.selectAll()

    def hide_bar(self) -> None:
        self.hide()
        ed = self._get_editor()
        if ed is not None:
            ed.setFocus()

    def _invalidate(self, *_) -> None:
        self._active = False
        self.status.clear()

    def _opts(self):
        return self.cb_regex.isChecked(), self.cb_case.isChecked(), self.cb_word.isChecked()

    def find_next(self) -> None:
        self._do_find(True)

    def find_prev(self) -> None:
        self._do_find(False)

    def _do_find(self, forward: bool) -> None:
        ed = self._get_editor()
        expr = self.find_edit.text()
        if ed is None or not expr:
            return
        re_, cs, wo = self._opts()
        if self._active and expr == self._expr and forward == self._forward:
            found = ed.findNext()
        else:
            found = ed.findFirst(expr, re_, cs, wo, True, forward)
            self._active = bool(found)
            self._expr = expr
            self._forward = forward
        self.status.setText("" if found else "sem ocorrencias")

    def replace_one(self) -> None:
        ed = self._get_editor()
        if ed is None or ed.isReadOnly():
            return
        if self._active and ed.hasSelectedText():
            ed.replace(self.replace_edit.text())
        self._do_find(True)

    def replace_all(self) -> int:
        ed = self._get_editor()
        expr = self.find_edit.text()
        if ed is None or ed.isReadOnly() or not expr:
            return 0
        re_, cs, wo = self._opts()
        count = 0
        ed.beginUndoAction()
        found = ed.findFirst(expr, re_, cs, wo, False, True, 0, 0)   # do inicio, sem wrap
        while found:
            ed.replace(self.replace_edit.text())
            count += 1
            found = ed.findNext()
        ed.endUndoAction()
        self._active = False
        self.status.setText(f"{count} substituida(s)")
        return count
