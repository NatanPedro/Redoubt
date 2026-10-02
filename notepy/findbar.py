"""Barra de Localizar/Substituir (Ctrl+F / Ctrl+H).

Opera sobre o editor atual via callback `get_editor`. Usa as primitivas do
QScintilla (findFirst/findNext/replace), com opcoes de regex, maiusc./minusc.
e palavra inteira.
"""

from __future__ import annotations

from PyQt6.Qsci import QsciScintilla
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QKeySequence, QShortcut

from .bgscan import SlicedJob
from PyQt6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QToolButton,
    QWidget,
)

# Backstop absoluto: nenhuma operacao de "Substituir tudo" pode iterar mais que
# isto. Defende contra qualquer loop inesperado congelar a GUI permanentemente.
_REPLACE_CAP = 500_000
# Ate este tamanho (bytes do documento), "Substituir tudo" roda de uma vez e devolve a contagem.
# Acima, roda FATIADO (bgscan.SlicedJob): a janela segue respondendo, com progresso e Cancelar.
_REPLACE_SYNC_LIMIT = 256_000
_FIND_STEP = 2_000             # ocorrencias achadas entre um ponto de progresso e o proximo
_REPLACE_BUDGET_MS = 30        # trabalho por volta do loop de eventos antes de devolver a janela


class FindBar(QWidget):
    def __init__(self, get_editor, parent=None):
        super().__init__(parent)
        self._get_editor = get_editor
        self._active = False          # ha uma busca em andamento (usar findNext)
        self._expr = None
        self._forward = True
        self._replace_job: SlicedJob | None = None
        self._replace_editor = None       # a aba em que o Substituir tudo fatiado esta rodando
        self._replace_count = 0

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
        self.btn_cancel = QToolButton(); self.btn_cancel.setText("Cancelar")
        self.btn_cancel.setToolTip("Para o Substituir tudo (o que ja foi feito sai com um Ctrl+Z)")
        self.btn_cancel.hide()
        btn_close = QToolButton(); btn_close.setText("✕"); btn_close.setToolTip("Fechar (Esc)")

        for w in (self.find_edit, btn_prev, btn_next, self.replace_edit, self.btn_rep,
                  self.btn_repall, self.cb_case, self.cb_word, self.cb_regex, self.status,
                  self.btn_cancel):
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
        self.btn_cancel.clicked.connect(self.cancel_replace)
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
            if "\n" not in sel and " " not in sel and sel:
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

    def replace_all(self) -> int | None:
        """Substitui todas as ocorrencias. Documento ate _REPLACE_SYNC_LIMIT: de uma vez, e
        devolve a contagem. Maior: FATIADO, com progresso e Cancelar — devolve None (a contagem
        sai no status ao terminar). Em ambos, um Ctrl+Z desfaz tudo e a Sentinela varre UMA vez,
        no fim (antes, com a Redacao ligada, varria o documento inteiro a CADA substituicao)."""
        ed = self._get_editor()
        expr = self.find_edit.text()
        if ed is None or ed.isReadOnly() or not expr or self._replace_job is not None:
            return 0
        re_, cs, wo = self._opts()
        job = SlicedJob(self._replace_steps(ed, expr, re_, cs, wo, self.replace_edit.text()), self,
                        budget_ms=_REPLACE_BUDGET_MS)
        if ed.length() <= _REPLACE_SYNC_LIMIT:
            count = job.run_to_end() or 0
            self._active = False
            self.status.setText(f"{count} substituida(s)")
            return count
        self._replace_job = job
        self._replace_editor = ed
        ed.setEnabled(False)               # nada de digitar no meio das substituicoes
        for w in (self.btn_rep, self.btn_repall):
            w.setEnabled(False)
        self.btn_cancel.show()
        self.status.setText("Substituindo… 0%")
        job.progress.connect(lambda pct: self.status.setText(f"Substituindo… {pct}%"))
        job.finished.connect(lambda count, e=ed: self._replace_finished(e, count))
        job.start()
        return None

    def cancel_replace(self) -> None:
        job = self._replace_job
        if job is None:
            return
        job.cancel()                       # o finally do gerador fecha o desfazer e varre
        self._replace_done_ui(self._replace_editor)
        self.status.setText(f"Cancelado: {self._replace_count} substituida(s) — Ctrl+Z desfaz")

    def _replace_finished(self, ed, count) -> None:
        self._replace_done_ui(ed)
        self.status.setText("Falhou: o documento mudou ou foi fechado" if count is None
                            else f"{count} substituida(s)")

    def _replace_done_ui(self, ed) -> None:
        self._replace_job = None
        self._replace_editor = None
        self._active = False
        self.btn_cancel.hide()
        for w in (self.btn_rep, self.btn_repall):
            w.setEnabled(True)
        try:
            if ed is not None:
                ed.setEnabled(True)
        except RuntimeError:               # a aba foi fechada no meio
            pass

    def _replace_steps(self, ed, expr, re_, cs, wo, rep):
        """Escolhe a rota. Rapida: ACHA todas as ocorrencias com o motor do Scintilla (os mesmos
        flags do findFirst: mesma regex, maiusculas e palavra inteira que a busca mostra) e troca
        o documento numa UNICA edicao. Trocar uma a uma custava cada vez mais conforme o documento
        avancava (60 mil trocas passavam de 2 minutos). A rota lenta, troca a troca, fica so para
        regex com `\\` no substituto (`\\1`, `\\t`...), que o Scintilla expande a cada achado."""
        if re_ and "\\" in rep:
            return (yield from self._replace_steps_one_by_one(ed, expr, re_, cs, wo, rep))
        return (yield from self._replace_steps_fast(ed, expr, re_, cs, wo, rep))

    def _replace_steps_fast(self, ed, expr, re_, cs, wo, rep):
        S = QsciScintilla
        flags = ((S.SCFIND_MATCHCASE if cs else 0) | (S.SCFIND_WHOLEWORD if wo else 0)
                 | (S.SCFIND_REGEXP if re_ else 0))
        needle = expr.encode("utf-8")
        self._replace_count = 0
        ed.SendScintilla(S.SCI_SETSEARCHFLAGS, flags)
        end = ed.SendScintilla(S.SCI_GETLENGTH)
        found: list[tuple[int, int]] = []
        pos = 0
        while len(found) < _REPLACE_CAP and pos <= end:
            ed.SendScintilla(S.SCI_SETTARGETSTART, pos)
            ed.SendScintilla(S.SCI_SETTARGETEND, end)
            if ed.SendScintilla(S.SCI_SEARCHINTARGET, len(needle), needle) < 0:
                break
            ts = ed.SendScintilla(S.SCI_GETTARGETSTART)
            te = ed.SendScintilla(S.SCI_GETTARGETEND)
            if ts == te:
                # Largura ZERO ("a*", "^"): nada a substituir — pula 1 caractere (como antes);
                # se nem isso avancar, para (era o loop que travava a GUI pra sempre).
                nxt = ed.SendScintilla(S.SCI_POSITIONAFTER, te)
                if nxt <= pos:
                    break
                pos = nxt
                continue
            found.append((ts, te))
            pos = te
            if len(found) % _FIND_STEP == 0:
                yield pos / max(1, end)        # cancelar AQUI nao deixa nada pela metade
        if not found:
            return 0
        doc = bytes(ed.bytes(0, end))[:end]     # bytes() devolve um NUL a mais no fim
        repb = rep.encode("utf-8")
        parts, last = [], 0
        for ts, te in found:
            parts += (doc[last:ts], repb)
            last = te
        parts.append(doc[last:])
        new = b"".join(parts)
        first = ed.firstVisibleLine()
        line, _idx = ed.getCursorPosition()
        bulk = getattr(ed, "begin_bulk_edit", None)
        if bulk is not None:
            bulk()
        ed.beginUndoAction()
        try:
            ed.SendScintilla(S.SCI_SETTARGETSTART, 0)
            ed.SendScintilla(S.SCI_SETTARGETEND, end)
            ed.SendScintilla(S.SCI_REPLACETARGET, len(new), new)
        finally:
            ed.endUndoAction()                 # um Ctrl+Z desfaz tudo
            done = getattr(ed, "end_bulk_edit", None)
            if done is not None:
                done()                         # uma varredura, com tudo ja substituido
        ed.setCursorPosition(min(line, max(0, ed.lines() - 1)), 0)
        ed.setFirstVisibleLine(first)
        self._replace_count = len(found)
        return len(found)

    def _replace_steps_one_by_one(self, ed, expr, re_, cs, wo, rep):
        """O laco de sempre (primitivas do QScintilla), como gerador: um ponto por substituicao."""
        count = 0
        self._replace_count = 0
        bulk = getattr(ed, "begin_bulk_edit", None)
        if bulk is not None:
            bulk()
        ed.beginUndoAction()
        try:
            found = ed.findFirst(expr, re_, cs, wo, False, True, 0, 0)   # do inicio, sem wrap
            last_zero = -1
            while found and count < _REPLACE_CAP:
                if not ed.hasSelectedText():
                    # Match de LARGURA ZERO (regex como "a*", "^", "\\b"): nao ha
                    # texto a substituir e o cursor nao avança sozinho -> o loop
                    # original travava a GUI pra sempre. Pulamos 1 posicao e
                    # seguimos; se nem o salto avançar, abortamos.
                    line, idx = ed.getCursorPosition()
                    pos = ed.positionFromLineIndex(line, idx)
                    if pos == last_zero or pos >= ed.length():
                        break
                    last_zero = pos
                    nl, ni = ed.lineIndexFromPosition(pos + 1)
                    found = ed.findFirst(expr, re_, cs, wo, False, True, nl, ni)
                    continue
                ed.replace(rep)
                count += 1
                self._replace_count = count
                found = ed.findNext()
                line, idx = ed.getCursorPosition()
                yield ed.positionFromLineIndex(line, idx) / max(1, ed.length())
        finally:
            ed.endUndoAction()
            end = getattr(ed, "end_bulk_edit", None)
            if end is not None:
                end()                      # uma varredura, com tudo ja substituido
        return count
