"""Trabalho pesado FATIADO na thread da interface — sem threads.

Uma thread nao resolveria: o `re` do Python nao solta o GIL durante uma busca em C, entao a
interface congelaria do mesmo jeito. Aqui o trabalho e um gerador que faz um pedaco por passo
(ex.: uma janela da varredura) e devolve o progresso (0.0 a 1.0); o `SlicedJob` roda passos ate
gastar ~`budget_ms` e devolve o controle ao loop de eventos, que redesenha a janela, atende o
mouse e o teclado, e chama o proximo lote. O resultado e o `return` do gerador.

Sem concorrencia: os dados so sao tocados na thread da interface, entre eventos.
"""

from __future__ import annotations

import time
from collections.abc import Generator
from typing import Any

from PyQt6.QtCore import QObject, QTimer, pyqtSignal


class SlicedJob(QObject):
    """Roda um gerador em fatias. Sinais: `progress(int 0..100)` e `finished(object)` — o
    resultado do gerador, ou None se ele levantou (quem usa trata como falha: fail-safe)."""

    progress = pyqtSignal(int)
    finished = pyqtSignal(object)

    def __init__(self, gen: Generator[float, None, Any], parent: QObject | None = None, *,
                 budget_ms: int = 30):
        super().__init__(parent)
        self._gen = gen
        self._budget = budget_ms / 1000
        self._timer = QTimer(self)               # filho: some junto se o dono for destruido
        self._timer.setSingleShot(True)
        self._timer.setInterval(0)
        self._timer.timeout.connect(self._tick)
        self.done = False
        self.cancelled = False
        self.failed = False
        self.result: Any = None
        self._last_pct = -1

    def start(self) -> None:
        if not (self.done or self.cancelled):
            self._timer.start()

    def cancel(self) -> None:
        """Para no ponto em que esta (o proximo lote nao roda) e descarta o resultado."""
        if self.done or self.cancelled:
            return
        self.cancelled = True
        self._timer.stop()
        self._gen.close()

    def run_to_end(self) -> Any:
        """Termina AGORA, sem fatiar (para quem precisa do resultado ja, e para os testes)."""
        self._timer.stop()
        while not (self.done or self.cancelled):
            self._advance()
        return self.result

    def _tick(self) -> None:
        deadline = time.perf_counter() + self._budget
        while not (self.done or self.cancelled):
            self._advance()
            if time.perf_counter() >= deadline:
                break
        if not (self.done or self.cancelled):
            self._timer.start()                  # devolve o controle ao loop; volta ja

    def _advance(self) -> None:
        try:
            frac = next(self._gen)
        except StopIteration as stop:
            self._finish(stop.value)
            return
        except Exception:                        # slot Qt: uma falha nunca derruba o app
            self.failed = True
            self._finish(None)
            return
        pct = max(0, min(99, int(frac * 100)))
        if pct != self._last_pct:
            self._last_pct = pct
            self.progress.emit(pct)

    def _finish(self, result: Any) -> None:
        self.done = True
        self.result = result
        self.progress.emit(100)
        self.finished.emit(result)
