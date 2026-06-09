"""O widget de edicao: QsciScintilla com a identidade Redoubt.

Alem de editar, o CodeEditor VIGIA o conteudo: a Sentinela de Segredos varre o
texto a cada alteracao, marca credenciais com um indicador vermelho e permite
"redigir" (tarjar) os trechos para compartilhamento de tela. Tambem calcula o
hash de cadeia de custodia do conteudo.
"""

from __future__ import annotations

import hashlib

from PyQt6.Qsci import QsciScintilla
from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QFontDatabase, QFontMetrics
from PyQt6.QtWidgets import QApplication

from . import secrets as secrets_mod
from . import theme
from . import vault
from .lexers import lexer_for_path

# Ordem de tentativa para decodificar arquivos. utf-8-sig captura o BOM.
_ENCODINGS = ("utf-8", "cp1252", "latin-1")

ENCODING_LABELS = {
    "utf-8-sig": "UTF-8 BOM",
    "utf-8": "UTF-8",
    "cp1252": "Windows-1252",
    "latin-1": "Latin-1",
}

# Ids de indicador do Scintilla (numeros altos p/ nao colidir com lexer/braces).
SECRET_INDICATOR = 8   # sublinhado vermelho sob segredos
REDACT_INDICATOR = 9   # tarja preta solida sobre segredos (modo redacao)
EXPOSURE_MARKER = 0    # marcador na margem (mapa de exposicao: onde ha segredo)

# Acima disso, nao varre a cada tecla (evita travar em arquivos enormes).
_SCAN_LIMIT = 2_000_000


def read_text(path: str) -> tuple[str, str]:
    """Le o arquivo detectando o encoding. Retorna (texto, codec usado).

    So rotula como 'UTF-8 BOM' se o arquivo REALMENTE comecar com o BOM — antes
    tentava utf-8-sig primeiro e marcava todo UTF-8 como BOM (e adicionaria um
    BOM ao salvar).
    """
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig"), "utf-8-sig"
    for enc in _ENCODINGS:
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace"), "latin-1"


def detect_eol(text: str) -> "QsciScintilla.EolMode":
    """Descobre o tipo de quebra de linha predominante no texto."""
    if "\r\n" in text:
        return QsciScintilla.EolMode.EolWindows
    if "\n" in text:
        return QsciScintilla.EolMode.EolUnix
    if "\r" in text:
        return QsciScintilla.EolMode.EolMac
    return QsciScintilla.EolMode.EolWindows


def _monospace_font(size: int = 11) -> QFont:
    """Escolhe a primeira fonte monoespacada REALMENTE instalada.

    'JetBrains Mono' raramente esta instalada e o Qt a substituia por uma fonte
    PROPORCIONAL (Tahoma!), quebrando o alinhamento do codigo e das tarjas de
    redacao. Aqui so escolhemos algo que exista de fato e seja fixed-pitch.
    """
    available = set(QFontDatabase.families())
    for cand in ("JetBrains Mono", "Cascadia Mono", "Cascadia Code",
                 "Consolas", "DejaVu Sans Mono", "Courier New"):
        if cand in available:
            font = QFont(cand, size)
            font.setFixedPitch(True)
            font.setStyleHint(QFont.StyleHint.Monospace)
            return font
    font = QFont("", size)            # ultimo recurso: deixa o Qt achar uma mono
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setFixedPitch(True)
    return font


class CodeEditor(QsciScintilla):
    """Editor de um unico documento (uma aba), com vigilancia de segredos."""

    # Emite o numero de segredos detectados sempre que o texto e revarrido.
    secretsChanged = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)

        # Metadados da aba (preenchidos pela janela principal).
        self.path: str | None = None
        self.encoding: str = "utf-8"
        self.display_name: str = ""
        self.language_name: str = "Texto"

        # Estado de seguranca.
        self._secret_matches: list[secrets_mod.Match] = []
        self._secret_byte_spans: list[tuple[int, int, str]] = []
        self._redaction_on: bool = False
        self._saved_hash: str | None = None
        self._scan_skipped: bool = False   # True se o arquivo e grande demais p/ varrer

        # Estado de cofre (.rdbt cifrado).
        self.is_vault: bool = False
        self._vault_password: str | None = None   # cacheada na sessao (zero-knowledge)
        self._locked: bool = False                 # travado por inatividade
        self._locked_blob: bytes | None = None     # conteudo cifrado em memoria enquanto travado
        self._locked_was_modified: bool = False

        # Burn note: aba efemera que so vive na RAM e se autodestroi.
        self.is_burn: bool = False

        self._setup_appearance()
        self._setup_indicators()
        theme.apply_editor_theme(self)
        self.marginClicked.connect(self._on_margin_clicked)

        # Varredura de segredos com debounce de 300ms.
        self._scan_timer = QTimer(self)
        self._scan_timer.setSingleShot(True)
        self._scan_timer.setInterval(300)
        self._scan_timer.timeout.connect(self._rescan_secrets)
        self.textChanged.connect(self._on_text_changed)

    # ------------------------------------------------------------------ #
    # Aparencia / comportamento
    # ------------------------------------------------------------------ #
    def _setup_appearance(self) -> None:
        font = _monospace_font(11)
        self.setFont(font)
        self.setUtf8(True)

        fm = QFontMetrics(font)
        self.setMarginType(0, QsciScintilla.MarginType.NumberMargin)
        self.setMarginLineNumbers(0, True)
        self.setMarginWidth(0, fm.horizontalAdvance("0000") + 10)
        self.setMarginsFont(font)

        self.setFolding(QsciScintilla.FoldStyle.BoxedTreeFoldStyle)
        self.setCaretLineVisible(True)

        self.setAutoIndent(True)
        self.setIndentationsUseTabs(False)
        self.setIndentationWidth(4)
        self.setTabWidth(4)
        self.setTabIndents(True)
        self.setBackspaceUnindents(True)
        self.setIndentationGuides(True)

        self.setBraceMatching(QsciScintilla.BraceMatch.SloppyBraceMatch)
        self.setWrapMode(QsciScintilla.WrapMode.WrapNone)
        self.setEolMode(QsciScintilla.EolMode.EolWindows)

    def _setup_indicators(self) -> None:
        # Segredo: sublinhado/caixa vermelha, desenhada SOB o texto.
        self.indicatorDefine(QsciScintilla.IndicatorStyle.SquiggleIndicator,
                             SECRET_INDICATOR)
        self.setIndicatorForegroundColor(QColor(theme.RED), SECRET_INDICATOR)
        # Redacao: caixa preta SOLIDA desenhada SOBRE o texto (tarja).
        self.indicatorDefine(QsciScintilla.IndicatorStyle.FullBoxIndicator,
                             REDACT_INDICATOR)
        self.setIndicatorForegroundColor(QColor("#000000"), REDACT_INDICATOR)
        try:
            self.setIndicatorDrawUnder(True, SECRET_INDICATOR)
            self.setIndicatorDrawUnder(False, REDACT_INDICATOR)
            self.SendScintilla(QsciScintilla.SCI_INDICSETALPHA, REDACT_INDICATOR, 255)
            self.SendScintilla(QsciScintilla.SCI_INDICSETOUTLINEALPHA, REDACT_INDICATOR, 255)
        except Exception:
            pass

        # Mapa de exposicao: marcador vermelho na margem 1 (onde ha segredo).
        self.markerDefine(QsciScintilla.MarkerSymbol.Circle, EXPOSURE_MARKER)
        self.setMarkerForegroundColor(QColor(theme.RED), EXPOSURE_MARKER)
        self.setMarkerBackgroundColor(QColor(theme.RED), EXPOSURE_MARKER)
        self.setMarginType(1, QsciScintilla.MarginType.SymbolMargin)
        self.setMarginWidth(1, 10)
        self.setMarginMarkerMask(1, 0b11111111)   # markers 0-7 aparecem nesta margem
        self.setMarginSensitivity(1, True)         # clicavel (pula pra linha)

    # ------------------------------------------------------------------ #
    # Linguagem / tema
    # ------------------------------------------------------------------ #
    def apply_lexer_for_path(self, path: str | None) -> None:
        lexer = lexer_for_path(path, self.font(), self)
        self.setLexer(lexer)
        theme.retheme_lexer(lexer)
        if lexer is not None:
            lexer.setFont(self.font())       # forca monospace em TODOS os estilos
        theme.apply_editor_theme(self)       # setLexer reseta margens/caret
        self.setMarginsFont(self.font())
        self.language_name = lexer.language() if lexer is not None else "Texto"

    # ------------------------------------------------------------------ #
    # Sentinela de Segredos
    # ------------------------------------------------------------------ #
    def _on_text_changed(self) -> None:
        # Com a Redacao LIGADA (modo screen-share), varremos IMEDIATA e
        # sincronamente: senao um segredo COLADO fica visivel ~300ms (o debounce)
        # antes de ser tarjado — uma janela de exposicao numa transmissao de tela.
        # No modo normal, mantemos o debounce de 300ms (performance ao digitar).
        if self._redaction_on:
            self._rescan_secrets()
        else:
            self._scan_timer.start()

    def _rescan_secrets(self) -> None:
        if self.is_vault:
            # Cofre: o conteudo ja e protegido por cifragem; nao faz sentido
            # marca-lo como "exposto". Limpa qualquer indicador remanescente.
            if self._secret_matches:
                self._secret_matches = []
                self._secret_byte_spans = []
                self._clear_indicator(SECRET_INDICATOR)
                self._clear_indicator(REDACT_INDICATOR)
            self.markerDeleteAll(EXPOSURE_MARKER)
            self.secretsChanged.emit(0)
            return
        text = self.text()
        if len(text) > _SCAN_LIMIT:
            # Grande demais p/ varrer (custo). Mas NAO fingimos "LIMPO": sinalizamos
            # "nao verificado" para o selo nao dar falsa seguranca.
            self._scan_skipped = True
            self._secret_matches = []
            self._secret_byte_spans = []
            self._clear_indicator(SECRET_INDICATOR)
            self._clear_indicator(REDACT_INDICATOR)
            self.markerDeleteAll(EXPOSURE_MARKER)
            self.secretsChanged.emit(0)
            return
        self._scan_skipped = False
        self._secret_matches = secrets_mod.scan(text)
        # Offsets de caractere -> byte (posicoes do Scintilla sao bytes). O
        # 'surrogatepass' evita crash com surrogates solitarios (colaveis do clipboard).
        spans: list[tuple[int, int, str]] = []
        for m in self._secret_matches:
            bstart = len(text[:m.start].encode("utf-8", "surrogatepass"))
            blen = len(text[m.start:m.end].encode("utf-8", "surrogatepass"))
            spans.append((bstart, blen, m.kind))
        self._secret_byte_spans = spans

        self._fill_indicator(SECRET_INDICATOR, spans)
        if self._redaction_on:
            self._fill_indicator(REDACT_INDICATOR, spans)
        self._update_exposure_markers(spans)
        self.secretsChanged.emit(len(self._secret_matches))

    def _update_exposure_markers(self, spans: list[tuple[int, int, str]]) -> None:
        """Mapa de exposicao: 1 marcador na margem por LINHA que contem segredo."""
        self.markerDeleteAll(EXPOSURE_MARKER)
        seen: set[int] = set()
        for bstart, _blen, _kind in spans:
            line = self.lineIndexFromPosition(bstart)[0]
            if line not in seen:
                self.markerAdd(line, EXPOSURE_MARKER)
                seen.add(line)

    def _on_margin_clicked(self, margin: int, line: int, _state) -> None:
        if margin == 1:                 # clicou no mapa de exposicao -> pula pra linha
            self.setCursorPosition(line, 0)
            self.ensureLineVisible(line)

    def _clear_indicator(self, indic: int) -> None:
        self.SendScintilla(QsciScintilla.SCI_SETINDICATORCURRENT, indic)
        self.SendScintilla(QsciScintilla.SCI_INDICATORCLEARRANGE, 0, self.length())

    def _fill_indicator(self, indic: int, spans: list[tuple[int, int, str]]) -> None:
        self._clear_indicator(indic)
        self.SendScintilla(QsciScintilla.SCI_SETINDICATORCURRENT, indic)
        for bstart, blen, _kind in spans:
            self.SendScintilla(QsciScintilla.SCI_INDICATORFILLRANGE, bstart, blen)

    def secret_matches(self) -> list[secrets_mod.Match]:
        return self._secret_matches

    def is_redacted(self) -> bool:
        return self._redaction_on

    def scan_skipped(self) -> bool:
        return self._scan_skipped

    def set_redaction(self, on: bool) -> None:
        self._redaction_on = on
        if on:
            self._fill_indicator(REDACT_INDICATOR, self._secret_byte_spans)
        else:
            self._clear_indicator(REDACT_INDICATOR)

    def goto_next_secret(self) -> bool:
        """Move o cursor para o proximo segredo (com wrap-around)."""
        if not self._secret_byte_spans:
            return False
        cur = self.SendScintilla(QsciScintilla.SCI_GETCURRENTPOS)
        target = next((s for s in self._secret_byte_spans if s[0] > cur), None)
        if target is None:
            target = self._secret_byte_spans[0]
        line, idx = self.lineIndexFromPosition(target[0])
        self.setCursorPosition(line, idx)
        self.ensureLineVisible(line)
        return True

    # ------------------------------------------------------------------ #
    # Cadeia de custodia
    # ------------------------------------------------------------------ #
    def content_hash(self) -> str:
        # surrogatepass: nunca crashar a custodia por causa de surrogate solitario.
        return hashlib.sha256(self.text().encode("utf-8", "surrogatepass")).hexdigest()

    def mark_saved(self) -> None:
        self._saved_hash = self.content_hash()

    @property
    def saved_hash(self) -> str | None:
        return self._saved_hash

    # ------------------------------------------------------------------ #
    # Cofre: travar / destravar (auto-lock)
    # ------------------------------------------------------------------ #
    def is_locked(self) -> bool:
        return self._locked

    def lock(self) -> bool:
        """Trava o cofre: cifra o conteudo em memoria, esconde o texto e ESQUECE a senha."""
        if not self.is_vault or self._locked or not self._vault_password:
            return False
        try:
            self._locked_blob = vault.encrypt(self.text(), self._vault_password)
        except Exception:
            return False
        self._locked_was_modified = self.isModified()
        self._vault_password = None         # esquece a senha ate destravar (zero-knowledge)
        self._locked = True
        self.setReadOnly(False)
        self.setText("🔒 Cofre travado por inatividade.\n\n"
                     "Seguranca ▸ Destravar cofre (Ctrl+Shift+U) e informe a senha-mestra.")
        self.setReadOnly(True)
        self.setModified(False)
        return True

    def unlock(self, password: str) -> bool:
        """Destrava: decifra o blob em memoria e restaura o conteudo. Pode levantar WrongPassword."""
        if not self._locked or self._locked_blob is None:
            return False
        text = vault.decrypt(self._locked_blob, password)   # WrongPassword se a senha falhar
        self.setReadOnly(False)
        self.setText(text)
        self.setModified(self._locked_was_modified)
        self._vault_password = password
        self._locked = False
        self._locked_blob = None
        return True
