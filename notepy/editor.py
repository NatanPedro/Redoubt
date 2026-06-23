"""O widget de edicao: QsciScintilla com a identidade Redoubt.

Alem de editar, o CodeEditor VIGIA o conteudo: a Sentinela de Segredos varre o
texto a cada alteracao, marca credenciais com um indicador vermelho e permite
"redigir" (tarjar) os trechos para compartilhamento de tela. Tambem calcula o
hash de cadeia de custodia do conteudo.
"""

from __future__ import annotations

import hashlib

from PyQt6.Qsci import QsciScintilla
from PyQt6.QtCore import QEvent, QTimer, pyqtSignal
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFontMetrics
from PyQt6.QtWidgets import QApplication

from . import config
from . import redaction
from . import secrets as secrets_mod
from . import theme
from . import vault
from .lexers import lexer_for_path, make_lexer_for_label

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

# Letras de Ctrl+Shift+<letra> que o app reserva como QAction de janela. O editor
# NAO deve reivindica-las (nem no keymap, nem via ShortcutOverride), senao a acao
# (Selar/Destravar/...) nunca dispara pelo teclado.
_RESERVED_CTRLSHIFT = frozenset(ord(c) for c in "RESLKUBHGFPD")


def read_text(path: str) -> tuple[str, str]:
    """Le o arquivo detectando o encoding. Retorna (texto, codec usado).

    So rotula como 'UTF-8 BOM' se o arquivo REALMENTE comecar com o BOM — antes
    tentava utf-8-sig primeiro e marcava todo UTF-8 como BOM (e adicionaria um
    BOM ao salvar).
    """
    with open(path, "rb") as fh:
        raw = fh.read()

    def _finish(text: str, enc: str) -> tuple[str, str]:
        # O Scintilla usa SCI_SETTEXT (terminado em NUL): um \x00 embutido TRUNCA
        # o conteudo no carregamento -> tudo apos o NUL some e o selo mostraria
        # "LIMPO" para um arquivo que pode conter credencial depois do \x00.
        # Trocamos por um simbolo visivel (␀) para nada ser truncado e a Sentinela
        # varrer o arquivo inteiro. (Sinaliza binario; nao e p/ editar binario aqui.)
        if "\x00" in text:
            text = text.replace("\x00", "␀")
        return text, enc

    if raw.startswith(b"\xef\xbb\xbf"):
        return _finish(raw.decode("utf-8-sig"), "utf-8-sig")
    # UTF-32 ANTES de UTF-16: o BOM UTF-32 LE (FF FE 00 00) comeca com o BOM UTF-16 LE.
    if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return _finish(raw.decode("utf-32"), "utf-32")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return _finish(raw.decode("utf-16"), "utf-16")
    for enc in _ENCODINGS:
        try:
            return _finish(raw.decode(enc), enc)
        except UnicodeDecodeError:
            continue
    return _finish(raw.decode("latin-1", errors="replace"), "latin-1")


def detect_eol(text: str) -> "QsciScintilla.EolMode":
    """Descobre o tipo de quebra de linha predominante no texto."""
    if "\r\n" in text:
        return QsciScintilla.EolMode.EolWindows
    if "\n" in text:
        return QsciScintilla.EolMode.EolUnix
    if "\r" in text:
        return QsciScintilla.EolMode.EolMac
    return QsciScintilla.EolMode.EolWindows


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
        # Menu Linguagem: None = auto pela extensao; senao um rotulo de lexers.LANGUAGE_GROUPS
        # (inclui "Texto puro"). Sobrepoe a auto-deteccao e sobrevive a salvar/recarregar.
        self._lang_override: str | None = None

        # Estado de seguranca.
        self._secret_matches: list[secrets_mod.Match] = []
        self._secret_byte_spans: list[tuple[int, int, str]] = []
        self._redaction_on: bool = False
        self._saved_hash: str | None = None
        self._scan_skipped: bool = False   # True se o arquivo e grande demais p/ varrer

        # Estado de cofre (.rdbt cifrado — envelope RDBT2 com key-slots).
        self.is_vault: bool = False
        self._vault_password: str | None = None   # legado/compat (senha unica)
        self._vault_key: bytes | None = None       # chave-de-conteudo (CK) enquanto destravado
        self._vault_slots: list[bytes] = []        # destravadores (senhas/keyfiles) crus
        self._locked: bool = False                 # travado por inatividade
        self._locked_blob: bytes | None = None     # conteudo cifrado em memoria enquanto travado
        self._locked_was_modified: bool = False

        # Burn note: aba efemera que so vive na RAM e se autodestroi.
        self.is_burn: bool = False

        # "Oculto" (gated): arquivo EM CLARO que contem credencial, restaurado com
        # o conteudo escondido ate o usuario revelar. PRIVACIDADE (anti screen-share),
        # NAO cifragem — o texto real fica so em RAM (_gated_text), nunca exibido.
        self._gated: bool = False
        self._gated_text: str | None = None
        self._gated_count: int = 0

        self._setup_appearance()
        self._setup_indicators()
        self._free_app_shortcuts()
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
        font = config.editor_font()
        self.setFont(font)
        self.setUtf8(True)

        fm = QFontMetrics(font)
        self.setMarginType(0, QsciScintilla.MarginType.NumberMargin)
        self.setMarginLineNumbers(0, True)
        self.setMarginWidth(0, fm.horizontalAdvance("0000") + 10)
        self.setMarginsFont(font)

        self.setFolding(QsciScintilla.FoldStyle.BoxedTreeFoldStyle)
        self.setCaretLineVisible(True)

        tw = config.get("tab_width")
        self.setAutoIndent(True)
        self.setIndentationsUseTabs(False)
        self.setIndentationWidth(tw)
        self.setTabWidth(tw)
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

    def _free_app_shortcuts(self) -> None:
        """Libera, no keymap interno do QScintilla, as combinacoes Ctrl+Shift+<letra>
        que o Redoubt reserva para acoes da janela. Sem isto, com o editor focado o
        Scintilla SEQUESTRA a tecla (ex.: Ctrl+Shift+L = apagar linha; Ctrl+Shift+U =
        MAIUSCULAS) e a QAction (Selar / Destravar / ...) nunca dispara."""
        SHIFT, CTRL = 1, 2
        mod = (CTRL | SHIFT) << 16
        # Todos os Ctrl+Shift+<letra> que viram QAction no app (selar/travar/destravar/
        # redacao/relatorio/salvar-como/burn/custodia/assinar/busca/paleta/diff).
        for ch in "RESLKUBHGFPD":
            self.SendScintilla(QsciScintilla.SCI_CLEARCMDKEY, ord(ch) | mod)

    def event(self, ev):
        # Limpar o keymap (acima) impede o Scintilla de EXECUTAR a tecla, mas ele ainda
        # a REIVINDICA via ShortcutOverride — e a QAction da janela nao dispara ("nao faz
        # nada"). Aqui recusamos o override das teclas reservadas, deixando o atalho da
        # janela (Selar/Destravar/...) disparar normalmente.
        if ev.type() == QEvent.Type.ShortcutOverride:
            m = ev.modifiers()
            Mod = Qt.KeyboardModifier
            if (m & Mod.ControlModifier and m & Mod.ShiftModifier
                    and not (m & (Mod.AltModifier | Mod.MetaModifier))
                    and ev.key() in _RESERVED_CTRLSHIFT):
                ev.ignore()
                return False
        return super().event(ev)

    # ------------------------------------------------------------------ #
    # Linguagem / tema
    # ------------------------------------------------------------------ #
    def apply_lexer_for_path(self, path: str | None) -> None:
        if self._lang_override is None:                  # auto pela extensao
            lexer = lexer_for_path(path, self.font(), self)
            name = lexer.language() if lexer is not None else "Texto"
        else:                                            # forcado pelo menu Linguagem
            lexer = make_lexer_for_label(self._lang_override, self.font(), self)
            name = self._lang_override
        self._install_lexer(lexer, name)

    def _install_lexer(self, lexer, name: str) -> None:
        self.setLexer(lexer)
        theme.retheme_lexer(lexer)
        if lexer is not None:
            lexer.setFont(self.font())       # forca monospace em TODOS os estilos
        theme.apply_editor_theme(self)       # setLexer reseta margens/caret
        self.setMarginsFont(self.font())
        self.language_name = name

    def set_language(self, label: str | None) -> None:
        """Forca o lexer manualmente (menu Linguagem). label=None volta para auto pela
        extensao; senao um rotulo de lexers.LANGUAGE_GROUPS (inclui 'Texto puro')."""
        self._lang_override = label
        self.apply_lexer_for_path(self.path)

    def apply_prefs(self) -> None:
        """Re-aplica fonte e largura de tab das preferencias (em tempo real)."""
        font = config.editor_font()
        self.setFont(font)
        fm = QFontMetrics(font)
        self.setMarginWidth(0, fm.horizontalAdvance("0000") + 10)
        tw = config.get("tab_width")
        self.setIndentationWidth(tw)
        self.setTabWidth(tw)
        lexer = self.lexer()
        if lexer is not None:
            lexer.setFont(font)
        theme.apply_editor_theme(self)
        self.setMarginsFont(font)

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
        if self.is_vault or self._gated:
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
        matches = secrets_mod.scan(text)
        # Lista de redacao: segredos LITERAIS que o usuario registrou (cifrados; destravados na
        # sessao) entram como matches. snippet = o proprio trecho -> tarja, mapa de exposicao e
        # mascaramento de clipboard cobrem tambem o que voce cadastrou.
        for s, e in redaction.find_in(text):
            matches.append(secrets_mod.Match(s, e, "segredo registrado", text[s:e]))
        matches.sort(key=lambda m: (m.start, m.end))
        self._secret_matches = matches
        # Offsets de caractere -> byte (as posicoes do Scintilla sao em bytes) numa UNICA passada
        # O(n+m): matches ordenados por start + cursor cumulativo, em vez de re-codificar text[:start]
        # a cada match (era O(n*m) -> congelava a GUI com muitos matches da lista de redacao).
        # 'surrogatepass' evita crash com surrogates solitarios (colaveis do clipboard).
        spans: list[tuple[int, int, str]] = []
        char_pos = byte_pos = 0
        for m in self._secret_matches:
            if m.start > char_pos:
                byte_pos += len(text[char_pos:m.start].encode("utf-8", "surrogatepass"))
                char_pos = m.start
            blen = len(text[m.start:m.end].encode("utf-8", "surrogatepass"))
            spans.append((byte_pos, blen, m.kind))
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

    def rescan_secrets(self) -> None:
        """Re-varre o conteudo agora (ex.: depois que a Lista de redacao mudou/destravou)."""
        self._rescan_secrets()

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
    def custody_text(self) -> str:
        """Conteudo REAL para custodia/assinatura. Quando OCULTO, devolve o texto
        em RAM (_gated_text), nao o banner exibido."""
        return self._gated_text if (self._gated and self._gated_text is not None) else self.text()

    def content_hash(self) -> str:
        # surrogatepass: nunca crashar a custodia por causa de surrogate solitario.
        return hashlib.sha256(self.custody_text().encode("utf-8", "surrogatepass")).hexdigest()

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
        """Trava o cofre: re-cifra em memoria PRESERVANDO os destravadores, esconde o
        texto e ESQUECE a chave (zero-knowledge)."""
        if not self.is_vault or self._locked:
            return False
        if self._vault_key is None and not self._vault_password:
            return False
        try:
            if self._vault_key is not None:
                # preserva TODOS os slots (varias senhas/keyfiles) ao re-selar
                self._locked_blob = vault.reseal(self.text(), self._vault_key, self._vault_slots)
            else:
                self._locked_blob = vault.encrypt(self.text(), self._vault_password)
        except Exception:
            return False
        self._locked_was_modified = self.isModified()
        self._vault_password = None         # esquece tudo ate destravar (zero-knowledge)
        self._vault_key = None
        self._vault_slots = []
        self._locked = True
        self.setReadOnly(False)
        self.setText("🔒 Cofre travado por inatividade.\n\n"
                     "Seguranca ▸ Destravar cofre (Ctrl+Shift+U) e informe a senha-mestra.")
        # Esvazia o undo: sem isso o Ctrl+Z reconstroi o texto-claro anterior ao
        # travamento (versoes que o usuario achava removidas ficavam recuperaveis).
        self.SendScintilla(QsciScintilla.SCI_EMPTYUNDOBUFFER)
        self.setReadOnly(True)
        self.setModified(False)
        return True

    # ------------------------------------------------------------------ #
    # "Oculto" (gated): arquivo em claro com credencial, escondido ate revelar
    # ------------------------------------------------------------------ #
    def is_gated(self) -> bool:
        return self._gated

    def gated_count(self) -> int:
        return self._gated_count

    def gate(self, text: str, count: int) -> None:
        """Esconde o conteudo (em claro) de um arquivo ate o usuario revelar. NAO
        cifra: e privacidade (nao joga segredo na tela ao restaurar). O texto real
        fica so em RAM e nunca e exibido.

        count > 0  -> tantas credenciais detectadas.
        count == 0 -> arquivo grande demais p/ varrer: oculto por PRECAUCAO
                      (fail-safe — nunca abrir em claro algo que nao foi verificado)."""
        self._gated = True
        self._gated_text = text
        self._gated_count = count
        if count > 0:
            head = f"🛡️ Este arquivo contem {count} credencial(is) detectada(s)."
        else:
            head = "🛡️ Arquivo grande demais para verificar — oculto por precaucao."
        self.setReadOnly(False)
        self.setText(
            head + "\n\n"
            "O conteudo esta OCULTO (privacidade). Use a barra acima:\n"
            "  • Revelar — mostra o conteudo (continua em texto puro no disco)\n"
            "  • Selar como cofre — cifra de verdade (.rdbt, pede senha-mestra)")
        self.SendScintilla(QsciScintilla.SCI_EMPTYUNDOBUFFER)
        self.setReadOnly(True)
        self.setModified(False)

    def reveal(self) -> str | None:
        """Revela o conteudo oculto e devolve o texto (o chamador re-varre/lexa)."""
        if not self._gated or self._gated_text is None:
            return None
        text = self._gated_text
        self.setReadOnly(False)
        self.setText(text)
        self.SendScintilla(QsciScintilla.SCI_EMPTYUNDOBUFFER)
        self.setModified(False)
        self._gated = False
        self._gated_text = None
        self._gated_count = 0
        return text

    def restore_locked(self, blob: bytes) -> None:
        """Restaura um cofre de sessao em estado TRAVADO, SEM senha (zero-knowledge).

        Reaproveita o `_locked_blob` (os bytes .rdbt cifrados do disco) — o
        `unlock(senha)` decifra normalmente quando o usuario quiser. Nenhuma senha
        e pedida nem guardada ao restaurar.
        """
        self.is_vault = True
        self._locked = True
        self._locked_blob = blob
        self._vault_password = None
        self._vault_key = None
        self._vault_slots = []
        self._locked_was_modified = False
        self.setReadOnly(False)
        self.setText("🔒 Cofre (sessao restaurada).\n\n"
                     "Seguranca ▸ Destravar cofre (Ctrl+Shift+U) e informe a senha-mestra.")
        self.SendScintilla(QsciScintilla.SCI_EMPTYUNDOBUFFER)
        self.setReadOnly(True)
        self.setModified(False)

    def unlock(self, password: str | None = None, keyfile: bytes | None = None) -> bool:
        """Destrava com senha OU arquivo-chave; restaura conteudo + a chave/slots em
        memoria (p/ re-selar preservando destravadores). Pode levantar WrongPassword."""
        if not self._locked or self._locked_blob is None:
            return False
        opened = vault.open_vault(self._locked_blob, password=password, keyfile=keyfile)
        self.setReadOnly(False)
        self.setText(opened.text)
        self.SendScintilla(QsciScintilla.SCI_EMPTYUNDOBUFFER)   # nao deixa desfazer p/ o banner travado
        self.setModified(self._locked_was_modified)
        self._vault_key = opened.key
        self._vault_slots = opened.slots
        self._vault_password = None
        self._locked = False
        self._locked_blob = None
        return True
