"""Janela principal do Redoubt: abas + barra de cadeia de custodia + seguranca."""

from __future__ import annotations

import html
import os

from PyQt6.QtCore import QEvent, Qt, QTimer
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStyle,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import (APP_NAME, APP_TAGLINE, APP_VERSION, config, custody, difftool,
               palette, redaction, seal, searchfiles, secrets as secrets_mod, theme, vault)
from .editor import CodeEditor, ENCODING_LABELS, detect_eol, read_text

# Acima deste tamanho nao varremos um arquivo na restauracao (mesmo limite do editor).
_RESTORE_SCAN_LIMIT = 2_000_000
# Teto de arquivos reabertos por sessao (defesa: "session/paths" vive no registro e
# pode ser adulterado — sem teto, N caminhos poderiam travar/inundar a inicializacao).
_MAX_RESTORE = 50
from .findbar import FindBar
from .preferences import PreferencesDialog

VAULT_FILTER = "Cofre Redoubt (*.rdbt)"


class CommandBar(QLineEdit):
    """Barra de comando ':' — Esc devolve o foco ao editor."""

    def __init__(self, on_escape, parent=None):
        super().__init__(parent)
        self._on_escape = on_escape

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key.Key_Escape:
            self.clear()
            self._on_escape()
            return
        super().keyPressEvent(event)

FILE_FILTER = (
    # "Todos os arquivos" PRIMEIRO (filtro padrao): com ele ativo, digitar
    # qualquer nome+extensao grava como esta. Os grupos seguintes existem para
    # descoberta e para o dialogo nativo auto-completar a extensao (ex.: escolher
    # "PowerShell" e digitar "deploy" grava "deploy.ps1").
    "Todos os arquivos (*.*)"
    ";;Texto (*.txt *.text *.log)"
    ";;Python (*.py *.pyw *.pyi)"
    ";;PowerShell (*.ps1 *.psm1 *.psd1)"
    ";;Shell / Batch (*.sh *.bash *.zsh *.bat *.cmd)"
    ";;Web (*.html *.htm *.css *.scss *.js *.mjs *.ts *.jsx *.tsx *.vue)"
    ";;C / C++ / C# / Java (*.c *.h *.cpp *.hpp *.cc *.cs *.java)"
    ";;Outros scripts (*.rb *.pl *.lua *.tcl)"
    ";;Dados / Config (*.json *.xml *.yaml *.yml *.toml *.ini *.cfg *.conf *.env)"
    ";;SQL (*.sql)"
    ";;Markdown / Docs (*.md *.markdown *.tex)"
)


class SearchDialog(QDialog):
    """Busca em arquivos (grep numa pasta) com resultados clicaveis."""

    def __init__(self, on_open, start_dir: str = "", parent=None):
        super().__init__(parent)
        self._on_open = on_open
        self.setWindowTitle("Buscar em arquivos — Redoubt")
        self.resize(720, 480)
        lay = QVBoxLayout(self)

        row = QHBoxLayout()
        self.q = QLineEdit(); self.q.setPlaceholderText("Texto ou expressao regular…")
        self.cb_case = QCheckBox("Aa"); self.cb_case.setToolTip("Diferenciar maiusculas/minusculas")
        self.cb_regex = QCheckBox(".*"); self.cb_regex.setToolTip("Expressao regular")
        btn = QPushButton("Buscar")
        row.addWidget(self.q, 1); row.addWidget(self.cb_case)
        row.addWidget(self.cb_regex); row.addWidget(btn)
        lay.addLayout(row)

        row2 = QHBoxLayout()
        self.folder = QLineEdit(start_dir); self.folder.setPlaceholderText("Pasta a varrer…")
        browse = QPushButton("Pasta…")
        row2.addWidget(QLabel("Em:")); row2.addWidget(self.folder, 1); row2.addWidget(browse)
        lay.addLayout(row2)

        self.tree = QTreeWidget(); self.tree.setHeaderHidden(True)
        lay.addWidget(self.tree, 1)
        self.status = QLabel(""); lay.addWidget(self.status)

        btn.clicked.connect(self.run_search)
        self.q.returnPressed.connect(self.run_search)
        browse.clicked.connect(self._browse)
        self.tree.itemActivated.connect(self._activate)

    def _browse(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Escolher pasta", self.folder.text())
        if d:
            self.folder.setText(d)

    def run_search(self) -> int:
        root, query = self.folder.text().strip(), self.q.text()
        self.tree.clear()
        if not (root and os.path.isdir(root) and query):
            self.status.setText("Informe uma pasta valida e um texto.")
            return 0
        hits = searchfiles.search_in_dir(root, query,
                                         regex=self.cb_regex.isChecked(), case=self.cb_case.isChecked())
        by_file: dict[str, list] = {}
        for h in hits:
            by_file.setdefault(h.path, []).append(h)
        for path, hs in by_file.items():
            top = QTreeWidgetItem([f"{os.path.relpath(path, root)}  ({len(hs)})"])
            for h in hs:
                child = QTreeWidgetItem([f"  {h.line}: {h.text}"])
                child.setData(0, Qt.ItemDataRole.UserRole, (h.path, h.line))
                top.addChild(child)
            self.tree.addTopLevelItem(top)
        self.tree.expandAll()
        self.status.setText(f"{len(hits)} resultado(s) em {len(by_file)} arquivo(s)"
                            + ("  (limite atingido)" if len(hits) >= 2000 else ""))
        return len(hits)

    def _activate(self, item, _col=0) -> None:
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if data:
            self._on_open(*data)


class CommandPalette(QDialog):
    """Paleta de comandos (Ctrl+Shift+P): acha e executa qualquer comando por nome.

    `commands` = lista de (label, atalho, callable) — cobre tanto QActions de menu
    quanto comandos que so existem como botao/preferencia (tema, revelar oculto...)."""

    def __init__(self, commands, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Paleta de comandos")
        self.resize(560, 420)
        self._items = list(commands)                 # (label, atalho, callable)
        self._labels = [lbl for lbl, _sc, _fn in self._items]
        lay = QVBoxLayout(self)
        self.edit = QLineEdit(); self.edit.setPlaceholderText("Digite um comando…")
        self.list = QListWidget()
        lay.addWidget(self.edit)
        lay.addWidget(self.list, 1)
        self.edit.textChanged.connect(self._refilter)
        self.edit.returnPressed.connect(self._run_current)
        self.list.itemActivated.connect(lambda *_: self._run_current())
        self.edit.installEventFilter(self)      # setas navegam a lista
        self._refilter("")
        self.edit.setFocus()

    def eventFilter(self, obj, ev):
        if obj is self.edit and ev.type() == QEvent.Type.KeyPress and self.list.count():
            k = ev.key()
            if k in (Qt.Key.Key_Down, Qt.Key.Key_Up):
                row = self.list.currentRow() + (1 if k == Qt.Key.Key_Down else -1)
                self.list.setCurrentRow(max(0, min(self.list.count() - 1, row)))
                return True
        return super().eventFilter(obj, ev)

    def _refilter(self, text: str) -> None:
        self.list.clear()
        order = palette.rank(text, self._labels) if text else list(range(len(self._labels)))
        for i in order:
            lbl, sc, fn = self._items[i]
            item = QListWidgetItem(f"{lbl}    {sc}" if sc else lbl)
            item.setData(Qt.ItemDataRole.UserRole, fn)
            self.list.addItem(item)
        if self.list.count():
            self.list.setCurrentRow(0)

    def _run_current(self) -> None:
        item = self.list.currentItem()
        if item is None:
            return
        fn = item.data(Qt.ItemDataRole.UserRole)
        self.accept()
        if callable(fn):
            fn()


class DiffDialog(QDialog):
    """Compara dois arquivos (unified diff, estilo git, com verde/vermelho)."""

    def __init__(self, default_a: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Comparar arquivos — Redoubt")
        self.resize(820, 560)
        lay = QVBoxLayout(self)
        self.a = QLineEdit(default_a); self.a.setPlaceholderText("Arquivo A (original)…")
        self.b = QLineEdit(); self.b.setPlaceholderText("Arquivo B (modificado)…")
        ba = QPushButton("A…"); bb = QPushButton("B…")
        btn = QPushButton("Comparar")
        r1 = QHBoxLayout(); r1.addWidget(QLabel("A:")); r1.addWidget(self.a, 1); r1.addWidget(ba)
        r2 = QHBoxLayout(); r2.addWidget(QLabel("B:")); r2.addWidget(self.b, 1); r2.addWidget(bb)
        r2.addWidget(btn)
        lay.addLayout(r1); lay.addLayout(r2)
        self.view = QTextEdit(); self.view.setReadOnly(True)
        self.view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        lay.addWidget(self.view, 1)
        self.status = QLabel(""); lay.addWidget(self.status)
        ba.clicked.connect(lambda: self._pick(self.a))
        bb.clicked.connect(lambda: self._pick(self.b))
        btn.clicked.connect(self.compare)

    def _pick(self, field: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Escolher arquivo", field.text())
        if path:
            field.setText(path)

    def compare(self) -> int:
        ta = difftool.read_file(self.a.text().strip())
        tb = difftool.read_file(self.b.text().strip())
        if ta is None or tb is None:
            self.view.clear()
            self.status.setText("Nao foi possivel ler um dos arquivos (inexistente ou binario).")
            return -1
        diff = difftool.unified(ta, tb, os.path.basename(self.a.text()) or "A",
                                os.path.basename(self.b.text()) or "B")
        colors = {"add": theme.GREEN, "del": theme.RED, "hunk": theme.AMBER,
                  "hdr": theme.DIM, "ctx": theme.TEXT}
        rows = "\n".join(
            f'<span style="color:{colors[k]}">{html.escape(ln) or "&nbsp;"}</span>'
            for k, ln in diff)
        self.view.setHtml(f'<pre style="font-family:Consolas,monospace;font-size:12px">{rows}</pre>')
        adds, dels = difftool.stats(diff)
        self.status.setText("Arquivos identicos." if not diff
                            else f"+{adds} / -{dels} linha(s).")
        return len(diff)


class RedactionListDialog(QDialog):
    """Gerenciador da Lista de redacao. NUNCA mostra o segredo em claro — so indice +
    tamanho. Adicionar pede o valor com echo mascarado; cada mudanca re-cifra (reseal,
    sem re-derivar o KDF -> rapido). Pressupoe a lista JA destravada."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{APP_NAME} — Lista de redação")
        self.resize(440, 340)
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Segredos LITERAIS que o Modo Redação sempre tarja "
                             "(guardados cifrados; nunca exibidos aqui):"))
        self.listw = QListWidget(self)
        lay.addWidget(self.listw)
        row = QHBoxLayout()
        b_add = QPushButton("Adicionar…", self)
        b_rem = QPushButton("Remover", self)
        b_lock = QPushButton("Bloquear", self)
        b_close = QPushButton("Fechar", self)
        for b in (b_add, b_rem, b_lock, b_close):
            row.addWidget(b)
        lay.addLayout(row)
        b_add.clicked.connect(self._add)
        b_rem.clicked.connect(self._remove)
        b_lock.clicked.connect(self._lock)
        b_close.clicked.connect(self.accept)
        self._refresh()

    def _refresh(self) -> None:
        self.listw.clear()
        for i, s in enumerate(redaction.entries(), 1):
            self.listw.addItem(f"Segredo #{i} — {len(s)} caractere(s)")

    def _persist(self) -> bool:
        try:
            redaction.save()
            return True
        except Exception as exc:
            QMessageBox.critical(self, APP_NAME, f"Não foi possível salvar a lista:\n{exc}")
            return False

    def _ensure_unlocked(self) -> bool:
        if redaction.is_unlocked():
            return True
        QMessageBox.information(self, APP_NAME,
                               "A lista foi bloqueada (inatividade). Reabra para gerenciar.")
        self.reject()
        return False

    def _add(self) -> None:
        if not self._ensure_unlocked():
            return
        val, ok = QInputDialog.getText(self, "Adicionar segredo",
                                       "Valor literal a tarjar (senha/credencial, mín. 4 caracteres):",
                                       QLineEdit.EchoMode.Password)
        if not ok or not val:
            return
        try:
            added = redaction.add(val)
        except vault.VaultError:
            self.reject()
            return
        if not added:
            QMessageBox.information(self, APP_NAME,
                                    "Não adicionado: curto demais (mín. 4), duplicado, longo demais ou lista cheia.")
            return
        if self._persist():
            self._refresh()

    def _remove(self) -> None:
        if not self._ensure_unlocked():
            return
        i = self.listw.currentRow()
        ents = redaction.entries()
        if not (0 <= i < len(ents)):
            return
        try:
            redaction.remove(ents[i])
        except vault.VaultError:
            self.reject()
            return
        if self._persist():
            self._refresh()

    def _lock(self) -> None:
        redaction.lock()
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1024, 720)
        self.setAcceptDrops(True)

        self._untitled_counter = 0
        self._search_dialog: SearchDialog | None = None

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self._on_tab_changed)

        # Barra ':' onipresente no rodape (comandos de seguranca/arquivo).
        self.cmd_bar = CommandBar(self._focus_current_editor)
        self.cmd_bar.setPlaceholderText(
            ":  comando  —  seal · burn · redact · hash · goto N · w · q · open <arquivo>"
            "   (Ctrl+P foca aqui, Esc volta ao editor)")
        self.cmd_bar.returnPressed.connect(self._run_command)

        # Barra de Localizar/Substituir (Ctrl+F / Ctrl+H), oculta por padrao.
        self.find_bar = FindBar(self.current_editor)

        # Barra de "conteudo oculto" (arquivo restaurado com credencial): so aparece
        # quando a aba atual esta gated. Oferece Revelar / Selar como cofre.
        self.gate_bar = QWidget()
        gb = QHBoxLayout(self.gate_bar)
        gb.setContentsMargins(8, 4, 8, 4)
        gb.setSpacing(8)
        self.gate_label = QLabel("")
        self.gate_label.setStyleSheet(f"color:{theme.AMBER}; font-weight:600;")
        btn_reveal = QPushButton("Revelar")
        btn_reveal.setToolTip("Mostra o conteudo (continua em texto puro no disco)")
        btn_reveal.clicked.connect(self.reveal_current)
        btn_seal = QPushButton("Selar como cofre")
        btn_seal.setToolTip("Cifra de verdade (.rdbt, AES-256-GCM, pede senha-mestra)")
        btn_seal.clicked.connect(self._gate_seal)
        gb.addWidget(self.gate_label)
        gb.addStretch(1)
        gb.addWidget(btn_reveal)
        gb.addWidget(btn_seal)
        self.gate_bar.hide()

        container = QWidget()
        lay = QVBoxLayout(container)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        lay.addWidget(self.find_bar)
        lay.addWidget(self.gate_bar)
        lay.addWidget(self.tabs)
        lay.addWidget(self.cmd_bar)
        self.setCentralWidget(container)

        self._create_actions()
        self._create_menus()
        self._create_toolbar()
        self._create_statusbar()

        # Auto-lock: trava cofres apos inatividade (intervalo vem das preferencias).
        self._idle_timer = QTimer(self)
        self._idle_timer.setSingleShot(True)
        self._idle_timer.timeout.connect(self._auto_lock_vaults)
        self._apply_autolock()

        # Redacao do clipboard na CAMADA do clipboard: pega TODOS os caminhos de
        # copia (inclusive os nativos do Scintilla — SCI_COPY/COPYRANGE/retangular/
        # Ctrl+Insert/Shift+Del), que furavam o override por metodo.
        self._clip_guard = False
        QApplication.clipboard().dataChanged.connect(self._sanitize_clipboard)

        self.new_file()

    def _sanitize_clipboard(self) -> None:
        if self._clip_guard:
            return
        # Reune os segredos de TODAS as abas em redacao — nao so a focada. Senao
        # uma copia feita numa aba redigida VAZA se outra aba (sem redacao) estiver
        # em foco no instante do dataChanged (bug do pentest: a aba dona da copia
        # nao e necessariamente a current_editor()).
        # Separa os REGISTRADOS (declaracao explicita do usuario — podem ser curtos) dos
        # detectados por padrao/entropia (estes mantem o piso de 6 contra falso-positivo).
        reg: list[str] = []
        other: list[str] = []
        for i in range(self.tabs.count()):
            ed = self.tabs.widget(i)
            if isinstance(ed, CodeEditor) and ed.is_redacted():
                for m in ed.secret_matches():
                    if m.snippet:
                        (reg if m.kind == "segredo registrado" else other).append(m.snippet)
        snippets = reg + other
        if not snippets:
            return
        cb = QApplication.clipboard()
        txt = cb.text()
        if not txt:
            return
        new = txt
        for snip in snippets:                       # mascara segredos INTEIROS presentes
            if snip in new:
                new = new.replace(snip, "●" * len(snip))
        if new == txt:                              # nada inteiro? checa copia PARCIAL (fragmento)
            stripped = txt.strip()
            # Registrado: mascara fragmento >= 2 chars (PIN/senha curta nao pode vazar pela copia
            # parcial). Detectado: mantem piso 6. Mascara so o FRAGMENTO (nao apaga o clipboard
            # inteiro), pra nao destruir uma copia legitima que so colide com um segredo maior.
            hit = ((len(stripped) >= 2 and any(stripped in s for s in reg))
                   or (len(stripped) >= 6 and any(stripped in s for s in other)))
            if hit:
                new = txt.replace(stripped, "●" * len(stripped))
        if new != txt:
            self._clip_guard = True
            cb.setText(new)
            self._clip_guard = False

    def _touch_idle(self) -> None:
        if config.get("auto_lock_min") > 0:      # so reinicia se auto-lock ativo
            self._idle_timer.start()

    def _apply_autolock(self) -> None:
        minutes = config.get("auto_lock_min")
        if minutes > 0:
            self._idle_timer.setInterval(minutes * 60 * 1000)
            self._idle_timer.start()
        else:
            self._idle_timer.stop()

    # ================================================================== #
    # Interface
    # ================================================================== #
    def _create_actions(self) -> None:
        style = self.style()
        SP = QStyle.StandardPixmap
        SK = QKeySequence.StandardKey

        def make(text, icon, shortcut, slot, checkable=False):
            act = QAction(style.standardIcon(icon), text, self)
            if shortcut is not None:
                act.setShortcut(shortcut)
            act.setCheckable(checkable)
            act.triggered.connect(slot)
            return act

        # Arquivo
        self.act_new = make("&Novo", SP.SP_FileIcon, SK.New, self.new_file)
        self.act_open = make("&Abrir…", SP.SP_DialogOpenButton, SK.Open, self.open_file_dialog)
        self.act_save = make("&Salvar", SP.SP_DialogSaveButton, SK.Save, self.save_file)
        self.act_save_as = make("Salvar &como…", SP.SP_DialogSaveButton, SK.SaveAs, self.save_file_as)
        # Ctrl+W / Ctrl+Q explicitos: no Windows o StandardKey.Close vira Ctrl+F4
        # e o StandardKey.Quit nao tem tecla — fixamos o que o usuario espera.
        self.act_close_tab = make("&Fechar aba", SP.SP_DialogCloseButton, QKeySequence("Ctrl+W"), self.close_current_tab)
        self.act_quit = make("Sai&r", SP.SP_DialogCloseButton, QKeySequence("Ctrl+Q"), self.close)

        # Edicao
        self.act_undo = make("Desfazer", SP.SP_ArrowBack, SK.Undo, lambda: self._edit("undo"))
        self.act_redo = make("Refazer", SP.SP_ArrowForward, SK.Redo, lambda: self._edit("redo"))
        self.act_cut = make("Recortar", SP.SP_FileIcon, SK.Cut, lambda: self._edit("cut"))
        self.act_copy = make("Copiar", SP.SP_FileIcon, SK.Copy, lambda: self._edit("copy"))
        self.act_paste = make("Colar", SP.SP_FileIcon, SK.Paste, lambda: self._edit("paste"))
        self.act_select_all = make("Selecionar tudo", SP.SP_FileIcon, SK.SelectAll, lambda: self._edit("selectAll"))
        self.act_find = make("&Localizar…", SP.SP_FileDialogContentsView,
                             QKeySequence("Ctrl+F"), lambda: self.find_bar.open_find())
        self.act_replace = make("Substitui&r…", SP.SP_FileDialogContentsView,
                                QKeySequence("Ctrl+H"), lambda: self.find_bar.open_find(True))
        self.act_find_next = make("Localizar pr&oxima", SP.SP_ArrowDown,
                                  QKeySequence("F3"), lambda: self.find_bar.find_next())
        self.act_find_prev = make("Localizar &anterior", SP.SP_ArrowUp,
                                  QKeySequence("Shift+F3"), lambda: self.find_bar.find_prev())
        self.act_search_files = make("Buscar em &arquivos…", SP.SP_FileDialogContentsView,
                                     QKeySequence("Ctrl+Shift+F"), self.search_in_files)
        self.act_palette = make("&Paleta de comandos…", SP.SP_FileDialogDetailedView,
                                QKeySequence("Ctrl+Shift+P"), self.command_palette)
        self.act_diff = make("Comparar arquivos (&diff)…", SP.SP_FileDialogContentsView,
                             QKeySequence("Ctrl+Shift+D"), self.diff_files)

        # Seguranca (a identidade do Redoubt)
        self.act_redact = make("Modo &Redacao (tarjar segredos)",
                               SP.SP_MessageBoxWarning,
                               QKeySequence("Ctrl+Shift+R"),
                               self.toggle_redaction, checkable=True)
        self.act_next_secret = make("Ir ao pr&oximo segredo",
                                    SP.SP_ArrowForward,
                                    QKeySequence("F8"),
                                    self.goto_next_secret)
        # Ctrl+Shift+E (Exposicao): evita conflito com Salvar como (Ctrl+Shift+S).
        self.act_scan_report = make("&Relatorio de segredos",
                                    SP.SP_FileDialogInfoView,
                                    QKeySequence("Ctrl+Shift+E"),
                                    self.show_secret_report)
        self.act_redaction_list = make("&Lista de redação (segredos a tarjar)…",
                                       SP.SP_DialogSaveButton, None,
                                       self.manage_redaction_list)
        # Cofre: sela a aba atual (sera gravada cifrada como .rdbt).
        self.act_seal = make("Selar como &cofre…",
                             SP.SP_DriveHDIcon,
                             QKeySequence("Ctrl+Shift+L"),
                             self.seal_current)
        self.act_seal_to_recipient = make("Selar para &destinatário (X25519)…",
                                          SP.SP_DriveHDIcon, None, self.seal_to_recipient)
        self.act_export_recipient = make("Exportar minha &chave de destinatário…",
                                         SP.SP_DialogSaveButton, None, self.export_recipient_key)
        self.act_lock_now = make("&Travar cofre agora",
                                 SP.SP_DriveHDIcon,
                                 QKeySequence("Ctrl+Shift+K"),
                                 self.lock_current)
        self.act_unlock = make("&Destravar cofre…",
                               SP.SP_DialogYesButton,
                               QKeySequence("Ctrl+Shift+U"),
                               self.unlock_current)
        self.act_unlock_keyfile = make("Destravar com arquivo-&chave…",
                                       SP.SP_DialogYesButton, None, self.unlock_with_keyfile)
        self.act_add_pw = make("Cofre: adicionar &senha…",
                               SP.SP_DriveHDIcon, None, self.add_vault_password)
        self.act_add_keyfile = make("Cofre: adicionar arquivo-cha&ve…",
                                    SP.SP_DriveHDIcon, None, self.add_vault_keyfile)
        self.act_new_burn = make("Nova nota de &queima",
                                 SP.SP_TrashIcon,
                                 QKeySequence("Ctrl+Shift+B"),
                                 self.new_burn)
        self.act_verify = make("Verificar custodia (&hash)",
                               SP.SP_FileDialogContentsView,
                               QKeySequence("Ctrl+Shift+H"),
                               self.verify_custody)
        self.act_command = make("Barra de comando :",
                                SP.SP_FileDialogDetailedView,
                                QKeySequence("Ctrl+P"),
                                lambda: self.cmd_bar.setFocus())
        self.act_settings = make("&Preferencias…",
                                 SP.SP_FileDialogInfoView,
                                 QKeySequence("Ctrl+,"),
                                 self.open_preferences)

        self.act_sign = make("&Assinar e exportar (.sig)…",
                             SP.SP_DialogYesButton,
                             QKeySequence("Ctrl+Shift+G"),
                             self.sign_and_export)
        self.act_protect_repo = make("&Proteger repositorio git (hook anti-segredo)…",
                                     SP.SP_DialogApplyButton, None, self.protect_repo)
        self.act_protect_id = make("Proteger &identidade com senha…",
                                   SP.SP_DialogYesButton, None, self.protect_identity)
        self.act_export_anchor = make("Exportar â&ncora de custódia…",
                                      SP.SP_DialogSaveButton, None, self.export_custody_anchor)
        self.act_check_anchor = make("&Verificar âncora de custódia…",
                                     SP.SP_FileDialogInfoView, None, self.check_custody_anchor)
        self.act_prov_seal = make("&Selo de proveniência (.rdbt-seal)…",
                                  SP.SP_DialogSaveButton, None, self.export_provenance_seal)
        self.act_verify_seal = make("Verificar se&lo de proveniência…",
                                    SP.SP_FileDialogInfoView, None, self.verify_provenance_seal)

        self.act_about = make(f"Sobre o {APP_NAME}", SP.SP_MessageBoxInformation, None, self._about)

    def _create_menus(self) -> None:
        bar = self.menuBar()

        m_file = bar.addMenu("&Arquivo")
        for act in (self.act_new, self.act_open):
            m_file.addAction(act)
        m_file.addAction(self.act_command)
        m_file.addSeparator()
        for act in (self.act_save, self.act_save_as):
            m_file.addAction(act)
        m_file.addSeparator()
        m_file.addAction(self.act_close_tab)
        m_file.addAction(self.act_quit)

        m_edit = bar.addMenu("&Editar")
        for act in (self.act_undo, self.act_redo):
            m_edit.addAction(act)
        m_edit.addSeparator()
        for act in (self.act_cut, self.act_copy, self.act_paste):
            m_edit.addAction(act)
        m_edit.addSeparator()
        m_edit.addAction(self.act_select_all)
        m_edit.addSeparator()
        for act in (self.act_find, self.act_replace, self.act_find_next, self.act_find_prev,
                    self.act_search_files):
            m_edit.addAction(act)
        m_edit.addSeparator()
        m_edit.addAction(self.act_palette)
        m_edit.addAction(self.act_diff)
        m_edit.addAction(self.act_settings)

        m_sec = bar.addMenu("&Seguranca")
        m_sec.addAction(self.act_redact)
        m_sec.addAction(self.act_next_secret)
        m_sec.addAction(self.act_scan_report)
        m_sec.addAction(self.act_redaction_list)
        m_sec.addAction(self.act_verify)
        m_sec.addAction(self.act_sign)
        m_sec.addAction(self.act_protect_id)
        m_sec.addAction(self.act_export_anchor)
        m_sec.addAction(self.act_check_anchor)
        m_sec.addAction(self.act_prov_seal)
        m_sec.addAction(self.act_verify_seal)
        m_sec.addSeparator()
        m_sec.addAction(self.act_seal)
        m_sec.addAction(self.act_seal_to_recipient)
        m_sec.addAction(self.act_export_recipient)
        m_sec.addAction(self.act_lock_now)
        m_sec.addAction(self.act_unlock)
        m_sec.addAction(self.act_unlock_keyfile)
        m_sec.addAction(self.act_add_pw)
        m_sec.addAction(self.act_add_keyfile)
        m_sec.addAction(self.act_new_burn)
        m_sec.addSeparator()
        m_sec.addAction(self.act_protect_repo)

        m_help = bar.addMenu("A&juda")
        m_help.addAction(self.act_about)

    def _create_toolbar(self) -> None:
        tb = self.addToolBar("Principal")
        tb.setMovable(False)
        for act in (self.act_new, self.act_open, self.act_save):
            tb.addAction(act)
        tb.addSeparator()
        for act in (self.act_undo, self.act_redo):
            tb.addAction(act)
        tb.addSeparator()
        for act in (self.act_redact, self.act_next_secret):
            tb.addAction(act)

    def _create_statusbar(self) -> None:
        sb = self.statusBar()
        # Selo de estado de seguranca (esquerda).
        self.lbl_seal = QLabel("● LIMPO")
        self.lbl_seal.setStyleSheet(f"color:{theme.GREEN}; font-weight:700; padding:0 8px;")
        sb.addWidget(self.lbl_seal)

        # Cadeia de custodia + posicao/linguagem/encoding (direita).
        self.lbl_hash = QLabel("custodia: —")
        self.lbl_pos = QLabel("Lin 1, Col 1")
        self.lbl_lang = QLabel("Texto")
        self.lbl_enc = QLabel("UTF-8")
        for lbl in (self.lbl_hash, self.lbl_pos, self.lbl_lang, self.lbl_enc):
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            sb.addPermanentWidget(lbl)

    # ================================================================== #
    # Helpers de aba/editor
    # ================================================================== #
    def current_editor(self) -> CodeEditor | None:
        return self.tabs.currentWidget()

    def _new_editor(self) -> CodeEditor:
        editor = CodeEditor()
        editor._last_secret_count = 0
        editor.modificationChanged.connect(lambda _=False, e=editor: self._refresh_tab(e))
        editor.cursorPositionChanged.connect(lambda *_: self._update_status())
        editor.cursorPositionChanged.connect(lambda *_: self._touch_idle())
        editor.textChanged.connect(self._touch_idle)
        editor.secretsChanged.connect(lambda n, e=editor: self._on_secrets_changed(e, n))
        return editor

    def _add_tab(self, editor: CodeEditor, make_current: bool = True) -> None:
        idx = self.tabs.addTab(editor, self._name_for(editor))
        if make_current:
            self.tabs.setCurrentIndex(idx)
        self._refresh_tab(editor)

    @staticmethod
    def _name_for(editor: CodeEditor) -> str:
        return os.path.basename(editor.path) if editor.path else editor.display_name

    def _refresh_tab(self, editor: CodeEditor) -> None:
        idx = self.tabs.indexOf(editor)
        if idx < 0:
            return
        prefix = ""
        if editor.is_vault:
            prefix += "🔒 "
        elif not editor.is_burn and editor.secret_matches():
            prefix += "▲ "
        if editor.isModified() and not editor.is_burn:
            prefix += "• "
        self.tabs.setTabText(idx, prefix + self._name_for(editor))
        self.tabs.setTabToolTip(idx, editor.path or self._name_for(editor))
        if editor is self.current_editor():
            self._update_window_title()

    def _update_window_title(self) -> None:
        editor = self.current_editor()
        if editor is None:
            self.setWindowTitle(APP_NAME)
            return
        star = "• " if editor.isModified() else ""
        flag = "  [▲ EXPOSTO]" if editor.secret_matches() else ""
        self.setWindowTitle(f"{star}{self._name_for(editor)} — {APP_NAME}{flag}")

    def _update_seal(self) -> None:
        editor = self.current_editor()
        if editor is None:
            self.lbl_seal.setText("")
            return
        n = len(editor.secret_matches())
        if editor.is_burn:
            text, color = "🔥 BURN (so RAM)", theme.RED
        elif editor.is_gated():
            text, color = f"🛡️ OCULTO · {editor.gated_count()}", theme.AMBER
        elif editor.is_vault and editor.is_locked():
            text, color = "🔒 TRAVADO", theme.AMBER
        elif editor.is_vault:
            text, color = "🔒 COFRE", theme.GREEN
        elif editor.scan_skipped():
            text, color = "⚠ NAO VERIFICADO", theme.AMBER
        elif n == 0:
            text, color = "● LIMPO", theme.GREEN
        elif editor.is_redacted():
            text, color = f"■ REDIGIDO · {n}", theme.AMBER
        else:
            text, color = f"▲ EXPOSTO · {n}", theme.RED
        self.lbl_seal.setText(text)
        self.lbl_seal.setStyleSheet(f"color:{color}; font-weight:700; padding:0 8px;")

    def _hash_text(self, editor: CodeEditor) -> str:
        if editor.saved_hash is None:
            return "custodia: —"
        if editor.isModified():
            return "custodia: ░ alterado"
        return f"custodia: {editor.saved_hash[:8]}"

    def _update_status(self) -> None:
        editor = self.current_editor()
        if editor is None:
            return
        line, col = editor.getCursorPosition()
        self.lbl_pos.setText(f"Lin {line + 1}, Col {col + 1}")
        self.lbl_lang.setText(editor.language_name)
        self.lbl_enc.setText(ENCODING_LABELS.get(editor.encoding, editor.encoding.upper()))
        self.lbl_hash.setText(self._hash_text(editor))
        self._update_seal()

    def _on_tab_changed(self, _index: int) -> None:
        editor = self.current_editor()
        self.act_redact.setChecked(editor.is_redacted() if editor else False)
        self._update_gate_bar()
        self._update_status()
        self._update_window_title()

    def _update_gate_bar(self) -> None:
        editor = self.current_editor()
        if editor is not None and editor.is_gated():
            self.gate_label.setText(
                f"🛡️ Conteudo oculto — {editor.gated_count()} credencial(is) detectada(s).")
            self.gate_bar.show()
        else:
            self.gate_bar.hide()

    def _on_secrets_changed(self, editor: CodeEditor, count: int) -> None:
        prev = getattr(editor, "_last_secret_count", 0)
        editor._last_secret_count = count
        self._refresh_tab(editor)
        if editor is self.current_editor():
            self._update_seal()
            self._update_window_title()
        if count > prev and count > 0:
            kinds = ", ".join(sorted({m.kind for m in editor.secret_matches()}))
            self.statusBar().showMessage(
                f"⚠ {count} segredo(s) detectado(s): {kinds}  —  "
                "Ctrl+Shift+R p/ tarjar · F8 p/ ir ao proximo", 7000)

    def _edit(self, method: str) -> None:
        editor = self.current_editor()
        if editor is not None:
            getattr(editor, method)()

    # ================================================================== #
    # Seguranca
    # ================================================================== #
    def toggle_redaction(self, checked: bool) -> None:
        editor = self.current_editor()
        if editor is not None:
            editor.set_redaction(checked)
        self._update_seal()
        self._update_window_title()

    def _rescan_all_editors(self) -> None:
        """Re-varre todas as abas (ex.: a Lista de redação mudou/destravou/travou)."""
        for i in range(self.tabs.count()):
            ed = self.tabs.widget(i)
            if isinstance(ed, CodeEditor):
                ed.rescan_secrets()
        self._update_seal()
        self._update_status()

    def manage_redaction_list(self) -> None:
        """Gerencia a Lista de redação: segredos LITERAIS, guardados CIFRADOS num Cofre, que o
        Modo Redação sempre tarja. Destrava (ou cria) com senha; nunca vai em claro ao disco."""
        if not redaction.is_unlocked():
            if redaction.exists():
                pw, ok = QInputDialog.getText(self, "Lista de redação",
                                              "Senha da lista de redação:", QLineEdit.EchoMode.Password)
                if not ok or not pw:
                    return
                if not redaction.unlock(pw):
                    QMessageBox.warning(self, APP_NAME, "Senha incorreta (ou lista corrompida).")
                    return
            else:
                resp = QMessageBox.question(
                    self, APP_NAME,
                    "Ainda não há Lista de redação. Criar uma agora, protegida por senha?\n\n"
                    "Ela guarda segredos LITERAIS (suas senhas/credenciais) que o Modo Redação "
                    "vai sempre tarjar — cifrada no disco (AES-256-GCM + Argon2id).")
                if resp != QMessageBox.StandardButton.Yes:
                    return
                pw1, ok = QInputDialog.getText(self, "Criar lista de redação",
                                               "Crie uma senha para a lista:", QLineEdit.EchoMode.Password)
                if not ok or not pw1:
                    return
                if len(pw1) < 4:
                    QMessageBox.warning(self, APP_NAME, "Senha muito curta (mínimo 4 caracteres).")
                    return
                pw2, ok = QInputDialog.getText(self, "Criar lista de redação",
                                               "Confirme a senha:", QLineEdit.EchoMode.Password)
                if not ok or pw1 != pw2:
                    QMessageBox.warning(self, APP_NAME, "As senhas não conferem.")
                    return
                try:
                    redaction.init_new(pw1)
                    redaction.save()                 # cria o cofre (vazio) no disco
                except Exception as exc:
                    QMessageBox.critical(self, APP_NAME, f"Não foi possível criar a lista:\n{exc}")
                    return

        # Pausa o auto-lock enquanto o gerenciador modal esta aberto: senao o idle poderia
        # travar a lista por baixo do dialogo e a proxima acao bateria em lista travada.
        self._idle_timer.stop()
        try:
            RedactionListDialog(self).exec()
        finally:
            self._touch_idle()                       # rearma o auto-lock (se ativo)
        self._rescan_all_editors()                   # reflete as mudanças nas tarjas já abertas

    def goto_next_secret(self) -> None:
        editor = self.current_editor()
        if editor is None or not editor.goto_next_secret():
            self.statusBar().showMessage("Nenhum segredo detectado neste documento.", 3000)

    def show_secret_report(self) -> None:
        editor = self.current_editor()
        if editor is None:
            return
        matches = editor.secret_matches()
        if not matches:
            QMessageBox.information(self, f"{APP_NAME} — Cadeia de custodia",
                                    "Nenhum segredo detectado. Documento LIMPO. ●")
            return
        # Reusa os byte-offsets ja computados (lineares, ordenados) em vez de re-codificar
        # text[:start] por match (era O(n*m)); e limita as linhas exibidas (lista de redacao
        # com literal comum pode gerar milhares de matches — diálogo gigante é inutil).
        spans = editor._secret_byte_spans
        lines = [f"{len(matches)} segredo(s) detectado(s):\n"]
        shown = 0
        for m, (bstart, _blen, _k) in zip(matches, spans):
            if shown >= 50:
                lines.append(f"  … e mais {len(matches) - 50}.")
                break
            line, _ = editor.lineIndexFromPosition(bstart)
            lines.append(f"  • linha {line + 1}: {m.kind}")
            shown += 1
        lines.append("\nCtrl+Shift+R tarja todos para compartilhar a tela com seguranca.")
        QMessageBox.warning(self, f"{APP_NAME} — Relatorio de segredos", "\n".join(lines))

    def _ask_seal_password(self, editor: CodeEditor) -> str | None:
        """Avisa + pede/confirma a senha-mestra. Devolve a senha, ou None se
        cancelado/invalido. NAO muda o estado do editor (pode rodar com a aba ainda
        OCULTA, sem revelar nada)."""
        if editor.is_vault:
            QMessageBox.information(self, APP_NAME, "Esta aba ja e um cofre.")
            return None
        if editor.is_burn:
            QMessageBox.information(self, APP_NAME, "Uma nota de queima e efemera e nao pode virar cofre.")
            return None
        SB = QMessageBox.StandardButton
        if QMessageBox.warning(
            self, f"{APP_NAME} — Selar cofre",
            "O conteudo sera CIFRADO (AES-256-GCM) ao salvar, num arquivo .rdbt.\n\n"
            "ZERO-KNOWLEDGE: a senha-mestra nao e guardada em lugar nenhum. Se voce "
            "esquece-la, o conteudo fica IRRECUPERAVEL — nao ha recuperacao nem backdoor.\n\n"
            "Continuar?",
            SB.Ok | SB.Cancel, SB.Cancel) != SB.Ok:
            return None
        pw1, ok = QInputDialog.getText(self, "Selar cofre", "Defina a senha-mestra:",
                                       QLineEdit.EchoMode.Password)
        if not ok:
            return None
        if len(pw1) < 4:
            QMessageBox.warning(self, APP_NAME, "Senha muito curta (minimo 4 caracteres).")
            return None
        pw2, ok = QInputDialog.getText(self, "Selar cofre", "Confirme a senha-mestra:",
                                       QLineEdit.EchoMode.Password)
        if not ok:
            return None
        if pw1 != pw2:
            QMessageBox.warning(self, APP_NAME, "As senhas nao conferem.")
            return None
        return pw1

    def _apply_seal(self, editor: CodeEditor, pw: str) -> None:
        editor.is_vault = True
        editor._vault_key = vault.generate_key()                       # chave-de-conteudo
        editor._vault_slots = vault.add_unlocker(editor._vault_key, [], password=pw)
        editor._vault_password = None
        editor.path = None             # forca salvar como novo .rdbt (nao clobbra o original)
        editor._rescan_secrets()       # limpa indicadores de "exposto"
        editor.setModified(True)
        self._refresh_tab(editor)
        self._update_status()
        self.statusBar().showMessage("Aba selada. Salve (Ctrl+S) para gravar o cofre .rdbt.", 6000)

    def seal_current(self) -> bool:
        """Sela a aba atual como cofre. Retorna True se selou, False se cancelou."""
        editor = self.current_editor()
        if editor is None:
            return False
        pw = self._ask_seal_password(editor)
        if pw is None:
            return False
        self._apply_seal(editor, pw)
        return True

    def lock_current(self) -> None:
        editor = self.current_editor()
        if editor is None or not editor.is_vault:
            self.statusBar().showMessage("Esta aba nao e um cofre (Ctrl+Shift+L para selar).", 3000)
            return
        if editor.is_locked():
            return
        if editor._vault_key is None and not editor._vault_password:
            QMessageBox.information(self, APP_NAME, "Sele o cofre (Ctrl+Shift+L) antes de travar.")
            return
        if editor.lock():
            self._refresh_tab(editor)
            self._update_status()
            self.statusBar().showMessage("Cofre travado.", 3000)

    def unlock_current(self) -> None:
        editor = self.current_editor()
        if editor is None or not (editor.is_vault and editor.is_locked()):
            self.statusBar().showMessage("Nenhum cofre travado nesta aba.", 3000)
            return
        pw, ok = QInputDialog.getText(self, "Destravar cofre", "Senha-mestra:",
                                      QLineEdit.EchoMode.Password)
        if not ok:
            return
        try:
            editor.unlock(pw)
        except vault.WrongPassword:
            QMessageBox.critical(self, APP_NAME, "Senha incorreta.")
            return
        except vault.VaultError as exc:
            # cofre adulterado/truncado/versao ou KDF invalidos (ex.: blob corrompido
            # no disco ou caminho de sessao envenenado) -> NAO deixa a excecao escapar
            # do slot Qt e derrubar o app.
            QMessageBox.critical(self, APP_NAME, f"Cofre invalido ou adulterado:\n{exc}")
            return
        self._refresh_tab(editor)
        self._update_status()
        self.statusBar().showMessage("Cofre destravado.", 3000)

    def _auto_lock_vaults(self) -> None:
        locked = 0
        for i in range(self.tabs.count()):
            ed = self.tabs.widget(i)
            if ed.is_vault and not ed.is_locked() and ed._vault_key is not None and ed.lock():
                locked += 1
                self._refresh_tab(ed)
        red = redaction.is_unlocked()
        if red:
            redaction.lock()                  # esquece os segredos da lista (estavam em RAM)
            self._rescan_all_editors()        # limpa as tarjas vindas da lista
        if locked or red:
            self._update_status()
            parts = ([f"{locked} cofre(s)"] if locked else []) + (["lista de redação"] if red else [])
            self.statusBar().showMessage(f"Travado por inatividade: {', '.join(parts)}.", 5000)

    # --- Cofre++: multiplos destravadores (senhas / arquivos-chave) ---------- #
    def _unlocked_vault(self) -> CodeEditor | None:
        ed = self.current_editor()
        if ed is None or not ed.is_vault or ed.is_locked() or ed._vault_key is None:
            QMessageBox.information(
                self, APP_NAME, "Abra ou sele um cofre (destravado) antes de gerenciar credenciais.")
            return None
        return ed

    def add_vault_password(self) -> None:
        ed = self._unlocked_vault()
        if ed is None:
            return
        pw1, ok = QInputDialog.getText(self, "Adicionar senha", "Nova senha-mestra:",
                                       QLineEdit.EchoMode.Password)
        if not ok or not pw1:
            return
        if len(pw1) < 4:
            QMessageBox.warning(self, APP_NAME, "Senha muito curta (minimo 4 caracteres).")
            return
        pw2, ok = QInputDialog.getText(self, "Adicionar senha", "Confirme:",
                                       QLineEdit.EchoMode.Password)
        if not ok or pw1 != pw2:
            QMessageBox.warning(self, APP_NAME, "As senhas nao conferem.")
            return
        ed._vault_slots = vault.add_unlocker(ed._vault_key, ed._vault_slots, password=pw1)
        ed.setModified(True)
        QMessageBox.information(self, APP_NAME,
                                "Senha adicionada. Salve (Ctrl+S) para gravar o cofre com a nova credencial.")

    def add_vault_keyfile(self) -> None:
        ed = self._unlocked_vault()
        if ed is None:
            return
        path, _ = QFileDialog.getOpenFileName(self, "Escolher arquivo-chave")
        if not path:
            return
        try:
            with open(path, "rb") as fh:
                kf = fh.read()
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"Nao foi possivel ler o arquivo-chave:\n{exc}")
            return
        if not kf:
            QMessageBox.warning(self, APP_NAME, "Arquivo-chave vazio.")
            return
        ed._vault_slots = vault.add_unlocker(ed._vault_key, ed._vault_slots, keyfile=kf)
        ed.setModified(True)
        QMessageBox.information(
            self, APP_NAME, "Arquivo-chave adicionado. Salve (Ctrl+S) para gravar.\n"
            "Guarde o arquivo-chave em local seguro — ele destrava este cofre.")

    def unlock_with_keyfile(self) -> None:
        editor = self.current_editor()
        if editor is None or not (editor.is_vault and editor.is_locked()):
            self.statusBar().showMessage("Nenhum cofre travado nesta aba.", 3000)
            return
        path, _ = QFileDialog.getOpenFileName(self, "Destravar com arquivo-chave")
        if not path:
            return
        try:
            with open(path, "rb") as fh:
                kf = fh.read()
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"Nao foi possivel ler o arquivo-chave:\n{exc}")
            return
        try:
            editor.unlock(keyfile=kf)
        except vault.WrongPassword:
            QMessageBox.critical(self, APP_NAME, "Arquivo-chave nao confere com este cofre.")
            return
        except vault.VaultError as exc:
            QMessageBox.critical(self, APP_NAME, f"Cofre invalido ou adulterado:\n{exc}")
            return
        self._refresh_tab(editor)
        self._update_status()
        self.statusBar().showMessage("Cofre destravado com arquivo-chave.", 3000)

    def new_burn(self) -> None:
        self._untitled_counter += 1
        editor = self._new_editor()
        editor.is_burn = True
        editor.display_name = f"🔥 Queima {self._untitled_counter}"
        self._add_tab(editor)
        editor.setFocus()
        self.statusBar().showMessage(
            "Nota de queima: vive so na RAM, NAO vai pro disco e e apagada ao fechar.", 6000)

    def _audit(self, event: str, editor: CodeEditor, content_hash: str = "") -> None:
        """Registra um evento na trilha de auditoria (best-effort: nunca quebra o app)."""
        try:
            label = editor.path or editor.display_name or "(sem titulo)"
            custody.log_event(event, detail=label, content_hash=content_hash)
        except Exception:
            pass

    def verify_custody(self) -> None:
        editor = self.current_editor()
        if editor is None:
            return
        if editor.is_locked():
            QMessageBox.information(self, APP_NAME, "Destrave o cofre (Ctrl+Shift+U) para verificar a custodia.")
            return
        full = editor.content_hash()           # hash VIVO (nao confia no flag isModified)
        if editor.saved_hash is None:
            status = "Documento ainda nao salvo (sem linha de base)."
        elif full != editor.saved_hash:
            status = "⚠ ALTERADO desde o ultimo salvamento (o hash difere da linha de base)."
        else:
            status = "✓ INTEGRO: confere com a linha de base do ultimo salvamento."

        # Assinatura .sig (se exportada): tamper-evidence COM chave contra o conteudo atual.
        sig_line = ""
        sig_path = (editor.path + ".sig") if editor.path else None
        if sig_path and os.path.exists(sig_path):
            try:
                sig = open(sig_path, encoding="utf-8").read().strip()
                confere = custody.verify(editor.custody_text(), sig)
                sig_line = (f"Assinatura ({os.path.basename(sig_path)}): "
                            + ("✓ CONFERE — nao mudou desde que voce assinou.\n\n"
                               if confere else
                               "⚠ NAO CONFERE — conteudo mudou, ou .sig de outro arquivo/chave.\n\n"))
            except OSError:
                sig_line = ""

        ok_chain, idx = custody.verify_chain()
        st = custody.audit_stats()
        n = st["total"]
        trilha = "✓ CADEIA INTEGRA" if ok_chain else f"⚠ CADEIA QUEBRADA na entrada {idx}"
        base = f"Linha de base (ultimo salvamento):\n{editor.saved_hash}\n\n" if editor.saved_hash else ""
        orfao = ("\n⚠ ATENCAO: ha uma copia EM CLARO da chave (identity.ed25519) coexistindo com a "
                 "identidade protegida — provavel proteger/desproteger interrompido. Assine algo "
                 "(vai pedir a senha) e o Redoubt remove a copia automaticamente.\n"
                 if custody.identity_has_orphan_pem() else "")
        QMessageBox.information(
            self, f"{APP_NAME} — Cadeia de custodia",
            f"SHA-256 do conteudo atual:\n{full}\n\n{base}{sig_line}{status}\n\n"
            f"Identidade (fingerprint da chave publica): {self._safe_fingerprint()}\n"
            f"Trilha de auditoria: {n} evento(s) (seq {st['head_seq']}, {st['signed']} assinado(s)) — {trilha}\n{orfao}\n"
            "Assine e exporte (.sig) em Seguranca ▸ Assinar e exportar — quem tiver sua "
            "chave publica verifica que o arquivo nao mudou.")

    def export_custody_anchor(self) -> None:
        """Exporta uma âncora assinada da trilha (anti-reset). Pede senha se a identidade estiver protegida."""
        import json
        if not custody.read_audit():
            QMessageBox.information(self, APP_NAME, "A trilha de auditoria está vazia — nada a ancorar ainda.")
            return
        try:
            anchor = custody.export_anchor()
        except custody.IdentityLocked:
            if not self._unlock_identity_dialog():
                return
            try:
                anchor = custody.export_anchor()
            except Exception as exc:
                QMessageBox.critical(self, APP_NAME, f"Não foi possível exportar a âncora:\n{exc}")
                return
        except Exception as exc:
            QMessageBox.critical(self, APP_NAME, f"Não foi possível exportar a âncora:\n{exc}")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Salvar âncora de custódia",
                                              "custody-anchor.json", "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(anchor, fh, ensure_ascii=True, indent=2)
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"Não foi possível salvar:\n{exc}")
            return
        QMessageBox.information(
            self, APP_NAME,
            f"Âncora exportada (seq {anchor['seq']}, fingerprint {anchor['fingerprint']}).\n\n"
            "Guarde este arquivo FORA da máquina (e-mail, nuvem, pendrive). Depois, "
            "'Verificar âncora' detecta se a trilha foi resetada ou truncada.")

    def check_custody_anchor(self) -> None:
        """Verifica uma âncora exportada contra a trilha ATUAL (detecta reset/truncamento/reescrita)."""
        import json
        path, _ = QFileDialog.getOpenFileName(self, "Escolher âncora de custódia", "", "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as fh:
                anchor = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            QMessageBox.critical(self, APP_NAME, f"Não foi possível ler a âncora:\n{exc}")
            return
        r = custody.check_anchor(anchor)        # default: amarra à identidade LOCAL (anti-forja)
        icon = QMessageBox.Icon.Information if r["ok"] else QMessageBox.Icon.Warning
        ident = ("✓ confere com a identidade LOCAL" if r["identity_match"]
                 else "⚠ NÃO confere com a identidade local")
        QMessageBox(icon, f"{APP_NAME} — Verificar âncora",
                    f"Assinatura: {'✓ válida' if r['sig_ok'] else '⚠ INVÁLIDA'}\n"
                    f"Fingerprint da âncora: {r['fingerprint']} — {ident}\n\n"
                    f"{r['detail']}\n\n"
                    f"Veredito: {'✓ TRILHA ÍNTEGRA E AUTÊNTICA' if r['ok'] else '⚠ NÃO CONFIRMADA'}\n\n"
                    "Nota: 'identidade local' = a chave desta instalação. Contra uma máquina "
                    "comprometida, confira o fingerprint acima com o que você conhece do autor "
                    "(fora da máquina) e proteja a identidade com senha.",
                    parent=self).exec()

    def _safe_fingerprint(self) -> str:
        """Fingerprint para EXIBIR; tolera identity.pub ilegivel (protegida+travada) sem abortar o fluxo."""
        try:
            return custody.fingerprint()
        except custody.CustodyError:
            return "protegida (publica ilegivel)"

    def _unlock_identity_dialog(self) -> bool:
        """Pede a senha (ou arquivo-chave) da identidade protegida e destrava por esta sessao."""
        kinds = custody.identity_unlockers()
        if vault.KIND_PASSWORD in kinds:
            pw, ok = QInputDialog.getText(
                self, "Identidade protegida",
                f"Senha da sua identidade ({self._safe_fingerprint()}) para assinar:",
                QLineEdit.EchoMode.Password)
            if not ok:
                return False
            if pw and custody.unlock_identity(pw):
                return True
            if pw:
                QMessageBox.warning(self, APP_NAME, "Senha incorreta.")
        if vault.KIND_KEYFILE in kinds:
            resp = QMessageBox.question(
                self, APP_NAME, "Destravar a identidade com um arquivo-chave?")
            if resp == QMessageBox.StandardButton.Yes:
                path, _ = QFileDialog.getOpenFileName(self, "Arquivo-chave da identidade")
                if path:
                    try:
                        with open(path, "rb") as fh:
                            kf = fh.read()
                    except OSError as exc:
                        QMessageBox.critical(self, APP_NAME, f"Nao foi possivel ler:\n{exc}")
                        return False
                    if custody.unlock_identity(keyfile=kf):
                        return True
                    QMessageBox.warning(self, APP_NAME, "Arquivo-chave incorreto.")
        return False

    def _sign_or_unlock(self, text: str) -> str | None:
        """Assina `text`; se a identidade estiver travada, pede a credencial e tenta de novo.
        Devolve a assinatura, ou None se o usuario cancelar o desbloqueio."""
        try:
            return custody.sign(text)
        except custody.IdentityLocked:
            if not self._unlock_identity_dialog():
                return None
            return custody.sign(text)

    def protect_identity(self) -> None:
        """Protege a identidade Ed25519 com senha (opt-in) — ou adiciona credencial se ja protegida."""
        if custody.is_protected():
            cur, ok = QInputDialog.getText(self, "Adicionar credencial",
                                           "Senha ATUAL da identidade:", QLineEdit.EchoMode.Password)
            if not ok or not cur:
                return
            new, ok = QInputDialog.getText(self, "Adicionar credencial",
                                           "NOVA senha (rota de backup):", QLineEdit.EchoMode.Password)
            if not ok or not new:
                return
            try:
                custody.add_identity_unlocker(passphrase=cur, new_password=new)
            except vault.VaultError:
                QMessageBox.warning(self, APP_NAME, "Senha atual incorreta.")
                return
            QMessageBox.information(self, APP_NAME, "Senha de backup adicionada a sua identidade.")
            return

        pw1, ok = QInputDialog.getText(self, "Proteger identidade",
                                       "Crie uma senha para sua identidade Ed25519:",
                                       QLineEdit.EchoMode.Password)
        if not ok or not pw1:
            return
        if len(pw1) < 4:
            QMessageBox.warning(self, APP_NAME, "Senha muito curta (minimo 4 caracteres).")
            return
        pw2, ok = QInputDialog.getText(self, "Proteger identidade", "Confirme a senha:",
                                       QLineEdit.EchoMode.Password)
        if not ok or pw1 != pw2:
            QMessageBox.warning(self, APP_NAME, "As senhas nao conferem.")
            return
        try:
            custody.protect_identity(pw1)
        except Exception as exc:
            QMessageBox.critical(self, APP_NAME, f"Nao foi possivel proteger:\n{exc}")
            return
        QMessageBox.information(
            self, APP_NAME,
            f"Identidade ({custody.fingerprint()}) protegida. A chave privada agora exige "
            "senha para assinar (pedida 1x por sessao).\n\nIMPORTANTE: nao ha recuperacao — "
            "esqueceu a senha, perdeu a identidade (a chave publica exportada ainda verifica o "
            "que voce ja assinou). Considere adicionar uma 2a senha/arquivo-chave de backup.")

    def sign_and_export(self) -> None:
        """Assina o conteudo (Ed25519) e grava a assinatura destacada .sig + a chave publica."""
        editor = self.current_editor()
        if editor is None:
            return
        if editor.is_burn or editor.is_locked():
            QMessageBox.information(self, APP_NAME, "Nota de queima / cofre travado nao pode ser assinado.")
            return
        if not editor.path:
            QMessageBox.information(self, APP_NAME, "Salve o arquivo antes de assinar.")
            return
        try:
            signature = self._sign_or_unlock(editor.custody_text())
            if signature is None:
                return                                  # usuario cancelou o desbloqueio
            sig_path = editor.path + ".sig"
            with open(sig_path, "w", encoding="utf-8") as fh:
                fh.write(signature + "\n")
            pub_path = os.path.join(custody._data_dir(), "redoubt-pubkey.txt")
            with open(pub_path, "w", encoding="utf-8") as fh:
                fh.write(custody.public_key_b64() + "\n")
        except Exception as exc:
            QMessageBox.critical(self, APP_NAME, f"Nao foi possivel assinar:\n{exc}")
            return
        self._audit("assinou", editor, editor.content_hash())
        QMessageBox.information(
            self, f"{APP_NAME} — Assinatura exportada",
            f"Assinatura Ed25519 gravada em:\n{sig_path}\n\n"
            f"Chave publica (para quem for verificar):\n{pub_path}\n"
            f"Fingerprint: {custody.fingerprint()}\n\n"
            "Verificar custodia (Ctrl+Shift+H) confere o .sig contra o conteudo atual.")

    def export_provenance_seal(self) -> None:
        """Sela o arquivo (RDBT-SEAL1): liga conteudo + identidade + trilha num .rdbt-seal portatil."""
        import json
        from datetime import datetime, timezone
        editor = self.current_editor()
        if editor is None:
            return
        if editor.is_burn or editor.is_locked():
            QMessageBox.information(self, APP_NAME, "Nota de queima / cofre travado nao pode ser selado.")
            return
        if not editor.path:
            QMessageBox.information(self, APP_NAME, "Salve o arquivo antes de selar.")
            return
        if editor.content_hash() != editor.saved_hash:
            QMessageBox.information(
                self, APP_NAME,
                "O selo reflete o arquivo SALVO em disco. Salve as alteracoes (Ctrl+S) antes de selar.")
            return
        when = datetime.now(timezone.utc).isoformat(timespec="seconds")

        def _make():
            return seal.seal_file(editor.path, sign_fn=custody.sign,
                                  public_key_b64=custody.public_key_b64(),
                                  fingerprint=custody.fingerprint(),
                                  sealed_at=when, trail=seal.current_trail())
        try:
            obj = _make()
        except custody.IdentityLocked:
            if not self._unlock_identity_dialog():
                return
            try:
                obj = _make()
            except Exception as exc:
                QMessageBox.critical(self, APP_NAME, f"Nao foi possivel selar:\n{exc}")
                return
        except Exception as exc:
            QMessageBox.critical(self, APP_NAME, f"Nao foi possivel selar:\n{exc}")
            return

        seal_path = editor.path + seal.SEAL_SUFFIX
        try:
            with open(seal_path, "w", encoding="utf-8") as fh:
                json.dump(obj, fh, ensure_ascii=True, indent=2)
                fh.write("\n")
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"Nao foi possivel salvar o selo:\n{exc}")
            return
        payload = json.loads(obj["signed_payload"])
        self._audit("selou", editor, payload["sha256"])
        trecho = (f", no ponto seq {payload['trail']['seq']} da trilha"
                  if isinstance(payload.get("trail"), dict) else "")
        QMessageBox.information(
            self, f"{APP_NAME} — Selo de proveniencia",
            f"Selo gravado em:\n{seal_path}\n\n"
            f"Liga o conteudo ({payload['sha256'][:16]}…) a sua identidade {custody.fingerprint()}{trecho}.\n\n"
            "Envie o arquivo + o .rdbt-seal: qualquer um verifica a origem e a integridade, "
            "offline e sem instalar o Redoubt, com verify_seal.py.")

    def verify_provenance_seal(self) -> None:
        """Verifica o arquivo atual contra o seu .rdbt-seal (origem + integridade)."""
        import json
        editor = self.current_editor()
        if editor is None:
            return
        if not editor.path:
            QMessageBox.information(self, APP_NAME, "Salve o arquivo para verificar o selo.")
            return
        seal_path = editor.path + seal.SEAL_SUFFIX
        if not os.path.exists(seal_path):
            QMessageBox.information(
                self, APP_NAME,
                f"Nenhum selo ao lado do arquivo ({os.path.basename(seal_path)}).\n\n"
                "Gere um em Seguranca ▸ Selo de proveniencia.")
            return
        try:
            with open(seal_path, encoding="utf-8") as fh:
                obj = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            QMessageBox.critical(self, APP_NAME, f"Nao foi possivel ler o selo:\n{exc}")
            return
        # Ancora = a identidade LOCAL (read-only; verifica os SEUS selos). Para selos de
        # terceiros, use verify_seal.py --pubkey <a chave do autor>.
        try:
            r = seal.verify_seal(obj, editor.path,
                                 expect_fingerprint=custody._local_fingerprint_or_none())
        except Exception as exc:                       # defesa em profundidade: nunca crashar a UI
            QMessageBox.critical(self, APP_NAME, f"Nao foi possivel verificar o selo:\n{exc}")
            return
        if r["error"]:
            QMessageBox.critical(self, APP_NAME, f"Selo invalido:\n{r['error']}")
            return
        icon = QMessageBox.Icon.Information if r["ok"] else QMessageBox.Icon.Warning
        if r["authentic"] is True:
            autor = "✓ a SUA identidade local"
        elif r["authentic"] is False:
            autor = "⚠ OUTRA identidade — confira o fingerprint com o autor"
        else:
            autor = "nao verificada (sem identidade local)"
        if not r["present"]:
            conteudo = "⚠ arquivo AUSENTE"
        elif r["io_error"]:
            conteudo = f"⚠ nao consegui ler o arquivo ({r['io_error']})"
        elif r["content_ok"]:
            conteudo = "✓ confere com o selo"
        else:
            conteudo = "⚠ NAO confere — o conteudo mudou desde que foi selado"
        nome = "" if r["name_match"] else f"\n(selado originalmente como {r['declared_name']!r})"
        trilha = (f"\nTrilha selada: seq {r['trail'].get('seq')}"
                  if isinstance(r.get("trail"), dict) else "")
        QMessageBox(icon, f"{APP_NAME} — Verificar selo",
                    f"Fingerprint do selo: {r['fingerprint']} — {autor}\n"
                    f"Assinatura: {'✓ valida' if r['signature_ok'] else '⚠ INVALIDA'}\n"
                    f"Conteudo: {conteudo}{nome}{trilha}\n\n"
                    f"Veredito: {'✓ INTEGRO E AUTENTICO' if r['ok'] else '⚠ NAO CONFIRMADO'}\n\n"
                    "Para um selo de OUTRO autor, verifique com verify_seal.py --pubkey <a chave dele>.",
                    parent=self).exec()

    # ================================================================== #
    # Barra de comando ':'
    # ================================================================== #
    def _focus_current_editor(self) -> None:
        ed = self.current_editor()
        if ed is not None:
            ed.setFocus()

    def _run_command(self) -> None:
        raw = self.cmd_bar.text().strip()
        self.cmd_bar.clear()
        if raw.startswith(":"):
            raw = raw[1:].strip()
        if not raw:
            self._focus_current_editor()
            return
        parts = raw.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        ed = self.current_editor()
        simple = {
            "w": self.save_file, "save": self.save_file,
            "q": self.close_current_tab, "close": self.close_current_tab,
            "new": self.new_file, "seal": self.seal_current, "burn": self.new_burn,
            "redact": self.act_redact.trigger, "hash": self.verify_custody,
            "lock": self.lock_current, "unlock": self.unlock_current,
            "next": self.goto_next_secret, "report": self.show_secret_report,
            "find": self.find_bar.open_find, "replace": lambda: self.find_bar.open_find(True),
        }
        if cmd == "goto" and ed is not None:
            try:
                n = int(arg)                       # aceita bigint; ValueError p/ digito unicode
            except ValueError:
                self.statusBar().showMessage("goto: informe um numero (ex.: goto 10)", 3000)
            else:
                ln = max(0, min(n - 1, ed.lines() - 1))   # clampa: nada de overflow nem pulo pro topo
                ed.setCursorPosition(ln, 0)
                ed.ensureLineVisible(ln)
        elif cmd == "open" and arg:
            self.open_path(arg)
        elif cmd in simple:
            simple[cmd]()
        else:
            self.statusBar().showMessage(
                f"Comando desconhecido: '{cmd}'  —  seal · burn · redact · hash · "
                "goto N · w · q · open <arquivo>", 5000)
        self._focus_current_editor()

    def _wipe_editor(self, editor: CodeEditor) -> None:
        """Sobrescreve o buffer, esvazia o UNDO e limpa o clipboard se contiver o
        conteudo (best-effort; o Python nao garante zerar a RAM)."""
        try:
            content = editor.text()
            editor.setReadOnly(False)
            if content:
                editor.setText("█" * len(content))
            editor.setText("")
            editor.SendScintilla(editor.SCI_EMPTYUNDOBUFFER)   # Ctrl+Z nao reconstroi o segredo
            cb = QApplication.clipboard()
            if content and cb.text() and cb.text() in content:
                cb.clear()                                      # tira o segredo do clipboard
        except Exception:
            pass
        self._audit("queimou", editor)             # registra o evento (sem conteudo)

    def open_preferences(self) -> None:
        dlg = PreferencesDialog(self)
        if dlg.exec():
            dlg.save()
            self._apply_autolock()
            self.apply_theme()                  # tema (re-tematiza app + editores + lexers)
            for i in range(self.tabs.count()):
                self.tabs.widget(i).apply_prefs()
            self.statusBar().showMessage("Preferencias aplicadas.", 3000)

    def apply_theme(self) -> None:
        """Aplica o tema das preferencias ao app, a todas as abas e aos lexers (ao vivo)."""
        theme.set_theme(config.get("theme"))
        app = QApplication.instance()
        if app is not None:
            theme.apply_app(app)
        for i in range(self.tabs.count()):
            ed = self.tabs.widget(i)
            theme.apply_editor_theme(ed)
            lx = ed.lexer()
            if lx is not None:
                theme.retheme_lexer(lx)
        self.gate_label.setStyleSheet(f"color:{theme.AMBER}; font-weight:600;")
        self._update_status()                   # re-aplica a cor do selo

    def protect_repo(self) -> None:
        """Instala o hook pre-commit anti-segredo num repositorio git escolhido."""
        from . import scan_cli
        repo = QFileDialog.getExistingDirectory(self, "Selecione o repositorio git a proteger")
        if not repo:
            return
        if not os.path.exists(os.path.join(repo, ".git")):
            QMessageBox.warning(self, APP_NAME,
                                "Isso nao parece um repositorio git (.git nao encontrado).")
            return
        try:
            path = scan_cli.install_hook(repo)
        except Exception as exc:
            QMessageBox.critical(self, APP_NAME, f"Nao foi possivel instalar o hook:\n{exc}")
            return
        QMessageBox.information(
            self, APP_NAME,
            "Hook anti-segredo instalado! A partir de agora, commits com credencial "
            f"neste repo serao BLOQUEADOS.\n\n{path}\n\nBypass pontual: git commit --no-verify")

    # ================================================================== #
    # Acoes de arquivo
    # ================================================================== #
    def new_file(self) -> None:
        self._untitled_counter += 1
        editor = self._new_editor()
        editor.display_name = f"Sem titulo {self._untitled_counter}"
        self._add_tab(editor)
        editor.setFocus()

    def open_file_dialog(self) -> None:
        start_dir = ""
        cur = self.current_editor()
        if cur is not None and cur.path:
            start_dir = os.path.dirname(cur.path)
        paths, _ = QFileDialog.getOpenFileNames(self, "Abrir arquivo(s)", start_dir, FILE_FILTER)
        for path in paths:
            self.open_path(path)

    def search_in_files(self) -> None:
        """Abre (ou traz pra frente) o dialogo de busca em arquivos (grep na pasta)."""
        cur = self.current_editor()
        start = os.path.dirname(cur.path) if (cur is not None and cur.path) else ""
        if self._search_dialog is None:
            self._search_dialog = SearchDialog(self._open_at_line, start, self)
        elif start and not self._search_dialog.folder.text():
            self._search_dialog.folder.setText(start)
        self._search_dialog.show()
        self._search_dialog.raise_()
        self._search_dialog.activateWindow()
        self._search_dialog.q.setFocus()

    def _open_at_line(self, path: str, line: int) -> None:
        """Callback do dialogo de busca: abre o arquivo e pula para a linha."""
        self.open_path(path)
        ed = self.current_editor()
        if ed is not None:
            ln = max(0, line - 1)
            ed.setCursorPosition(ln, 0)
            ed.ensureLineVisible(ln)
            ed.setFocus()

    def palette_commands(self) -> list[tuple]:
        """Comandos da paleta = (label, atalho, callable). Reúne as QActions de menu
        MAIS comandos que só existem como botão/preferência (tema, revelar oculto)."""
        cmds, seen = [], set()
        for a in self.findChildren(QAction):
            lbl = a.text().replace("&", "").strip()
            if not lbl or a is self.act_palette or lbl in seen:
                continue
            seen.add(lbl)
            sc = a.shortcut().toString() if not a.shortcut().isEmpty() else ""
            cmds.append((lbl, sc, a.trigger))
        extras = [
            ("Tema: claro", "", lambda: self._palette_set_theme("light")),
            ("Tema: escuro", "", lambda: self._palette_set_theme("dark")),
            ("Revelar conteudo oculto", "", self.reveal_current),
        ]
        for lbl, sc, fn in extras:
            if lbl not in seen:
                seen.add(lbl)
                cmds.append((lbl, sc, fn))
        cmds.sort(key=lambda c: c[0].lower())
        return cmds

    def _palette_set_theme(self, name: str) -> None:
        config.set_("theme", name)
        self.apply_theme()
        self.statusBar().showMessage(f"Tema aplicado: {name}", 3000)

    def command_palette(self) -> None:
        CommandPalette(self.palette_commands(), self).exec()

    def diff_files(self) -> None:
        cur = self.current_editor()
        default_a = cur.path if (cur is not None and cur.path) else ""
        DiffDialog(default_a, self).exec()

    def open_path(self, path: str) -> None:
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            QMessageBox.warning(self, APP_NAME, f"Arquivo nao encontrado:\n{path}")
            return

        try:
            if os.path.getsize(path) > 50_000_000:
                SB = QMessageBox.StandardButton
                if QMessageBox.warning(
                    self, APP_NAME,
                    "Arquivo muito grande (>50 MB). Abrir pode travar a interface. Continuar?",
                    SB.Ok | SB.Cancel, SB.Cancel) != SB.Ok:
                    return
        except OSError:
            pass

        for i in range(self.tabs.count()):
            ed = self.tabs.widget(i)
            if ed.path and os.path.normcase(ed.path) == os.path.normcase(path):
                self.tabs.setCurrentIndex(i)
                return

        if vault.is_vault_file(path):          # cofre .rdbt -> pede senha e decifra
            self._open_vault(path)
            return

        try:
            text, encoding = read_text(path)
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"Nao foi possivel abrir o arquivo:\n{exc}")
            return

        editor = self._new_editor()
        editor.path = path
        editor.encoding = encoding
        eol = detect_eol(text)
        editor.setEolMode(eol)
        editor.setText(text)
        editor.convertEols(eol)
        editor.apply_lexer_for_path(path)
        editor.setModified(False)
        editor.mark_saved()
        editor.setCursorPosition(0, 0)

        self._add_tab(editor)
        self._maybe_close_initial_empty()
        self._audit("abriu", editor, editor.saved_hash or "")
        self.statusBar().showMessage(f"Aberto: {path}", 3000)

    def export_recipient_key(self) -> None:
        """Mostra + copia a sua chave PUBLICA de destinatario (X25519) para compartilhar."""
        try:
            pub = custody.recipient_public_b64()
            fp = custody.recipient_fingerprint()
        except Exception as exc:
            QMessageBox.critical(self, APP_NAME, f"Nao foi possivel obter sua chave:\n{exc}")
            return
        self._clip_guard = True
        QApplication.clipboard().setText(pub)
        self._clip_guard = False
        QMessageBox.information(
            self, f"{APP_NAME} — Minha chave de destinatário",
            f"Sua chave PÚBLICA de destinatário (fingerprint {fp}) foi copiada para a área de "
            f"transferência:\n\n{pub}\n\nCompartilhe-a para que selem cofres para você "
            f"(Segurança ▸ Selar para destinatário). A chave PRIVADA fica local e nunca sai.")

    def seal_to_recipient(self) -> None:
        """Sela o conteúdo atual num cofre cifrado PARA a chave pública X25519 de um destinatário
        (e também para você, p/ manter acesso). Salva um .rdbt para enviar."""
        import base64
        editor = self.current_editor()
        if editor is None:
            return
        if editor.is_burn or editor.is_locked() or editor.is_vault:
            QMessageBox.information(self, APP_NAME, "Nota de queima / cofre não pode ser selado para destinatário.")
            return
        pub_b64, ok = QInputDialog.getText(
            self, "Selar para destinatário",
            "Cole a chave PÚBLICA de destinatário (base64) de quem vai abrir:")
        if not ok or not pub_b64.strip():
            return
        try:
            recipient = base64.b64decode(pub_b64.strip(), validate=True)
            if len(recipient) != 32:
                raise ValueError
        except Exception:
            QMessageBox.warning(self, APP_NAME, "Chave pública inválida (esperado base64 de 32 bytes).")
            return
        try:
            ck = vault.generate_key()
            slots = vault.add_recipient(ck, [], recipient)                # para o destinatário
            my_pub = base64.b64decode(custody.recipient_public_b64(), validate=True)
            if my_pub != recipient:                                       # e para você (manter acesso)
                slots = vault.add_recipient(ck, slots, my_pub)
            blob = vault.reseal(editor.custody_text(), ck, slots)
        except Exception as exc:
            QMessageBox.critical(self, APP_NAME, f"Não foi possível selar:\n{exc}")
            return
        suggested = (os.path.basename(editor.path) if editor.path else "cofre") + ".rdbt"
        out, _ = QFileDialog.getSaveFileName(self, "Salvar cofre para destinatário", suggested, VAULT_FILTER)
        if not out:
            return
        try:
            with open(out, "wb") as fh:
                fh.write(blob)
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"Não foi possível salvar:\n{exc}")
            return
        self._audit("selou p/ destinatario", editor, editor.content_hash())
        QMessageBox.information(
            self, f"{APP_NAME} — Selado para destinatário",
            f"Cofre cifrado salvo:\n{out}\n\nSó quem tem a chave privada correspondente (ou você) "
            f"consegue abrir. Envie o .rdbt — o conteúdo nunca trafega em claro.")

    def _open_vault(self, path: str) -> None:
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError as exc:
            QMessageBox.critical(self, APP_NAME, f"Nao foi possivel ler o cofre:\n{exc}")
            return
        # 1) Selado para VOCE (slot X25519)? Abre sem senha com a SUA chave de destinatario — mas só
        # se ela JÁ existe (read-only: abrir um cofre de terceiro não deve materializar uma chave sua).
        opened = None
        if custody.recipient_exists():
            try:
                opened = vault.open_vault(blob, x25519_private=custody.recipient_private_bytes())
            except Exception:                      # best-effort: qualquer falha cai no fluxo de senha
                opened = None
        # 2) Senao, pede a senha-mestra.
        if opened is None:
            pw, ok = QInputDialog.getText(
                self, "Abrir cofre", f"Senha-mestra de {os.path.basename(path)}:",
                QLineEdit.EchoMode.Password)
            if not ok:
                return
            try:
                opened = vault.open_vault(blob, password=pw)
            except vault.WrongPassword:
                QMessageBox.critical(self, APP_NAME,
                                     "Senha incorreta, cofre adulterado, ou voce nao e destinatario.")
                return
            except vault.VaultError as exc:
                QMessageBox.critical(self, APP_NAME, f"Nao foi possivel abrir o cofre:\n{exc}")
                return

        editor = self._new_editor()
        editor.path = path
        editor.encoding = "utf-8"
        editor.is_vault = True
        editor._vault_key = opened.key             # preserva os slots p/ re-selar
        editor._vault_slots = opened.slots
        editor.setText(opened.text)
        editor.setModified(False)
        editor.mark_saved()
        editor.setCursorPosition(0, 0)
        self._add_tab(editor)
        self._maybe_close_initial_empty()
        self._audit("abriu cofre", editor, editor.saved_hash or "")
        self.statusBar().showMessage(f"Cofre aberto: {path}", 3000)

    def save_file(self, editor: CodeEditor | None = None) -> bool:
        editor = editor or self.current_editor()
        if editor is None:
            return False
        if editor.is_burn:
            QMessageBox.information(self, APP_NAME, "Nota de queima e efemera — nao vai pro disco.")
            return False
        if editor.is_gated():
            QMessageBox.information(self, APP_NAME, "Revele o conteudo (barra acima) antes de salvar.")
            return False
        if editor.is_locked():
            QMessageBox.information(self, APP_NAME, "Destrave o cofre (Ctrl+Shift+U) antes de salvar.")
            return False
        if editor.path is None:
            return self.save_file_as(editor)
        return self._write(editor, editor.path)

    def save_file_as(self, editor: CodeEditor | None = None) -> bool:
        editor = editor or self.current_editor()
        if editor is None:
            return False
        if editor.is_burn:
            QMessageBox.information(self, APP_NAME, "Nota de queima e efemera — nao vai pro disco.")
            return False
        if editor.is_gated():
            QMessageBox.information(self, APP_NAME, "Revele o conteudo (barra acima) antes de salvar.")
            return False
        if editor.is_vault:
            start = editor.path or f"{editor.display_name or 'cofre'}.rdbt"
            path, _ = QFileDialog.getSaveFileName(self, "Salvar cofre", start, VAULT_FILTER)
        else:
            start = editor.path or f"{editor.display_name}.txt"
            path, _ = QFileDialog.getSaveFileName(self, "Salvar como", start, FILE_FILTER)
        if not path:
            return False
        return self._write(editor, path)

    def _write_vault(self, editor: CodeEditor, path: str) -> bool:
        if not path.lower().endswith(".rdbt"):
            path += ".rdbt"
        try:
            if editor._vault_key is not None:
                blob = vault.reseal(editor.text(), editor._vault_key, editor._vault_slots)
            else:
                blob = vault.encrypt(editor.text(), editor._vault_password or "")
            with open(path, "wb") as fh:
                fh.write(blob)
        except (OSError, vault.VaultError) as exc:
            QMessageBox.critical(self, APP_NAME, f"Nao foi possivel gravar o cofre:\n{exc}")
            return False
        editor.path = path
        editor.setModified(False)
        editor.mark_saved()
        self._refresh_tab(editor)
        self._update_status()
        self._audit("selou cofre", editor, editor.saved_hash or "")
        self.statusBar().showMessage(
            f"Cofre selado: {path}  ·  custodia {editor.saved_hash[:8]}", 4000)
        return True

    def _write(self, editor: CodeEditor, path: str) -> bool:
        if editor.is_burn:
            QMessageBox.information(self, APP_NAME, "Nota de queima e efemera — nao vai pro disco.")
            return False
        if editor.is_gated():
            # chokepoint: sem isto, gravar uma aba OCULTA poria o BANNER por cima do
            # arquivo original (perda de dados). Protege qualquer caller de _write.
            QMessageBox.information(self, APP_NAME, "Revele o conteudo (barra acima) antes de salvar.")
            return False
        if editor.is_locked():
            QMessageBox.information(self, APP_NAME, "Destrave o cofre (Ctrl+Shift+U) antes de salvar.")
            return False
        if editor.is_vault:
            return self._write_vault(editor, path)
        try:
            with open(path, "w", encoding=editor.encoding, newline="") as fh:
                fh.write(editor.text())
        except (OSError, UnicodeError) as exc:
            QMessageBox.critical(
                self, APP_NAME,
                f"Nao foi possivel salvar o arquivo:\n{exc}\n\n"
                "Se houver caracteres invalidos (ex.: surrogate solitario colado), "
                "remova-os e tente de novo.")
            return False

        changed_path = editor.path != path
        editor.path = path
        editor.setModified(False)
        editor.mark_saved()
        if changed_path:
            editor.apply_lexer_for_path(path)
        self._refresh_tab(editor)
        self._update_status()
        self._audit("salvou", editor, editor.saved_hash or "")
        self.statusBar().showMessage(f"Salvo: {path}  ·  custodia {editor.saved_hash[:8]}", 4000)
        return True

    # ================================================================== #
    # Fechamento
    # ================================================================== #
    def close_current_tab(self) -> None:
        self.close_tab(self.tabs.currentIndex())

    def close_tab(self, index: int) -> None:
        editor = self.tabs.widget(index)
        if editor is None:
            return
        if not self._maybe_save(editor):
            return
        if editor.is_burn:
            self._wipe_editor(editor)      # apaga o conteudo antes de descartar
        self.tabs.removeTab(index)
        editor.deleteLater()
        if self.tabs.count() == 0:
            self.new_file()

    def _maybe_save(self, editor: CodeEditor) -> bool:
        if editor.is_burn:
            return True          # efemera: nao pergunta nem salva (sera apagada)
        if editor.is_locked():
            if not editor._locked_was_modified:
                return True
            self.tabs.setCurrentWidget(editor)
            SB = QMessageBox.StandardButton
            ret = QMessageBox.warning(
                self, APP_NAME,
                "Este cofre esta TRAVADO e tem alteracoes nao salvas.\nDestrave "
                "(Ctrl+Shift+U) para salvar, ou descarte para fechar.",
                SB.Discard | SB.Cancel, SB.Cancel)
            return ret == SB.Discard
        if not editor.isModified():
            return True
        self.tabs.setCurrentWidget(editor)
        SB = QMessageBox.StandardButton
        ret = QMessageBox.warning(
            self, APP_NAME,
            f'O documento "{self._name_for(editor)}" tem alteracoes nao salvas.\nDeseja salvar?',
            SB.Save | SB.Discard | SB.Cancel, SB.Save,
        )
        if ret == SB.Save:
            return self.save_file(editor)
        if ret == SB.Cancel:
            return False
        return True

    def _maybe_close_initial_empty(self) -> None:
        current = self.current_editor()
        for i in range(self.tabs.count()):
            ed = self.tabs.widget(i)
            if ed is current:
                continue
            if ed.path is None and not ed.isModified() and ed.length() == 0:
                self.tabs.removeTab(i)
                ed.deleteLater()
                return

    def closeEvent(self, event) -> None:
        for i in range(self.tabs.count()):
            if not self._maybe_save(self.tabs.widget(i)):
                event.ignore()
                return
        self._save_session()                      # so caminhos (antes de apagar burns)
        for i in range(self.tabs.count()):        # apaga notas de queima ao sair
            ed = self.tabs.widget(i)
            if ed.is_burn:
                self._wipe_editor(ed)
        event.accept()

    # ================================================================== #
    # Sessao: lembra QUAIS arquivos estavam abertos (nunca o conteudo)
    # ================================================================== #
    def _save_session(self) -> None:
        paths: list[str] = []
        for i in range(self.tabs.count()):
            ed = self.tabs.widget(i)
            if ed.is_burn:          # nota de queima: efemera, NUNCA persistir
                continue
            if ed.path:             # so arquivos com caminho real (exclui "sem titulo")
                paths.append(ed.path)
        config.save_session(paths, self.tabs.currentIndex())

    def restore_session(self) -> int:
        """Reabre os arquivos da ultima sessao. Cofres reaparecem TRAVADOS (sem
        pedir senha). Arquivos sumidos sao ignorados em silencio. Retorna a qtd
        reaberta."""
        if not config.get("restore_session"):
            return 0
        paths, active = config.load_session()
        opened = 0
        for p in paths[:_MAX_RESTORE]:              # teto: lista vem do registro
            # Ignora UNC/remoto no auto-restore: um caminho \\host\... adulterado no
            # registro travaria a inicializacao (timeout SMB, antes do show) e poderia
            # induzir autenticacao NTLM contra um host arbitrario.
            if p.startswith("\\\\") or p.startswith("//"):
                continue
            if not os.path.isfile(p):
                continue
            already = any(self.tabs.widget(i).path and
                          os.path.normcase(self.tabs.widget(i).path) == os.path.normcase(p)
                          for i in range(self.tabs.count()))
            if already:
                continue
            try:
                self._restore_one(p)
                opened += 1
            except Exception:
                continue                            # um arquivo problematico nao derruba o resto
        if opened:
            self._maybe_close_initial_empty()
            if 0 <= active < self.tabs.count():
                self.tabs.setCurrentIndex(active)
            self._update_gate_bar()
        return opened

    def _restore_one(self, path: str) -> None:
        """Reabre 1 arquivo na restauracao. Cofre -> travado. Arquivo em claro COM
        credencial -> OCULTO (gated). Arquivo limpo -> abre normal."""
        if vault.is_vault_file(path):
            self._restore_vault_locked(path)
            return
        try:
            text, encoding = read_text(path)
        except OSError:
            return
        too_big = len(text) > _RESTORE_SCAN_LIMIT
        try:
            hits = 0 if too_big else len(secrets_mod.scan(text))
        except Exception:
            hits = 0
        # FAIL-SAFE: arquivo grande demais p/ varrer NAO abre em claro (poderia jogar
        # credencial na tela ao restaurar) — oculta por precaucao. So abre normal o
        # que foi varrido e esta limpo.
        if too_big or hits > 0:
            editor = self._new_editor()
            editor.path = path
            editor.encoding = encoding
            editor.apply_lexer_for_path(path)
            editor.gate(text, hits)                 # hits==0 + too_big -> "nao verificado"
            self._add_tab(editor)
        else:                                       # varrido e limpo -> abre normal
            self.open_path(path)

    def reveal_current(self) -> None:
        """Revela o conteudo de uma aba OCULTA (privacidade, sem senha)."""
        editor = self.current_editor()
        if editor is None or not editor.is_gated():
            return
        editor.reveal()
        editor.apply_lexer_for_path(editor.path or "")
        editor.setModified(False)
        editor.mark_saved()                         # baseline de custodia = conteudo do arquivo
        editor._rescan_secrets()                    # agora marca/tarja os segredos normalmente
        self._update_gate_bar()
        self._update_status()
        self._update_window_title()

    def _gate_seal(self) -> None:
        """Botao 'Selar como cofre' da aba OCULTA: pede a senha ANTES de revelar.
        Se o usuario cancelar, a aba PERMANECE oculta (nao expoe o conteudo)."""
        editor = self.current_editor()
        if editor is None:
            return
        if not editor.is_gated():
            self.seal_current()
            return
        pw = self._ask_seal_password(editor)        # pergunta com a aba ainda OCULTA
        if pw is None:
            return                                  # cancelou -> segue oculto, nada exposto
        editor.reveal()                             # so agora materializa o texto real
        editor.apply_lexer_for_path(editor.path or "")
        self._apply_seal(editor, pw)
        self._update_gate_bar()
        self._update_status()

    def _restore_vault_locked(self, path: str) -> None:
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            return
        if not vault.looks_like_vault(blob):
            return
        editor = self._new_editor()
        editor.path = path
        editor.encoding = "utf-8"
        editor.restore_locked(blob)
        self._add_tab(editor)

    # ================================================================== #
    # Arrastar e soltar
    # ================================================================== #
    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        for url in event.mimeData().urls():
            if url.isLocalFile():
                self.open_path(url.toLocalFile())

    # ================================================================== #
    # Sobre
    # ================================================================== #
    def _about(self) -> None:
        QMessageBox.about(
            self, f"Sobre o {APP_NAME}",
            f"<h3>{APP_NAME} {APP_VERSION}</h3>"
            f"<p><i>{APP_TAGLINE}</i></p>"
            "<p>Editor que trata cada arquivo como evidencia: vigia segredos, "
            "marca exposicoes e mantem cadeia de custodia (hash SHA-256).</p>"
            "<p>Python · PyQt6 · QScintilla.</p>",
        )
