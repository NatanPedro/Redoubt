# Arquitetura do Redoubt

> **Redoubt** v1.0.0 — *editor que trata cada arquivo como evidência.*
> Tagline: **"Nada vaza sem você mandar."**

Este documento descreve **como o Redoubt é montado por dentro**: as camadas, os
módulos e suas responsabilidades, o fluxo de dados que liga uma tecla digitada à
varredura de segredos e ao selo de estado, os subsistemas de segurança (Cofre,
Custódia, Hook git, Release assinado) e as principais decisões de arquitetura
(ADRs).

Tudo aqui descreve o que está **no código** — e separa, com honestidade, o que
cada subsistema **garante** do que **não garante**. A honestidade do modelo de
ameaça é parte da identidade do produto; este documento não promete o que o
código não entrega.

> **Marco 1.0.** A "Fase 3" do roadmap antigo (Cofre cifrado, Burn Note, barra
> `:`, mapa de exposição na margem) foi **100% entregue** — e o projeto foi além:
> **Cofre++** (múltiplos destravadores), **Custódia assinada Ed25519**, **Hook
> git anti-segredo**, **Release assinado**, busca em arquivos, paleta de comandos
> e diff. Por isso não há mais uma seção "Roadmap" neste documento: o que era
> backlog agora é arquitetura corrente.

---

## 1. Visão geral

O Redoubt é um editor de texto/código **desktop**, em **Python 3.11**, construído
sobre **PyQt6** e **PyQt6-QScintilla** (o mesmo motor Scintilla que o Notepad++
usa). Não há servidor, nuvem nem chamadas de rede: **tudo roda localmente**.

A diferença em relação a um editor comum é a **segurança como identidade**.
Quatro defesas locais sustentam a tagline *"nada vaza sem você mandar"*:

1. **Ver** — a *Sentinela de Segredos* varre cada documento a cada alteração e
   marca credenciais/PII.
2. **Tarjar** — o *Modo Redação* cobre os segredos na **tela** e mascara o
   **clipboard** antes de compartilhar.
3. **Cifrar** — o *Cofre `.rdbt`* cifra o conteúdo em repouso (AES-256-GCM), com
   múltiplas senhas e/ou arquivo-chave.
4. **Provar** — a *Custódia assinada* (Ed25519) + trilha de auditoria prova que o
   arquivo não foi adulterado; o *Hook git* blinda o repositório; o *Release
   assinado* prova a integridade do próprio download.

> **Nota sobre o nome do pacote.** O produto se chama **Redoubt**, mas o pacote
> Python preserva o nome histórico **`notepy/`** e a pasta do projeto se chama
> `Notepad`. A identidade vive em `notepy/__init__.py`
> (`APP_NAME = "Redoubt"`, `APP_VERSION = "1.0.0"`). Para renomear o app inteiro,
> basta trocar essa constante.

### As duas camadas

A arquitetura é deliberadamente partida em duas camadas, e essa separação é a
decisão de design mais importante do projeto:

- **Núcleos puros** — Python sem Qt, testáveis isolados e *headless*. Toda a
  lógica de segurança vive aqui. Alguns dependem da biblioteca `cryptography`
  (Cofre, Custódia, Release), **nenhum** depende do Qt.
- **Camada UI (PyQt6)** — os widgets e a janela. Orquestram os núcleos e
  traduzem seus resultados em selos, abas e diálogos, mas não contêm a lógica de
  detecção/cifragem.

```
┌──────────────────────────── CAMADA UI (PyQt6) ────────────────────────────┐
│  main.py → mainwindow.MainWindow → editor.CodeEditor                       │
│            findbar · preferences · (lexers/theme: aparência)               │
└────────────────────────────────┬──────────────────────────────────────────┘
                                  │ chama / orquestra
┌────────────────────────────────▼──────────────── NÚCLEOS PUROS (sem Qt) ──┐
│  secrets   vault   custody   release   scan_cli                            │
│  searchfiles   palette   difftool   config                                 │
│  (vault · custody · release dependem de `cryptography`, não do Qt)          │
└─────────────────────────────────────────────────────────────────────────────┘
        ▲ verify_release.py (standalone na raiz, espelha release.py)
```

### Mapa de módulos

```
Notepad/                     (pasta do projeto — o produto é o "Redoubt")
├── main.py                  ponto de entrada: tema, ícone, abre arquivos do argv
├── verify_release.py        verificador standalone (embute a pubkey do autor)
├── requirements.txt         PyQt6 + PyQt6-QScintilla + cryptography
├── requirements-dev.txt     pyinstaller + pillow (só build)
├── run.bat                  abre sem console (pythonw)
├── build.bat                empacota dist\Redoubt.exe (PyInstaller)
├── build-installer.bat      gera o instalador + SHA256SUMS + RELEASE.json
├── installer/redoubt.iss    pacote Inno Setup (associa .rdbt)
├── exemplo_segredos.py      fixture de demonstração (dispara a Sentinela)
└── notepy/                  (pacote — nome histórico)
    ├── __init__.py          identidade: APP_NAME / APP_VERSION / APP_TAGLINE
    │
    │   ── núcleos puros (sem Qt) ──
    ├── secrets.py           Sentinela de Segredos — scan(text)
    ├── vault.py             Cofre++ .rdbt — AES-256-GCM + scrypt, envelope RDBT2
    ├── custody.py           Custódia assinada Ed25519 + trilha de auditoria
    ├── release.py           Manifesto de release assinado (RDBT-REL1)
    ├── scan_cli.py          CLI da Sentinela + hook git pre-commit
    ├── searchfiles.py       Busca em arquivos / grep recursivo na pasta
    ├── palette.py           Busca fuzzy da paleta de comandos
    ├── difftool.py          Diff entre arquivos (difflib)
    ├── config.py            QSettings wrapper: auto-lock, fonte, tema, sessão
    │
    │   ── camada UI (PyQt6) ──
    ├── editor.py            CodeEditor (QsciScintilla): vigilância + custódia + cofre/oculto/burn
    ├── mainwindow.py        MainWindow: abas, menus, barra :, selo, orquestração dos núcleos
    ├── findbar.py           Barra Localizar/Substituir (regex, F3)
    ├── preferences.py       Diálogo de Preferências (Ctrl+,)
    ├── lexers.py            extensão de arquivo → lexer QScintilla (~50 linguagens)
    └── theme.py             paletas dark/light, QSS e re-tematização dos lexers
```

> **Onde está `cryptography`.** O `requirements.txt` traz três dependências:
> `PyQt6`, `PyQt6-QScintilla` e **`cryptography`** (necessária ao Cofre, à
> Custódia e ao Release). O documento antigo listava só as duas primeiras — antes
> de o Cofre existir.

### Dependências entre módulos

```mermaid
graph TD
    main["main.py"] --> mw["mainwindow.MainWindow"]
    main --> theme["theme.apply_app"]
    main --> init["notepy.__init__"]

    mw --> editor["editor.CodeEditor"]
    mw --> findbar["findbar"]
    mw --> prefs["preferences"]
    mw --> theme

    editor --> lexers["lexers.lexer_for_path"]
    editor --> theme
    editor --> secrets["secrets.scan"]
    editor --> vault["vault (Cofre RDBT2)"]
    editor --> custody["custody (Ed25519 + trilha)"]

    mw --> secrets
    mw --> vault
    mw --> custody
    mw --> scancli["scan_cli (hook git)"]
    mw --> searchfiles["searchfiles (grep)"]
    mw --> palette["palette (fuzzy)"]
    mw --> difftool["difftool (diff)"]
    mw --> config["config (QSettings)"]

    scancli --> secrets
    release["release (RDBT-REL1)"] --> custody
    verify["verify_release.py (standalone)"] -. espelha .-> release

    vault --> crypto["cryptography"]
    custody --> crypto
    release --> crypto

    lexers --> qsci["PyQt6.Qsci"]
    theme --> qt["PyQt6.QtGui"]

    classDef sec fill:#2a0f10,stroke:#F85149,color:#F85149;
    classDef pure fill:#0d1f12,stroke:#3FB950,color:#3FB950;
    class secrets,vault,custody,release,scancli pure;
    class editor,mw sec;
```

Repare nas setas-chave: **a UI depende dos núcleos, mas nenhum núcleo depende do
Qt.** `secrets`, `vault`, `custody`, `release`, `scan_cli`, `searchfiles`,
`palette`, `difftool` e `config` são todos testáveis sem interface gráfica (ver
[Testabilidade](#7-testabilidade-e-ambiente)). `vault`, `custody` e `release`
dependem de `cryptography` — mas não do Qt.

---

## 2. Responsabilidade de cada módulo

### `main.py` — ponto de entrada

Fino de propósito. Cria a `QApplication`, define o nome de aplicação a partir de
`APP_NAME`, aplica o ícone e o tema global (`theme.apply_app`) e instancia a
`MainWindow`. Em seguida abre cada caminho passado em `sys.argv[1:]` (suporte a
"Abrir com…" e linha de comando, incluindo `.rdbt`) e, se algum arquivo foi
aberto, descarta a aba inicial vazia.

```
python main.py [arquivo1 arquivo2 ...]
```

### `notepy/__init__.py` — identidade

Três constantes: `APP_NAME = "Redoubt"`, `APP_VERSION = "1.0.0"` e
`APP_TAGLINE = "Nada vaza sem você mandar."`. É o ponto único de verdade sobre
nome/versão do produto; todos os outros módulos importam daqui.

### Núcleos puros (sem Qt)

#### `notepy/secrets.py` — a Sentinela de Segredos

Detector **puro Python, sem Qt**. Expõe a dataclass `Match(start, end, kind,
snippet)` e a função `scan(text, *, entropy=True) -> list[Match]`. A detecção é
em **5 camadas**, da maior para a menor confiança, com filtro global de
placeholder e deduplicação O(n) por sobreposição de *spans* (teto
`MAX_MATCHES = 2000`). Detalhada na [seção 6](#6-segurança-modelo-e-limitações-honestas)
e na [ADR-4](#adr-4--detecção-em-camadas-com-filtro-de-placeholder).

#### `notepy/vault.py` — o Cofre++ (`.rdbt`)

Cifragem em repouso, **sem Qt**, dependendo de `cryptography`. Formato **RDBT2**
em *envelope* / *key-slots* (estilo LUKS/age): uma **chave-de-conteúdo (CK)**
aleatória de 256 bits cifra o texto com **AES-256-GCM**; cada destravador (senha
**ou** arquivo-chave) é um *slot* de 80 bytes que **embrulha** a CK via chave
derivada por **scrypt**. API: `new_vault` / `open_vault` / `reseal` /
`add_unlocker` / `slot_kinds` (e `encrypt`/`decrypt` mantidos por
retrocompatibilidade). Lê e migra em memória o formato legado **RDBT1** (senha
única). Detalhado na [seção 6](#o-cofre--confidencialidade-em-repouso) e na
[ADR-5](#adr-5--cofre-em-envelope-rdbt2-múltiplos-destravadores).

#### `notepy/custody.py` — Custódia assinada + trilha de auditoria

**Sem Qt**, depende de `cryptography`. Mantém uma **identidade Ed25519 por
instalação**; assina/verifica conteúdo; exporta a chave pública (`identity.pub`,
em claro). Mantém uma **trilha de auditoria hash-chain append-only**
(`audit.log`) dos eventos (abrir/salvar/selar/queimar/assinar), em que cada
entrada inclui o hash da anterior — adulterar um evento passado quebra a cadeia
(`verify_chain`). Por padrão a chave privada é PEM local **sem senha**
(`identity.ed25519`); opcionalmente (opt-in *Proteger identidade*) a privada é
embrulhada num Cofre RDBT2 (`identity.rdbt`) e o PEM é apagado. Detalhado na
[seção 6](#a-custódia-assinada--integridade--autenticidade) e na
[ADR-7](#adr-7--identidade-protegida-opt-in).

#### `notepy/release.py` — manifesto de release assinado

**Sem Qt**, depende de `cryptography`. Gera, ao lado dos binários, um
`SHA256SUMS` + um `RELEASE.json` no formato **RDBT-REL1**: um **`signed_payload`**
(string JSON canônica com produto/versão/data/pubkey/fingerprint e
sha256+tamanho de cada artefato) + uma **assinatura Ed25519** dessa string.
`verify_manifest` checa a assinatura **sobre a string** e só então parseia. O
fingerprint é **sempre derivado** da chave (`sha256(pubkey)[:16]`), nunca lido de
um campo. Detalhado na [seção 6](#o-release-assinado--prova-do-próprio-download)
e na [ADR-6](#adr-6--release-assinado-pela-string-canônica--âncora-de-pubkey).

#### `notepy/scan_cli.py` — CLI da Sentinela + hook git

**Sem Qt**, reusa `secrets.scan`. `python -m notepy.scan_cli [arquivos]` varre
arquivos; `--staged` varre o *stage* (via `git show :arquivo` — exatamente o que
será commitado); `--install-hook` instala um `pre-commit` que bloqueia o commit
(saída ≠ 0) se houver credencial, com backup de hook alheio. `_decode` trata BOM
UTF-16/UTF-32 e densidade de NUL (não pula arquivos *wide-encoded*); pula binário
denso e arquivos > 2 MB (avisando). É **fail-closed** quando o git falha dentro
de um repo. O relatório **nunca** imprime o segredo (só `arquivo:linha:coluna`,
tipo e prévia mascarada `●●●`).

#### `notepy/searchfiles.py`, `palette.py`, `difftool.py`, `config.py`

- **`searchfiles.py`** — grep recursivo numa pasta (texto ou regex), com proteção
  anti-ReDoS, pulando binários, arquivos > 2 MB e pastas pesadas (`.git`,
  `node_modules`…), com teto de resultados.
- **`palette.py`** — busca fuzzy da paleta de comandos (`fuzzy_score`/`rank`).
- **`difftool.py`** — *unified diff* estilo git via `difflib`.
- **`config.py`** — wrapper de `QSettings` (auto-lock, fonte, largura de tab,
  tema, sessão); clampa inteiros e coage tipos (defesa contra registro adulterado);
  `save_session`/`load_session` guardam **só caminhos**, nunca conteúdo.

### Camada UI (PyQt6)

#### `notepy/editor.py` — `CodeEditor`, o widget que vigia

Herda de `QsciScintilla` e representa **um documento (uma aba)**. É o coração da
vigilância. Responsabilidades:

- **Aparência/comportamento**: fonte monoespaçada (a 1ª realmente instalada —
  Cascadia/Consolas — via `_monospace_font()`), números de linha, *folding*,
  auto-indent, *brace matching*, EOL Windows por padrão, UTF-8.
- **Indicadores de segurança**: `SECRET_INDICATOR = 8` (squiggle vermelho sob o
  texto) e `REDACT_INDICATOR = 9` (tarja preta sólida sobre o texto — o Modo
  Redação).
- **Vigilância com debounce**: um `QTimer` *single-shot* de **300 ms** é
  reiniciado a cada `textChanged`; ao disparar chama `secrets.scan`, converte
  offsets de *caractere* → *byte*, preenche os indicadores e **emite
  `secretsChanged(int)`**. Acima de `_SCAN_LIMIT` (2 000 000 chars) a varredura
  por digitação é suspensa. Com a redação **ligada**, a varredura roda síncrona
  (sem debounce) para não deixar janela de exposição.
- **Custódia**: `content_hash()` (SHA-256 do conteúdo **vivo**), `mark_saved()`,
  `saved_hash`; `custody_text` usa o texto real em RAM (não o banner de oculto).
- **Cofre / oculto / burn**: `lock`/`unlock` (re-cifra em memória, esvazia o undo
  com `SCI_EMPTYUNDOBUFFER`), `gate`/`reveal`/`is_gated` (conteúdo oculto),
  `is_burn`/`_wipe_editor` (Burn Note).
- **Leitura robusta**: `read_text(path)` tenta `utf-8-sig` → `utf-8` → `cp1252`
  → `latin-1`, detecta BOM UTF-16/UTF-32 e neutraliza NUL (`→ ␀`, não trunca);
  `detect_eol(text)` infere o EOL predominante.

#### `notepy/mainwindow.py` — `MainWindow`, a casca

Herda de `QMainWindow`. Orquestra a UI, reage aos sinais do `CodeEditor` e chama
os núcleos:

- **Abas** (`QTabWidget`, fecháveis/móveis/document mode), cada uma um
  `CodeEditor`.
- **Menus** Arquivo / Editar / Segurança / Ajuda; toolbar; barra de status.
- **Barra de status (selo + custódia)**: selo de estado (`● LIMPO` /
  `▲ EXPOSTO · n` / `■ REDIGIDO · n` / `🔒 COFRE`·`TRAVADO` / `🛡️ OCULTO` /
  `🔥 BURN` / `⚠ NÃO VERIFICADO`); `custódia: <hash 8 hex>` (ou `░ alterado`),
  `Lin/Col`, linguagem, encoding.
- **Ações de segurança**: Modo Redação (`Ctrl+Shift+R`), Ir ao próximo segredo
  (`F8`), Relatório (`Ctrl+Shift+E`), Verificar custódia (`Ctrl+Shift+H`),
  Assinar e exportar `.sig` (`Ctrl+Shift+G`), Selar como cofre (`Ctrl+Shift+L`),
  Travar/Destravar (`Ctrl+Shift+K` / `Ctrl+Shift+U`), Burn (`Ctrl+Shift+B`),
  Proteger repositório git, Proteger identidade.
- **`_sanitize_clipboard`**: ligado no sinal `dataChanged` do `QClipboard`,
  mascara segredos detectados de **todas** as abas em redação (pega todos os
  caminhos nativos do Scintilla).
- **Produtividade**: Busca em arquivos (`Ctrl+Shift+F`), Paleta (`Ctrl+Shift+P`),
  Diff (`Ctrl+Shift+D`), barra `:` (`Ctrl+P`).
- **Padrão**: Novo/Abrir/Salvar/Salvar como/Fechar/Sair, drag & drop, aviso ao
  fechar com alterações não salvas.

> **Nota sobre atalhos (Windows).** *Fechar aba* e *Sair* usam `Ctrl+W`/`Ctrl+Q`
> explícitos (no Windows `StandardKey.Close` resolveria para `Ctrl+F4`). O
> `CodeEditor` **libera** (`SCI_CLEARCMDKEY`) as combinações `Ctrl+Shift+<letra>`
> que o Redoubt usa como ação de janela — sem isso o keymap interno do QScintilla
> as consumia (apagar linha / MAIÚSCULAS) e o atalho só funcionava pelo menu.

#### `notepy/findbar.py`, `preferences.py`, `lexers.py`, `theme.py`

- **`findbar.py`** — barra Localizar/Substituir com regex, *match* de largura
  zero tratado (anti-loop) e teto `_REPLACE_CAP`.
- **`preferences.py`** — diálogo `Ctrl+,` (auto-lock, fonte, tab, tema,
  restaurar sessão), aplicado ao vivo.
- **`lexers.py`** — mapeia extensão/nome → classe de lexer do QScintilla
  (`_EXT_LEXER` ~50 linguagens, `_NAME_LEXER` para `makefile`/`.gitignore`…) e
  devolve a instância configurada, ou `None` se a versão instalada não tiver
  aquele lexer (não quebra).
- **`theme.py`** — paletas `dark` (carbono) e `light`, ambas semânticas (âmbar =
  atenção/marca, verde = selado/limpo, vermelho = exposto), QSS via
  `string.Template`, `apply_app`/`apply_editor_theme`/`retheme_lexer` e
  `set_theme` (re-tematização ao vivo). Detalhado na
  [seção 4](#4-re-tematização-de-lexer-via-description).

---

## 3. Fluxo de dados: do arquivo ao selo

O caminho que liga "abrir/editar um arquivo" ao "selo de estado + custódia"
passa por debounce, detector e sinal Qt:

```mermaid
sequenceDiagram
    autonumber
    actor U as Usuário
    participant MW as MainWindow
    participant ED as CodeEditor (QsciScintilla)
    participant T as QTimer (300 ms)
    participant S as secrets.scan

    Note over U,MW: Abertura
    U->>MW: open_path(arquivo) / drag&drop / argv
    MW->>ED: read_text, detect_eol, setText
    MW->>ED: apply_lexer_for_path, mark_saved
    ED-->>MW: textChanged (carga inicial)

    Note over ED,T: Edição (debounce)
    U->>ED: digita / cola
    ED->>T: textChanged → timer.start() reinicia 300 ms
    Note right of T: redação ON → varre síncrono (sem debounce)
    T->>ED: timeout → _rescan_secrets()
    ED->>S: scan(text)
    S-->>ED: list[Match]
    ED->>ED: offsets char→byte, preenche SECRET_INDICATOR (e REDACT se redação ON)
    ED-->>MW: secretsChanged(n)

    Note over MW: Atualização da casca
    MW->>MW: _refresh_tab (prefixo ▲/•)
    MW->>MW: _update_seal (LIMPO / EXPOSTO / REDIGIDO)
    MW->>MW: _update_window_title
    MW-->>U: aviso transitório se n aumentou
```

Pontos importantes do fluxo:

1. **O debounce evita travar.** Cada tecla reinicia o `QTimer`; a varredura roda
   uma vez 300 ms após a última tecla. **Exceção:** com o Modo Redação **ligado**,
   a varredura roda síncrona a cada mudança — não pode haver uma janela de ~300 ms
   com o segredo em claro durante um *screen-share*.
2. **Offsets char → byte.** `secrets.scan` raciocina em offsets de *caractere*; o
   Scintilla endereça em *bytes UTF-8*. O `CodeEditor` faz a conversão antes de
   preencher os indicadores — crucial para arquivos com acentos/multibyte.
3. **`secretsChanged(int)` é o contrato.** O `CodeEditor` não sabe de selos, abas
   ou títulos; só emite a contagem. A `MainWindow` traduz isso em UI. Acoplamento
   solto via sinal Qt.
4. **A custódia compara o hash vivo.** `mark_saved()` fixa a baseline; a
   verificação usa o `content_hash()` do momento (não `isModified()`), então
   adulteração externa aparece de relance ao reabrir.

---

## 4. Re-tematização de lexer via `description()`

**O problema.** Cada `QsciLexer*` traz suas **próprias cores padrão** (a cara do
Notepad++) e numera os "estilos" (comentário, palavra-chave, string…) com **ids
diferentes por linguagem**. Mapear ids manualmente seria frágil.

**A solução** (`theme.retheme_lexer`). Em vez de ids, o Redoubt usa a
**descrição textual** de cada estilo. Para cada `style` de `0` a `127`, lê
`lexer.description(style)`, normaliza e classifica por palavra contida:

| Descrição contém…                          | Cor aplicada      |
|--------------------------------------------|-------------------|
| `comment`                                  | `DIM` (apagado)   |
| `keyword` / `key word`                     | `AMBER` (marca)   |
| `string` / `char` / `heredoc`              | `GREEN`           |
| `number` / `numeric`                       | `CYAN`            |
| `preprocessor` / `directive` / `decorator` | `TERRACOTA`       |
| `class` / `type` / `tag`                   | `VIOLET`          |
| `function` / `method` / `identifier`       | `TEXT` (base)     |
| (vazia / nenhum dos acima)                 | `TEXT` (base)     |

O papel (fundo) de **todos** os estilos é fixado em `BG`. Resultado: **uma única
função pinta qualquer um dos ~50 lexers** de forma consistente, sem tabela por
linguagem. Desde a v0.9.0 a paleta é trocável em runtime (`set_theme`): trocar de
tema re-tematiza o app, todas as abas e seus lexers ao vivo.

**Quem chama, e por que duas vezes.** `CodeEditor.apply_lexer_for_path` faz
`setLexer` → `retheme_lexer` → **`apply_editor_theme`** → restaurar fonte das
margens. A chamada extra a `apply_editor_theme` *depois* de `setLexer` é
deliberada: trocar o lexer reseta cores de margem/caret que não pertencem ao
lexer.

---

## 5. Subsistemas de segurança (visão de arquitetura)

Os quatro subsistemas de segurança não-Sentinela compartilham um princípio:
**lógica no núcleo puro, orquestração na UI.** A `MainWindow` nunca implementa
cripto; ela chama `vault`/`custody`/`release`/`scan_cli` e traduz o resultado.

| Subsistema   | Núcleo (sem Qt)        | Cripto             | Eixo que cobre                  |
|--------------|------------------------|--------------------|---------------------------------|
| Cofre `.rdbt`| `vault.py`             | AES-256-GCM + scrypt | Confidencialidade em repouso    |
| Custódia     | `custody.py`           | Ed25519 + SHA-256  | Integridade + autenticidade     |
| Hook git     | `scan_cli.py`          | (reusa `secrets`)  | Prevenção de vazamento no commit|
| Release      | `release.py` + `verify_release.py` | Ed25519  | Integridade + autenticidade do download |

A identidade Ed25519 é **uma só**: a mesma chave que a Custódia usa para assinar
arquivos assina o `RELEASE.json`. O fingerprint oficial do autor é
`4e391f28930f3b6e`.

---

## 6. Segurança: modelo e limitações honestas

O Redoubt é uma ferramenta de **defesa local e best-effort**. O modelo de ameaça
separa **três eixos** — e o que protege um eixo não protege os outros:

- **Confidencialidade em repouso → o Cofre.** (cifra o conteúdo no disco)
- **Integridade + autenticidade → a Custódia assinada / o Release.** (prova que
  não mudou e de quem veio — não esconde nada)
- **Detecção e privacidade → a Sentinela / ocultar / redação.** (best-effort;
  ocultar não cifra)

### A Sentinela em 5 camadas

`secrets.scan` aplica as camadas em ordem de confiança e **deduplica por
sobreposição**, descartando matches que casem com o filtro de placeholder:

1. **Padrões de provedor** (~26 padrões, alta confiança): AWS `AKIA`/`ASIA`, JWT,
   chave privada PEM (incl. `ENCRYPTED`/`PGP BLOCK`), GitHub clássico +
   fine-grained (`github_pat_`), GitLab (`glpat-`), Slack token + webhook, OpenAI
   (`sk-`/`sk-proj-`), Stripe, SendGrid, Twilio, npm, Google API (`AIza`), Google
   OAuth (`GOCSPX-`), Telegram, Azure Storage (`AccountKey=`), Shopify
   (`shpat_`…), DigitalOcean (`dop_v1_`), Square (`sq0atp-`/`sq0csp-`), PyPI
   (`pypi-AgEI`), HashiCorp Vault (`hvs.`), Doppler (`dp.`…), Basic Auth, Bearer,
   *connection strings*.
2. **Atribuição `keyword = valor`** com/sem aspas, com porteira de complexidade
   (≥ 8 chars, ≥ 2 classes, não-UUID) e contextos benignos ignorados (csrf,
   paginação, anti-forgery).
3. **PII brasileira**: CPF e CNPJ, mascarados e sem máscara, validados por
   **dígito verificador**.
4. **Cartão de crédito**: validado por **Luhn** + comprimento (13/14/15/16/19) +
   IIN.
5. **Rede de entropia (Shannon)**: limiar **4.5** para tokens ≥ 32 chars,
   excluindo hex puro (md5/sha1/sha256), *data URIs* e hashes SRI.

**Filtro de placeholder (global).** Descarta material de exemplo (`example`,
`dummy`, `placeholder`, `changeme`, `your-`, `-here`, `xxxx`, `${`, `{{`,
`fixme`, `todo`, `redacted`, `lorem`, `<…>`, e 8+ chars idênticos via
`_REPEAT_RE`). Por isso `AKIAIOSFODNN7EXAMPLE` **não** dispara alarme.

**Garante:** detecção local (sem rede) de credenciais/PII de formato conhecido ou
alta entropia, com validação real onde possível (dígito verificador, Luhn).
Medido contra o corpus adversarial de 80 casos: **Recall ~92% / Precisão ~87%**
(v1 ingênua era 46% / 55%).

**Não garante:** não é oráculo. Segredo sem padrão conhecido, ofuscado/dividido,
ou degenerado escapa (~8% FN). Há falsos-positivos (base64 de imagem, JS
minificado, SKU com forma de chave). **"LIMPO" = "nada detectado", não "sem
segredo".**

### O Cofre — confidencialidade em repouso

`vault.py`, formato **RDBT2** (*envelope* / *key-slots*). Uma CK aleatória cifra
o conteúdo com **AES-256-GCM**; cada destravador (senha **ou** arquivo-chave) é
um slot que embrulha a CK via chave derivada por **scrypt** (não PBKDF2 — o
roadmap antigo errava ao dizer PBKDF2). Até 16 slots; **múltiplas senhas e/ou
arquivos-chave** abrem o mesmo cofre; `reseal` preserva todos os slots. A AAD liga
o conteúdo a todos os slots (anti slot-strip); `_check_kdf` valida `log2n/r/p`
(anti scrypt-bomb). Lê e migra RDBT1 legado em memória.

**Garante:** confidencialidade em repouso, **zero-knowledge** (nenhuma credencial
é gravada; esqueceu = irrecuperável). GCM autenticado: senha errada e adulteração
de ciphertext/salt/nonce/slot viram `InvalidTag → WrongPassword`. Disco sempre
cifrado.

**Não garante:** não protege integridade/autoria de quem cifrou (isso é a
Custódia); não recupera senha esquecida; não elimina resíduo de plaintext em
RAM/swap enquanto destravado.

### A Custódia assinada — integridade + autenticidade

`custody.py`, **identidade Ed25519 por instalação**. Assina/verifica conteúdo;
exporta `.sig` + chave pública (`identity.pub`, claro). Trilha de auditoria
**hash-chain append-only** (`audit.log`): cada entrada inclui o hash da anterior,
então adulterar um evento passado quebra `verify_chain`. Por padrão a privada é
PEM local **sem senha**; opt-in *Proteger identidade* embrulha-a num Cofre RDBT2
(senha + arquivo-chave) e apaga o PEM (escrita atômica + wipe + rollback;
auto-cura de PEM órfão). Só **assinar** pede senha (lazy + cache de sessão);
fingerprint/verificação não.

**Garante:** prova *"veio desta instalação e não mudou desde que assinei"*, desde
que a chave não vaze. Protegida: a privada só é útil com a credencial
(zero-knowledge). A trilha detecta adulteração retroativa de eventos.

**Não garante:** não dá confidencialidade do conteúdo. **Sem proteção, quem tem a
máquina assina como você** (a privada é local). O `content_hash` sozinho não prova
nada (qualquer um recalcula) — a prova é a **assinatura**.

### O Release assinado — prova do próprio download

`release.py` + `verify_release.py` (standalone na raiz, embute a pubkey do autor
`4e391f28930f3b6e`). Gera `SHA256SUMS` + `RELEASE.json` (**RDBT-REL1**):
`signed_payload` (string JSON canônica) + assinatura Ed25519 sobre **essa
string**. O verificador checa a assinatura sobre a string e só então parseia
(zero divergência gerador/verificador); o fingerprint é sempre **derivado** da
chave.

**Garante:** integridade (assinatura válida + hashes batem) **E** autenticidade —
`ok=True` só quando o fingerprint derivado bate com a âncora embutida/`--pubkey`.
Binário re-assinado com outra chave é rejeitado; o manifesto falha se algum hash
não bater.

**Não garante:** a assinatura **sozinha** não prova autenticidade (a pubkey viaja
no payload; um atacante re-assina com a própria chave) — por isso depende da
âncora. A chave privada do autor é local e por padrão sem senha.

### Modo Redação, Ocultar e Burn — privacidade (não cifra)

- **Modo Redação** (`Ctrl+Shift+R`): tarja os segredos na **tela** (visual) e
  **mascara o clipboard** (`_sanitize_clipboard` no `dataChanged`). *Garante:*
  esconde de olhos/câmeras e mascara o clipboard para o que a Sentinela
  **detectou**. *Não garante:* a tarja é visual — o conteúdo real permanece no
  documento e no disco; segredo sem padrão (ou cópia parcial < 6 chars) escapa do
  mascaramento.
- **Restaurar com conteúdo OCULTO**: ao restaurar um arquivo em claro com
  credencial detectada, abre **oculto** (anti screen-share), com *Revelar* /
  *Selar como cofre*; salvar bloqueado enquanto oculto. *Não garante:* ocultar
  **não cifra** — o arquivo segue em claro no disco. A proteção real em repouso é
  *Selar como cofre*.
- **Burn Note** (`Ctrl+Shift+B`): aba só-RAM, nunca vai ao disco, apagada ao
  fechar (buffer sobrescrito, undo zerado, clipboard limpo). *Não garante:* não
  elimina resíduo em RAM/swap (Python não zera strings imutáveis; o GC libera).
  **Reduz, não elimina.**

### Limitações transversais (parte do contrato)

- **(a) RAM não é zerável de forma garantida.** Burn e *lock* **reduzem** o
  resíduo, não o eliminam.
- **(b) Detecção é best-effort.** Há falsos-positivos e falsos-negativos.
- **(c) Tudo roda LOCAL.** Sem rede, sem telemetria, sem nuvem.

---

## 7. Testabilidade e ambiente

- **Núcleos isoláveis.** `secrets`, `vault`, `custody`, `release`, `scan_cli`,
  `searchfiles`, `palette`, `difftool` e `config` não importam Qt e são testados
  sem interface gráfica. `exemplo_segredos.py` é fixture da Sentinela.
- **Teste headless.** Para a UI, use `QT_QPA_PLATFORM=offscreen` e
  `PYTHONIOENCODING=utf-8` — os glifos de selo (`●`/`▲`/`■`/`░`/`🔒`/`🔥`) quebram
  no console cp1252 do Windows, mas funcionam dentro do Qt.
- **Suíte.** **212 testes** (pytest), 0 falhas, validados também por 4 pentests
  adversariais (relatório §1–§7 em `docs/SECURITY-TEST-REPORT.md`) e por
  verificação ponta-a-ponta do hook num repositório git real.
- **`run.bat`** abre o app sem console (via `pythonw`).

---

## 8. Decisões de arquitetura (ADRs)

### ADR-1 — Stack PyQt6 / QScintilla

**Contexto.** Era preciso um editor desktop nativo, com realce maduro para muitas
linguagens, sem arrastar um runtime web.
**Decisão.** **Python 3.11 + PyQt6 + PyQt6-QScintilla**. QScintilla é o mesmo
motor Scintilla do Notepad++, com lexers prontos para ~50 linguagens.
**Alternativas.** Electron + Monaco (peso do Chromium, superfície web), Tauri +
Rust (curva de Rust), C#/.NET WPF (amarra a Windows/.NET).
**Consequências.** Dependências enxutas (`PyQt6`, `PyQt6-QScintilla`; mais
`cryptography` para os cofres); realce maduro "de graça"; herda as cores default
do Scintilla — resolvido pela re-tematização da [seção 4](#4-re-tematização-de-lexer-via-description).

### ADR-2 — Identidade "Redoubt"

**Contexto.** O produto precisava de um nome e identidade visual que
comunicassem **segurança**.
**Decisão.** Adotar **Redoubt** (forte/reduto), paleta carbono+âmbar com cor
semântica, escolhido por **Natan**.
**Consequências.** O nome do produto descola do pacote (`notepy/`, histórico) e
da pasta (`Notepad`); a renomeação fica centralizada em `APP_NAME`.

### ADR-3 — Sem virtualenv (por causa do OneDrive)

**Contexto.** A pasta do projeto vive **dentro do OneDrive**, que sincroniza
continuamente.
**Decisão.** **Não criar `venv`**; instalar dependências no Python global.
**Motivo.** Um `venv` dentro do OneDrive geraria milhares de arquivos
sincronizados, com risco de corrupção e custo de sync.
**Consequências.** Reprodutibilidade depende do Python global; `requirements.txt`
é a fonte de verdade das dependências. Aceito conscientemente para este projeto
pessoal.

### ADR-4 — Detecção em camadas com filtro de placeholder

**Contexto.** Um detector ingênuo grita "lobo" demais (placeholders, hashes) ou
de menos (formatos não cobertos).
**Decisão.** Detector em **5 camadas por confiança decrescente** + **filtro
global de placeholder** + **validação real** (dígito verificador CPF/CNPJ, Luhn,
exclusão de hash por comprimento) + **entropia de Shannon** como rede final.
Manter `secrets.py` **sem Qt**.
**Validação.** Endurecido contra um corpus de 80 casos: Recall 46% → 92%,
Precisão 55% → 87%.
**Consequências.** Detector testável headless e isolado; trade-off explícito
FP×FN, documentado nas [limitações honestas](#a-sentinela-em-5-camadas).

### ADR-5 — Cofre em envelope RDBT2 (múltiplos destravadores)

**Contexto.** Cifrar o conteúdo com uma única senha derivada amarraria o cofre a
um segredo só — sem rotação de senha, sem "algo que você tem".
**Decisão.** Formato **envelope** (estilo LUKS/age): uma CK aleatória cifra o
conteúdo; cada destravador (senha **ou** arquivo-chave) é um **slot** que embrulha
a CK via **scrypt** (memory-hard, validado contra scrypt-bomb). Até 16 slots; a
AAD liga o conteúdo aos slots (anti slot-strip); `reseal` re-cifra sem re-derivar
credenciais. Lê/migra RDBT1.
**Consequências.** Múltiplas senhas independentes e arquivo-chave abrem o mesmo
cofre; rotação trivial. **Scrypt** (não PBKDF2) é a KDF efetiva. Mantém
retrocompatibilidade com cofres antigos.

### ADR-6 — Release assinado pela string canônica + âncora de pubkey

**Contexto.** Assinar um objeto JSON e re-serializá-lo no verificador abre
divergência gerador↔verificador; e uma assinatura "auto-contida" (pubkey no
payload) prova integridade, não autenticidade.
**Decisão.** A assinatura cobre **a string canônica `signed_payload`**, não o
objeto; o verificador checa a assinatura sobre a string e só então parseia. O
fingerprint é **sempre derivado** (`sha256(pubkey)[:16]`); `verify_release.py`
**embute** a pubkey do autor e só dá `ok=True` quando o derivado bate com a
âncora.
**Consequências.** Zero divergência de serialização; autenticidade real contra a
âncora (binário re-assinado com outra chave é rejeitado). Limite honesto: a
âncora chega pelo mesmo canal/repositório que você já confia.

### ADR-7 — Identidade protegida opt-in

**Contexto.** Por padrão a chave privada Ed25519 é PEM local **sem senha** —
quem tem a máquina assina como o autor. Forçar senha em todo uso atritaria o fluxo
normal de custódia.
**Decisão.** Manter o padrão sem senha (uso pessoal), com **opt-in** *Proteger
identidade*: embrulha a privada num Cofre RDBT2 (`identity.rdbt`, senha +
arquivo-chave, multi-slot) e apaga o PEM; a pública fica em claro
(`identity.pub`). Só **assinar** pede a credencial (lazy + cache de sessão);
fingerprint/verificação não. Proteger/desproteger é atômico (wipe + rollback) com
auto-cura de PEM órfão.
**Consequências.** O usuário escolhe o trade-off conveniência×proteção da chave.
Protegida, a privada é zero-knowledge; o fingerprint da identidade é preservado na
transição.