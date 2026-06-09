# Arquitetura do Redoubt

> **Redoubt** v0.2.0 — *editor que trata cada arquivo como evidência.*
> Tagline: **"Nada vaza sem você mandar."**

Este documento descreve **como o Redoubt é montado por dentro**: os módulos, suas
responsabilidades, o fluxo de dados que liga uma tecla digitada à varredura de
segredos e ao selo de estado na barra de status, o mecanismo de re-tematização
dos lexers e as principais decisões de arquitetura (ADRs).

Tudo aqui descreve o que está **no código** — não há promessas de funcionalidades
ainda inexistentes. O backlog declarado de funcionalidades futuras está isolado
na seção [Roadmap (Fase 3)](#roadmap-fase-3).

---

## 1. Visão geral

O Redoubt é um editor de texto/código **desktop**, em **Python 3.11**, construído
sobre **PyQt6** e **PyQt6-QScintilla** (o mesmo motor Scintilla que o Notepad++
usa). Não há servidor, nuvem nem chamadas de rede: **tudo roda localmente**.

A diferença em relação a um editor comum é a **segurança como identidade**. Cada
documento aberto é vigiado por uma *Sentinela de Segredos*, que varre o conteúdo
a cada alteração, marca credenciais/PII com um indicador vermelho e permite
"redigir" (tarjar) os trechos. Cada documento também carrega uma **cadeia de
custódia**: um hash SHA-256 mostrado na barra de status, que muda de relance se o
conteúdo for adulterado.

> **Nota sobre o nome do pacote.** O produto se chama **Redoubt**, mas o pacote
> Python preserva o nome histórico **`notepy/`** e a pasta do projeto se chama
> `Notepad`. A renomeação vive em `notepy/__init__.py`
> (`APP_NAME = "Redoubt"`). Para renomear o app inteiro, basta trocar essa
> constante.

### Mapa de módulos

```
Notepad/                      (pasta do projeto)
├── main.py                   ponto de entrada
├── requirements.txt          PyQt6, PyQt6-QScintilla
├── run.bat                   abre sem console (pythonw)
├── exemplo_segredos.py       arquivo de demonstração do detector
└── notepy/                   (pacote — nome histórico)
    ├── __init__.py           identidade: APP_NAME / APP_VERSION / APP_TAGLINE
    ├── lexers.py             extensão de arquivo  -> lexer QScintilla
    ├── editor.py             CodeEditor (QsciScintilla) + vigilância de segredos
    ├── theme.py              paleta carbono, QSS e re-tematização dos lexers
    ├── secrets.py            Sentinela de Segredos (detector, sem Qt)
    └── mainwindow.py         MainWindow: abas, menus, barra de custódia, selo
```

### Dependências entre módulos

```mermaid
graph TD
    main["main.py"] --> mw["mainwindow.MainWindow"]
    main --> theme["theme.apply_app"]
    main --> init["notepy.__init__ (APP_NAME)"]

    mw --> editor["editor.CodeEditor"]
    mw --> theme
    mw --> init

    editor --> lexers["lexers.lexer_for_path"]
    editor --> theme
    editor --> secrets["secrets.scan"]

    lexers --> qsci["PyQt6.Qsci"]
    theme --> qt["PyQt6.QtGui"]

    classDef sec fill:#2a0f10,stroke:#F85149,color:#F85149;
    class secrets,editor sec;
```

Repare na seta-chave: **`editor` depende de `secrets`, mas `secrets` não depende
de nada do Qt.** O detector é deliberadamente isolado para ser testável headless
(ver [ADR-4](#adr-4--detecção-em-camadas-com-filtro-de-placeholder) e
[Testabilidade](#6-testabilidade-e-ambiente)).

---

## 2. Responsabilidade de cada módulo

### `main.py` — ponto de entrada

Fino de propósito. Cria a `QApplication`, define o nome de aplicação a partir de
`APP_NAME`, aplica o tema global (`theme.apply_app`) e instancia a `MainWindow`.
Em seguida abre cada caminho passado em `sys.argv[1:]` (suporte a "Abrir com…" e
linha de comando) e, se algum arquivo foi aberto, descarta a aba inicial vazia.

```
python main.py [arquivo1 arquivo2 ...]
```

### `notepy/__init__.py` — identidade

Apenas três constantes: `APP_NAME = "Redoubt"`, `APP_VERSION = "0.2.0"` e
`APP_TAGLINE = "Nada vaza sem você mandar."`. É o ponto único de verdade sobre o
nome/versão do produto; todos os outros módulos importam daqui.

### `notepy/lexers.py` — linguagem a partir do arquivo

Mapeia **extensão/nome de arquivo → classe de lexer do QScintilla** e devolve uma
instância já configurada com a fonte do editor — ou `None` para texto puro.

- `_EXT_LEXER`: dicionário de cerca de 50 linguagens (`.py` → `QsciLexerPython`,
  `.ts`/`.tsx` → `QsciLexerJavaScript`, `.yaml` → `QsciLexerYAML`,
  `.env`/`.toml`/`.ini` → `QsciLexerProperties`, etc.).
- `_NAME_LEXER`: nomes sem extensão (`makefile`, `cmakelists.txt`, `.gitignore`,
  `.editorconfig`).
- `lexer_for_path(path, font, parent)`: resolve o nome da classe, busca-a em
  `PyQt6.Qsci` via `getattr` e — se a versão instalada do QScintilla não tiver
  aquele lexer — retorna `None` em vez de quebrar. Aplica a fonte
  monoespaçada a todos os estilos antes de devolver.

### `notepy/editor.py` — `CodeEditor`, o widget que vigia

Herda de `QsciScintilla` e representa **um documento (uma aba)**. É o coração da
vigilância. Responsabilidades:

- **Aparência/comportamento** (`_setup_appearance`): fonte (JetBrains Mono com
  *fallback* para Consolas), margem de números de linha, *folding*, auto-indent
  de 4 espaços (sem tabs), *brace matching*, EOL Windows por padrão, UTF-8.
- **Indicadores de segurança** (`_setup_indicators`): dois indicadores do
  Scintilla com ids altos para não colidir com os do lexer —
  `SECRET_INDICATOR = 8` (rabisco/sublinhado vermelho desenhado **sob** o texto)
  e `REDACT_INDICATOR = 9` (caixa preta sólida desenhada **sobre** o texto, a
  tarja do Modo Redação).
- **Vigilância de segredos com debounce**: um `QTimer` *single-shot* de **300 ms**
  é (re)iniciado a cada `textChanged`; quando dispara, chama `_rescan_secrets`,
  que invoca `secrets.scan(text)`, converte os offsets de *caractere* para
  *byte* (as posições do Scintilla são em bytes), preenche os indicadores e
  **emite o sinal `secretsChanged(int)`** com a contagem de segredos. Arquivos
  acima de `_SCAN_LIMIT` (2 MB) não são varridos a cada tecla.
- **Redação visual** (`set_redaction`): liga/desliga o `REDACT_INDICATOR` sobre
  os mesmos *spans*. É **apenas visual** — o conteúdo real permanece no documento
  (ver [Limitações honestas](#5-segurança-modelo-e-limitações-honestas)).
- **Navegação** (`goto_next_secret`): pula o cursor ao próximo segredo, com
  *wrap-around*.
- **Cadeia de custódia**: `content_hash()` devolve o SHA-256 do conteúdo;
  `mark_saved()` fixa o hash do estado salvo; `saved_hash` expõe esse valor.
- **Leitura robusta**: `read_text(path)` tenta os encodings na ordem
  `utf-8-sig` (captura BOM) → `utf-8` → `cp1252` → `latin-1`, e devolve
  `(texto, codec)`; `detect_eol(text)` infere o tipo de quebra de linha
  predominante.

### `notepy/theme.py` — paleta carbono e re-tematização

Concentra a aparência. A cor é **semântica**: âmbar = atenção/marca,
verde = selado/limpo, vermelho = exposto/segredo.

- Paleta `BG #0E1116`, `PANEL #161B22`, `AMBER #E8A33D`, `GREEN #3FB950`,
  `RED #F85149` (entre outras).
- `QSS`: folha de estilo do *chrome* (menus, abas, barra de status, scrollbars,
  diálogos), montada com `string.Template` — escolhido porque trata `{ }` como
  literal e substitui apenas `$VAR`, evitando conflito com a sintaxe CSS-like do
  Qt Style Sheets.
- `apply_app(app)`: aplica o estilo **Fusion**, a `QPalette` escura e o `QSS`.
- `apply_editor_theme(ed)`: pinta o *canvas* do editor (papel, margens, caret,
  seleção, *braces*, guias de indentação) — as cores que o lexer **não** mexe.
- `retheme_lexer(lexer)`: repinta **todos os estilos do lexer** na paleta Redoubt.
  O mecanismo é detalhado na [seção 4](#4-re-tematização-de-lexer-via-description).

### `notepy/secrets.py` — a Sentinela de Segredos

Detector **puro Python, sem Qt**. Expõe a dataclass `Match(start, end, kind,
snippet)` e a função `scan(text, *, entropy=True) -> list[Match]`. A detecção é
em **5 camadas**, da maior para a menor confiança, com filtro global de
placeholder e deduplicação por sobreposição de *spans*. Detalhada na
[seção 5](#5-segurança-modelo-e-limitações-honestas) e na
[ADR-4](#adr-4--detecção-em-camadas-com-filtro-de-placeholder).

### `notepy/mainwindow.py` — `MainWindow`, a casca

Herda de `QMainWindow`. Orquestra a UI e reage aos sinais do `CodeEditor`.

- **Abas**: `QTabWidget` com abas fecháveis, móveis e em *document mode*. Cada
  aba é um `CodeEditor`.
- **Menus**: Arquivo / Editar / Segurança / Ajuda; uma toolbar; e uma barra de
  status.
- **Barra de status (cadeia de custódia)**: à esquerda o **selo de estado**
  (`● LIMPO` / `▲ EXPOSTO · n` / `■ REDIGIDO · n`); à direita
  `custódia: <hash 8 hex>` (ou `░ alterado` enquanto há edição não salva),
  `Lin/Col`, linguagem e encoding.
- **Marcação de abas**: prefixo `▲ ` quando há segredo, `• ` quando há alteração
  não salva.
- **Ações de segurança**: Modo Redação (`Ctrl+Shift+R`, *checkable*), Ir ao
  próximo segredo (`F8`), Relatório de segredos (`Ctrl+Shift+E`).
- **Ações padrão**: Novo (`Ctrl+N`), Abrir (`Ctrl+O`), Salvar (`Ctrl+S`), Salvar
  como (`Ctrl+Shift+S`), Fechar aba (`Ctrl+W`), Sair (`Ctrl+Q`); desfazer/refazer/
  recortar/copiar/colar/selecionar tudo.
- **Drag & drop** de arquivos abre; **aviso ao fechar** abas/janela com
  alterações não salvas.

> **Nota sobre atalhos (Windows):** *Fechar aba* e *Sair* usam
> `QKeySequence("Ctrl+W")` e `QKeySequence("Ctrl+Q")` **explícitos** — no Windows o
> `StandardKey.Close` resolveria para `Ctrl+F4` e o `StandardKey.Quit` ficaria sem
> tecla. O *Relatório de segredos* usa `Ctrl+Shift+E` para **não colidir** com
> *Salvar como…* (`Ctrl+Shift+S`, via `StandardKey.SaveAs`).

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
    Note right of T: só dispara após 300 ms sem novas teclas
    T->>ED: timeout → _rescan_secrets()
    ED->>S: scan(text)
    S-->>ED: list[Match]
    ED->>ED: offsets char→byte, preenche SECRET_INDICATOR e REDACT se redação ON
    ED-->>MW: secretsChanged(n)

    Note over MW: Atualização da casca
    MW->>MW: _refresh_tab (prefixo ▲/•)
    MW->>MW: _update_seal (LIMPO / EXPOSTO / REDIGIDO)
    MW->>MW: _update_window_title
    MW-->>U: aviso transitório se n aumentou
```

Pontos importantes do fluxo:

1. **O debounce evita travar.** Cada tecla reinicia o `QTimer`; a varredura só
   roda 300 ms após a última tecla. Em rajadas de digitação, `scan` roda uma vez,
   não a cada caractere.
2. **Offsets char → byte.** `secrets.scan` raciocina em offsets de *caractere*;
   o Scintilla endereça em *bytes UTF-8*. O `CodeEditor` faz a conversão
   (`len(text[:m.start].encode("utf-8"))`) antes de preencher os indicadores —
   crucial para arquivos com acentos/multibyte.
3. **`secretsChanged(int)` é o contrato.** O `CodeEditor` não sabe nada de selos,
   abas ou títulos; ele só emite a contagem. A `MainWindow` é quem traduz isso em
   UI (`_on_secrets_changed`). Acoplamento solto via sinal Qt.
4. **A custódia muda ao salvar/abrir.** `mark_saved()` fixa o hash; enquanto
   `isModified()` for verdadeiro, a barra mostra `░ alterado`. Adulteração externa
   aparece de relance porque o hash exibido após reabrir não baterá com o
   esperado.

---

## 4. Re-tematização de lexer via `description()`

**O problema.** Cada `QsciLexer*` do QScintilla traz suas **próprias cores
padrão** — que são a cara do Notepad++ — e numera os "estilos" (comentário,
palavra-chave, string, número…) com **ids diferentes por linguagem**. O estilo
"Comment" pode ser `1` em Python e outro número em C++. Mapear ids manualmente
seria frágil e exigiria uma tabela por lexer.

**A solução** (`theme.retheme_lexer`). Em vez de ids, o Redoubt usa a
**descrição textual** de cada estilo. Para cada `style` de `0` a `127`,
lê `lexer.description(style)`, normaliza para minúsculas e classifica por
palavra contida na descrição:

| Descrição contém…                              | Cor aplicada            |
|------------------------------------------------|-------------------------|
| `comment`                                      | `DIM` (apagado)         |
| `keyword` / `key word`                         | `AMBER` (marca)         |
| `string` / `char` / `heredoc`                  | `GREEN`                 |
| `number` / `numeric`                           | `CYAN`                  |
| `preprocessor` / `directive` / `decorator`     | `TERRACOTA`             |
| `class` / `type` / `tag`                       | `VIOLET`                |
| `function` / `method` / `identifier`           | `TEXT` (base)           |
| (descrição vazia / nenhum dos acima)           | `TEXT` (base)           |

O papel (fundo) de **todos** os estilos é fixado em `BG`, e
`setDefaultPaper`/`setDefaultColor` garantem que estilos não enumerados também
caiam na paleta carbono. O resultado: **uma única função pinta qualquer um dos
~50 lexers** de forma consistente, sem tabelas por linguagem.

**Quem chama, e por que duas vezes.** `CodeEditor.apply_lexer_for_path` faz:

```
setLexer(lexer)            # 1. troca o lexer (reseta margens/caret p/ default)
theme.retheme_lexer(lexer) # 2. repinta os estilos do lexer na paleta Redoubt
theme.apply_editor_theme   # 3. repinta o canvas — setLexer havia resetado margens/caret
setMarginsFont(...)        # 4. restaura a fonte das margens
```

A chamada extra a `apply_editor_theme` **depois** de `setLexer` é deliberada:
trocar o lexer reseta cores de margem/caret que não pertencem ao lexer, então
elas precisam ser re-aplicadas.

---

## 5. Segurança: modelo e limitações honestas

### A Sentinela em 5 camadas

`secrets.scan` aplica as camadas em ordem de confiança e **deduplica por
sobreposição** (um trecho só é reportado uma vez), descartando qualquer match que
case com o filtro de placeholder:

1. **Padrões de provedor** (alta confiança): Chave AWS (`AKIA` + 16), JWT
   (`eyJ…`, 2 ou 3 partes), Chave privada PEM, Token do GitHub
   (`ghp_`/`gho_`/…), Token e Webhook do Slack, OpenAI (`sk-` e `sk-proj-`),
   Stripe (`sk_live`/`sk_test`/`rk_…`), SendGrid (`SG.x.y`), Twilio
   (`AC`/`SK` + 32 hex), npm (`npm_` + 36), Google API (`AIza` + 35),
   Basic Auth, Bearer e *connection strings*
   (`mongodb`/`postgres`/`mysql`/`redis`/`amqp` com `user:senha@host`).
2. **Atribuição `keyword = valor`** com **ou sem** aspas
   (`password`/`senha`/`secret`/`api_key`/`token`/…), com **porteira de
   complexidade** do valor (≥ 8 chars, ≥ 2 classes de caractere, não-UUID) e uma
   **lista de contextos benignos** ignorados (`csrf`, paginação, anti-forgery…).
3. **PII brasileira**: CPF e CNPJ, **mascarados e sem máscara** (só dígitos),
   validados pelos **dígitos verificadores**.
4. **Cartão de crédito**: validado por **Luhn** + comprimento real
   (13/14/15/16/19) + IIN (começa em 2–6).
5. **Rede de entropia (Shannon)**: limiar **4.5** para tokens genéricos ≥ 32
   chars, excluindo hex puro de 32/40/64 (md5/sha1/sha256), *data URIs* e hashes
   SRI; rótulo "Possível segredo (alta entropia)".

**Filtro de placeholder (global).** Descarta matches contendo `example`,
`dummy`, `placeholder`, `changeme`, `your-`, `-here`, `xxxx`, `${`, `{{`,
`fixme`, `todo`, `redacted`, `lorem`, `<...>`, etc. Por isso a chave-exemplo
canônica da AWS `AKIAIOSFODNN7EXAMPLE` **não** é marcada.

### Red-team do detector (números medidos)

Um workflow gerou **80 casos adversariais** em 4 lentes (evasão de cloud/CI,
falso-positivo, PII brasileira, arquivos reais). Medido contra o próprio scanner:

| Versão              | Recall | Precisão |
|---------------------|:------:|:--------:|
| v1 (ingênuo)        | 46%    | 55%      |
| **v2 (endurecido)** | **92%**| **87%**  |

O endurecimento (v2) adicionou Stripe/SendGrid/Twilio/npm/Basic/Bearer/webhook
Slack, senha **sem** aspas, CPF/CNPJ **sem** máscara, cartão (Luhn) e o filtro de
placeholder; corrigiu um bug em que o regex de entropia incluía `=` e grudava o
nome-da-variável no valor, furando a exclusão de hash. A regressão dos casos
originais permaneceu intacta.

### Limitações honestas

- **(a) RAM não é zerável de forma garantida.** Python não garante apagar
  segredos da memória (strings imutáveis + GC). O *Burn Note* planejado
  **reduz** o resíduo, não o elimina.
- **(b) Detecção é *best-effort*.** Há **falsos-positivos** (ex.: base64 de
  imagem, JS minificado, um SKU com formato idêntico a chave AWS) e
  **falsos-negativos** (formatos de provedor desconhecidos, segredos
  ofuscados).
- **(c) Modo Redação é VISUAL.** A tarja cobre a tela, mas o **conteúdo real
  permanece no documento** — copiar o trecho ainda traz o segredo.
- **(d) Tudo roda LOCAL.** Sem rede, sem telemetria.

---

## 6. Testabilidade e ambiente

- **Detector isolável.** `secrets.py` não importa Qt; pode ser testado sem
  interface gráfica. `exemplo_segredos.py` serve de fixture de demonstração.
- **Teste headless.** Use `QT_QPA_PLATFORM=offscreen` e
  `PYTHONIOENCODING=utf-8` — os glifos de selo (`●`/`▲`/`■`/`░`) quebram no
  console cp1252 do Windows, mas funcionam dentro do Qt.
- **`run.bat`** abre o app sem console (via `pythonw`).

---

## 7. Decisões de arquitetura (ADRs)

### ADR-1 — Stack PyQt6 / QScintilla

**Contexto.** Era preciso um editor desktop nativo, com realce de sintaxe maduro
para muitas linguagens, sem arrastar um runtime web.
**Decisão.** **Python 3.11 + PyQt6 6.11 + PyQt6-QScintilla 2.14**. QScintilla é o
mesmo motor Scintilla do Notepad++, com lexers prontos para ~50 linguagens.
**Alternativas consideradas.** Electron + Monaco (peso do Chromium, superfície
web), Tauri + Rust (curva de Rust), C#/.NET WPF (amarra a Windows/.NET).
**Consequências.** Binário único de dependências enxutas (só PyQt6 e o add-on
QScintilla); realce maduro "de graça"; em troca, herda as cores default do
Scintilla — resolvido pela re-tematização da [seção 4](#4-re-tematização-de-lexer-via-description).

### ADR-2 — Identidade "Redoubt"

**Contexto.** O protótipo precisava de um nome e de uma identidade visual que
comunicassem **segurança**.
**Decisão.** Adotar **Redoubt** (forte/reduto), com paleta carbono+âmbar e cor
semântica, escolhido por **Natan**.
**Processo.** Um workflow gerou **6 conceitos** (Sereno, GLYPH, Redoubt, Sabiá e
duas variações de Lumen) por lentes criativas distintas e os julgou com **3
juízes**.
**Consequências.** O nome do produto (Redoubt) descola do nome do pacote
(`notepy/`, histórico) e da pasta (`Notepad`); a renomeação fica centralizada em
`APP_NAME` (ver [ADR centralizado em `__init__.py`](#notepyinit_py--identidade)).

### ADR-3 — Sem virtualenv (por causa do OneDrive)

**Contexto.** A pasta do projeto vive **dentro do OneDrive**, que sincroniza para
a nuvem continuamente.
**Decisão.** **Não criar `venv`**; instalar as dependências no Python global.
**Motivo.** Um `venv` dentro do OneDrive geraria milhares de arquivos
sincronizados, com risco de corrupção e custo de sincronização.
**Consequências.** Reprodutibilidade depende do Python global da máquina;
`requirements.txt` continua sendo a fonte de verdade das dependências. Aceito
conscientemente para este protótipo pessoal.

### ADR-4 — Detecção em camadas com filtro de placeholder

**Contexto.** Um detector ingênuo grita "lobo" demais (placeholders, hashes) ou
de menos (formatos de provedor não cobertos).
**Decisão.** Detector em **5 camadas por confiança decrescente** + **filtro
global de placeholder** + **validação real** onde possível (dígitos
verificadores de CPF/CNPJ, Luhn para cartão, exclusão de hash md5/sha por
comprimento) + **entropia de Shannon** como rede final. Manter o detector
(`secrets.py`) **sem dependência de Qt**.
**Validação.** Endurecido contra um corpus de **80 casos** de red-team; Recall
subiu de 46% → 92% e Precisão de 55% → 87% (v1 → v2).
**Consequências.** Detector testável headless e isolado do Qt; trade-off
explícito entre falsos-positivos e falsos-negativos, documentado nas
[limitações honestas](#limitações-honestas).

---

## Roadmap (Fase 3)

> Backlog declarado — **ainda não implementado**. Listado aqui apenas para
> contexto de evolução; nada nesta seção existe no código atual.

- **Cofre `.rdbt` cifrado** — AES-GCM, senha via PBKDF2 (adiciona a dependência
  `cryptography`).
- **Burn Note** — aba efêmera, só em RAM, que se autodestrói (reduz resíduo, ver
  limitação (a)).
- **Barra `:` onipresente** — `:seal` / `:burn` / `:redact` / `:hash`,
  substituindo o menu clássico.
- **Mapa de exposição na margem** — onde estão os segredos no arquivo.
