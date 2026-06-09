# Guia do Desenvolvedor — Redoubt

> **Redoubt** v0.2.0 — *editor que trata cada arquivo como evidência.*
> *Nada vaza sem você mandar.*

Este documento explica como configurar o ambiente, rodar, testar e **estender** o
Redoubt. Ele é voltado a quem vai mexer no código — para a visão de produto e a
parte de segurança, veja o `README.md` e (quando existir) `docs/SECURITY.md`.

> **Nota sobre nomes.** O *produto* se chama **Redoubt**. O *pacote Python* ainda
> se chama `notepy/` e a pasta do projeto se chama `Notepad/` — nomes históricos.
> O nome de exibição vive em `notepy/__init__.py` (`APP_NAME = "Redoubt"`); para
> renomear o app, basta trocar essa constante.

---

## Sumário

- [1. Pré-requisitos](#1-pré-requisitos)
- [2. Setup (sem venv — por causa do OneDrive)](#2-setup-sem-venv--por-causa-do-onedrive)
- [3. Como rodar](#3-como-rodar)
- [4. Como testar (headless)](#4-como-testar-headless)
- [5. Estrutura de pastas](#5-estrutura-de-pastas)
- [6. Como estender](#6-como-estender)
  - [6.1 Adicionar uma nova linguagem (lexer)](#61-adicionar-uma-nova-linguagem-lexer)
  - [6.2 Adicionar um novo padrão de segredo](#62-adicionar-um-novo-padrão-de-segredo)
  - [6.3 Criar/ajustar um tema](#63-criarajustar-um-tema)
- [7. Convenções e dicas](#7-convenções-e-dicas)

---

## 1. Pré-requisitos

| Item | Versão usada no desenvolvimento |
| --- | --- |
| Python | **3.11.9** |
| PyQt6 | **6.11.0** (`requirements.txt`: `PyQt6>=6.0.3`) |
| PyQt6-QScintilla | **2.14.1** (`requirements.txt`: `PyQt6-QScintilla>=2.14`) |

Não há outras dependências de runtime. O `PyQt6-QScintilla` traz o mesmo motor
**Scintilla** que o Notepad++ usa — é dele que vêm os lexers de syntax highlight e
os *indicators* usados para marcar/tarjar segredos.

A fonte preferida do editor é **JetBrains Mono**; se ela não estiver instalada, o
Qt cai automaticamente para **Consolas**/monospace (veja
`CodeEditor._setup_appearance` em `notepy/editor.py`). Não é obrigatório instalá-la.

---

## 2. Setup (sem venv — por causa do OneDrive)

A pasta do projeto fica **dentro do OneDrive**, que sincroniza tudo para a nuvem.
Um `venv` aqui significaria sincronizar milhares de arquivos binários do
interpretador — lento e propenso a corromper. Por isso, **neste projeto não se cria
venv**: as dependências são instaladas no **Python global**.

```powershell
# A partir da raiz do projeto (a pasta Notepad\)
pip install -r requirements.txt
```

Para confirmar que o PyQt6 e o QScintilla estão visíveis no Python global:

```powershell
python -c "import PyQt6, PyQt6.Qsci; print('PyQt6 OK'); print(PyQt6.Qsci.__file__)"
```

> **Por que isso importa.** Se você normalmente trabalha com venv, lembre-se de que
> aqui o `pip install` e o `python main.py` usam o **mesmo** Python global. Não
> ative nenhum ambiente virtual dentro desta pasta.

---

## 3. Como rodar

### Pela linha de comando

```powershell
# Abre o editor vazio (uma aba "Sem titulo 1")
python main.py

# Abre um ou mais arquivos já na inicialização
python main.py exemplo_segredos.py
python main.py notepy\secrets.py README.md
```

O `main.py` aplica o tema (`theme.apply_app`), cria a `MainWindow` e abre cada
arquivo passado em `sys.argv[1:]` via `window.open_path(...)`. Se algum arquivo for
aberto, a aba inicial vazia é descartada automaticamente
(`_maybe_close_initial_empty`).

### Sem janela de console (Windows)

O `run.bat` inicia o app com **`pythonw`**, ou seja, **sem** janela de console:

```bat
start "" pythonw "%~dp0main.py" %*
```

Você pode dar duplo-clique no `run.bat` ou **arrastar arquivos para cima dele** —
os arquivos arrastados chegam como `%*` e são abertos em abas. (Dentro do app,
arrastar-e-soltar arquivos na janela também os abre.)

> Use `python main.py` (com console) durante o desenvolvimento — é onde aparecem
> tracebacks e `print`. Use `run.bat` (`pythonw`) para o uso do dia a dia.

---

## 4. Como testar (headless)

### Suíte de testes (pytest) — a forma oficial

```bash
pip install -r requirements-dev.txt
pytest            # roda tudo (~55 testes); o conftest já força o modo offscreen
pytest -m "not slow"   # pula o teste de DoS/performance
```

A suíte vive em `tests/`:
- `test_secrets.py` — Sentinela: verdadeiros/falsos-positivos, validadores
  (CPF/CNPJ/Luhn), resistência ao *placeholder-poison*, exclusão de hash, e o teste
  `slow` de DoS (teto `MAX_MATCHES`).
- `test_vault.py` — Cofre: round-trip, senha errada, adulteração, *scrypt-bomb*, etc.
- `test_redteam_corpus.py` — roda o corpus adversarial (`tests/fixtures/redteam_corpus.json`,
  80 casos) e exige **recall ≥ 85% / precisão ≥ 78%** (pega regressão grande do scanner).
- `test_app.py` — integração (cofre selar/lock/unlock, redação do clipboard, burn,
  encoding/BOM, mapa de exposição). Usa a fixture `win` (MainWindow com diálogos mockados).

> **Regra de ouro:** mexeu em `notepy/secrets.py` ou `notepy/vault.py`? Rode `pytest`
> antes de commitar — é o que protege as garantias de segurança contra regressão.

### Rodando o app à mão (headless)

O Redoubt é uma app Qt, então qualquer teste que instancie `QApplication`,
`CodeEditor` ou `MainWindow` precisa de uma plataforma Qt. Em CI / terminal sem
display, use a plataforma **offscreen** do Qt:

```powershell
# PowerShell
$env:QT_QPA_PLATFORM = "offscreen"
$env:PYTHONIOENCODING = "utf-8"
python main.py exemplo_segredos.py
```

```bash
# Bash (cmd.exe usa: set "QT_QPA_PLATFORM=offscreen")
QT_QPA_PLATFORM=offscreen PYTHONIOENCODING=utf-8 python main.py exemplo_segredos.py
```

Duas variáveis de ambiente importam:

- **`QT_QPA_PLATFORM=offscreen`** — faz o Qt renderizar sem abrir janela nem exigir
  servidor gráfico. Essencial para rodar em CI ou sessões sem display.
- **`PYTHONIOENCODING=utf-8`** — o console padrão do Windows é **cp1252**, e os
  glifos do **selo de estado** na barra de status (`●` LIMPO, `▲` EXPOSTO,
  `■` REDIGIDO) e o `░` da cadeia de custódia **quebram** ao serem impressos em
  cp1252. Forçar UTF-8 na E/S do Python evita o `UnicodeEncodeError`. Dentro do Qt
  esses glifos funcionam normalmente — o problema é só o **console** do Windows.

### O scanner é testável isolado — sem Qt

A **Sentinela de Segredos** (`notepy/secrets.py`) é **puro Python**: não importa Qt
nem nada de PyQt6. Ela é o coração da identidade do produto e o componente mais
fácil de testar de forma determinística — você pode exercitá-la sem `QApplication`,
sem display e sem as variáveis de ambiente acima:

```powershell
python -c "from notepy import secrets; print(secrets.scan(open('exemplo_segredos.py', encoding='utf-8').read()))"
```

Um teste rápido inline (cada `Match` tem `start`, `end`, `kind` e `snippet`):

```python
from notepy.secrets import scan, shannon_entropy

# Deve detectar a chave AWS...
ms = scan('AWS_ACCESS_KEY = "AKIA3FK7XQ2MNP8RTUVW"')
assert any(m.kind == "Chave de acesso AWS" for m in ms)

# ...mas NÃO o placeholder canônico da AWS (filtro de placeholder/exemplo):
assert scan('AKIAIOSFODNN7EXAMPLE') == []

# A entropia pode ser desligada para isolar as camadas de padrão:
scan(texto, entropy=False)
```

O arquivo **`exemplo_segredos.py`** na raiz é um corpus de demonstração: a parte
"BENIGNO" (hash git, sha256, UUID, `your-api-key-here`) **não** deve ser marcada; a
parte "SEGREDOS" (chave AWS, token GitHub, Stripe, connection string, JWT, cartão,
CPF/CNPJ com e sem máscara) **deve**. Use-o como fixture de regressão.

> **Por que isolar o scanner.** O `scan()` é determinístico e independente do Qt;
> testá-lo sozinho é rápido e estável. Os testes que tocam `CodeEditor` /
> `MainWindow` precisam do `QT_QPA_PLATFORM=offscreen` porque instanciam widgets.

---

## 5. Estrutura de pastas

```
Notepad/                     # pasta do projeto (nome histórico)
├── main.py                  # ponto de entrada: aplica tema, abre argv
├── run.bat                  # inicia sem console (pythonw) + drag&drop
├── requirements.txt         # PyQt6 + PyQt6-QScintilla
├── exemplo_segredos.py      # corpus de demonstração da Sentinela
├── README.md
├── CHANGELOG.md             # histórico de versões
├── CONTRIBUTING.md          # guia de contribuição
├── LICENSE                  # licença MIT
├── docs/
│   ├── ARCHITECTURE.md      # módulos, fluxo de dados e decisões (ADRs)
│   ├── SECURITY.md          # Sentinela, red-team, threat model, limitações
│   └── DEVELOPMENT.md       # este guia
└── notepy/                  # o pacote Python (nome histórico)
    ├── __init__.py          # APP_NAME / APP_VERSION / APP_TAGLINE
    ├── secrets.py           # Sentinela de Segredos (puro Python, sem Qt)
    ├── lexers.py            # mapa extensão -> lexer QScintilla
    ├── editor.py            # CodeEditor (QsciScintilla) + vigilância
    ├── theme.py             # paleta carbono, QSS e repintura dos lexers
    └── mainwindow.py        # MainWindow: abas, menus, barra de custódia
```

Responsabilidade de cada módulo:

| Arquivo | O que faz |
| --- | --- |
| `main.py` | Cria `QApplication`, aplica o tema, instancia `MainWindow`, abre os arquivos do `argv`. |
| `notepy/__init__.py` | Constantes de identidade do produto (`APP_NAME`, `APP_VERSION`, `APP_TAGLINE`). |
| `notepy/lexers.py` | `lexer_for_path(path, font, parent)` → instância de `QsciLexer*` (ou `None` p/ texto puro), a partir da extensão ou nome de arquivo. |
| `notepy/editor.py` | `CodeEditor(QsciScintilla)`: aparência, *indicators* de segredo/redação, varredura com *debounce*, leitura com detecção de encoding/EOL, cadeia de custódia (SHA-256). |
| `notepy/theme.py` | Paleta semântica + QSS do *chrome* + `apply_app`/`apply_editor_theme`/`retheme_lexer`. |
| `notepy/secrets.py` | `scan(text)` → lista de `Match`. Detecção de segredos em 5 camadas, **sem Qt**. |
| `notepy/mainwindow.py` | `MainWindow(QMainWindow)`: `QTabWidget`, menus Arquivo/Editar/Segurança/Ajuda, toolbar, barra de status com selo + cadeia de custódia. |

### Atalhos de teclado (de `mainwindow.py`)

| Ação | Atalho |
| --- | --- |
| Novo | `Ctrl+N` |
| Abrir | `Ctrl+O` |
| Salvar | `Ctrl+S` |
| Salvar como | `Ctrl+Shift+S` (sequência padrão do Qt) |
| Fechar aba | `Ctrl+W` |
| Modo Redação (tarjar segredos) | `Ctrl+Shift+R` |
| Ir ao próximo segredo | `F8` |
| Relatório de segredos | `Ctrl+Shift+E` |

---

## 6. Como estender

### 6.1 Adicionar uma nova linguagem (lexer)

Toda a detecção de linguagem mora em **`notepy/lexers.py`**. O fluxo é:
`lexer_for_path` olha o nome-base do arquivo em **`_NAME_LEXER`** (arquivos sem
extensão, como `Makefile`), depois a extensão em **`_EXT_LEXER`**, resolve a classe
de lexer dentro de `PyQt6.Qsci` por `getattr` e devolve uma instância já com a fonte
aplicada — ou `None` para texto puro.

Para suportar uma nova extensão, basta acrescentar uma entrada no mapa. Por exemplo,
para tratar arquivos `.go` com o lexer C++ (aproximação visual aceitável):

```python
# notepy/lexers.py, dentro de _EXT_LEXER
    ".go": "QsciLexerCPP",
```

Para um arquivo reconhecido por **nome** (sem extensão), use `_NAME_LEXER` com a
chave em minúsculas:

```python
# notepy/lexers.py, dentro de _NAME_LEXER
    "dockerfile": "QsciLexerBash",   # aproximação
```

Pontos de atenção:

- A chave (extensão **com o ponto** ou nome de arquivo) deve estar **em
  minúsculas** — `lexer_for_path` faz `.lower()` antes de procurar.
- O valor é o **nome da classe** (string) dentro de `PyQt6.Qsci`. Se a sua versão
  do QScintilla não tiver essa classe, `getattr` devolve `None` e o arquivo abre
  como texto puro — sem erro.
- Você **não** precisa pintar o lexer: o `CodeEditor.apply_lexer_for_path` já chama
  `theme.retheme_lexer(lexer)`, que repinta qualquer `QsciLexer*` pela descrição
  dos estilos (veja [6.3](#63-criarajustar-um-tema)).

Para testar:

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -c "from PyQt6.QtGui import QFont; from notepy.lexers import lexer_for_path; print(lexer_for_path('teste.go', QFont()))"
```

---

### 6.2 Adicionar um novo padrão de segredo

A Sentinela vive em **`notepy/secrets.py`** e roda em **5 camadas**, da maior para a
menor confiança, com um **filtro global de placeholder/exemplo** aplicado a todos os
matches:

1. **Padrões de provedor** (`_PATTERNS`) — alta confiança (AWS, JWT, PEM, GitHub,
   Slack, OpenAI, Stripe, SendGrid, Twilio, npm, Google API, Basic/Bearer,
   connection string...).
2. **Atribuição `keyword=valor`** (`_ASSIGN_RE`), com ou sem aspas, com porteira de
   complexidade (`_looks_like_secret_value`) e contextos benignos ignorados
   (`_BENIGN_CONTEXT`: csrf, paginação...).
3. **PII brasileira** — CPF/CNPJ com e sem máscara, validados pelos dígitos
   verificadores (`_valid_cpf`, `_valid_cnpj`).
4. **Cartão de crédito** — validado por **Luhn** (`_luhn_ok`) + comprimento real +
   IIN.
5. **Rede de entropia** — Shannon (`_ENTROPY_THRESHOLD = 4.5`) para tokens genéricos
   de 32+ chars, excluindo hashes puros (md5/sha1/sha256), data URIs e SRI.

#### Caso A — um formato de provedor conhecido (regex específica)

Esta é a forma preferida: alta precisão. Acrescente uma tupla `(rótulo, regex)` em
**`_PATTERNS`**. Exemplo para um token fictício `acme_` seguido de 32+ alfanuméricos:

```python
# notepy/secrets.py, dentro de _PATTERNS
    ("Token ACME", re.compile(r"\bacme_[A-Za-z0-9]{32,}\b")),
```

Boas práticas para o regex:

- Ancore com `\b` (ou um prefixo fixo, como `acme_`) para reduzir falso-positivo.
- O texto casado é o que o **filtro de placeholder** (`_PLACEHOLDER_RE`) inspeciona;
  se o token puder conter `example`, `dummy`, `your-`, `xxxx`, `{{`, `${`, etc., ele
  será descartado — geralmente o comportamento desejado.
- A função `scan()` resolve **sobreposições**: o primeiro match (camadas de maior
  confiança rodam primeiro) vence; a rede de entropia só considera trechos ainda não
  cobertos.

#### Caso B — quando NÃO há formato fixo (deixe a entropia pegar)

Se o segredo não tem um prefixo/formato reconhecível, normalmente você **não** cria
regex nova: a camada 5 (entropia) já captura tokens genéricos de alta entropia. Se
ela estiver deixando passar um caso legítimo, ajuste a heurística em vez de criar um
padrão frágil:

- `_ENTROPY_THRESHOLD` (padrão `4.5`) — limiar de Shannon; abaixar aumenta recall e
  reduz precisão.
- `_TOKEN_RE` — o que conta como "token candidato" (32+ chars do alfabeto
  `[A-Za-z0-9+/_-]`, com `=` só como *padding* final).
- `_looks_secretish` — exige letra **e** dígito e exclui hex puro de 32/40/64 chars
  (md5/sha1/sha256).
- `_ENTROPY_SKIP_CTX` — contextos antes do token que indicam hash público/recurso
  (`data:`, `sha256-`, `@sha256:`, `integrity=`).

#### Validar após mexer no scanner

Sempre rode o corpus de demonstração para garantir que a regressão dos casos
existentes continua intacta (lembre-se: a Sentinela **não** precisa de Qt):

```powershell
python -c "from notepy import secrets; [print(m.kind, repr(m.snippet)) for m in secrets.scan(open('exemplo_segredos.py', encoding='utf-8').read())]"
```

O esperado é marcar a seção "SEGREDOS" e **não** marcar a seção "BENIGNO" (hash git,
sha256, UUID e `your-api-key-here`). Como referência de qualidade: o endurecimento
contra o corpus adversarial de red-team levou o scanner de Recall 46% / Precisão 55%
(v1 ingênua) para **Recall 92% / Precisão 87%** (v2). Mantenha esse padrão ao
estender.

---

### 6.3 Criar/ajustar um tema

O tema mora em **`notepy/theme.py`**. A cor é **semântica**:

| Constante | Hex | Significado |
| --- | --- | --- |
| `BG` | `#0E1116` | fundo carbono |
| `PANEL` | `#161B22` | painéis / *chrome* |
| `BORDER` | `#21262D` | bordas / divisores |
| `TEXT` | `#C9D1D9` | texto base |
| `DIM` | `#5B6673` | texto apagado / números de linha |
| `AMBER` | `#E8A33D` | **atenção / marca** |
| `GREEN` | `#3FB950` | **selado / limpo / seguro** |
| `RED` | `#F85149` | **exposto / segredo** |
| `CYAN` | `#6BD0FF` | números / literais |
| `VIOLET` | `#9B5DE5` | tipos / classes |
| `TERRACOTA` | `#C45A3B` | preprocessador / diretiva |
| `CARET_LN` | `#11161D` | fundo da linha atual |
| `SELECTION` | `#1F2D3D` | seleção |

Há três funções de aplicação:

- **`apply_app(app)`** — estilo `Fusion` + `QPalette` escura + a folha de estilo
  `QSS` (todo o *chrome*: menus, abas, toolbar, barra de status, scrollbars,
  diálogos).
- **`apply_editor_theme(ed)`** — pinta o *canvas* do editor (papel, margens, caret,
  seleção, *braces*, guias de indentação) — as cores que o lexer **não** mexe.
- **`retheme_lexer(lexer)`** — repinta **todos** os estilos de qualquer
  `QsciLexer*`. Em vez de mapear ids numéricos (que mudam de lexer para lexer), usa
  a **descrição textual** de cada estilo (`lexer.description(style)`) e casa por
  palavra-chave: *comment* → `DIM`, *keyword* → `AMBER`, *string/char* → `GREEN`,
  *number* → `CYAN*`, *preprocessor/directive/decorator* → `TERRACOTA`,
  *class/type/tag* → `VIOLET`, e assim por diante.

#### Para mudar a aparência

- **Trocar uma cor globalmente:** altere a constante no topo de `theme.py`. Tudo que
  a referencia (canvas, lexers, QSS) acompanha — exceto valores **literais**
  embutidos no QSS (ex.: tamanhos, `font-family`), que não usam o `Template`.
- **Mudar como uma categoria de token é pintada:** ajuste o `if/elif` por descrição
  dentro de `retheme_lexer`. Como ele casa pela descrição (e não por ids), a mudança
  vale para **todas** as ~50 linguagens de uma vez.
- **Mexer no QSS do chrome:** o `QSS` é um `string.Template`; apenas `$VAR` é
  substituído (as chaves `{ }` do CSS ficam literais). Se introduzir um novo `$VAR`,
  adicione-o à chamada `.substitute(...)` no fim do bloco — senão dá `KeyError` no
  import.

Após mexer no tema, abra o app para conferir visualmente (com janela, pois é um
ajuste de aparência):

```powershell
python main.py exemplo_segredos.py
```

---

## 7. Convenções e dicas

- **Indicators do Scintilla.** Segredos usam `SECRET_INDICATOR = 8` (rabisco
  vermelho, desenhado **sob** o texto); o Modo Redação usa `REDACT_INDICATOR = 9`
  (tarja preta sólida **sobre** o texto). Ids altos para não colidir com os do lexer
  e do *brace matching*. As posições do Scintilla são em **bytes**, não em
  caracteres — por isso o `CodeEditor` converte os offsets de caractere dos `Match`
  para bytes antes de preencher os indicators.
- **Debounce de varredura.** A Sentinela roda a cada `textChanged`, mas com um
  `QTimer` *single-shot* de **300 ms**, para não revarrer a cada tecla. Acima de
  `_SCAN_LIMIT = 2_000_000` caracteres, a varredura é pulada (evita travar em
  arquivos enormes).
- **Cadeia de custódia.** `content_hash()` é o SHA-256 do conteúdo; `mark_saved()`
  fixa o hash ao salvar/abrir; enquanto há edição não salva, a barra mostra
  `░ alterado`. Permite flagrar adulteração externa de relance.
- **Modo Redação é VISUAL.** A tarja cobre a tela, mas o **conteúdo real permanece
  no documento** — copiar ainda traz o segredo. Não é redação destrutiva; é proteção
  para compartilhamento de tela.
- **Tudo roda local.** A Sentinela não faz rede. Qualquer feature nova deve manter
  essa propriedade — é parte da promessa "*Nada vaza sem você mandar.*".
- **Encoding ao salvar.** O arquivo é gravado no mesmo codec em que foi lido
  (`utf-8-sig`/`utf-8`/`cp1252`/`latin-1`, via `read_text`) e com `newline=""` para
  preservar o EOL detectado (`detect_eol`). Não force UTF-8 ao salvar.
