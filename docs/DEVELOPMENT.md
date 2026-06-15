# Guia do Desenvolvedor — Redoubt

> **Redoubt** v1.0.0 — *editor que trata cada arquivo como evidência.*
> *Nada vaza sem você mandar.*

Este documento explica como configurar o ambiente, **rodar**, **testar** e
**empacotar/assinar** o Redoubt, além de como **estender** seus núcleos. É voltado a
quem mexe no código — para a visão de produto e o modelo de ameaça, veja o
`README.md`, o `docs/SECURITY.md` e o `docs/ARCHITECTURE.md`.

> **Nota sobre nomes.** O *produto* se chama **Redoubt**. O *pacote Python* ainda se
> chama `notepy/` e a pasta do projeto se chama `Notepad/` — nomes históricos
> (herança). O nome de exibição vive em `notepy/__init__.py` (`APP_NAME = "Redoubt"`);
> para renomear o app, basta trocar essa constante (`APP_NAME` / `APP_VERSION` /
> `APP_TAGLINE`).

---

## Sumário

- [1. Pré-requisitos](#1-pré-requisitos)
- [2. Setup (sem venv — por causa do OneDrive)](#2-setup-sem-venv--por-causa-do-onedrive)
- [3. Como rodar](#3-como-rodar)
- [4. Como testar (headless)](#4-como-testar-headless)
- [5. Empacotar, instalar e assinar o release](#5-empacotar-instalar-e-assinar-o-release)
- [6. Estrutura de pastas](#6-estrutura-de-pastas)
- [7. Como estender](#7-como-estender)
  - [7.1 Adicionar uma nova linguagem (lexer)](#71-adicionar-uma-nova-linguagem-lexer)
  - [7.2 Adicionar um novo padrão de segredo](#72-adicionar-um-novo-padrão-de-segredo)
  - [7.3 Criar/ajustar um tema](#73-criarajustar-um-tema)
  - [7.4 Mexer nos núcleos de segurança (cofre, custódia, release)](#74-mexer-nos-núcleos-de-segurança-cofre-custódia-release)
- [8. Convenções e dicas](#8-convenções-e-dicas)

---

## 1. Pré-requisitos

| Item | Versão usada no desenvolvimento | Onde está declarado |
| --- | --- | --- |
| Python | **3.11.x** | — |
| PyQt6 | **6.x** | `requirements.txt`: `PyQt6>=6.0.3` |
| PyQt6-QScintilla | **2.14+** | `requirements.txt`: `PyQt6-QScintilla>=2.14` |
| cryptography | **42+** | `requirements.txt`: `cryptography>=42` |

São **três** dependências de runtime, não duas: o `cryptography` foi adicionado
quando o Cofre `.rdbt`, a Custódia assinada e o manifesto de release passaram a
existir. Ele é a base criptográfica de `notepy/vault.py` (AES-256-GCM + scrypt),
`notepy/custody.py` (Ed25519 + hash-chain) e `notepy/release.py` (assinatura do
manifesto). **Sem `cryptography`, importar qualquer um desses três módulos falha** —
mas note que esses núcleos *não* importam Qt.

O `PyQt6-QScintilla` traz o mesmo motor **Scintilla** que o Notepad++ usa — é dele
que vêm os lexers de syntax highlight e os *indicators* usados para marcar/tarjar
segredos.

As **ferramentas de desenvolvimento/build** ficam num arquivo separado
(`requirements-dev.txt`) e **não** são necessárias para rodar o app:

```
pytest>=7        # suíte de testes
pyinstaller>=6   # empacota o .exe (build.bat)
pillow>=10       # gera o ícone (tools/gen_icon.py)
```

A fonte preferida do editor é **JetBrains Mono**; se ela não estiver instalada, o Qt
cai automaticamente para **Consolas**/monospace (veja `CodeEditor._setup_appearance`
em `notepy/editor.py`). Não é obrigatório instalá-la.

---

## 2. Setup (sem venv — por causa do OneDrive)

A pasta do projeto fica **dentro do OneDrive**, que sincroniza tudo para a nuvem. Um
`venv` aqui significaria sincronizar milhares de arquivos binários do interpretador —
lento e propenso a corromper. Por isso, **neste projeto não se cria venv**: as
dependências são instaladas no **Python global**.

```powershell
# A partir da raiz do projeto (a pasta Notepad\)
pip install -r requirements.txt        # runtime: PyQt6, QScintilla, cryptography
pip install -r requirements-dev.txt    # dev/build: pytest, pyinstaller, pillow
```

Para confirmar que tudo está visível no Python global:

```powershell
python -c "import PyQt6, PyQt6.Qsci, cryptography; print('runtime OK'); print(PyQt6.Qsci.__file__)"
```

> **Por que isso importa.** Se você normalmente trabalha com venv, lembre-se de que
> aqui o `pip install` e o `python main.py` usam o **mesmo** Python global. Não ative
> nenhum ambiente virtual dentro desta pasta.

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
aberto, a aba inicial vazia é descartada automaticamente.

### Sem janela de console (Windows)

O `run.bat` inicia o app com **`pythonw`**, ou seja, **sem** janela de console:

```bat
start "" pythonw "%~dp0main.py" %*
```

Você pode dar duplo-clique no `run.bat` ou **arrastar arquivos para cima dele** — os
arquivos arrastados chegam como `%*` e são abertos em abas. (Dentro do app,
arrastar-e-soltar arquivos na janela também os abre.)

> Use `python main.py` (com console) durante o desenvolvimento — é onde aparecem
> tracebacks e `print`. Use `run.bat` (`pythonw`) para o uso do dia a dia.

---

## 4. Como testar (headless)

### Suíte de testes (pytest) — a forma oficial

```powershell
pip install -r requirements-dev.txt
pytest                  # roda tudo (272 testes); o conftest força offscreen
pytest -m "not slow"    # pula o teste de DoS/performance do scanner
pytest tests/test_vault.py -q   # só um arquivo
python tools/run_tests.py       # runner resiliente (ver abaixo) — também é o que o hook usa
```

O `pyproject.toml` já fixa `pythonpath = ["."]`, `testpaths = ["tests"]` e
`addopts = "-q"`, então `pytest` puro a partir da raiz **já encontra e roda tudo**. O
marcador `slow` está registrado lá (`tests/test_redteam_corpus.py` e o teto de DoS do
scanner).

### Runner resiliente + hook `pre-push`

A suíte combinada às vezes sofre um **crash de teardown do Qt offscreen** (exit `0xC0000005`
no shutdown do interpretador) — *flaky*, não é falha de teste. Por isso `tools/run_tests.py`
**isola cada arquivo** num processo, lê o resultado por `--junitxml` e **re-tenta 1×** se o XML
não sair; soma tudo e sai `!= 0` se algo falhar. Use-o quando o `pytest` combinado der esse crash.

`install-hooks.bat` instala um hook **`pre-push`** (em `.git/hooks/`, coexistindo com o
`pre-commit` anti-segredo) que roda esse runner e **bloqueia o push se a suíte quebrar**. É
**local** (sem CI de servidor); `git push --no-verify` pula numa emergência.

A suíte vive em `tests/` e cobre **núcleo a núcleo**:

| Arquivo | O que cobre |
| --- | --- |
| `test_secrets.py` | Sentinela: verdadeiros/falsos-positivos, validadores (CPF/CNPJ/Luhn), resistência a *placeholder-poison*, exclusão de hash, teto `MAX_MATCHES`. |
| `test_redteam_corpus.py` | Roda o corpus adversarial (`tests/fixtures/redteam_corpus.json`) e exige piso de **recall/precisão** — pega regressão grande do scanner. Marcado `slow`. |
| `test_vault.py` | Cofre RDBT3 (Argon2id por slot): round-trip, senha errada → `WrongPassword`, adulteração de ciphertext/salt/nonce/slot, *bomba* de KDF + **teto de custo agregado** (anti-DoS), anti-downgrade, slot ruim pulado, múltiplos slots, **retrocompat scrypt RDBT2/RDBT1**. |
| `test_custody.py` | Identidade Ed25519, assinar/verificar, hash-chain append-only (`verify_chain`), proteger/desproteger a identidade com o Cofre (escrita atômica + wipe + rollback), âncora anti-reset. |
| `test_release.py` | Manifesto RDBT-REL1: assinatura sobre o `signed_payload`, hashes batem, fingerprint derivado da chave, rejeição de re-assinatura com outra chave / âncora divergente. |
| `test_seal.py` | Selo de proveniência RDBT-SEAL1: round-trip, conteúdo adulterado, **anti-substituição** (selo de outro arquivo), re-assinatura forjada rejeitada, `name` inerte (sem traversal), leitura blindada a `OSError`, verificador standalone (`verify_seal.py`). |
| `test_scan_cli.py` | CLI da Sentinela e hook git: `--staged`, `--install-hook` (backup de hook alheio), decodificação UTF-16/32 e NUL, *fail-closed*, whitelist `redoubt:allow`, relatório nunca imprime o segredo. |
| `test_searchfiles.py`, `test_palette.py`, `test_difftool.py`, `test_config.py`, `test_theme.py`, `test_findbar.py` | Núcleos puros de busca, paleta fuzzy, diff, wrapper de QSettings, paletas/QSS/retheme e a barra Localizar/Substituir. |
| `test_app.py` | Integração de UI: selar/lock/unlock cofre, redação do clipboard, burn, encoding/BOM, mapa de exposição, restauração com conteúdo oculto. Usa a fixture `win`. |

> **Regra de ouro:** mexeu em `notepy/secrets.py`, `vault.py`, `custody.py` ou
> `release.py`? Rode `pytest` antes de commitar — é o que protege as garantias de
> segurança contra regressão.

### O conftest e a fixture `win`

`tests/conftest.py` define `os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")`
**antes de qualquer import de Qt**, então a suíte roda headless sem você exportar
nada. Ele oferece duas fixtures:

- **`qapp`** (escopo de sessão) — uma única `QApplication` reaproveitada.
- **`win`** — uma `MainWindow` pronta com os diálogos neutralizados
  (`QMessageBox`/`QInputDialog`/`QFileDialog` mockados via `monkeypatch`), para nada
  bloquear a suíte. Respostas de `QInputDialog.getText` (ex.: senhas de cofre) vêm de
  uma fila: `win._inbox.append(("minha-senha", True))` antes da ação que pede a senha.

### Gotcha headless: **não** dependa de `QTest.keyClick`

A suíte **não usa `QTest`** em lugar nenhum — e isso é intencional. Sob
`QT_QPA_PLATFORM=offscreen`, sintetizar teclas com `QTest.keyClick`/`keyClicks` no
`QsciScintilla` é instável (o evento muitas vezes não chega ao buffer do Scintilla, e
o teste passa a depender de timing). Em vez disso, os testes **dirigem os widgets
diretamente**:

- inserem texto com `editor.setText(...)` / `findbar.find_edit.setText(...)`;
- disparam ações chamando os *slots*/métodos (`fb.find_next()`, `win._seal_vault()`,
  etc.) ou emitindo o sinal correspondente;
- alimentam diálogos pela fila `win._inbox`.

Ao escrever um teste de UI, **siga esse padrão** (estado via `setText` + chamada
direta de método), não tente simular digitação.

### O scanner é testável isolado — sem Qt

A **Sentinela de Segredos** (`notepy/secrets.py`) é **puro Python**: não importa Qt.
É o componente mais fácil de testar de forma determinística — sem `QApplication`, sem
display e sem variáveis de ambiente:

```powershell
python -c "from notepy import secrets; print(secrets.scan(open('exemplo_segredos.py', encoding='utf-8').read()))"
```

Um teste rápido inline (cada `Match` tem `start`, `end`, `kind` e `snippet`):

```python
from notepy.secrets import scan, shannon_entropy

# Deve detectar a chave AWS...
ms = scan('AWS_ACCESS_KEY = "AKIA3FK7XQ2MNP8RTUVW"')
assert any("AWS" in m.kind for m in ms)

# ...mas NAO o placeholder canonico da AWS (filtro de placeholder/exemplo):
assert scan('AKIAIOSFODNN7EXAMPLE') == []

# A entropia pode ser desligada para isolar as camadas de padrao:
scan(texto, entropy=False)
```

O mesmo vale para os demais núcleos puros: `vault`, `custody`, `release`, `scan_cli`,
`searchfiles`, `palette`, `difftool`, `config`, `theme` podem ser exercitados sem
instanciar `MainWindow`. Só os testes que tocam `CodeEditor`/`MainWindow` precisam do
offscreen (e o conftest já cuida disso).

### Rodando o app à mão (headless)

Se quiser instanciar a UI fora do pytest (ex.: para depurar em CI/SSH sem display):

```powershell
# PowerShell
$env:QT_QPA_PLATFORM = "offscreen"
$env:PYTHONIOENCODING = "utf-8"
python main.py exemplo_segredos.py
```

```bash
# Bash  (cmd.exe usa:  set "QT_QPA_PLATFORM=offscreen")
QT_QPA_PLATFORM=offscreen PYTHONIOENCODING=utf-8 python main.py exemplo_segredos.py
```

Duas variáveis importam:

- **`QT_QPA_PLATFORM=offscreen`** — faz o Qt renderizar sem abrir janela nem exigir
  servidor gráfico.
- **`PYTHONIOENCODING=utf-8`** — o console padrão do Windows é **cp1252**, e os glifos
  do **selo de estado** na barra de status (`●` LIMPO, `▲` EXPOSTO, `■` REDIGIDO) e o
  `░` da cadeia de custódia **quebram** ao serem impressos em cp1252. Forçar UTF-8 na
  E/S do Python evita o `UnicodeEncodeError`. Dentro do Qt esses glifos funcionam
  normalmente — o problema é só o **console** do Windows.

---

## 5. Empacotar, instalar e assinar o release

O fluxo de distribuição tem **três etapas em sequência**, todas locais e sem rede:

### 5.1 `.exe` standalone — `build.bat`

`build.bat` empacota tudo num único executável via **PyInstaller**:

```powershell
pip install pyinstaller pillow      # ou: pip install -r requirements-dev.txt
build.bat
# -> dist\Redoubt.exe
```

Detalhes do `build.bat`: usa `--noconsole --onefile`, ícone
`assets\redoubt.ico`, embute a pasta `assets` (`--add-data`) e força
`--hidden-import PyQt6.Qsci` (o PyInstaller não detecta o QScintilla sozinho). Os
intermediários vão para `%TEMP%\redoubt-build` (**fora** do OneDrive, para não
sincronizar lixo de build); só o `.exe` final cai em `dist\` (ignorado pelo git).

### 5.2 Instalador Windows — `build-installer.bat`

Gera `dist\Redoubt-Setup-<versao>.exe` via **Inno Setup 6**, a partir de
`installer\redoubt.iss`:

```powershell
winget install JRSoftware.InnoSetup    # uma vez
build.bat                              # dist\Redoubt.exe precisa existir antes
build-installer.bat
```

O script falha cedo (mensagem clara) se o Inno Setup não estiver instalado ou se
`dist\Redoubt.exe` ainda não existir.

### 5.3 Manifesto de release assinado — `python -m notepy.release make`

Logo após gerar o instalador, o `build-installer.bat` chama:

```powershell
python -m notepy.release make --dist dist
```

Isso produz, ao lado dos binários:

- **`SHA256SUMS`** — hashes dos artefatos;
- **`RELEASE.json`** (formato **RDBT-REL1**) — um `signed_payload` (string JSON
  canônica com produto/versão/data/pubkey/fingerprint/artefatos) **mais** a assinatura
  Ed25519 da identidade do Redoubt sobre essa string.

A CLI tem dois subcomandos:

```powershell
python -m notepy.release make   --dist dist [--version X] [--date YYYY-MM-DD] [--artifacts ...]
python -m notepy.release verify dist [--expect-fingerprint ...] [--expect-pubkey ...]
```

### 5.4 Verificar o release — `verify_release.py` (standalone)

Na **raiz** do projeto há um verificador independente do pacote, `verify_release.py`,
que **embute a chave pública do autor** (fingerprint oficial `4e391f28930f3b6e`):

```powershell
python verify_release.py dist
```

Ele checa a assinatura **sobre a string** e só então parseia (zero divergência
gerador↔verificador), confirma que os hashes batem **e** que a chave derivada bate com
a âncora embutida. Binário re-assinado com outra chave é rejeitado.

> **Honestidade do modelo.** A chave privada de custódia/release é, por padrão,
> **local e sem senha** — quem tiver a máquina do autor consegue assinar como ele, a
> menos que a opção *Proteger identidade* (opt-in) embrulhe a privada num Cofre RDBT2.
> A âncora embutida no `verify_release.py` é o que dá **autenticidade** ao
> verificador; a assinatura sozinha, sem âncora, não prova autoria (a pubkey viaja no
> payload).

---

## 6. Estrutura de pastas

```
Notepad/                       # pasta do projeto (nome historico)
├── main.py                    # ponto de entrada: aplica tema, abre argv
├── verify_release.py          # verificador standalone (embute a pubkey do autor)
├── run.bat                    # inicia sem console (pythonw) + drag&drop
├── build.bat                  # empacota dist\Redoubt.exe (PyInstaller --onefile)
├── build-installer.bat        # instalador (Inno Setup) + release.make assinado
├── requirements.txt           # runtime: PyQt6, PyQt6-QScintilla, cryptography
├── requirements-dev.txt       # dev/build: pytest, pyinstaller, pillow
├── pyproject.toml             # config do pytest (pythonpath, testpaths, markers)
├── exemplo_segredos.py        # corpus de demonstracao da Sentinela
├── README.md  CHANGELOG.md  CONTRIBUTING.md  LICENSE
├── assets/                    # icone .ico e recursos embutidos no .exe
├── installer/                 # redoubt.iss (script do Inno Setup)
├── tools/                     # gen_icon.py (gera o icone via pillow)
├── docs/
│   ├── ARCHITECTURE.md        # modulos, fluxo de dados e decisoes (ADRs)
│   ├── SECURITY.md            # Sentinela, cofre, custodia, threat model
│   └── DEVELOPMENT.md         # este guia
├── tests/                     # ~212 testes (pytest, offscreen)
│   ├── conftest.py            # offscreen + fixtures (qapp, win, _inbox)
│   ├── fixtures/              # redteam_corpus.json
│   └── test_*.py              # 14 arquivos: secrets, vault, custody, release,
│                              #   scan_cli, app, searchfiles, palette, difftool,
│                              #   config, theme, findbar, redteam_corpus
└── notepy/                    # o pacote Python (nome historico; produto = Redoubt)
    ├── __init__.py            # APP_NAME / APP_VERSION (1.0.0) / APP_TAGLINE
    │
    │   # --- NUCLEOS PUROS (sem Qt; testaveis isolados) ---
    ├── secrets.py             # Sentinela de Segredos (5 camadas)
    ├── vault.py               # Cofre .rdbt RDBT2 (AES-256-GCM + scrypt)   [cryptography]
    ├── custody.py             # Identidade Ed25519 + hash-chain            [cryptography]
    ├── release.py             # Manifesto RDBT-REL1 assinado               [cryptography]
    ├── scan_cli.py            # CLI da Sentinela + hook git pre-commit
    ├── searchfiles.py         # busca em arquivos (grep)
    ├── palette.py             # paleta de comandos (fuzzy)
    ├── difftool.py            # diff
    ├── config.py              # wrapper de QSettings + save/load_session
    ├── theme.py               # paletas, QSS, retheme de lexers
    ├── lexers.py              # mapa extensao/nome -> lexer QScintilla
    │
    │   # --- CAMADA UI (PyQt6) ---
    ├── editor.py              # CodeEditor (QsciScintilla): indicators, scan,
    │                          #   lock/unlock cofre, gate/reveal oculto, burn
    ├── mainwindow.py          # MainWindow: abas, menus, barra ':' (Ctrl+P),
    │                          #   selo de estado, custodia, _sanitize_clipboard
    ├── findbar.py             # Localizar/Substituir
    └── preferences.py         # dialogo de preferencias (Ctrl+,)
```

### Atalhos de teclado (de `mainwindow.py`)

| Ação | Atalho |
| --- | --- |
| Novo / Abrir / Salvar | `Ctrl+N` / `Ctrl+O` / `Ctrl+S` |
| Salvar como | `Ctrl+Shift+S` |
| Fechar aba | `Ctrl+W` |
| Paleta / barra `:` (seal, burn, redact, hash, goto, lock/unlock…) | `Ctrl+P` |
| Modo Redação (tarjar segredos, tela + clipboard) | `Ctrl+Shift+R` |
| Burn Note (aba só-RAM) | `Ctrl+Shift+B` |
| Selar como cofre `.rdbt` | `Ctrl+Shift+L` |
| Custódia: verificar / assinar e exportar `.sig` | `Ctrl+Shift+H` / `Ctrl+Shift+G` |
| Ir ao próximo segredo / Relatório de segredos | `F8` / `Ctrl+Shift+E` |

---

## 7. Como estender

### 7.1 Adicionar uma nova linguagem (lexer)

Toda a detecção de linguagem mora em **`notepy/lexers.py`**. `lexer_for_path` olha o
nome-base em **`_NAME_LEXER`** (arquivos sem extensão, como `Makefile`), depois a
extensão em **`_EXT_LEXER`**, resolve a classe dentro de `PyQt6.Qsci` por `getattr` e
devolve uma instância já com a fonte aplicada — ou `None` para texto puro.

```python
# notepy/lexers.py, dentro de _EXT_LEXER
    ".go": "QsciLexerCPP",     # aproximacao visual aceitavel

# notepy/lexers.py, dentro de _NAME_LEXER
    "dockerfile": "QsciLexerBash",
```

Pontos de atenção:

- A chave (extensão **com o ponto** ou nome de arquivo) deve estar **em minúsculas** —
  `lexer_for_path` faz `.lower()` antes de procurar.
- O valor é o **nome da classe** (string). Se a sua versão do QScintilla não tiver
  essa classe, `getattr` devolve `None` e o arquivo abre como texto puro — sem erro.
- Você **não** precisa pintar o lexer: `CodeEditor.apply_lexer_for_path` já chama
  `theme.retheme_lexer(lexer)` (veja [7.3](#73-criarajustar-um-tema)).

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -c "from PyQt6.QtGui import QFont; from notepy.lexers import lexer_for_path; print(lexer_for_path('teste.go', QFont()))"
```

---

### 7.2 Adicionar um novo padrão de segredo

A Sentinela vive em **`notepy/secrets.py`** e roda em **5 camadas**, da maior para a
menor confiança, com um **filtro global de placeholder/exemplo** sobre todos os
matches:

1. **Padrões de provedor** (`_PATTERNS`) — alta confiança (~26 provedores: AWS
   AKIA/ASIA, JWT, PEM, GitHub clássico + fine-grained, GitLab, Slack token/webhook,
   OpenAI `sk-`/`sk-proj-`, Stripe, SendGrid, Twilio, npm, Google API, Google OAuth
   `GOCSPX-`, Telegram, Azure `AccountKey=`, Shopify, DigitalOcean `dop_v1_`, Square,
   PyPI, HashiCorp Vault `hvs.`, Doppler `dp.`, Basic/Bearer, connection string…).
2. **Atribuição `keyword=valor`** (`_ASSIGN_RE`), com porteira de complexidade
   (`_looks_like_secret_value`) e contextos benignos ignorados (`_BENIGN_CONTEXT`:
   csrf, paginação, anti-forgery…).
3. **PII brasileira** — CPF/CNPJ com e sem máscara, validados pelos dígitos
   verificadores (`_valid_cpf`, `_valid_cnpj`).
4. **Cartão de crédito** — validado por **Luhn** (`_luhn_ok`) + comprimento + IIN.
5. **Rede de entropia** — Shannon (`_ENTROPY_THRESHOLD = 4.5`) para tokens de 32+
   chars, excluindo hashes puros, data URIs e SRI.

Dedup é O(n) por bytearray de cobertura, com teto `MAX_MATCHES = 2000`.

#### Caso A — formato de provedor conhecido (regex específica) — **preferido**

```python
# notepy/secrets.py, dentro de _PATTERNS
    ("Token ACME", re.compile(r"\bacme_[A-Za-z0-9]{32,}\b")),
```

- Ancore com `\b` (ou prefixo fixo, como `acme_`) para reduzir falso-positivo.
- O texto casado passa pelo filtro de placeholder (`_PLACEHOLDER_RE` + `_REPEAT_RE`):
  se contém `example`/`dummy`/`your-`/`xxxx`/`{{`/`${` ou é degenerado (8+ chars
  iguais), é descartado — geralmente o desejado.
- As camadas de maior confiança rodam primeiro; a entropia só vê trechos ainda não
  cobertos.

#### Caso B — quando NÃO há formato fixo (deixe a entropia pegar)

Em vez de criar regex frágil, ajuste a heurística: `_ENTROPY_THRESHOLD` (4.5),
`_TOKEN_RE` (o que conta como token candidato), `_looks_secretish` (exige letra **e**
dígito; exclui hex puro md5/sha1/sha256), `_ENTROPY_SKIP_CTX` (`data:`, `sha256-`,
`@sha256:`, `integrity=`).

#### Validar após mexer no scanner

```powershell
python -c "from notepy import secrets; [print(m.kind, repr(m.snippet)) for m in secrets.scan(open('exemplo_segredos.py', encoding='utf-8').read())]"
pytest tests/test_secrets.py tests/test_redteam_corpus.py -q
```

Esperado: marcar a seção "SEGREDOS" e **não** a "BENIGNO". Referência de qualidade: o
endurecimento contra o corpus adversarial levou o scanner de Recall ~46% / Precisão
~55% (ingênuo) para **Recall ~92% / Precisão ~87%**. O `test_redteam_corpus.py`
impõe um piso — não deixe regredir.

---

### 7.3 Criar/ajustar um tema

O tema mora em **`notepy/theme.py`** e a cor é **semântica** (carbono + âmbar/laranja
da marca, verde = selado/limpo, vermelho = exposto/segredo). Há três funções:

- **`apply_app(app)`** — `Fusion` + `QPalette` escura + a folha `QSS` (todo o
  *chrome*: menus, abas, toolbar, barra de status, scrollbars, diálogos).
- **`apply_editor_theme(ed)`** — pinta o *canvas* do editor (papel, margens, caret,
  seleção, *braces*, guias) — as cores que o lexer **não** mexe.
- **`retheme_lexer(lexer)`** — repinta **todos** os estilos de qualquer `QsciLexer*`
  pela **descrição textual** de cada estilo (`lexer.description(style)`), não por ids
  numéricos. Casa por palavra-chave (*comment*, *keyword*, *string*, *number*,
  *preprocessor*, *class/type/tag*…), então a mudança vale para todas as linguagens de
  uma vez.

Cuidados: o `QSS` é um `string.Template` (só `$VAR` é substituído; as chaves `{ }` do
CSS ficam literais). Se introduzir um novo `$VAR`, adicione-o ao `.substitute(...)` —
senão dá `KeyError` no import. Para conferir visualmente, abra o app com janela:
`python main.py exemplo_segredos.py`.

---

### 7.4 Mexer nos núcleos de segurança (cofre, custódia, release)

Os três núcleos criptográficos são **puro Python** (dependem de `cryptography`, não de
Qt), o que facilita testá-los isolados. Regras ao estendê-los:

- **`vault.py` (Cofre RDBT2)** — formato envelope/key-slots estilo LUKS/age: uma
  *content-key* aleatória cifra o texto com AES-256-GCM; cada destravador (senha **ou**
  arquivo-chave) é um slot que embrulha a CK via scrypt. **Use scrypt, não PBKDF2.**
  O AAD liga o conteúdo a todos os slots (anti slot-strip) e `_check_kdf` valida
  `log2n/r/p` (anti scrypt-bomb). Preserve a leitura/migração de **RDBT1** legado.
  Qualquer mudança no formato precisa de teste de round-trip + adulteração em
  `test_vault.py`.
- **`custody.py` (Ed25519 + hash-chain)** — a privada é PEM local **sem senha** por
  padrão (`identity.ed25519`); a opção *Proteger identidade* a embrulha num Cofre
  RDBT2 (`identity.rdbt`) e apaga o PEM, com escrita atômica + wipe + rollback. Só
  **assinar** pede senha (lazy + cache de sessão); fingerprint/verificação não pedem.
  A trilha `audit.log` é append-only com `verify_chain` — não reescreva entradas
  passadas.
- **`release.py` + `verify_release.py`** — o verificador checa a assinatura **sobre a
  string** `signed_payload` e **só então** parseia (zero divergência). Se mudar o
  payload, mude os **dois** em sincronia e rode `test_release.py`. O fingerprint é
  sempre **derivado** da chave (`sha256(pubkey)[:16]`); o `verify_release.py` embute a
  âncora `4e391f28930f3b6e`.

> **Não prometa o que o código não faz.** Cofre = confidencialidade em repouso;
> Custódia = integridade/autenticidade (chave opcionalmente protegida); ocultar
> conteúdo = privacidade (não cifra — o arquivo segue em claro no disco até *Selar como
> cofre*); Sentinela = detecção best-effort. Mantenha essa separação honesta na UI e
> na documentação.

---

## 8. Convenções e dicas

- **Indicators do Scintilla.** Segredos usam `SECRET_INDICATOR = 8` (rabisco vermelho,
  desenhado **sob** o texto); o Modo Redação usa `REDACT_INDICATOR = 9` (tarja preta
  sólida **sobre** o texto). Ids altos para não colidir com os do lexer e do *brace
  matching*. As posições do Scintilla são em **bytes**, não em caracteres — o
  `CodeEditor` converte os offsets de caractere dos `Match` para bytes antes de
  preencher os indicators.
- **Debounce de varredura.** A Sentinela roda a cada `textChanged`, mas com um
  `QTimer` *single-shot* de **300 ms** (não revarre a cada tecla) e emite
  `secretsChanged(int)`. Acima de `_SCAN_LIMIT = 2_000_000` caracteres a varredura é
  pulada (evita travar). **Com o Modo Redação ligado, a varredura roda síncrona** (sem
  debounce) para não deixar um segredo colado visível por ~300 ms.
- **Custódia ≠ hash nu.** A barra mostra um SHA-256 de relance (`░ alterado` enquanto
  há edição não salva), mas a **prova** de integridade/autoria é a **assinatura
  Ed25519** + a trilha hash-chain (`notepy/custody.py`), não o hash sozinho — qualquer
  um recalcula um hash.
- **Modo Redação: tela = visual, clipboard = mascarado.** A tarja cobre a tela, mas o
  **conteúdo real permanece no documento e no disco**. O **clipboard**, porém, é de
  fato mascarado (`mainwindow._sanitize_clipboard` no sinal `dataChanged`): copiar um
  segredo **detectado** entrega `●`. Ressalva honesta: só mascara o que a Sentinela
  detectou, e cópia parcial < 6 chars escapa.
- **Ocultar não cifra.** Restaurar sessão guarda **apenas caminhos**; arquivo com
  credencial reabre **OCULTO** (privacidade anti screen-share), mas em claro no disco.
  Proteção em repouso de verdade = **Selar como cofre**.
- **Burn Note reduz, não elimina.** Aba só-RAM, nunca vai ao disco, apagada ao fechar
  (buffer sobrescrito, undo zerado, clipboard limpo). Python não garante zerar strings
  imutáveis — resíduo em RAM/swap pode persistir.
- **Tudo roda local.** Nenhum núcleo faz rede. Qualquer feature nova deve manter essa
  propriedade — é parte da promessa *"Nada vaza sem você mandar."*.
- **Encoding ao salvar.** O arquivo é gravado no mesmo codec em que foi lido
  (`utf-8-sig`/`utf-8`/`cp1252`/`latin-1`, via `read_text`) e com `newline=""` para
  preservar o EOL detectado (`detect_eol`). Não force UTF-8 ao salvar.

---

> **Redoubt** v1.0.0 — Python · PyQt6 · QScintilla · cryptography
> *Nada vaza sem você mandar.*