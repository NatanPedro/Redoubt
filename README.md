<div align="center">

# Redoubt

### *Nada vaza sem você mandar.*

**O editor que trata cada arquivo como evidência.**

[![Python 3.11](https://img.shields.io/badge/Python-3.11.9-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![PyQt6](https://img.shields.io/badge/PyQt6-6.11.0-41CD52?logo=qt&logoColor=white)](https://pypi.org/project/PyQt6/)
[![QScintilla](https://img.shields.io/badge/QScintilla-2.14.1-2D2D2D)](https://pypi.org/project/PyQt6-QScintilla/)
[![Licença: MIT](https://img.shields.io/badge/Licen%C3%A7a-MIT-E8A33D)](#licença)
[![Status](https://img.shields.io/badge/status-v0.2.0%20%C2%B7%20alfa-3FB950)](CHANGELOG.md)

</div>

---

## O que é o Redoubt

O **Redoubt** é um editor de texto e código desktop, leve, escrito em Python puro com PyQt6 e QScintilla — o mesmo motor Scintilla que move o Notepad++. Edita ~50 linguagens com realce de sintaxe, abas, *drag & drop* e detecção de encoding.

Mas o Redoubt nasceu com uma identidade que o separa de qualquer outro editor: **segurança não é um plugin, é o eixo.** Enquanto você digita, uma **Sentinela de Segredos** varre o conteúdo em busca de credenciais, chaves de API, tokens, PII brasileira e cartões de crédito — e avisa **antes** que algo escape numa captura de tela, num *commit* ou num *paste* no chat de suporte.

> *redoubt* (substantivo): um pequeno forte, geralmente isolado, construído para defender uma posição. É o último reduto.

### Por que ele existe

Vazamento de segredo quase nunca é ataque sofisticado — é descuido cotidiano. Um `.env` aberto numa demo. Um log colado no Slack. Uma chave AWS num *screenshot* de tutorial. O Redoubt parte do princípio de que **o momento mais perigoso de um segredo é quando ele está na sua tela**, e dá ao operador três defesas locais:

1. **Ver** o segredo destacado no instante em que ele aparece.
2. **Tarjar** o segredo na tela antes de compartilhar (Modo Redação).
3. **Provar** que o arquivo não foi adulterado, via cadeia de custódia (hash SHA-256).

Tudo isso **roda 100% localmente. Sem rede. Sem telemetria. Sem nuvem.**

> 📸 *Placeholder de screenshot — HUD carbono + âmbar com o selo de estado e a cadeia de custódia na barra de status.*
> `docs/screenshot.png`

---

## Funcionalidades

### 🛡️ Sentinela de Segredos — a estrela

A varredura roda no fundo a cada alteração (com *debounce* de 300 ms, sem travar a digitação) e trabalha em **5 camadas, da maior para a menor confiança**, sempre passando por um **filtro de placeholder/exemplo** para não "gritar lobo":

| # | Camada | Detecta |
|---|--------|---------|
| 1 | **Padrões de provedor** | Chave AWS (`AKIA…`), JWT, chave privada PEM, tokens GitHub / Slack, *webhook* Slack, OpenAI (`sk-` / `sk-proj-`), Stripe, SendGrid, Twilio, npm, Google API, Basic Auth, Bearer, *connection strings* (mongodb/postgres/mysql/redis/amqp com `user:senha@host`) |
| 2 | **Atribuição `chave=valor`** | `password`, `senha`, `secret`, `api_key`, `access_key`, `token`… com **ou sem aspas**, atrás de uma porteira de complexidade (≥ 8 chars, ≥ 2 classes de caractere, não-UUID) e ignorando contextos benignos (CSRF, paginação) |
| 3 | **PII brasileira** | CPF e CNPJ — **com e sem máscara** — validados pelos **dígitos verificadores** |
| 4 | **Cartão de crédito** | Validado por **Luhn** + comprimento real (13/14/15/16/19) + IIN |
| 5 | **Rede de entropia (Shannon)** | Tokens genéricos ≥ 32 chars com alta entropia, excluindo hashes puros (md5/sha1/sha256), *data URIs* e *hashes* SRI |

O **filtro de placeholder** descarta automaticamente material de exemplo (`example`, `dummy`, `placeholder`, `changeme`, `your-`, `-here`, `xxxx`, `${…}`, `fixme`, `todo`, `redacted`, `lorem`…). É por isso que `AKIAIOSFODNN7EXAMPLE`, a chave-exemplo canônica da AWS, **não** dispara alarme.

> O detector foi endurecido contra um *corpus* adversarial de *red-team* de 80 casos. O scanner ingênuo (v1) tinha **Recall 46% / Precisão 55%**; após o endurecimento (v2) chegou a **Recall 92% / Precisão 87%**, sem regressão nos casos originais. Detalhes em [`docs/SECURITY.md`](docs/SECURITY.md).

### 🔒 Modo Redação

`Ctrl+Shift+R` cobre **todos** os segredos detectados com uma tarja preta sólida — ideal para compartilhar a tela em call sem expor credenciais.

> ⚠️ A redação é **visual**: tarja a tela, mas o conteúdo real continua no documento (copiar ainda traz o segredo). Veja as [limitações honestas](#segurança).

### 🧾 Cadeia de custódia

A barra de status mostra o **hash SHA-256** do conteúdo (8 primeiros dígitos hex). Ele é recalculado ao abrir e ao salvar, e exibe **"alterado"** enquanto houver edição não salva — permitindo flagrar adulteração externa de relance.

### 🚦 Selo de estado

Na barra de status, um selo semântico resume a situação do documento:

- 🟢 **● LIMPO** — nenhum segredo detectado
- 🔴 **▲ EXPOSTO · N** — N segredos visíveis
- 🟠 **■ REDIGIDO · N** — N segredos tarjados

As abas com segredo ganham um **▲** no título, e a janela carrega `[▲ EXPOSTO]` quando há exposição.

### ✍️ Editor de verdade

- **~50 linguagens** com realce via lexers do QScintilla (Python, JS/TS, C/C++, C#, Java, Go via texto, SQL, YAML, HTML, CSS, Markdown, Bash, e muito mais).
- Abas **fecháveis e arrastáveis**, *drag & drop* de arquivos para abrir.
- Detecção automática de **encoding** (UTF-8, UTF-8 BOM, Windows-1252, Latin-1) e de quebra de linha (CRLF/LF/CR).
- Numeração de linhas, *folding*, *auto-indent*, guias de indentação, casamento de chaves.
- Tema **HUD carbono + âmbar** onde a cor é semântica: âmbar = atenção, verde = selado, vermelho = exposto.
- Aviso ao fechar com alterações não salvas.

---

## Como instalar

**Pré-requisito:** Python 3.11+.

```bash
pip install -r requirements.txt
```

O `requirements.txt` traz apenas duas dependências — `PyQt6` e `PyQt6-QScintilla`. Nada mais.

> ### ⚠️ Sobre o `venv`
> A pasta do projeto vive dentro de uma pasta do **OneDrive**, que sincroniza para a nuvem. Por isso **não criamos um ambiente virtual** aqui — um `venv` sincronizado é lento e quebradiço. Os pacotes são instalados no Python **global** da máquina. Se você clonar para fora do OneDrive, fique à vontade para usar `venv` normalmente.

---

## Como rodar

```bash
python main.py
```

Você também pode abrir arquivos direto pela linha de comando (ou via "Abrir com…" do Windows):

```bash
python main.py caminho/arquivo1.py outro/arquivo.env
```

No Windows, **`run.bat`** abre o app **sem janela de console** (usa `pythonw`) e repassa quaisquer arquivos arrastados sobre ele.

---

## Build — executável standalone (`.exe`)

Para gerar um **`Redoubt.exe`** que roda sem Python instalado (ideal para usar no
dia a dia ou compartilhar):

```bash
pip install -r requirements-dev.txt   # pyinstaller + pillow
build.bat                             # gera dist\Redoubt.exe (~39 MB, sem console)
```

O `build.bat` empacota tudo num único `.exe` com o ícone próprio (gerado por
`tools/gen_icon.py`). Os intermediários vão para `%TEMP%`; o executável final fica
em `dist\` (ignorado pelo git).

---

## Atalhos de teclado

| Ação | Atalho |
|------|--------|
| Novo arquivo | `Ctrl+N` |
| Abrir… | `Ctrl+O` |
| Salvar | `Ctrl+S` |
| Salvar como… | `Ctrl+Shift+S` |
| Fechar aba | `Ctrl+W` |
| Sair | `Ctrl+Q` |
| Desfazer / Refazer | `Ctrl+Z` / `Ctrl+Y` |
| Recortar / Copiar / Colar | `Ctrl+X` / `Ctrl+C` / `Ctrl+V` |
| Selecionar tudo | `Ctrl+A` |
| Localizar / Substituir | `Ctrl+F` / `Ctrl+H` |
| Próxima / anterior ocorrência | `F3` / `Shift+F3` |
| Barra de comando `:` | `Ctrl+P` |
| Preferências | `Ctrl+,` |
| **Modo Redação** (tarjar segredos) | `Ctrl+Shift+R` |
| **Ir ao próximo segredo** | `F8` |
| **Relatório de segredos** | `Ctrl+Shift+E` |
| **Verificar custódia** (hash) | `Ctrl+Shift+H` |
| **Selar como cofre** | `Ctrl+Shift+L` |
| **Travar / Destravar cofre** | `Ctrl+Shift+K` / `Ctrl+Shift+U` |
| **Nova nota de queima** (Burn) | `Ctrl+Shift+B` |

> Os atalhos de edição e arquivo usam as *standard keys* do Qt; os atalhos de **Segurança** são fixos. A barra `:` (`Ctrl+P`) aceita `seal · burn · redact · hash · goto N · w · q · open <arquivo> · lock · unlock · next`.

---

## Estrutura do projeto

```
Notepad/                     ← pasta histórica do projeto (o produto é o "Redoubt")
├── main.py                  Ponto de entrada: tema, ícone, abre arquivos do argv
├── run.bat                  Inicia sem console (pythonw), repassa arquivos
├── build.bat                Empacota o dist\Redoubt.exe (PyInstaller)
├── requirements.txt         PyQt6 + PyQt6-QScintilla + cryptography
├── requirements-dev.txt     pyinstaller + pillow (só para build)
├── exemplo_segredos.py      Arquivo de demonstração (dispara a Sentinela)
├── README.md                Você está aqui
├── CHANGELOG.md             Histórico de versões (Keep a Changelog)
├── CONTRIBUTING.md          Como contribuir
├── LICENSE                  Licença MIT
├── assets/                  redoubt.ico / redoubt.png (ícone do app)
├── tools/                   gen_icon.py (regenera o ícone)
├── dist/                    Redoubt.exe (gerado pelo build, ignorado no git)
├── docs/                    Documentação detalhada
│   ├── ARCHITECTURE.md      Módulos, fluxo de dados e decisões (ADRs)
│   ├── SECURITY.md          Sentinela, red-team, threat model, limitações
│   ├── SECURITY-TEST-REPORT.md  Relatório dos pentests (Sentinela, Cofre, Fase 3)
│   ├── DEVELOPMENT.md       Setup, testes headless, como estender
│   └── Redoubt-Documentacao-Tecnica.docx   Documento formal (Word)
└── notepy/                  Pacote Python (nome histórico)
    ├── __init__.py          APP_NAME / APP_VERSION / APP_TAGLINE
    ├── mainwindow.py        Janela: abas, menus, barra :, custódia, cofre, burn
    ├── editor.py            CodeEditor (QsciScintilla): vigilância + hash + encoding
    ├── secrets.py           Sentinela de Segredos — scan(text) (testável sem Qt)
    ├── vault.py             Cofre .rdbt — AES-256-GCM + scrypt (testável sem Qt)
    ├── findbar.py           Barra Localizar/Substituir (regex, F3)
    ├── preferences.py       Diálogo de preferências (Ctrl+,)
    ├── config.py            QSettings: auto-lock, fonte, tab (testável sem Qt)
    ├── lexers.py            Mapa extensão → lexer (~50 linguagens)
    └── theme.py             Paleta carbono, QSS e repintura dos lexers
```

> O pacote ainda se chama `notepy/` por razão histórica, mas o produto foi renomeado para **Redoubt** em `notepy/__init__.py` (`APP_NAME = "Redoubt"`). Para renomear o app, basta trocar `APP_NAME`.

---

## Segurança

O Redoubt é uma ferramenta de **defesa local e best-effort** — e é honesto sobre o que **não** consegue fazer. As limitações abaixo são parte do contrato:

- **(a) RAM:** o Python não garante zerar segredos da memória (strings imutáveis + *garbage collector*). O *burn note* planejado **reduz** o resíduo, não o elimina.
- **(b) Detecção é best-effort:** existem falsos-positivos (base64 de imagem, JS minificado, um SKU com formato idêntico a chave AWS) e falsos-negativos (formatos de provedor desconhecidos, segredos ofuscados).
- **(c) Modo Redação é visual:** tarja a tela, mas o conteúdo real permanece no documento — copiar ainda traz o segredo.
- **(d) Tudo é local:** nenhum dado sai da máquina. Sem rede, sem telemetria.

📖 **Leia o modelo de ameaça completo, os números do *red-team* e as garantias em [`docs/SECURITY.md`](docs/SECURITY.md).**

---

## Documentação

| Documento | Conteúdo |
|-----------|----------|
| [`docs/SECURITY.md`](docs/SECURITY.md) | Modelo de ameaça, garantias, limitações e resultados do *red-team* do detector |
| [`docs/SECURITY-TEST-REPORT.md`](docs/SECURITY-TEST-REPORT.md) | Relatório do pentest adversarial (59 ataques): bugs corrigidos, limitações confirmadas, garantias que resistiram |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Arquitetura, decisões de stack (PyQt6/QScintilla *vs.* Electron/Tauri/WPF) e fluxo de dados |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Como rodar testes *headless*, convenções e ambiente de desenvolvimento |
| [`CHANGELOG.md`](CHANGELOG.md) | Histórico de versões |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Como contribuir |

> **Testes *headless*:** a Sentinela (`notepy/secrets.py`) é testável isolada, **sem Qt**. Para a interface, use `QT_QPA_PLATFORM=offscreen` e `PYTHONIOENCODING=utf-8` (os glifos do selo quebram no console cp1252 do Windows, mas funcionam no Qt). Detalhes em [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

---

## Roadmap

A Fase 3 mira transformar o Redoubt de "editor que vê segredos" em "editor que os contém":

- 🔐 **Cofre `.rdbt` cifrado** — arquivos AES-GCM, senha derivada por PBKDF2 (adiciona a dependência `cryptography`).
- 🔥 **Burn Note** — aba efêmera que vive só na RAM e se autodestrói.
- ⌨️ **Barra `:` onipresente** — comandos `:seal` / `:burn` / `:redact` / `:hash` substituindo o menu clássico.
- 🗺️ **Mapa de exposição** — indicadores na margem mostrando onde os segredos estão no arquivo.

---

## Licença

Distribuído sob a licença **MIT**. Veja o arquivo `LICENSE` para os termos completos.

---

<div align="center">

**Redoubt** · v0.2.0 · *Python · PyQt6 · QScintilla*

*Nada vaza sem você mandar.*

</div>
