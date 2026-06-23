<div align="center">

# Redoubt

### *Nada vaza sem você mandar.*

**O editor que trata cada arquivo como evidência.**

[![Python 3.11](https://img.shields.io/badge/Python-3.11.9-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![PyQt6](https://img.shields.io/badge/PyQt6-6.11.0-41CD52?logo=qt&logoColor=white)](https://pypi.org/project/PyQt6/)
[![QScintilla](https://img.shields.io/badge/QScintilla-2.14.1-2D2D2D)](https://pypi.org/project/PyQt6-QScintilla/)
[![Licença: MIT](https://img.shields.io/badge/Licen%C3%A7a-MIT-E8A33D)](#licença)
[![Status](https://img.shields.io/badge/status-v1.3.0%20%C2%B7%20est%C3%A1vel-3FB950)](CHANGELOG.md)
[![Testes](https://img.shields.io/badge/testes-388%20passando-3FB950)](docs/SECURITY-TEST-REPORT.md)

</div>

---

## O que é o Redoubt

O **Redoubt** é um editor de texto e código desktop, leve, escrito em Python puro com PyQt6 e QScintilla — o mesmo motor Scintilla que move o Notepad++. Edita ~50 linguagens com realce de sintaxe, abas, *drag & drop* e detecção de encoding.

Mas o Redoubt nasceu com uma identidade que o separa de qualquer outro editor: **segurança não é um plugin, é o eixo.** Enquanto você digita, uma **Sentinela de Segredos** varre o conteúdo em busca de credenciais, chaves de API, tokens, PII brasileira e cartões de crédito — e avisa **antes** que algo escape numa captura de tela, num *commit* ou num *paste* no chat de suporte.

> *redoubt* (substantivo): um pequeno forte, geralmente isolado, construído para defender uma posição. É o último reduto.

### Por que ele existe

Vazamento de segredo quase nunca é ataque sofisticado — é descuido cotidiano. Um `.env` aberto numa demo. Um log colado no Slack. Uma chave AWS num *screenshot* de tutorial. O Redoubt parte do princípio de que **o momento mais perigoso de um segredo é quando ele está na sua tela**, e dá ao operador três defesas locais:

1. **Ver** o segredo destacado no instante em que ele aparece.
2. **Tarjar** o segredo — na tela **e no clipboard** — antes de compartilhar (Modo Redação).
3. **Cifrar** o conteúdo em repouso, com múltiplas senhas ou arquivo-chave (Cofre++).
4. **Provar** que o arquivo não foi adulterado, com custódia **assinada** (Ed25519) + trilha de auditoria — e blindar seu `git` contra *commit* de segredo.

Tudo isso **roda 100% localmente. Sem rede. Sem telemetria. Sem nuvem.**

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

`Ctrl+Shift+R` cobre **todos** os segredos detectados com tarja preta **e mascara o clipboard** — copiar um segredo entrega `●●●` no lugar do texto real. Ideal pra compartilhar a tela ou colar trechos em call sem vazar credencial.

Quer esconder segredos que a Sentinela **não** detecta (uma senha memorável, por exemplo)? **Segurança ▸ Lista de redação** deixa você cadastrar strings literais — guardadas **cifradas** num Cofre (`.rdbt`, Argon2id) — que a Redação passa a tarjar sempre, na tela e no clipboard.

> ⚠️ A tarja na tela é **visual** (o conteúdo real continua no documento); a proteção em repouso é o **Cofre**. Veja as [limitações honestas](#segurança).

### 🗝️ Cofre++ — cifragem em repouso

`Ctrl+Shift+L` sela a aba como um cofre **`.rdbt`** cifrado com **AES-256-GCM** (chave derivada por **Argon2id**, *memory-hard*; cofres scrypt legados seguem abrindo), *zero-knowledge* (a senha nunca é gravada). Formato **envelope** (estilo LUKS/age): **múltiplas senhas independentes** e/ou um **arquivo-chave** abrem o mesmo cofre. Auto-lock por inatividade, travar/destravar, e o conteúdo **nunca toca o disco em claro**.

**Cifrar para um destinatário (X25519).** Cada instalação tem um par de chaves de destinatário. *Segurança ▸ Exportar minha chave de destinatário* copia a sua **chave pública**; *Segurança ▸ Selar para destinatário* cifra a aba **para a pública de outra pessoa** (estilo `age`) — e também para você, pra manter acesso. Abrir um `.rdbt` selado para você é **automático**: a chave local destrava sem senha. Como no `age`, isso **não autentica o remetente**, e na v1 a chave privada de destinatário fica local em claro (igual à identidade Ed25519 sem proteção).

### 🔏 Custódia assinada + trilha de auditoria

Cada arquivo é tratado como **evidência**. Além do hash SHA-256, o Redoubt assina o conteúdo com uma **identidade Ed25519** local: `Ctrl+Shift+G` exporta a assinatura `.sig` + a chave pública, e **qualquer um com a chave pública verifica** que o arquivo não mudou desde que você assinou. Uma **trilha de auditoria encadeada** (hash-chain) registra abrir/salvar/selar/queimar/assinar — adulterar um evento passado **quebra a cadeia**. `Ctrl+Shift+H` mostra hash + assinatura + integridade da cadeia.

### 🛡️ Hook git anti-segredo

A Sentinela sai do editor e blinda o seu `git`: **Segurança ▸ Proteger repositório** instala um `pre-commit` que **bloqueia o commit** se houver credencial no *stage* (`python -m notepy.scan_cli --staged`). O relatório **nunca** imprime o segredo (só `arquivo:linha` + tipo mascarado). Bypass pontual: `git commit --no-verify`; *whitelist* por linha: `redoubt:allow`.

### 🔥 Burn Note + restaurar sessão

- **Burn Note** (`Ctrl+Shift+B`) — aba efêmera que vive **só na RAM**, nunca vai pro disco e é apagada ao fechar (com o *undo* zerado).
- **Restaurar sessão** — reabre os arquivos da última vez, guardando **só os caminhos, nunca o conteúdo**. Cofre reaparece **travado**; arquivo em claro com credencial reaparece **🛡️ OCULTO** (anti screen-share), com botões *Revelar* / *Selar*.

### 🚦 Selo de estado

Na barra de status, um selo semântico resume a situação do documento:

- 🟢 **● LIMPO** — nenhum segredo detectado
- 🔴 **▲ EXPOSTO · N** — N segredos visíveis
- 🟠 **■ REDIGIDO · N** — N segredos tarjados
- 🔒 **COFRE / TRAVADO** · 🛡️ **OCULTO** · 🔥 **BURN**

As abas com segredo ganham um **▲** no título, e a janela carrega `[▲ EXPOSTO]` quando há exposição.

### ✍️ Editor de verdade

- **~50 linguagens** com realce via lexers do QScintilla (Python, JS/TS, C/C++, C#, Java, SQL, YAML, HTML, CSS, Markdown, Bash, e muito mais) — auto-detectadas pela extensão ou **forçadas pelo menu *Linguagem*** (inclui PowerShell via Bash; *Auto* e *Texto puro*).
- **Localizar/Substituir** (`Ctrl+F` / `Ctrl+H`, com regex), **Busca em arquivos** (`Ctrl+Shift+F`, grep recursivo na pasta com resultados clicáveis), **Paleta de comandos** (`Ctrl+Shift+P`, busca fuzzy de qualquer comando) e **Diff** entre arquivos (`Ctrl+Shift+D`, estilo *git*).
- **Codec — codificar/decodificar** (*Editar ▸ Codificar/Decodificar*): **Base64**, **Base64 URL**, **Hex**, **URL**, **Quoted-printable** e **decode de JWT** — tudo **local**, sem colar segredo em site. Bloqueado em aba oculta/cofre travado e **re-varre a Sentinela após decodar** (uma credencial revelada já fica flagrável).
- **Operações de linha** (*Editar ▸ Linha*): ordenar, remover duplicadas/linhas em branco, *trim* à direita, MAIÚSC/minúsc — e um **gerador de senha/passphrase** (*Editar ▸ Gerar*) com CSPRNG (`secrets`) e a entropia em bits à mostra.
- **Tema claro e escuro** (alterna em Preferências, `Ctrl+,`), HUD carbono+âmbar onde a cor é semântica: âmbar = atenção, verde = selado, vermelho = exposto.
- Abas fecháveis/arrastáveis, *drag & drop*, **encoding** (UTF-8/BOM/UTF-16/Windows-1252/Latin-1) e EOL (CRLF/LF/CR) automáticos, *folding*, *auto-indent*, guias de indentação, casamento de chaves.
- Preferências persistentes (auto-lock, fonte, largura de tab, tema, restaurar sessão) e aviso ao fechar com alterações não salvas.

---

## Como instalar

### Via Scoop (Windows — o jeito mais rápido)

Sem Python, num comando: o [Scoop](https://scoop.sh) baixa o `Redoubt.exe`, **confere o SHA-256** e cria o atalho no menu Iniciar.

```powershell
scoop install https://raw.githubusercontent.com/NatanPedro/Redoubt/main/scoop/redoubt.json
```

Atualizar depois: `scoop update redoubt`. Para conferir também a **assinatura** do binário (não só o hash), rode o `verify_release.py` — veja [Verificar o download](#verificar-o-download-release-assinado).

### A partir do código (Python 3.11+)

**Pré-requisito:** Python 3.11+.

```bash
pip install -r requirements.txt
```

O `requirements.txt` traz três dependências de runtime — `PyQt6`, `PyQt6-QScintilla` e `cryptography` (esta para o Cofre, a custódia Ed25519 e o release assinado).

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

### Instalador Windows

Para um **instalador de verdade** — instala em *Program Files*, cria atalhos, **associa
`.rdbt`** ao Redoubt (duplo-clique abre o cofre) e registra um *uninstaller* — use o
[Inno Setup](https://jrsoftware.org/isdl.php):

```bash
winget install JRSoftware.InnoSetup   # uma vez
build-installer.bat                   # gera dist\Redoubt-Setup-<versao>.exe
```

O pacote é definido em [`installer/redoubt.iss`](installer/redoubt.iss). O
`Redoubt-Setup-*.exe` final fica em `dist\` (ignorado pelo git).

---

## Verificar o download (release assinado)

Coerente com a tagline — *nada vaza sem você mandar* — o Redoubt **prova a própria
integridade**. Cada release traz, ao lado dos binários:

- **`SHA256SUMS`** — o SHA-256 de cada arquivo (formato `sha256sum` padrão);
- **`RELEASE.json`** — um manifesto **assinado com a identidade Ed25519 do Redoubt** (a
  mesma custódia que o editor usa para assinar arquivos).

Para conferir o que você baixou — **sem nem instalar o Redoubt** (só Python +
`cryptography`) — rode o verificador [`verify_release.py`](verify_release.py) na pasta
dos binários:

```bash
python verify_release.py .
```

Saída esperada:

```text
Chave de confiança (fingerprint): 4e391f28930f3b6e
Assinatura confere com a chave do autor: SIM
Artefatos:
  [OK] Redoubt-Setup-1.3.0.exe
  [OK] Redoubt.exe

Veredito: INTEGRO E AUTENTICO
```

O `verify_release.py` **embute a chave pública do autor** e valida a assinatura contra
ela — então um binário adulterado e re-assinado com outra chave é **rejeitado** (a
assinatura não confere com a âncora), e o `RELEASE.json` falha se qualquer hash não bater.

> **Fingerprint oficial:** `4e391f28930f3b6e`
> **Chave pública (Ed25519, base64):** `RZZBbCP6irycPMcBLFs5raHw5gONJOU5LMYZwGawrBA=`
>
> Confirme que o fingerprint impresso bate com este. **Modelo de confiança (honesto):** a
> assinatura prova integridade + que o release veio desta chave, que chega pelo mesmo
> repositório que você já confia. A chave privada é local e sem senha — quem tiver a
> máquina do autor pode assinar como ele. Para verificar um release de **outra** pessoa:
> `python verify_release.py <dir> --pubkey <chave-base64>`.

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
| **Buscar em arquivos** (grep na pasta) | `Ctrl+Shift+F` |
| **Paleta de comandos** | `Ctrl+Shift+P` |
| **Comparar arquivos** (diff) | `Ctrl+Shift+D` |
| Barra de comando `:` | `Ctrl+P` |
| Preferências (tema, fonte, auto-lock…) | `Ctrl+,` |
| **Modo Redação** (tarjar segredos) | `Ctrl+Shift+R` |
| **Ir ao próximo segredo** | `F8` |
| **Relatório de segredos** | `Ctrl+Shift+E` |
| **Lista de redação** (segredos literais a tarjar) | menu Segurança |
| **Verificar custódia** (hash + assinatura) | `Ctrl+Shift+H` |
| **Assinar e exportar** (`.sig`) | `Ctrl+Shift+G` |
| **Selo de proveniência** (`.rdbt-seal`) / **Verificar selo** | menu Segurança |
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
│   ├── SECURITY-TEST-REPORT.md  Relatório dos pentests adversariais (§1–§7)
│   ├── CUSTODY.md           Custódia assinada (Ed25519) + trilha de auditoria
│   ├── GIT-HOOK.md          Hook pre-commit anti-segredo (uso e bypass)
│   ├── DEVELOPMENT.md       Setup, testes headless, como estender
│   └── Redoubt-Documentacao-Tecnica.docx   Documento formal (Word)
└── notepy/                  Pacote Python (nome histórico)
    ├── __init__.py          APP_NAME / APP_VERSION / APP_TAGLINE
    ├── mainwindow.py        Janela: abas, menus, barra :, custódia, cofre, busca/paleta/diff
    ├── editor.py            CodeEditor (QsciScintilla): vigilância + hash + encoding
    ├── secrets.py           Sentinela de Segredos — scan(text) (testável sem Qt)
    ├── vault.py             Cofre++ .rdbt — AES-256-GCM, envelope RDBT4 (Argon2id + destinatário X25519, sem Qt)
    ├── custody.py           Custódia assinada Ed25519 + trilha de auditoria (sem Qt)
    ├── scan_cli.py          CLI da Sentinela + hook git pre-commit (sem Qt)
    ├── searchfiles.py       Busca em arquivos / grep na pasta (sem Qt)
    ├── palette.py           Busca fuzzy da paleta de comandos (sem Qt)
    ├── difftool.py          Diff entre arquivos via difflib (sem Qt)
    ├── findbar.py           Barra Localizar/Substituir (regex, F3)
    ├── preferences.py       Diálogo de preferências (Ctrl+,)
    ├── config.py            QSettings: auto-lock, fonte, tab, tema, sessão (sem Qt)
    ├── lexers.py            Mapa extensão → lexer (~50 linguagens)
    └── theme.py             Paletas dark/light, QSS e repintura dos lexers
```

> O pacote ainda se chama `notepy/` por razão histórica, mas o produto foi renomeado para **Redoubt** em `notepy/__init__.py` (`APP_NAME = "Redoubt"`). Para renomear o app, basta trocar `APP_NAME`.

---

## Segurança

O Redoubt é uma ferramenta de **defesa local e best-effort** — e é honesto sobre o que **não** consegue fazer. As limitações abaixo são parte do contrato:

- **(a) RAM:** o Python não garante zerar segredos da memória (strings imutáveis + *garbage collector*). A **Burn Note** e o *lock* do cofre **reduzem** o resíduo, não o eliminam.
- **(b) Detecção é best-effort:** existem falsos-positivos (base64 de imagem, JS minificado, um SKU com formato idêntico a chave AWS) e falsos-negativos (formatos de provedor desconhecidos, segredos ofuscados).
- **(c) Tela × clipboard:** a tarja **na tela** é um indicador visual (o texto real continua no documento); mas, com a redação ligada, o **clipboard é de fato mascarado**. Confidencialidade em repouso é trabalho do **Cofre**.
- **(d) Custódia assinada:** a chave privada Ed25519 fica **local** — opcionalmente **protegida por senha/arquivo-chave** (*Segurança ▸ Proteger identidade*, embrulhada no mesmo Cofre AES-256-GCM); prova *"veio desta instalação e não mudou"*, desde que a chave não vaze.
- **(e) Cifrar-para-destinatário (X25519):** como no `age`, **não autentica o remetente** (qualquer um cifra para a sua pública); a privada de destinatário fica **local em claro** na v1 — quem tem a máquina decifra o que selaram pra você (proteger com senha está na visão).
- **(f) Tudo é local:** nenhum dado sai da máquina. Sem rede, sem telemetria.

📖 **Leia o modelo de ameaça completo, os números do *red-team* e as garantias em [`docs/SECURITY.md`](docs/SECURITY.md).**

---

## Documentação

| Documento | Conteúdo |
|-----------|----------|
| [`docs/SECURITY.md`](docs/SECURITY.md) | Modelo de ameaça, garantias, limitações e resultados do *red-team* do detector |
| [`docs/SECURITY-TEST-REPORT.md`](docs/SECURITY-TEST-REPORT.md) | Relatório dos pentests adversariais (§1–§7): bugs corrigidos, limitações confirmadas, garantias que resistiram |
| [`docs/CUSTODY.md`](docs/CUSTODY.md) | Custódia assinada (Ed25519): assinar, verificar, trilha de auditoria |
| [`docs/GIT-HOOK.md`](docs/GIT-HOOK.md) | Hook pre-commit anti-segredo: instalar, verificar, *bypass* |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Arquitetura, decisões de stack (PyQt6/QScintilla *vs.* Electron/Tauri/WPF) e fluxo de dados |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Como rodar testes *headless*, convenções e ambiente de desenvolvimento |
| [`CHANGELOG.md`](CHANGELOG.md) | Histórico de versões |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Como contribuir |

> **Testes *headless*:** a Sentinela (`notepy/secrets.py`) é testável isolada, **sem Qt**. Para a interface, use `QT_QPA_PLATFORM=offscreen` e `PYTHONIOENCODING=utf-8` (os glifos do selo quebram no console cp1252 do Windows, mas funcionam no Qt). Detalhes em [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

---

## Status

O que era backlog (o Cofre cifrado, Burn Note, barra `:`, mapa de exposição) **já é arquitetura corrente** — e o projeto foi muito além: **Cofre++** (múltiplas senhas / arquivo-chave **e cifrar-para-destinatário X25519**), **custódia assinada Ed25519** + trilha de auditoria (com **identidade protegível por senha**), **hook git anti-segredo**, **release assinado** (`RELEASE.json` + verificador), **selo de proveniência** (`.rdbt-seal` portátil, verificável offline), **lista de redação cifrada**, **distribuição via Scoop**, **tema claro/escuro**, **restaurar sessão** (com conteúdo oculto), **busca em arquivos**, **paleta de comandos** e **diff**.

**Pentests adversariais** sobrevividos e **388 testes** automatizados sustentam o produto (eram 176 no corte do 1.0.0; subiram com release assinado, selo de proveniência, lista de redação e o cofre cifrado para destinatário X25519).

> Visão (sem data): destravar a identidade com **FIDO2** / chave de hardware; **diff com proveniência**; proteger a chave de destinatário **X25519** com senha (hoje fica local em claro, como a Ed25519).

---

## Licença

Distribuído sob a licença **MIT**. Veja o arquivo `LICENSE` para os termos completos.

---

<div align="center">

**Redoubt** · v1.3.0 · *Python · PyQt6 · QScintilla*

*Nada vaza sem você mandar.*

</div>
