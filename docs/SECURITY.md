# Segurança do Redoubt

> **Redoubt** — *editor que trata cada arquivo como evidência.*
> Tagline: **"Nada vaza sem você mandar."**

Este é o documento mais importante do projeto. Ele descreve, com honestidade técnica,
**o que o Redoubt protege**, **como protege** e — igualmente importante — **o que ele
não protege**. Nada aqui promete mais do que o código entrega; a honestidade do modelo
de ameaça é parte da identidade do produto.

Toda a segurança do Redoubt roda **localmente, sem rede**. Não há telemetria, não há
chamada de API, não há upload. A análise e a criptografia acontecem dentro do processo
do editor, na sua máquina.

> **Os três eixos.** O Redoubt protege três coisas distintas — não as confunda:
>
> | Eixo | Defesa principal | O que prova |
> | --- | --- | --- |
> | **Confidencialidade em repouso** | Cofre `.rdbt` (AES-256-GCM) | quem não tem a credencial não lê o conteúdo |
> | **Integridade + autenticidade** | Custódia assinada (Ed25519) + trilha de auditoria; Release assinado | "veio desta instalação e não mudou desde que assinei" |
> | **Detecção / privacidade** | Sentinela, Modo Redação, Hook git, Ocultar, Burn | reduz a chance de vazamento *acidental* na hora da edição |
>
> Detectar um segredo **não** o cifra. Cifrar um segredo **não** prova quem o cifrou.
> Cada defesa cobre um eixo; o documento separa, defesa a defesa, o que cada uma
> **garante** do que **não garante**.

---

## Sumário

- [1. A Sentinela de Segredos](#1-a-sentinela-de-segredos)
- [2. As 5 camadas de detecção](#2-as-5-camadas-de-deteccao)
- [3. Tabela dos tipos detectados](#3-tabela-dos-tipos-detectados)
- [4. O filtro de placeholder](#4-o-filtro-de-placeholder)
- [5. Cofre `.rdbt` — confidencialidade em repouso](#5-cofre-rdbt--confidencialidade-em-repouso)
- [6. Custódia assinada + trilha de auditoria](#6-custodia-assinada--trilha-de-auditoria)
- [7. Hook git anti-segredo](#7-hook-git-anti-segredo)
- [8. Release assinado + verificador standalone](#8-release-assinado--verificador-standalone)
- [9. Modo Redação (tela + clipboard)](#9-modo-redacao-tela--clipboard)
- [10. Burn Note + restaurar sessão com conteúdo oculto](#10-burn-note--restaurar-sessao-com-conteudo-oculto)
- [11. Resultados do red-team](#11-resultados-do-red-team)
- [12. Threat model completo (garante × não-garante)](#12-threat-model-completo-garante--nao-garante)
- [13. Limitações honestas](#13-limitacoes-honestas)
- [14. Como testar](#14-como-testar)

---

## 1. A Sentinela de Segredos

A **Sentinela de Segredos** (`notepy/secrets.py`) é o coração da identidade do Redoubt:
um varredor que lê o conteúdo do documento e aponta credenciais, tokens e PII expostos
**antes** que eles vazem em um commit, num compartilhamento de tela ou num arquivo de
configuração esquecido. É **núcleo puro** (Python, sem Qt) e o mesmo módulo alimenta o
editor, o **hook git** e a restauração de sessão.

### Como a varredura se integra ao editor

O `CodeEditor` (`notepy/editor.py`) vigia o texto a cada alteração:

- **Debounce de 300 ms.** Cada `textChanged` reinicia um `QTimer` de disparo único
  (`setInterval(300)`); só depois de 300 ms sem digitação o texto é revarrido. Isso
  evita reanalisar a cada tecla. **Exceção:** com o **Modo Redação ligado** a varredura
  roda **síncrona** (sem debounce), para não deixar o segredo visível em claro por ~300 ms
  antes da tarja.
- **Limite de tamanho.** Arquivos acima de `_SCAN_LIMIT = 2_000_000` caracteres não são
  varridos a cada alteração (para não travar o editor em arquivos enormes).
- **Marcação visual.** Cada segredo recebe o indicador `SECRET_INDICATOR = 8`
  (rabisco/sublinhado vermelho desenhado **sob** o texto). No Modo Redação, recebe
  também o `REDACT_INDICATOR = 9` (caixa preta sólida, alfa 255, desenhada **sobre** o
  texto).
- **Offsets em bytes.** Os `Match` da Sentinela usam offsets de **caractere**; o editor
  os converte para **bytes** (UTF-8) antes de mandar para o Scintilla, cujas posições
  são em bytes.
- **Sinal.** A cada varredura, o editor emite `secretsChanged(n)` com a contagem de
  segredos, que atualiza o selo de estado e o título da janela.

A função pública é uma só:

```python
from notepy import secrets
matches = secrets.scan(texto)          # -> list[secrets.Match]
matches = secrets.scan(texto, entropy=False)   # desliga a camada 5
```

Cada resultado é um `Match(start, end, kind, snippet)` — `start`/`end` são offsets de
caractere, `kind` é o rótulo legível (ex.: `"Chave de acesso AWS"`) e `snippet` é o
trecho casado.

### Princípio de design: da maior para a menor confiança

A `scan()` aplica as cinco camadas **em ordem de confiança decrescente** e usa controle
de **sobreposição**: uma vez que uma região do texto é reivindicada por uma camada de
alta confiança, camadas posteriores (em especial a rede de entropia) não a reivindicam
de novo. Assim, um JWT não vira também "alta entropia" — ele já é um JWT. A dedup é
**O(n)** por um `bytearray` de cobertura, com teto absoluto `MAX_MATCHES = 2000`.

Sobre **toda** a detecção paira um **filtro global de placeholder** (seção 4): qualquer
trecho que pareça exemplo/dummy é descartado antes de ser reportado.

---

## 2. As 5 camadas de detecção

### Camada 1 — Padrões de provedor (alta confiança)

Expressões regulares para formatos de credencial bem definidos. Quando o formato bate,
a confiança é alta (prefixo distintivo → baixíssimo falso-positivo). Os ~26 padrões
implementados (`_PATTERNS`):

- **Chave de acesso AWS** — `AKIA` **ou** `ASIA` (credencial temporária) + 16 `[0-9A-Z]`.
- **Token JWT** — `eyJ…` em 2 ou 3 partes separadas por ponto.
- **Chave privada PEM** — cabeçalho `-----BEGIN [RSA|EC|OPENSSH|DSA|PGP |ENCRYPTED ]PRIVATE KEY-----`
  (generalizado para `PGP PRIVATE KEY BLOCK` e `ENCRYPTED PRIVATE KEY`).
- **Token do GitHub** — clássico `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36+ caracteres.
- **Token fine-grained do GitHub** — `github_pat_` + 82 caracteres.
- **Token do GitLab** — `glpat-` + 20 caracteres.
- **Token do Slack** — `xoxb-`/`xoxa-`/`xoxp-`/`xoxr-`/`xoxs-` + cauda.
- **Webhook do Slack** — URL `https://hooks.slack.com/services/…`.
- **Chave da OpenAI** — `sk-` e `sk-proj-` + 20+ caracteres.
- **Chave Stripe** — `sk_live`/`sk_test`/`rk_live`/`rk_test` + 16+ caracteres.
- **Chave SendGrid** — `SG.<16+>.<16+>`.
- **Chave Twilio** — `AC`/`SK` + 32 hex.
- **Token npm** — `npm_` + 36 caracteres.
- **Chave Google API** — `AIza` + 35 caracteres.
- **Segredo OAuth do Google** — `GOCSPX-` + 28 caracteres.
- **Token do Telegram** — `<8–10 dígitos>:AA<33 caracteres>`.
- **Chave de conta Azure Storage** — `AccountKey=<86 base64>==`.
- **Token Shopify** — `shpat_`/`shpss_`/`shppa_`/`shpca_` + 32 hex.
- **Token DigitalOcean** — `dop_v1_` + 64 hex.
- **Token Square** — `sq0atp-`/`sq0csp-` + 22+ caracteres.
- **Token PyPI** — `pypi-AgEI` + 50+ caracteres.
- **Chave Postman** — `PMAK-<24 hex>-<34 hex>`.
- **Token HashiCorp Vault** — `hvs.` + 30+ caracteres (exige dígito, para não casar
  `obj.metodo_snake_case`).
- **Token Doppler** — `dp.pt.`/`dp.st.`/… + 40+ caracteres.
- **Credencial Basic Auth** — `Basic <base64>`.
- **Token Bearer** — `Bearer <token>`.
- **Connection string** — `mongodb`/`mongodb+srv`/`postgres`/`postgresql`/`mysql`/`redis`/`amqp`/`amqps` no formato `esquema://usuario:senha@host`.

### Camada 2 — Atribuição `chave = valor` (com ou sem aspas)

Captura o padrão clássico de `password = "..."`, `api_key: ...`, `token=...` etc. As
chaves reconhecidas incluem: `passwd`, `password`, `senha`, `pwd`, `secret_key`,
`client_secret`, `api_key`, `access_key`, `private_key`, `auth_token`, `access_token`,
`secret`, `token` (com variações de separador `_`/`-`). O valor pode estar **com ou sem
aspas**.

Para não disparar à toa, a camada aplica duas porteiras:

1. **Contextos benignos ignorados** (`_BENIGN_CONTEXT`). Se a chave ou as 24 posições
   antes dela mencionam `csrf`, `xsrf`, `next_page`/`page_token`, `pagination`,
   `continuation`, `anti_forgery` ou `requestverification`, o match é descartado — são
   tokens públicos/descartáveis, não segredos.
2. **Porteira de complexidade do valor** (`_looks_like_secret_value`). O valor só conta
   como segredo se tiver **no mínimo 8 caracteres**, **pelo menos 2 classes** de
   caractere (minúscula, maiúscula, dígito, símbolo) e **não for um UUID**. Isso
   descarta `token = foo` (curto demais) e valores que são apenas prosa simples.

### Camada 3 — PII brasileira (CPF / CNPJ)

Detecta **CPF** e **CNPJ**, tanto **mascarados** (`123.456.789-09`, `12.345.678/0001-95`)
quanto **sem máscara** (só dígitos: 11 dígitos para CPF, 14 para CNPJ). Crucialmente,
**os dígitos verificadores são validados** (`_valid_cpf`, `_valid_cnpj`): uma sequência
de 11 dígitos aleatórios **não** vira CPF — só vira se os dois dígitos verificadores
fecharem. Isso elimina a maior fonte de falso-positivo em números brasileiros.

### Camada 4 — Cartão de crédito

Sequências de 13 a 19 dígitos (com ou sem espaços/hífens) que passam por **três**
filtros combinados:

1. **Comprimento real** — 13, 14, 15, 16 ou 19 dígitos.
2. **IIN plausível** — o primeiro dígito está em `2–6` (faixas de bandeiras reais).
3. **Algoritmo de Luhn** (`_luhn_ok`) — o dígito verificador fecha.

Só com os três passando o número é reportado como cartão.

### Camada 5 — Rede de entropia (Shannon)

A rede de segurança para formatos de provedor **desconhecidos**. Tokens de 32+
caracteres no alfabeto `[A-Za-z0-9+/_-]` (com até `==` de padding final) têm sua
**entropia de Shannon** calculada; acima do limiar `_ENTROPY_THRESHOLD = 4.5` são
rotulados como **"Possível segredo (alta entropia)"**.

Para não confundir com material público de alta entropia, a camada **exclui**:

- **Hashes hexadecimais puros** de 32, 40 ou 64 caracteres (MD5 / SHA-1 / SHA-256).
- **Data URIs** (`data:`), **hashes SRI** (`sha256-`/`sha384-`/`sha512-`,
  `@sha256:`, `integrity=`).
- Tokens **sem mistura** de letra e dígito (`_looks_secretish` exige ambos).
- Regiões já reivindicadas por camadas anteriores (controle de sobreposição).

> **Nota de implementação:** o regex de entropia trata `=` **apenas como padding final**,
> nunca no meio. Isso corrige um bug antigo em que o nome da variável grudava no valor
> (`x=<hash>`) e furava a exclusão de hash.

---

## 3. Tabela dos tipos detectados

| Tipo | Exemplo de formato | Camada |
| --- | --- | :---: |
| Chave de acesso AWS | `AKIA` / `ASIA` + 16 `[0-9A-Z]` | 1 |
| Token JWT | `eyJ….<base64url>.<base64url>` (2–3 partes) | 1 |
| Chave privada PEM | `-----BEGIN [RSA\|EC\|OPENSSH\|DSA\|PGP \|ENCRYPTED ]PRIVATE KEY-----` | 1 |
| Token do GitHub | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` + 36+ | 1 |
| Token fine-grained do GitHub | `github_pat_` + 82 | 1 |
| Token do GitLab | `glpat-` + 20 | 1 |
| Token do Slack | `xoxb-` / `xoxa-` / `xoxp-` / `xoxr-` / `xoxs-` + cauda | 1 |
| Webhook do Slack | `https://hooks.slack.com/services/…` | 1 |
| Chave da OpenAI | `sk-…` e `sk-proj-…` (20+) | 1 |
| Chave Stripe | `sk_live` / `sk_test` / `rk_live` / `rk_test` + 16+ | 1 |
| Chave SendGrid | `SG.<16+>.<16+>` | 1 |
| Chave Twilio | `AC` / `SK` + 32 hex | 1 |
| Token npm | `npm_` + 36 | 1 |
| Chave Google API | `AIza` + 35 | 1 |
| Segredo OAuth do Google | `GOCSPX-` + 28 | 1 |
| Token do Telegram | `<8–10 díg.>:AA<33>` | 1 |
| Chave de conta Azure Storage | `AccountKey=<86 base64>==` | 1 |
| Token Shopify | `shpat_` / `shpss_` / `shppa_` / `shpca_` + 32 hex | 1 |
| Token DigitalOcean | `dop_v1_` + 64 hex | 1 |
| Token Square | `sq0atp-` / `sq0csp-` + 22+ | 1 |
| Token PyPI | `pypi-AgEI…` (50+) | 1 |
| Chave Postman | `PMAK-<24 hex>-<34 hex>` | 1 |
| Token HashiCorp Vault | `hvs.…` (30+, com dígito) | 1 |
| Token Doppler | `dp.pt.` / `dp.st.` / … + 40+ | 1 |
| Credencial Basic Auth | `Basic <base64>` | 1 |
| Token Bearer | `Bearer <token>` | 1 |
| Connection string | `mongodb\|postgres\|mysql\|redis\|amqp://user:senha@host` | 1 |
| Segredo em atribuição | `password = "…"`, `api_key: …`, `token=…` (com/sem aspas) | 2 |
| CPF | `123.456.789-09` (validado pelo dígito verificador) | 3 |
| CPF (sem máscara) | 11 dígitos válidos | 3 |
| CNPJ | `12.345.678/0001-95` (validado pelo dígito verificador) | 3 |
| CNPJ (sem máscara) | 14 dígitos válidos | 3 |
| Cartão de crédito | 13–19 dígitos, IIN 2–6, Luhn OK | 4 |
| Possível segredo (alta entropia) | token 32+ chars, entropia Shannon ≥ 4.5 | 5 |

---

## 4. O filtro de placeholder

Sobre **todas** as camadas atua um filtro global (`_is_placeholder`): qualquer trecho
casado é descartado se contiver marcadores típicos de exemplo/template. O detector não
"grita lobo" com material que claramente não é um segredo real. São descartados trechos
que contenham (sem diferenciar maiúsculas/minúsculas):

`example`, `dummy`, `placeholder`, `change_me`/`changeme`, `your-`/`your_`, `-here`,
oito ou mais caracteres idênticos seguidos (`_REPEAT_RE`, ex.: `xxxxxxxx`), `${`, `$(`,
`{{`, `%(`, `fixme`, `todo`, `redacted`, `foobar`, `lorem`, `insert_your`, e padrões
`<algo_assim>`.

> **Consequência prática:** a chave-exemplo canônica da AWS,
> `AKIAIOSFODNN7EXAMPLE`, **não** é marcada — ela contém `EXAMPLE`. Isso é intencional:
> documentação e exemplos não devem disparar alarme. O `_is_placeholder` veta apenas
> **exemplos claros** (template, repetição de 8+ chars, valor-exemplo conhecido); não
> esconde mais um segredo real só por conter um `dummy`/`todo` embutido (bypass
> "placeholder-poison" fechado).

---

## 5. Cofre `.rdbt` — confidencialidade em repouso

> **Eixo: confidencialidade.** O Cofre é a defesa real **em repouso** — não confunda com
> "ocultar" (seção 10), que é só privacidade visual e **não cifra**.

O **Cofre `.rdbt`** (`notepy/vault.py`, núcleo puro; depende da lib `cryptography`)
cifra o conteúdo em disco de verdade. Selar com `Ctrl+Shift+L`; travar/destravar com
`Ctrl+Shift+K` / `Ctrl+Shift+U`.

### Formato RDBT2 (envelope / key-slots, estilo LUKS/age)

- Uma **chave-de-conteúdo (CK)** aleatória de 256 bits cifra o texto com **AES-256-GCM**
  (cifragem autenticada).
- Cada **destravador** — uma **senha** *ou* um **arquivo-chave** — é um **slot** de 80
  bytes que **embrulha a CK** com uma chave derivada por **scrypt** (memory-hard).
- **Múltiplas senhas e/ou arquivos-chave independentes** abrem o **mesmo** cofre (até
  **16 slots**). Re-selar (`reseal`) preserva todos os slots: a CK fica em memória e o
  conteúdo é re-cifrado sem re-derivar as credenciais.
- O **AAD** liga o conteúdo a **todos** os slots (anti slot-strip: remover um slot
  invalida o GCM); `_check_kdf` valida `log2n`/`r`/`p` (anti **scrypt-bomb** — um `.rdbt`
  malicioso com `log2n` gigante alocaria petabytes).
- Lê e **migra em memória** o formato legado **RDBT1** (senha única) ao re-salvar.

### Garantias

- **Confidencialidade em repouso, zero-knowledge.** Nenhuma credencial é gravada;
  **esqueceu = irrecuperável**. O disco é **sempre** cifrado — nunca há plaintext em
  arquivo.
- **Cifragem autenticada (GCM).** Senha errada e adulteração de
  ciphertext/salt/nonce/slot são **barradas** (`InvalidTag` → `WrongPassword`).
- **Algo que você sabe + algo que você tem.** Senha e/ou arquivo-chave, combináveis.

### O que NÃO garante

- **NÃO prova integridade/autoria de quem cifrou** — isso é a Custódia (seção 6). O GCM
  garante que *o conteúdo não foi adulterado desde que foi selado com aquela CK*, mas
  qualquer um que tenha um destravador pode re-selar.
- **NÃO recupera senha esquecida** (consequência direta do zero-knowledge).
- **NÃO elimina resíduo de plaintext em RAM/swap** enquanto o cofre está **destravado**.

---

## 6. Custódia assinada + trilha de auditoria

> **Eixo: integridade + autenticidade.** A Custódia prova *"veio desta instalação e não
> mudou desde que assinei"* — **não** dá confidencialidade.

O Redoubt trata cada arquivo como **evidência** (`notepy/custody.py`, núcleo puro;
depende de `cryptography`). Verificar com `Ctrl+Shift+H`; assinar/exportar `.sig` com
`Ctrl+Shift+G`.

### Identidade Ed25519 por instalação

- Um par de chaves **Ed25519** é gerado por instalação. A **pública** é exportável
  (`identity.pub`, em claro) e qualquer um com ela **verifica** que o arquivo não mudou
  desde que você assinou.
- Por padrão a **privada** é um PEM **local sem senha** (`identity.ed25519`) — escolha de
  usabilidade. Consequência honesta: **quem tem a máquina assina como você**.
- **Opt-in "Proteger identidade"** (*Segurança ▸ Proteger identidade*): embrulha a chave
  privada num **Cofre RDBT2** (`identity.rdbt`, senha **+** arquivo-chave, multi-slot) e
  **apaga o PEM em claro**. A pública continua em claro, então *fingerprint* e
  *verificação* **não** pedem senha — só **assinar** pede (lazy, com cache de 1× por
  sessão). Proteger/desproteger faz **escrita atômica + wipe + rollback**, com
  *binding* pública↔chave e **auto-cura** de PEM órfão se cofre e PEM coexistirem após
  uma interrupção abrupta.

### Trilha de auditoria (hash-chain append-only)

Os eventos `abrir`/`salvar`/`selar`/`queimar`/`assinar` são registrados em `audit.log`,
cada entrada incluindo o **hash da anterior** + um `seq` (posição, no hash) e uma `sig`
Ed25519 *best-effort*. Adulterar/remover um evento passado **quebra a cadeia** de forma
detectável (`verify_chain`).

**Âncora anti-reset.** A hash-chain sozinha **não detecta reset** (apagar o `audit.log` e
recomeçar gera uma cadeia nova válida). Por isso há a **âncora exportável** (`export_anchor` →
`custody-anchor.json`, assinada): guardada **fora da máquina**, `check_anchor` depois acusa
reset / truncamento / reescrita. A verificação **amarra a âncora a uma identidade** — o
fingerprint derivado da chave tem que bater com o esperado (por padrão, a identidade local).
**Limitação honesta:** o padrão compara com a identidade *local*; um atacante que troca a
identidade local antes de forjar a âncora passaria o `identity_match`. Defesa: **proteja a
identidade** (ele não assina como você) e **confira o fingerprint da âncora com o que você
conhece do autor**, fora da máquina. A âncora que *você* guardou sempre detecta o reset.

### Hash SHA-256

`content_hash()` (SHA-256 do texto vivo, UTF-8) continua exibido na barra de status
(`custódia: a1b2c3d4`, `░ alterado`, `—`) como **conferência rápida de relance** de
edição não salva ou alteração externa. Mas atenção: **o hash nu sozinho não prova nada
contra um adversário** — qualquer um recalcula o SHA-256 de um arquivo adulterado. A
prova real é a **assinatura**.

### Garantias

- **Integridade + autenticidade**: prova "veio desta instalação e não mudou", **desde
  que a chave não vaze**.
- **Identidade protegida (opt-in)**: a privada só é útil com a credencial (zero-knowledge).
- A **trilha** detecta adulteração retroativa de eventos.

### O que NÃO garante

- **NÃO dá confidencialidade do conteúdo** (só integridade/autoria).
- **Sem** proteção da identidade, quem tem a máquina assina como você.
- `content_hash` **sozinho não prova autoria** — a prova é a assinatura.
- A hash-chain **sozinha não detecta RESET** (apagar a trilha e recomeçar) — só a **âncora**
  guardada fora da máquina detecta, e o binding dela é tão forte quanto a proteção da identidade.

---

## 7. Hook git anti-segredo

> **Eixo: detecção, fora do editor.** Leva a Sentinela para dentro do seu `git`.

A CLI `notepy/scan_cli.py` (núcleo puro, reusa `secrets.scan`) — instalável por
*Segurança ▸ Proteger repositório git*:

- `python -m notepy.scan_cli [arquivos…]` varre arquivos; `--staged` varre o **stage**
  via `git show :arquivo` (exatamente o que será commitado).
- `--install-hook` instala um **pre-commit** que **bloqueia o commit** (exit ≠ 0) se
  houver credencial; faz **backup** de hook pré-existente e **não o clobbra**.
  `--uninstall-hook` restaura o backup.
- `_decode` trata **BOM UTF-16/UTF-32** e densidade de **NUL** para não pular arquivos
  wide-encoded (bypass de encoding fechado); pula binário denso e arquivos **> 2 MB**
  (avisando, não em silêncio). **Fail-closed** quando o git falha dentro de um repo.

### Garantias

- **Bloqueia o commit** de credencial detectada pela Sentinela.
- O relatório **NUNCA imprime o segredo** em claro — só `arquivo:linha:coluna`, o tipo e
  uma prévia mascarada (`●●●`), para não vazar via logs de terminal/CI (saída forçada a
  UTF-8 para não quebrar em console cp1252).

### O que NÃO garante

- **Mesmas limitações de detecção da Sentinela** (best-effort).
- Arquivo **> 2 MB** não é varrido (só avisado).
- **Bypass**: `git commit --no-verify`; **whitelist** por linha: `redoubt:allow`.
- **Não é** um gate obrigatório de CI/CD — é uma rede local na hora do commit.

---

## 8. Release assinado + verificador standalone

> **Eixo: integridade + autenticidade do *download*.** Coerente com a tagline: o Redoubt
> prova a própria integridade.

`notepy/release.py` (núcleo puro) gera, ao lado dos binários, `SHA256SUMS` +
`RELEASE.json` (formato **RDBT-REL1**):

- Um **`signed_payload`** — string JSON canônica com produto/versão/data/pubkey/fingerprint
  e os artefatos (sha256 + tamanho).
- Uma **assinatura Ed25519** da identidade do Redoubt **sobre essa string**. O verificador
  confere a assinatura **sobre a string** e só então parseia (zero divergência
  gerador↔verificador). O *fingerprint* é sempre **derivado** da chave
  (`sha256(pubkey)[:16]`).

O verificador **standalone** `verify_release.py` (na raiz; só Python + `cryptography`,
não precisa instalar o app) **embute a chave pública do autor** (*fingerprint* oficial
**`4e391f28930f3b6e`**) e valida contra ela:

```bash
python verify_release.py .
```

### Garantias

- **Integridade** (assinatura válida + hashes batem) **e autenticidade** (`ok=True` só
  quando a chave derivada bate com a âncora embutida/`--pubkey`). Binário re-assinado com
  **outra** chave é **rejeitado**; o manifesto falha se qualquer hash não bater.

### O que NÃO garante

- **A assinatura sozinha não prova autenticidade** — a pubkey viaja no payload, e um
  atacante re-assina com a própria chave. Por isso a confiança depende da **âncora**
  embutida no verificador.
- A privada é **local e por padrão sem senha**: quem tem a máquina do autor pode assinar
  como ele (a menos que "Proteger identidade" esteja em uso).

---

## 9. Modo Redação (tela + clipboard)

O **Modo Redação** (`Ctrl+Shift+R`) cobre todos os segredos detectados com uma tarja
preta sólida (`REDACT_INDICATOR = 9`, caixa cheia com alfa 255 desenhada **sobre** o
texto) e, **com a redação ligada**, **mascara o clipboard**.

- **Tela.** A tarja cobre os pixels. É a ferramenta para **compartilhar a tela** /
  gravar / tirar screenshot sem expor credenciais.
- **Clipboard.** `mainwindow._sanitize_clipboard`, no sinal `dataChanged` do
  `QClipboard`, intercepta **todos** os caminhos nativos do Scintilla (`SCI_COPY`,
  `SCI_COPYRANGE`, seleção retangular, `Ctrl+Insert`, `Shift+Del`) e substitui um segredo
  detectado por `●` — inclusive cópias **parciais** ≥ 6 caracteres de um segredo. Reúne
  os segredos de **todas** as abas em redação, não só a focada.

### Garantias

- Esconde o segredo de **olhos/câmeras** (tela) e **mascara o clipboard** para o que a
  Sentinela detectou.

### O que NÃO garante

- A tarja na tela é **puramente VISUAL**: o **conteúdo real permanece no documento e no
  disco**. Salvar ou inspecionar a memória ainda traz o segredo. A proteção real em
  repouso é o **Cofre** (seção 5).
- O clipboard só mascara o que foi **DETECTADO** — um segredo sem padrão escapa, e cópia
  parcial **< 6 caracteres** não é mascarada (piso de projeto).

---

## 10. Burn Note + restaurar sessão com conteúdo oculto

### Burn Note (RAM-only) — `Ctrl+Shift+B`

Aba efêmera que **nunca vai ao disco** e é apagada ao fechar: `_wipe_editor` sobrescreve
o buffer, esvazia o **undo** (`SCI_EMPTYUNDOBUFFER`, para `Ctrl+Z` não reconstruir o
texto) e limpa o clipboard se contiver o conteúdo. Salvar/selar uma burn é **bloqueado**;
selo `🔥 BURN (só RAM)`. Burns não são persistidas na restauração de sessão.

- **Garante:** reduz o resíduo do segredo em memória; nada vai ao disco.
- **NÃO garante:** **não elimina** resíduo em RAM/swap — o Python não garante zerar
  strings imutáveis; o GC é quem libera. *Reduz, não elimina.*

### Restaurar sessão com conteúdo OCULTO

> **Eixo: privacidade — NÃO cifra.**

Reabre os arquivos da última sessão guardando **apenas os caminhos**, nunca o conteúdo
(`config.save_session`/`load_session`). Burns e abas sem título nunca são salvas. Cofres
reaparecem **TRAVADOS**, sem pedir senha (zero-knowledge). Um arquivo **em claro** onde a
Sentinela detecta credencial reabre **OCULTO** (selo `🛡️ OCULTO`), com barra *Revelar* /
*Selar como cofre*; salvar fica bloqueado enquanto oculto (a guarda `is_gated` está no
chokepoint `_write`). Arquivo **> 2 MB** é ocultado por precaução (fail-safe). Teto de
**50 arquivos**; **ignora caminhos UNC/remotos** (defesa contra registro adulterado:
trava de SMB / captura de hash NTLM).

- **Garante:** privacidade — não joga segredo na tela ao restaurar (anti screen-share);
  o conteúdo só fica em RAM e nunca é exibido até revelar; `content_hash`/custódia usam
  o **texto real**, não o banner.
- **NÃO garante:** **ocultar NÃO cifra** — o arquivo segue **em claro no disco**. A
  proteção real em repouso é **Selar como cofre**.

---

## 11. Resultados do red-team

O detector foi submetido a um exercício de **red-team**: um conjunto de **80 casos
adversariais** distribuídos em **4 lentes** de ataque — evasão de credenciais de
cloud/CI, indução de falso-positivo, PII brasileira e amostras de arquivos reais.

A versão ingênua original (**v1**) foi medida contra esse corpus; em seguida o detector
foi endurecido (**v2**) e remedido, mantendo intacta a regressão dos casos originais.

| Métrica | v1 (ingênuo) | v2 (endurecido) |
| --- | :---: | :---: |
| Recall (segredos reais detectados) | **46 %** | **92 %** |
| Precisão (achados que eram segredos de fato) | **55 %** | **87 %** |
| Casos adversariais | 80 (4 lentes) | 80 (4 lentes) |

Além do corpus do detector, o produto sobreviveu a **4 pentests adversariais** completos
(relatório em [`docs/SECURITY-TEST-REPORT.md`](SECURITY-TEST-REPORT.md)), e as features
de **identidade protegida** e **release assinado** passaram por red-team + 2 rodadas de
confirmação. A suíte automatizada soma **212 testes** (headless, `QT_QPA_PLATFORM=offscreen`).

> Os números acima foram **medidos contra o próprio scanner**; não são estimativas. Eles
> também deixam explícito que o detector **não é perfeito** — ~8 % dos segredos do corpus
> ainda escaparam (falso-negativo) e ~13 % dos achados não eram segredos (falso-positivo).
> Veja as limitações na seção 13.

---

## 12. Threat model completo (garante × não-garante)

O Redoubt mira o **vazamento acidental** de material sensível por humanos, e a
**proteção em repouso/integridade** do que for explicitamente selado/assinado. Tudo
**sem rede**: nada do que o Redoubt analisa ou cifra sai da sua máquina.

| Defesa | Eixo | Garante | NÃO garante |
| --- | --- | --- | --- |
| **Sentinela** | Detecção | Aponta credencial/PII de formato conhecido ou alta entropia, local, com validação real onde dá (CPF/CNPJ/Luhn) | Best-effort: segredo sem padrão/ofuscado escapa; há FP. `LIMPO` = "nada detectado", não "sem segredo" |
| **Cofre `.rdbt`** | Confidencialidade em repouso | Conteúdo cifrado AES-256-GCM, zero-knowledge, multi-destravador; disco sempre cifrado | Não prova autoria; não recupera senha; resíduo em RAM enquanto destravado |
| **Custódia (Ed25519)** | Integridade + autenticidade | "Veio desta instalação e não mudou desde que assinei"; trilha + âncora detectam adulteração e reset | Não dá confidencialidade; sem proteção da identidade, quem tem a máquina assina/forja como você |
| **Hook git** | Detecção (commit) | Bloqueia commit de credencial detectada; nunca imprime o segredo | Mesmas limitações da Sentinela; `--no-verify`/`redoubt:allow` desativam; >2 MB não varrido |
| **Release assinado** | Integridade + autenticidade do download | Integridade + autenticidade contra a âncora embutida | Assinatura sozinha não prova autoria (pubkey viaja no payload); chave local sem senha por padrão |
| **Modo Redação** | Privacidade (tela + clipboard) | Esconde de olhos/câmeras e mascara o clipboard para o detectado | Tela é só visual; conteúdo real permanece no disco; clipboard só mascara o detectado |
| **Burn Note** | Redução de resíduo | Nada vai ao disco; reduz resíduo em RAM | Não elimina resíduo em RAM/swap |
| **Ocultar (restaurar)** | Privacidade | Não exibe segredo ao restaurar; só em RAM até revelar | Não cifra — arquivo segue em claro no disco |

### O que o Redoubt explicitamente NÃO é

- **Não impede exfiltração por um atacante local.** Se um processo malicioso já roda na
  sua conta, ele lê os arquivos em claro e a memória do editor diretamente. (Um cofre
  **travado** protege o conteúdo em repouso; **destravado**, não.)
- **Não substitui um scanner de pipeline.** O hook é uma rede local na hora do commit,
  não um gate obrigatório de CI/CD.
- **Não é antivírus, sandbox ou DLP corporativo.**

---

## 13. Limitações honestas

Estas limitações são parte do produto e devem ser conhecidas por quem confia no Redoubt.

### (a) Resíduo de segredo na RAM/swap

Python **não permite zerar com garantia** uma string da memória: strings são imutáveis e
a liberação fica a cargo do garbage collector. A **Burn Note** e o **travar** do cofre
**reduzem** o resíduo, mas **não o eliminam** — cópias podem permanecer em buffers, no
swap ou em estruturas internas do interpretador e do Qt. *Reduz, não elimina.*

### (b) Detecção é best-effort (há FP e FN)

O detector é uma heurística em camadas, não um oráculo:

- **Falso-positivo (FP):** material legítimo de alta entropia pode disparar a camada 5 —
  por exemplo, um base64 de imagem embutido, JavaScript minificado, ou um
  SKU/identificador que por coincidência tem o formato de uma chave AWS.
- **Falso-negativo (FN):** segredos em **formatos de provedor desconhecidos**,
  **ofuscados/divididos** ao longo do texto, ou **degenerados** (8+ caracteres idênticos,
  vetados como placeholder por `_REPEAT_RE`) podem passar. O red-team mediu ~92 % de
  recall — ~8 % dos segredos do corpus escaparam.

Trate o selo `● LIMPO` como "nada foi detectado", **não** como "garantidamente não há
segredos".

### (c) Tela × clipboard (Modo Redação)

A tarja **na tela** é um indicador **visual** — o conteúdo real continua no documento e
no disco. Com a redação ligada, o **clipboard é de fato mascarado**, mas só para o que a
Sentinela **detectou** (segredo sem padrão escapa; cópia parcial < 6 chars não é
mascarada). Confidencialidade em repouso é trabalho do **Cofre**, não da redação.

### (d) Ocultar não cifra

Reabrir um arquivo com credencial como `🛡️ OCULTO` é **privacidade** (anti screen-share),
não criptografia: o arquivo segue **em claro no disco**. A proteção real é **Selar como
cofre**.

### (e) Chave privada local

A chave Ed25519 de custódia/release é, por padrão, **local e sem senha** — quem tem a
máquina do autor assina como ele. O opt-in *Proteger identidade* (embrulha a privada num
Cofre RDBT2) fecha isso, ao custo de pedir a credencial ao **assinar**.

### (f) Tudo roda local, sem rede

É uma força (privacidade total: nada sai da máquina) e um limite (não há inteligência de
ameaças remota, nem atualização dinâmica de padrões, nem verificação cruzada externa). O
detector sabe o que está codificado em `secrets.py` — nada além disso.

---

## 14. Como testar

A Sentinela (`notepy/secrets.py`), o Cofre (`vault.py`), a Custódia (`custody.py`), o
Release (`release.py`) e a CLI/hook (`scan_cli.py`) são **núcleos puros** (sem Qt) e
podem ser testados isolados:

```python
from notepy import secrets

texto = open("exemplo_segredos.py", encoding="utf-8").read()
for m in secrets.scan(texto):
    print(m.kind, "->", m.snippet)
```

```bash
# Hook git (CLI da Sentinela), sem abrir o editor:
python -m notepy.scan_cli arquivo.env
python -m notepy.scan_cli --staged          # varre o stage do git

# Verificar um release baixado (só Python + cryptography):
python verify_release.py .
```

- O arquivo **`exemplo_segredos.py`** na raiz do projeto serve de demonstração da Sentinela.
- Para rodar o **app inteiro em modo headless** (testes — 212 ao todo), defina
  `QT_QPA_PLATFORM=offscreen` e `PYTHONIOENCODING=utf-8`. A segunda é necessária porque
  os glifos do selo (`●`, `▲`, `■`) quebram no console cp1252 do Windows — embora
  funcionem normalmente na interface Qt.

---

*Redoubt v1.0.0 — Python · PyQt6 · QScintilla. Nada vaza sem você mandar.*
