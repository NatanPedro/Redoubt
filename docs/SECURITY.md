# Segurança do Redoubt

> **Redoubt** — *editor que trata cada arquivo como evidência.*
> Tagline: **"Nada vaza sem você mandar."**

Este é o documento mais importante do projeto. Ele descreve, com honestidade técnica,
**o que o Redoubt protege**, **como protege** e — igualmente importante — **o que ele
não protege**. Nada aqui promete mais do que o código entrega.

Toda a segurança do Redoubt roda **localmente, sem rede**. Não há telemetria, não há
chamada de API, não há upload. A análise acontece dentro do processo do editor, na sua
máquina.

---

## Sumário

- [1. A Sentinela de Segredos](#1-a-sentinela-de-segredos)
- [2. As 5 camadas de detecção](#2-as-5-camadas-de-deteccao)
- [3. Tabela dos tipos detectados](#3-tabela-dos-tipos-detectados)
- [4. O filtro de placeholder](#4-o-filtro-de-placeholder)
- [5. Cadeia de custódia (hash SHA-256)](#5-cadeia-de-custodia-hash-sha-256)
- [6. Modo Redação (tarja)](#6-modo-redacao-tarja)
- [7. Resultados do red-team](#7-resultados-do-red-team)
- [8. Threat model](#8-threat-model)
- [9. Limitações honestas](#9-limitacoes-honestas)
- [10. Como testar o detector](#10-como-testar-o-detector)

---

## 1. A Sentinela de Segredos

A **Sentinela de Segredos** (`notepy/secrets.py`) é o coração da identidade do Redoubt:
um varredor que lê o conteúdo do documento e aponta credenciais, tokens e PII expostos
**antes** que eles vazem em um commit, num compartilhamento de tela ou num arquivo de
configuração esquecido.

### Como a varredura se integra ao editor

O `CodeEditor` (`notepy/editor.py`) vigia o texto a cada alteração:

- **Debounce de 300 ms.** Cada `textChanged` reinicia um `QTimer` de disparo único
  (`setInterval(300)`); só depois de 300 ms sem digitação o texto é revarrido. Isso
  evita reanalisar a cada tecla.
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
de novo. Assim, um JWT não vira também "alta entropia" — ele já é um JWT.

Sobre **toda** a detecção paira um **filtro global de placeholder** (seção 4): qualquer
trecho que pareça exemplo/dummy é descartado antes de ser reportado.

---

## 2. As 5 camadas de detecção

### Camada 1 — Padrões de provedor (alta confiança)

Expressões regulares para formatos de credencial bem definidos. Quando o formato bate,
a confiança é alta. Os padrões implementados (`_PATTERNS`):

- **Chave de acesso AWS** — `AKIA` seguido de 16 caracteres `[0-9A-Z]`.
- **Token JWT** — `eyJ…` em 2 ou 3 partes separadas por ponto.
- **Chave privada PEM** — cabeçalho `-----BEGIN [RSA|EC|OPENSSH|DSA|PGP ]PRIVATE KEY-----`.
- **Token do GitHub** — `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36+ caracteres.
- **Token do Slack** — `xoxb-`/`xoxa-`/`xoxp-`/`xoxr-`/`xoxs-` + cauda.
- **Webhook do Slack** — URL `https://hooks.slack.com/services/…`.
- **Chave da OpenAI** — `sk-` e `sk-proj-` + 20+ caracteres.
- **Chave Stripe** — `sk_live`/`sk_test`/`rk_live`/`rk_test` + 16+ caracteres.
- **Chave SendGrid** — `SG.<16+>.<16+>`.
- **Chave Twilio** — `AC`/`SK` + 32 hex.
- **Token npm** — `npm_` + 36 caracteres.
- **Chave Google API** — `AIza` + 35 caracteres.
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
   descarta `password = senha123`? Não — `senha123` tem 2 classes. Descarta sim `token =
   foo` (curto demais) e valores que são apenas prosa simples.

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
> nunca no meio. Isso corrige um bug da v1 em que o nome da variável grudava no valor
> (`x=<hash>`) e furava a exclusão de hash.

---

## 3. Tabela dos tipos detectados

| Tipo | Exemplo de formato | Camada |
| --- | --- | :---: |
| Chave de acesso AWS | `AKIA` + 16 `[0-9A-Z]` | 1 |
| Token JWT | `eyJ….<base64url>.<base64url>` (2–3 partes) | 1 |
| Chave privada PEM | `-----BEGIN [RSA\|EC\|OPENSSH\|DSA\|PGP ]PRIVATE KEY-----` | 1 |
| Token do GitHub | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` + 36+ | 1 |
| Token do Slack | `xoxb-` / `xoxa-` / `xoxp-` / `xoxr-` / `xoxs-` + cauda | 1 |
| Webhook do Slack | `https://hooks.slack.com/services/…` | 1 |
| Chave da OpenAI | `sk-…` e `sk-proj-…` (20+) | 1 |
| Chave Stripe | `sk_live` / `sk_test` / `rk_live` / `rk_test` + 16+ | 1 |
| Chave SendGrid | `SG.<16+>.<16+>` | 1 |
| Chave Twilio | `AC` / `SK` + 32 hex | 1 |
| Token npm | `npm_` + 36 | 1 |
| Chave Google API | `AIza` + 35 | 1 |
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
quatro ou mais `x` seguidos (`xxxx`), `${`, `{{`, `fixme`, `todo`, `redacted`,
`foobar`, `lorem`, `insert_your`, e padrões `<algo_assim>`.

> **Consequência prática:** a chave-exemplo canônica da AWS,
> `AKIAIOSFODNN7EXAMPLE`, **não** é marcada — ela contém `EXAMPLE`. Isso é intencional:
> documentação e exemplos não devem disparar alarme.

---

## 5. Cadeia de custódia (hash SHA-256)

O Redoubt mantém uma **cadeia de custódia** do conteúdo, para que adulteração externa
(ou edição não salva) seja visível de relance:

- `content_hash()` calcula o **SHA-256** do texto atual (UTF-8).
- Ao **abrir** e ao **salvar** (`mark_saved`), o hash do estado salvo é registrado.
- A barra de status mostra (`_hash_text`):
  - `custódia: —` quando não há estado salvo (documento novo);
  - `custódia: ░ alterado` enquanto há edição **não salva**;
  - `custódia: <8 primeiros hex>` quando o documento está salvo e íntegro.

Os 8 primeiros dígitos hexadecimais são exibidos para conferência rápida. Reabrir um
arquivo e comparar o início do hash com um valor conhecido revela alteração externa.

---

## 6. Modo Redação (tarja)

O **Modo Redação** (`Ctrl+Shift+R`) cobre todos os segredos detectados com uma tarja
preta sólida (`REDACT_INDICATOR = 9`, caixa cheia com alfa 255 desenhada **sobre** o
texto). É a ferramenta para **compartilhar a tela** sem expor credenciais.

> **Atenção — a redação é puramente VISUAL.** A tarja cobre os pixels, mas o **conteúdo
> real permanece no documento**. Copiar o trecho tarjado, salvar o arquivo ou inspecionar
> a memória ainda traz o segredo. A redação protege contra **olhos e câmeras**, não
> contra cópia. Veja a seção 9.

O **selo de estado** na barra de status reflete a situação do documento atual:

| Selo | Significado |
| --- | --- |
| `● LIMPO` (verde) | nenhum segredo detectado |
| `▲ EXPOSTO · N` (vermelho) | N segredos visíveis no documento |
| `■ REDIGIDO · N` (âmbar) | N segredos detectados, atualmente tarjados |

A aba também é marcada com `▲` quando há segredo, e a janela ganha o flag
`[▲ EXPOSTO]` no título.

---

## 7. Resultados do red-team

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

### O que o endurecimento (v2) adicionou

- Padrões de provedor faltantes: **Stripe, SendGrid, Twilio, npm, Basic Auth, Bearer** e
  o **webhook do Slack**.
- Detecção de **senha sem aspas** na camada de atribuição.
- **CPF/CNPJ sem máscara** (só dígitos), validados pelo dígito verificador.
- **Cartão de crédito** com validação de Luhn + IIN + comprimento real.
- O **filtro global de placeholder** (seção 4).
- Correção do bug em que o regex de entropia incluía `=` no meio do token, grudava o
  nome da variável no valor e furava a exclusão de hashes hexadecimais.

> Os números acima foram **medidos contra o próprio scanner**; não são estimativas. Eles
> também deixam explícito que o detector **não é perfeito** — 8 % dos segredos do corpus
> ainda escaparam (falso-negativo) e 13 % dos achados não eram segredos (falso-positivo).
> Veja as limitações na seção 9.

---

## 8. Threat model

### O que o Redoubt protege

O Redoubt mira o **vazamento acidental** de material sensível por humanos, no momento da
edição. Em concreto, ele ajuda a evitar:

- **Credencial/PII commitada por engano.** O selo `▲ EXPOSTO` e a marcação vermelha
  avisam que há uma chave AWS, um token, uma senha ou um CPF no arquivo **antes** de você
  salvar e commitar.
- **Exposição em compartilhamento de tela / gravação.** O Modo Redação tarja os segredos
  para apresentações, calls e screenshots.
- **Segredo esquecido em arquivo de configuração.** Connection strings, `api_key=...` em
  `.env`/`.ini`, tokens em JSON/YAML — a Sentinela os aponta.
- **Adulteração externa do arquivo.** A cadeia de custódia (SHA-256) torna visível que o
  conteúdo mudou fora do editor ou que há edição não salva.

Tudo isso **sem rede**: nada do que o Redoubt analisa sai da sua máquina.

### O que o Redoubt NÃO protege

- **Não é um cofre.** O Redoubt **não criptografa** o arquivo no disco (na v0.2.0). Quem
  tiver acesso ao arquivo lê o conteúdo. *(Um cofre `.rdbt` cifrado com AES-GCM está no
  roadmap da Fase 3.)*
- **Não impede exfiltração por um atacante local.** Se um processo malicioso já roda na
  sua conta, ele lê o arquivo e a memória do editor diretamente.
- **Não substitui um scanner de pipeline.** É uma rede de proteção **no momento da
  edição**, não um gate obrigatório de CI/CD.
- **Não garante apagar o segredo da memória** (veja seção 9).
- **Não é antivírus, sandbox ou DLP corporativo.** É um editor com vigilância de
  segredos, não uma solução de prevenção de perda de dados.

---

## 9. Limitações honestas

Estas limitações são parte do produto e devem ser conhecidas por quem confia no Redoubt.

### (a) Resíduo de segredo na RAM

Python **não permite zerar com garantia** uma string da memória: strings são imutáveis e
a liberação fica a cargo do garbage collector. Qualquer recurso futuro de "queimar" um
segredo da memória (*burn note*, no roadmap) **reduz** o resíduo, mas **não o elimina** —
cópias podem permanecer em buffers, no swap ou em estruturas internas do interpretador e
do Qt.

### (b) Detecção é best-effort (há FP e FN)

O detector é uma heurística em camadas, não um oráculo:

- **Falso-positivo (FP):** material legítimo de alta entropia pode disparar a camada 5 —
  por exemplo, um base64 de imagem embutido, JavaScript minificado, ou um SKU/identificador
  que por coincidência tem o formato de uma chave AWS.
- **Falso-negativo (FN):** segredos em **formatos de provedor desconhecidos**, ou
  **ofuscados/divididos** ao longo do texto, podem passar despercebidos. O red-team mediu
  ~92 % de recall na v2 — ou seja, **~8 % dos segredos do corpus escaparam**.

Trate o selo `● LIMPO` como "nada foi detectado", **não** como "garantidamente não há
segredos".

### (c) O Modo Redação é apenas VISUAL

A tarja cobre o segredo na tela, mas o **conteúdo real continua no documento**. Copiar o
texto tarjado, salvar o arquivo ou inspecioná-lo por fora ainda revela o segredo. A
redação serve para **olhos e câmeras**, não para impedir cópia ou exfiltração.

### (d) Tudo roda local, sem rede

É uma força (privacidade total: nada sai da máquina) e um limite (não há inteligência de
ameaças remota, nem atualização dinâmica de padrões, nem verificação cruzada externa). O
detector sabe o que está codificado em `secrets.py` — nada além disso.

---

## 10. Como testar o detector

A Sentinela (`notepy/secrets.py`) **não depende do Qt** e pode ser testada isolada:

```python
from notepy import secrets

texto = open("exemplo_segredos.py", encoding="utf-8").read()
for m in secrets.scan(texto):
    print(m.kind, "->", m.snippet)
```

- O arquivo **`exemplo_segredos.py`** na raiz do projeto serve de demonstração.
- Para rodar o **app inteiro em modo headless** (testes), defina as variáveis de
  ambiente `QT_QPA_PLATFORM=offscreen` e `PYTHONIOENCODING=utf-8`. A segunda é necessária
  porque os glifos do selo (`●`, `▲`, `■`) quebram no console cp1252 do Windows — embora
  funcionem normalmente na interface Qt.

---

*Redoubt v0.2.0 — Python · PyQt6 · QScintilla. Nada vaza sem você mandar.*
