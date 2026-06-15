# Changelog

Todas as mudancas relevantes do **Redoubt** sao registradas neste arquivo.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e o projeto adota o [Versionamento Semantico](https://semver.org/lang/pt-BR/).

> **Redoubt** — *"Nada vaza sem voce mandar."*
> Editor que trata cada arquivo como evidencia: vigia segredos, sela o conteudo
> e mantem cadeia de custodia.
>
> Nota historica: o pacote Python continua se chamando `notepy/` por heranca,
> mas o produto foi renomeado para **Redoubt** em `notepy/__init__.py`.

---

## [Nao lancado]

Ideias futuras (sem data):
- Selo de proveniência exportável (`.rdbt-seal`).
- KDF do Cofre: scrypt → Argon2id (formato RDBT3 retrocompatível).
- Hook git local (pytest no pre-push).

---

## [1.1.0] - 2026-06-15 — Custódia forte: release assinado, identidade protegida, trilha ancorada 🔐

Marco de segurança: o eixo de **integridade + autenticidade** amadureceu — o Redoubt passa a
provar a própria distribuição, proteger a identidade que assina, e a trilha de auditoria detecta
reset. Cada entrega passou por *red-team* adversarial + rodada(s) de confirmação.

### Added
- **Release assinado + verificador standalone** — o Redoubt passa a provar a própria
  integridade. `build-installer.bat` gera, ao lado dos binários, um `SHA256SUMS` e um
  `RELEASE.json` **assinado com a identidade Ed25519** do Redoubt (núcleo puro em
  `notepy/release.py`). O verificador [`verify_release.py`](verify_release.py) — standalone,
  sem instalar o app — **embute a chave pública do autor** e valida a assinatura contra ela:
  binário re-assinado com outra chave é rejeitado, e o manifesto falha se qualquer hash não
  bater. Fingerprint oficial: `4e391f28930f3b6e`. Seção "Verificar o download" no README.
- **Identidade Ed25519 protegida por senha** (opt-in, *Segurança ▸ Proteger identidade*) —
  embrulha a chave privada no Cofre RDBT2 (`identity.rdbt`: senha **+ arquivo-chave**, multi-slot)
  e apaga o PEM em claro; a pública fica em `identity.pub` (claro), então *fingerprint*/verificação
  não pedem senha — só **assinar** pede (1× por sessão, cacheada). Preserva o fingerprint da
  identidade existente. Endurecida por *red-team* + 2 rodadas de confirmação: escrita atômica +
  *wipe* + remoção verificada com **rollback** (em proteger E desproteger), *binding* pública↔chave,
  robustez a `identity.pub`/cofre corrompidos, e **detecção + auto-cura** do PEM órfão quando cofre
  e chave em claro coexistirem (interrupção abrupta).
- **Trilha de auditoria assinada + âncora anti-reset** — cada entrada da trilha ganha `seq`
  (posição, dentro do hash) e uma `sig` Ed25519 *best-effort*; `verify_chain` passa a validar o
  `seq` (pega remoção no meio). Para o reset que a hash-chain não pega (apagar o `audit.log` e
  recomeçar), **Segurança ▸ Exportar/Verificar âncora de custódia**: uma âncora assinada
  (`custody-anchor.json`) guardada fora da máquina detecta reset/truncamento/reescrita.
  `check_anchor` **amarra a âncora à identidade** (fingerprint derivado da chave; default = a
  identidade local) — âncora forjada por outra chave é rejeitada. Endurecida por *red-team* +
  confirmação (binding de identidade, verificação read-only que não cria chave, robustez a
  trilha/âncora malformadas). Limitação documentada honestamente no `SECURITY.md`.
- **Testes**: +21 (`test_release.py`) + 31 (`test_custody.py`, 9→40 — casos de red-team das três
  features) → **229 testes no total, 0 falhas.**

### Changed
- Documentação técnica (`SECURITY.md`/`ARCHITECTURE.md`/`DEVELOPMENT.md`) sincronizada do estado
  congelado em v0.2.0 para o v1.x real (Cofre++, custódia, identidade protegida, release assinado,
  arquitetura em camadas); modelo de ameaça reescrito em 3 eixos honestos. README alinhado
  (badge de testes, dependências).

---

## [1.0.0] - 2026-06-10 — Primeiro release estável 🏁

Marco: o Redoubt sai do 0.x. **Sem feature nova** — é o selo de estabilidade sobre tudo
que foi construído e validado.

- **Pilares:** Sentinela de Segredos (24+ padrões, recall/precisão validados por corpus
  de *red-team*) · **Cofre++** (AES-256-GCM em envelope, múltiplas senhas + arquivo-chave) ·
  **Custódia assinada Ed25519** + trilha de auditoria · **Hook git anti-segredo** · Modo
  Redação (tela **e** clipboard) · Burn Note · Restaurar sessão com **conteúdo oculto** ·
  Localizar/Substituir · Busca em arquivos · Paleta de comandos · Diff · Temas claro/escuro.
- **Qualidade:** **4 pentests adversariais** (relatório §1–§7), **176 testes**
  automatizados, verificação ponta-a-ponta de todos os subsistemas (39 checagens) +
  hook validado em repositório git real.
- **Docs:** README atualizado para refletir o produto completo; `.gitignore` passa a
  ignorar `*.sig` (assinaturas de custódia).
- **Distribuição:** **instalador Windows** (Inno Setup — `installer/redoubt.iss` +
  `build-installer.bat`) que instala em *Program Files*, cria atalhos, **associa `.rdbt`**
  (duplo-clique abre o cofre) e registra *uninstaller*. Gera `dist\Redoubt-Setup-1.0.0.exe`.

### Fixed
- **Atalhos sequestrados pelo QScintilla:** `Ctrl+Shift+L` (selar cofre), `Ctrl+Shift+U`
  (destravar) e outros não disparavam pelo teclado — o *keymap* interno do editor os
  consumia (apagar linha / MAIÚSCULAS), e a ação só funcionava pelo menu. O `CodeEditor`
  agora **libera** (`SCI_CLEARCMDKEY`) todas as combinações `Ctrl+Shift+<letra>` que o
  Redoubt usa como ação de janela.

---

## [0.13.0] - 2026-06-10 — Produtividade (busca em arquivos, paleta, diff)

### Added
- **Busca em arquivos** (`Ctrl+Shift+F`) — grep recursivo numa pasta (texto ou regex,
  case on/off) com painel de resultados agrupado por arquivo; duplo-clique abre o
  arquivo na linha. Pula binários, arquivos > 2 MB e pastas pesadas (`.git`,
  `node_modules`…); cap de resultados e proteção anti-ReDoS. Núcleo `notepy/searchfiles.py`.
- **Paleta de comandos** (`Ctrl+Shift+P`) — estilo VS Code: busca **fuzzy** por nome
  e executa qualquer comando (↑/↓ navega, Enter executa). Reúne as ações de menu **+
  comandos extras** que só existiam como botão/preferência (Tema claro/escuro, Revelar
  conteúdo oculto). Núcleo `notepy/palette.py` (`fuzzy_score`/`rank`).
- **Comparar arquivos (diff)** (`Ctrl+Shift+D`) — unified diff estilo *git* com realce
  verde/vermelho e resumo `+N / -N`; o arquivo A já vem com a aba atual. Núcleo
  `notepy/difftool.py` (`difflib`).
- Os três núcleos são **Python puro (sem Qt)**, testáveis isolados. +21 testes (8 busca
  + 6 paleta + 6 diff + 1 GUI de cada) → **176 testes**.

---

## [0.12.0] - 2026-06-10 — Cofre++ (envelope / múltiplos destravadores)

### Added
- **Cofre com múltiplos destravadores** — o `.rdbt` virou formato **envelope RDBT2**
  (estilo LUKS/age): uma **chave-de-conteúdo (CK)** aleatória cifra o texto, e cada
  destravador (senha **ou** arquivo-chave) é um **slot** que embrulha a CK. Logo:
  - **Múltiplas senhas independentes** abrem o mesmo cofre.
  - **Arquivo-chave** (key-file) como destravador — algo que você *tem*, além de algo
    que você *sabe*.
  - **Re-selar preserva todos os slots** (CK em memória); o conteúdo é re-cifrado sem
    re-derivar as credenciais.
- **GUI (menu Segurança):** *Adicionar senha…*, *Adicionar arquivo-chave…*, *Destravar
  com arquivo-chave…*.
- **Retrocompatível:** lê `.rdbt` antigo (RDBT1, senha única) e o **migra para RDBT2**
  ao re-salvar.
- **Defesas:** parâmetros de KDF validados por slot (anti scrypt-bomb); AAD liga o
  conteúdo a todos os slots (anti slot-strip); até 16 slots. `notepy/vault.py` reescrito
  (`new_vault`/`open_vault`/`reseal`/`add_unlocker`/`slot_kinds`; `encrypt`/`decrypt`
  mantidos por compat). +11 testes (envelope: multi-senha, keyfile, reseal preserva,
  migração RDBT1, strip de slot) → **152 testes**.

---

## [0.11.0] - 2026-06-10 — Custódia assinada + trilha de auditoria

### Added
- **`notepy/custody.py`** — eleva a custódia de um SHA-256 nu (que qualquer um
  recalcula) para **prova de verdade**:
  - **Identidade Ed25519 por instalação** (par de chaves; a privada fica num arquivo
    local sem senha em `%APPDATA%\Redoubt\Redoubt\identity.ed25519`).
  - **Assinar/verificar** conteúdo; a chave **pública** é exportável → qualquer um
    verifica que o arquivo não mudou desde que você assinou.
  - **Trilha de auditoria encadeada** (hash-chain append-only) dos eventos —
    `abrir`/`salvar`/`selar`/`queimar`/`assinar`: adulterar um evento passado
    **quebra a cadeia** de forma detectável.
- **Verificar custódia** (`Ctrl+Shift+H`) agora mostra, além do SHA-256: o status da
  **assinatura `.sig`** (✓ confere / ⚠ mudou), o **fingerprint** da chave pública e a
  **integridade da cadeia** de auditoria.
- **Assinar e exportar** (`Ctrl+Shift+G`) — grava `<arquivo>.sig` (assinatura destacada)
  + a chave pública, prontos para verificação por terceiros.
- Honestidade: a chave privada é local e sem senha (escolha de uso) — prova "veio desta
  instalação e não mudou", desde que a chave não vaze. Tudo local, sem rede. Guia:
  `docs/CUSTODY.md`. +11 testes → **141 testes**.

---

## [0.10.1] - 2026-06-10 — Endurecimento (pentest v0.7–v0.10)

Pentest adversarial de 4 frentes (sessão, conteúdo oculto, hook git, tema+Sentinela).
~20 achados; corrigidos os de impacto. Suíte: **118 → 130 testes**.

### Fixed (Segurança)
- **🔴 Bypass do hook por encoding/NUL** — arquivo **UTF-16/UTF-32** (com ou sem BOM)
  ou texto com **`\x00` injetado** era tratado como binário e **pulado**, deixando um
  segredo passar pelo commit (o editor detectava, o hook não). `scan_cli._decode`
  agora trata BOMs e usa heurística de densidade de NUL para decodificar wide/limpar
  NUL. Confirmado em repo git real.
- **🟠 Crash ao destravar cofre adulterado** — `unlock_current` só pegava
  `WrongPassword`; um `.rdbt` truncado/corrompido (via registro/sessão) lançava
  `VaultError` que escapava do slot Qt e derrubava o app. Agora captura `VaultError`.
- **🟠 Conteúdo oculto exposto ao "Selar" e cancelar** — `_gate_seal` revelava o texto
  ANTES de pedir a senha; cancelar deixava o segredo na tela. Agora pede a senha com a
  aba ainda **oculta** e só revela se confirmar.
- **🟠 Restauração de arquivo grande abria em claro** (fail-open) — arquivo > 2 MB era
  aberto visível ao restaurar. Agora **oculta por precaução** (fail-safe).
- **🟠 Tema envenenado derrubava o app** — valor não-string em `theme` (registro
  corrompido) causava `TypeError` em `apply_theme`/startup. `config.get` coage para str
  e `theme.set_theme` valida o tipo.
- **🟡 Custódia do oculto** — `content_hash` agora usa o conteúdo real (não o banner).
- **🟡 Falso-positivo `hvs.`** bloqueava commits legítimos (`obj.metodo_snake_case`);
  padrão endurecido (exige dígito/comprimento). Telegram agora exige prefixo real `AA`.
- **🟡 Relatório do hook crashava em console cp1252** (●/…/—); saída forçada a UTF-8.
- **🟡 Guarda `is_gated` movida para o chokepoint `_write`** (defesa em profundidade).

### Hardened
- Hook **fail-closed** quando o git falha **dentro** de um repo (não libera commit às cegas).
- Restauração de sessão: **teto de 50 arquivos** + **ignora caminhos UNC/remotos**
  (defesa contra registro adulterado: trava de SMB / captura de hash NTLM).
- Hook **avisa** (em vez de pular em silêncio) quando um arquivo staged é grande demais.

### Notas (resistiram / limitações documentadas)
- Resistiram: copiar de aba oculta não vaza; `apply_theme` sobre oculto/cofre/burn não
  expõe nem quebra; saída do hook nunca mostra o segredo; regex novos sem ReDoS.
- Limitações: arquivo > 2 MB no hook é avisado mas não varrido; varredura da restauração
  é síncrona (~1 s/arquivo grande); assinar a lista de sessão (HMAC) fica como futuro.

---

## [0.10.0] - 2026-06-10 — Sentinela expandida

### Added
- **12 novos padrões de provedor** (alta confiança, prefixo distintivo → baixíssimo
  falso-positivo): GitHub fine-grained (`github_pat_`), GitLab (`glpat-`), segredo
  OAuth do Google (`GOCSPX-`), Telegram bot, Azure Storage (`AccountKey=`), Shopify
  (`shpat_`/`shpss_`/…), DigitalOcean (`dop_v1_`), Square (`sq0atp-`/`sq0csp-`), PyPI
  (`pypi-AgEI…`), Postman (`PMAK-`), HashiCorp Vault (`hvs.`), Doppler (`dp.pt.`…).
- **AWS** ampliado para credenciais temporárias (`ASIA…`), além de `AKIA…`.
- **PEM** generalizado: cobre `PGP PRIVATE KEY BLOCK` e `ENCRYPTED PRIVATE KEY`.
- Esses padrões reforçam de uma vez o **editor**, o **hook git** e o **conteúdo
  oculto** (todos usam o mesmo `secrets.scan`). +19 testes (cobertura de cada tipo +
  negativos de precisão) → **118 testes**; recall/precisão do corpus de red-team mantidos.

---

## [0.9.0] - 2026-06-10 — Tema claro + acabamento

### Added
- **Tema claro + troca de tema.** `notepy/theme.py` virou multi-paleta (`dark`
  carbono / `light` claro) com **a mesma semântica de cor** (âmbar=marca,
  verde=limpo, vermelho=exposto). `set_theme()` reescreve a paleta ativa e o QSS
  em runtime; seletor em **Preferências** aplica **ao vivo** (re-tematiza app +
  todas as abas + lexers). Preferência `theme` (padrão `dark`).
- **Hook anti-segredo na GUI** — menu **Segurança ▸ Proteger repositório git
  (hook anti-segredo)…**: escolhe a pasta do repo e instala o `pre-commit` num
  clique (reusa `scan_cli.install_hook`). +6 testes → **99 testes**.

---

## [0.8.0] - 2026-06-10 — Hook git anti-segredo (Sentinela fora do editor)

### Added
- **`notepy/scan_cli.py` — CLI da Sentinela + hook `pre-commit`.** Leva a detecção
  de segredos para **fora do editor**, blindando o `git`:
  - `python -m notepy.scan_cli [arquivos…]` varre arquivos; `--staged` varre o que
    está no *stage* (via `git show :arquivo` — exatamente o que vai ser commitado).
  - `--install-hook [repo]` instala um `pre-commit` que **bloqueia o commit** se houver
    credencial no stage (sai com código ≠ 0). `--uninstall-hook` remove (e restaura
    backup de hook pré-existente — não clobbra hook alheio).
  - **Bypass** pontual: `git commit --no-verify`. **Whitelist** por linha: comentário
    com `redoubt:allow` na mesma linha ignora aquele achado.
  - **Segurança do próprio relatório:** a saída **nunca imprime o segredo** — só
    `arquivo:linha:coluna`, o tipo e uma prévia mascarada (`●●●…`), pra não vazar
    via logs de terminal/CI.
  - Reusa `notepy/secrets.py` (Python puro, sem Qt) — roda leve no hook. Pula binários
    (NUL) e arquivos > 2 MB. +8 testes → **93 testes**. Validado num repo git real
    (bloqueia segredo, `--no-verify` passa, arquivo limpo passa, `redoubt:allow` passa).

---

## [0.7.0] - 2026-06-09 — Restaurar sessão

### Added
- **Restaurar sessão ao abrir** — o Redoubt reabre os arquivos que estavam abertos.
  Desenhado com a postura de segurança do produto:
  - Persiste **apenas os CAMINHOS** dos arquivos — **nunca o conteúdo**.
  - **Notas de queima** e **abas sem título** (buffers em RAM, possivelmente com
    segredo) **jamais** são salvas — nada de texto sensível vai para o registro.
  - **Cofres** reaparecem **TRAVADOS, sem pedir senha** (zero-knowledge): só o
    caminho é lembrado; o `.rdbt` no disco já é cifrado; destrava com `Ctrl+Shift+U`.
  - Liga/desliga em **Preferências** (`restore_session`, padrão ligado); argumentos
    de linha de comando têm prioridade sobre a sessão.
  - `notepy/config.py` ganhou `save_session`/`load_session` + suporte a preferência
    booleana; `editor.restore_locked()` reabre cofre lacrado.
- **Conteúdo oculto na restauração (privacidade, híbrido):** ao restaurar um arquivo
  **em claro** onde a Sentinela detecta credencial, o Redoubt abre com o conteúdo
  **OCULTO** (selo `🛡️ OCULTO`) + uma barra com **Revelar** e **Selar como cofre** —
  evita jogar segredo na tela num restore (anti screen-share). Arquivo limpo abre
  normal. Honestidade: ocultar **não cifra** (o texto fica só em RAM, nunca exibido,
  e o arquivo segue em claro no disco); a proteção real é o botão **Selar como cofre**
  (vira `.rdbt`). Salvar fica **bloqueado** enquanto oculto (não sobrescreve o original
  com o banner). +10 testes → **85 testes**.

---

## [0.6.1] - 2026-06-09 — Endurecimento (pentest v0.6)

Pentest adversarial focado na superficie nova (Localizar/Substituir, Preferências/
config) + regressão de toda a segurança. 8 achados; 5 corrigidos, 3 documentados
como limitação. Suíte: **67 → 75 testes**.

### Fixed (Segurança)
- **CRÍTICA — `Substituir tudo` com regex de match-vazio (`a*`, `^`, `\b`) entrava
  em loop infinito e congelava a GUI** (DoS auto-infligido, perda de trabalho não
  salvo). `findbar.replace_all` agora detecta match de largura zero e avança, com
  teto absoluto de iterações (`_REPLACE_CAP`) como cinto-e-suspensório.
- **ALTA — Redação do clipboard furava com 2+ abas**: `_sanitize_clipboard` olhava
  só a aba focada, não a aba dona da cópia. Agora mascara usando os segredos de
  **todas** as abas em redação.
- **MÉDIA — UTF-16/UTF-32 caíam em mojibake** (cp1252/latin-1 nunca falham), o
  segredo ficava invisível e o selo mostrava "LIMPO" falso. `read_text` agora
  detecta os BOMs UTF-16/UTF-32 e decodifica certo.
- **MÉDIA — NUL embutido truncava o conteúdo** (`SCI_SETTEXT` para no `\x00`):
  tudo após o NUL sumia e o selo mostrava "LIMPO". `read_text` neutraliza o NUL
  (→ `␀`), então nada é truncado e a Sentinela varre o arquivo inteiro.
- **MÉDIA — `lock()` não esvaziava o undo**: `Ctrl+Z` reconstruía o texto-claro
  anterior ao travamento. `lock()`/`unlock()` agora chamam `SCI_EMPTYUNDOBUFFER`.

### Hardened (defesa em profundidade)
- `config.get()` agora **clampa** os inteiros (`tab_width`, `font_size`,
  `auto_lock_min`) — registro adulterado/corrompido não injeta mais valores
  absurdos que o spinbox da tela já impede.

### Notas / limitações documentadas (sem mudança de código)
- Engine de regex do QScintilla é não-backtracking → **sem ReDoS clássico**.
- Token com 8+ caracteres idênticos seguidos é tratado como placeholder
  (`_REPEAT_RE`): veta corretamente `AKIAXXXX…`/`${...}`; o custo (não pegar um
  token real degenerado) é estatisticamente desprezível — trade-off a favor da precisão.
- Cópia parcial de segredo com < 6 caracteres não é mascarada (piso de projeto).

---

## [0.6.0] - 2026-06-09 — Preferências

### Added
- **Diálogo de Preferências** (`Ctrl+,`) — persiste via **QSettings**:
  - **Auto-lock do cofre** configurável (antes fixo em 5 min; `0` = desativado).
  - **Fonte** (monoespacadas instaladas), **tamanho da fonte** e **largura do tab**.
  - Aplicado em tempo real a todas as abas; novos editores ja nascem com a preferencia.
  - Modulos novos: `notepy/config.py` (wrapper de QSettings, testavel sem Qt) e
    `notepy/preferences.py` (o dialogo). +6 testes → **67 testes**.

---

## [0.5.0] - 2026-06-09 — Localizar/Substituir + suite de testes

### Added
- **Localizar/Substituir** (`Ctrl+F` / `Ctrl+H`) — barra de busca com **regex**,
  diferenciar maiusc./minusc., palavra inteira, proxima/anterior (`F3`/`Shift+F3`),
  substituir e substituir-tudo (uma so acao de desfazer). Tambem via barra `:`
  (`find`/`replace`). Esc fecha e devolve o foco ao editor. Modulo `notepy/findbar.py`.
- **Suite de testes (pytest)** — `tests/` com 61 testes cobrindo Sentinela,
  Cofre, integracao (cofre/clipboard/burn/encoding), Localizar/Substituir e o
  corpus adversarial de red-team (piso recall≥85% / precisao≥78%). Config em
  `pyproject.toml`. Rodar: `pip install -r requirements-dev.txt` + `pytest`.

---

## [0.4.1] - 2026-06-08 — Endurecimento pos-pentest da Fase 3

Pentest adversarial das features novas (35 achados, 4 criticas). Detalhes em
[`docs/SECURITY-TEST-REPORT.md`](docs/SECURITY-TEST-REPORT.md).

### Fixed
- **Redacao do clipboard reescrita na CAMADA do clipboard** (sinal `dataChanged`):
  o override por metodo era furado por TODOS os caminhos nativos do Scintilla
  (`SCI_COPY`, `SCI_COPYRANGE`, selecao retangular, `Ctrl+Insert`, `Shift+Del`) e
  pela copia PARCIAL de um segredo. Agora mascara por segredos detectados (inteiros
  **e** parciais) sem tocar no clipboard de outros apps.
- **scrypt-bomb**: um `.rdbt` malicioso com `log2n` gigante faria o scrypt alocar
  petabytes e travar — `vault.decrypt` valida `n`/`r`/`p` antes de derivar a chave.
- **Custodia confiava em `isModified()`** — `verify_custody` agora compara o **hash VIVO**.
- **Barra `:` robusta** — `:goto` com numero gigante/negativo/digito-unicode nao
  derruba mais (clampa ao arquivo); `:open` de arquivo >50 MB pede confirmacao.
- **Burn note** — o wipe esvazia o buffer de **UNDO** (`Ctrl+Z` nao reconstroi) e
  limpa o clipboard se contiver o conteudo; burns sao apagadas ao **fechar o app**;
  selar um burn e bloqueado.

### Security
- RESISTIRAM ao pentest: regressao da Sentinela (recall), do Cofre (round-trip +
  deteccao de adulteracao GCM) e do ciclo travar/destravar.
- Limitacoes honestas confirmadas: segredo SEM padrao nao e mascarado no clipboard
  (so se mascara o que a Sentinela detecta); custodia de arquivo em claro e
  best-effort (use o Cofre p/ tamper-evidence com chave).

---

## [0.4.0] - 2026-06-08 — Fase 3 completa

Fecha a Fase 3: o que faltava alem do Cofre.

### Added
- **Redacao do clipboard** — com a redacao ligada, copiar/recortar (menu **e**
  `Ctrl+C`/`Ctrl+X`) entrega a **mascara** (`●`) no lugar do segredo, nao o texto
  real. Fecha o vazamento via area de transferencia.
- **Burn Note** (`Ctrl+Shift+B`) — aba efemera que **nao vai pro disco** e e
  apagada ao fechar (`_wipe_editor` sobrescreve o buffer). Selo `🔥 BURN (so RAM)`.
- **Barra de comando `:`** (`Ctrl+P`) — linha no rodape com `seal` · `burn` ·
  `redact` · `hash` · `goto N` · `w` · `q` · `open <arquivo>` · `lock`/`unlock` ·
  `next`, reusando as acoes existentes. Esc volta ao editor.
- **Mapa de exposicao** — marcador vermelho na margem em cada linha com segredo;
  clicar pula pra linha.
- **Verificar custodia** (`Ctrl+Shift+H`) — mostra o SHA-256 completo e se o
  conteudo confere com a linha de base do ultimo salvamento.

### Fixed
- Salvar uma Burn Note abria o dialogo de "salvar como" (a guarda estava so no
  `_write`, depois do dialogo). Agora `save_file`/`save_file_as` bloqueiam antes.

### Security
- A **Burn Note** *reduz* o residuo em memoria; o Python nao garante limpar a RAM.
- A **redacao** (tela + clipboard) protege contra exposicao visual/copia; o dado em
  repouso continua sendo trabalho do **Cofre**.
- Tamper-evidence com **chave** continua sendo o Cofre (AES-GCM); a custodia de
  arquivo em claro e best-effort (hash sem chave + baseline em memoria).

---

## [0.3.0] - 2026-06-08 — Cofre cifrado

Redoubt deixa de so *ver* segredo e passa a *guardar*: agora da pra salvar senha
de conta (ou qualquer texto sem padrao) com seguranca real em repouso.

### Added
- **Cofre `.rdbt`** — conteudo cifrado com **AES-256-GCM** (cifragem autenticada)
  e chave derivada por **scrypt** (memory-hard), num arquivo binario proprio.
  **Zero-knowledge**: a senha-mestra nunca e gravada; esqueceu = irrecuperavel.
  Adiciona a dependencia `cryptography`. Modulo novo: `notepy/vault.py` (testavel sem Qt).
- **Selar aba/arquivo** (`Ctrl+Shift+L`) — transforma a aba atual em cofre; ao
  salvar, grava `.rdbt` cifrado. Abrir um `.rdbt` pede a senha e decifra.
- **Senha-mestra por cofre, cacheada na sessao** — destrava uma vez, fica aberto.
- **Auto-lock por inatividade** (5 min) + **Travar agora** (`Ctrl+Shift+K`) /
  **Destravar** (`Ctrl+Shift+U`): ao travar, o conteudo e re-cifrado em memoria, o
  texto some da tela e a senha e esquecida ate destravar. Selo `🔒 COFRE` / `🔒 TRAVADO`.

### Security
- Cofre verificado adversarialmente: round-trip, senha errada e adulteracao de
  ciphertext/salt/nonce **todas barradas** (GCM `InvalidTag`); disco sempre cifrado
  (sem plaintext); ciclo travar/destravar preserva o conteudo byte a byte.
- Em cofre, a Sentinela nao marca "exposto" (o conteudo ja e protegido por cifragem).

---

## [0.2.1] - 2026-06-08 — Endurecimento de seguranca (pos red-team)

Correcoes a partir de um pentest adversarial do proprio Redoubt (59 ataques,
executados de verdade). Detalhes em [`docs/SECURITY-TEST-REPORT.md`](docs/SECURITY-TEST-REPORT.md).

### Fixed
- **DoS O(n^2) no scanner** que congelava a GUI em arquivos com muitos matches:
  a deduplicacao passou a usar um mapa de cobertura O(n) (`bytearray`) com teto
  `MAX_MATCHES`. 8000 matches: **7,4 s → 0,2 s**.
- **Crash por surrogate solitario** no auto-rescan, na cadeia de custodia e ao
  salvar: `encode(..., 'surrogatepass')` em offsets/hash e captura de
  `UnicodeError` no `_write` (antes so `OSError`).
- **Fonte proporcional no editor:** como "JetBrains Mono" nao esta instalada, o Qt
  substituia por uma fonte PROPORCIONAL (Tahoma) — codigo desalinhado, comentarios
  invadindo o codigo e tarjas de redacao tortas. Agora `_monospace_font()` escolhe a
  1a monoespacada realmente instalada (Cascadia Mono / Consolas / …) e a aplica a
  todos os estilos do lexer.
- **Encoding rotulado como "UTF-8 BOM"** em arquivos SEM BOM (que ainda ganhariam um
  BOM ao salvar): `read_text` so usa `utf-8-sig` se o arquivo realmente comecar com o BOM.

### Security
- **Bypass "placeholder-poison" fechado:** embutir `dummy`/`xxxx`/`todo` dentro
  de um segredo real nao o esconde mais. `_is_placeholder` so veta exemplos
  CLAROS (template `${…}`, repeticao de 8+ chars, valor-exemplo conhecido,
  frases `your-…`/`…-here`), nunca por substring embutida.
- **Arquivo > 2 MB nao finge mais "LIMPO":** quando a varredura e pulada, o selo
  mostra `⚠ NAO VERIFICADO` em vez de dar falsa seguranca.
- **Modo Redacao sem janela de exposicao:** com a redacao LIGADA, a varredura roda
  IMEDIATA e sincronamente a cada mudanca (sem o debounce de 300 ms). Antes, colar
  um segredo o deixava visivel em claro por ~300 ms antes de ser tarjado — um
  vazamento real em transmissao de tela. Agora ele ja entra tarjado antes do repaint.
- Confirmado (auditoria estatica + runtime): **sem rede, sem RCE, sem autosave
  residual**.

---

## [0.2.0] - Redoubt

A virada de chave: de editor de texto generico para um **editor com seguranca
como identidade**. Esta versao introduz a Sentinela de Segredos, a cadeia de
custodia, o modo redacao e o tema carbono/ambar — e renomeia o produto para
**Redoubt**.

### Added
- **Identidade Redoubt** — `APP_NAME`, `APP_VERSION` e `APP_TAGLINE` centralizados
  em `notepy/__init__.py`; trocar o nome do app e questao de uma constante.
- **Sentinela de Segredos** (`notepy/secrets.py`) — varredura local (sem rede)
  do conteudo, em **cinco camadas** da maior para a menor confianca:
  1. **Padroes de provedor** — Chave de acesso AWS (`AKIA…`), Token JWT
     (`eyJ…`), Chave privada PEM, Token do GitHub (`ghp_`/`gho_`/…), Token do
     Slack (`xox…`), Webhook do Slack (`hooks.slack.com/services/…`), Chave da
     OpenAI (`sk-` e `sk-proj-`), Chave Stripe (`sk_live`/`sk_test`/`rk_…`),
     Chave SendGrid (`SG.x.y`), Chave Twilio (`AC`/`SK` + 32 hex), Token npm
     (`npm_…`), Chave Google API (`AIza…`), Credencial Basic Auth, Token Bearer
     e Connection string (`mongodb`/`postgres`/`mysql`/`redis`/`amqp` com
     `usuario:senha@host`).
  2. **Atribuicao `chave = valor`** — com ou sem aspas (`password`, `senha`,
     `secret`, `api_key`, `access_key`, `token`, …), com porteira de
     complexidade do valor (minimo 8 caracteres, ao menos 2 classes de caractere,
     descartando UUIDs) e lista de contextos benignos ignorados (CSRF, tokens de
     paginacao/continuacao, anti-forgery).
  3. **PII brasileira** — CPF e CNPJ, com mascara e sem mascara (so digitos),
     validados pelos **digitos verificadores**.
  4. **Cartao de credito** — validado por **Luhn**, com comprimento real
     (13/14/15/16/19 digitos) e IIN coerente (comeca em 2–6).
  5. **Rede de entropia** — entropia de Shannon (limiar **4.5**) para tokens
     genericos de 32+ caracteres, rotulados como *"Possivel segredo (alta
     entropia)"*.
- **Filtro global de placeholder/exemplo** — descarta candidatos contendo
  `example`, `dummy`, `placeholder`, `changeme`, `your-`, `-here`, `xxxx`,
  `${…}`, `{{…}}`, `fixme`, `todo`, `redacted`, `lorem`, `<…>` e afins. Por isso
  a chave-exemplo canonica da AWS (`AKIAIOSFODNN7EXAMPLE`) **nao** e marcada.
- **Vigilancia continua no editor** (`notepy/editor.py`) — o `CodeEditor`
  revarre o texto a cada alteracao com **debounce de 300 ms** (`QTimer` no sinal
  `textChanged`) e emite `secretsChanged(int)`. Acima de ~2.000.000 de
  caracteres a varredura por digitacao e suspensa para nao travar.
- **Indicadores visuais de segredo** — `SECRET_INDICATOR (8)`: sublinhado/squiggle
  vermelho desenhado **sob** o texto, marcando cada credencial encontrada.
- **Modo Redacao** (`Ctrl+Shift+R`) — `REDACT_INDICATOR (9)`: tarja preta solida
  desenhada **sobre** os segredos, para compartilhar a tela com seguranca.
  Alternavel por aba.
- **Ir ao proximo segredo** (`F8`) — pula o cursor de segredo em segredo, com
  *wrap-around* ao chegar ao fim.
- **Relatorio de segredos** (`Ctrl+Shift+E`) — caixa de dialogo listando a linha
  e o tipo de cada segredo detectado no documento atual.
- **Cadeia de custodia** — hash **SHA-256** do conteudo (`content_hash`),
  recalculado ao abrir e ao salvar (`mark_saved`). A barra de status mostra os
  8 primeiros hex (`custodia: a1b2c3d4`), `custodia: ░ alterado` enquanto ha
  edicao nao salva, ou `custodia: —` quando ainda nao houve gravacao — revelando
  adulteracao externa de relance.
- **Selo de estado na barra de status** — `● LIMPO` (verde), `▲ EXPOSTO · N`
  (vermelho) ou `■ REDIGIDO · N` (ambar), conforme o estado de seguranca da aba
  ativa.
- **Abas de evidencia** — abas com segredo recebem o marcador `▲` no titulo (e
  `•` quando ha alteracao nao salva); o titulo da janela ganha o selo
  `[▲ EXPOSTO]`.
- **Tema carbono "Redoubt"** (`notepy/theme.py`) — paleta semantica
  (`BG #0E1116`, `PANEL #161B22`, `AMBER #E8A33D` = atencao/marca,
  `GREEN #3FB950` = selado/limpo, `RED #F85149` = exposto), estilo Fusion,
  folha de estilo (QSS) do chrome via `string.Template` e funcoes
  `apply_app` / `apply_editor_theme` / `retheme_lexer`.
- **Menu Seguranca** dedicado, reunindo Modo Redacao, Ir ao proximo segredo e
  Relatorio de segredos; acoes de Redacao e Proximo segredo tambem na toolbar.
- **Aviso quando um segredo aparece** — ao detectar novos segredos, a barra de
  status sugere `Ctrl+Shift+R` para tarjar e `F8` para navegar.
- **Arquivo de demonstracao** `exemplo_segredos.py` para exercitar a Sentinela.

### Changed
- **Renomeado de "Notepy" para "Redoubt"** em toda a interface, embora o pacote
  Python permaneca `notepy/` por compatibilidade.
- **Repintura completa dos lexers** — `retheme_lexer` aplica a paleta carbono a
  todos os estilos do `QScintilla` usando a **descricao textual** de cada estilo
  (Comment/Keyword/String/Number/…) em vez de mapear ids fixos, funcionando de
  forma generica para qualquer `QsciLexer*`. O editor deixa de herdar o visual
  padrao do Scintilla (a "cara do Notepad++").
- **Sentinela endurecida (v2) por red-team** — apos um corpus de 80 casos
  adversariais (evasao cloud/CI, falso-positivo, PII brasileira e arquivos
  reais), o detector saltou de **Recall 46% / Precisao 55%** (v1 ingenua) para
  **Recall 92% / Precisao 87%**, mantendo a regressao dos casos originais
  intacta. O endurecimento adicionou os padroes Stripe/SendGrid/Twilio/npm/
  Basic/Bearer/webhook do Slack, a deteccao de senha **sem aspas**, CPF/CNPJ
  **sem mascara**, o cartao validado por Luhn e o filtro de placeholder.

### Fixed
- **Regex de entropia incluia `=` no meio** do token, grudando o nome da
  variavel ao valor e furando a exclusao de hashes; agora o `=` so e aceito como
  *padding* final, e hashes hex puros (MD5/SHA-1/SHA-256 de 32/40/64), *data
  URIs* e hashes SRI (`sha256-`/`sha384-`/`sha512-`) sao corretamente excluidos.

### Security
- Toda a deteccao roda **localmente, sem rede** — nada do conteudo sai da
  maquina.
- **Limitacoes honestas** desta versao:
  - O Python **nao garante** zerar segredos da RAM (strings imutaveis +
    coletor de lixo).
  - A deteccao e *best-effort*: ha **falsos-positivos** (ex.: base64 de imagem,
    JS minificado, SKU com formato identico a uma chave AWS) e **falsos-negativos**
    (formatos de provedor desconhecidos, segredos ofuscados).
  - O **Modo Redacao e apenas visual**: ele tarja a tela, mas o conteudo real
    permanece no documento — copiar um trecho tarjado ainda traz o segredo.

---

## [0.1.0]

Base do editor de texto/codigo, antes da virada de seguranca.

### Added
- **Abas multi-arquivo** — `QTabWidget` com abas fechaveis, moviveis e modo
  documento; abertura do mesmo arquivo reutiliza a aba existente.
- **Realce de sintaxe (~50 linguagens)** (`notepy/lexers.py`) — mapeamento de
  extensao/nome de arquivo para lexers do `QScintilla` (`lexer_for_path`),
  cobrindo Python, JavaScript/TypeScript, JSON, HTML/XML, CSS, C/C++, C#, Java,
  Bash/Batch, SQL, YAML, Markdown, TOML/INI, Makefile, CMake e muitas outras;
  arquivos desconhecidos caem para texto puro.
- **Numeracao de linhas** na margem e **fonte monoespacada** (JetBrains Mono,
  com recuo para Consolas quando indisponivel).
- **Dobra de codigo (folding)** em arvore, **guias de indentacao** e
  **realce de pares de chaves**.
- **Deteccao de encoding na leitura** (`read_text`) — tenta `utf-8-sig` (BOM),
  `utf-8`, `cp1252` e `latin-1` em ordem, com rotulos amigaveis na barra de
  status.
- **Deteccao de fim de linha (EOL)** (`detect_eol`) — Windows (`\r\n`),
  Unix (`\n`) ou Mac (`\r`), preservada ao abrir e ao salvar (gravacao com
  `newline=""`).
- **Arrastar e soltar** arquivos sobre a janela para abri-los.
- **Acoes padrao de arquivo e edicao** — Novo (`Ctrl+N`), Abrir (`Ctrl+O`),
  Salvar (`Ctrl+S`), Salvar como, Fechar aba (`Ctrl+W`), Sair; Desfazer/Refazer,
  Recortar/Copiar/Colar, Selecionar tudo.
- **Aviso ao fechar com alteracoes nao salvas** — opcao de Salvar / Descartar /
  Cancelar por aba e na saida.
- **Barra de status** com posicao do cursor (Lin/Col), linguagem detectada e
  encoding.
- **Ponto de entrada** (`main.py`) que aplica o tema e abre os arquivos passados
  por linha de comando (suporta "Abrir com…").

[Nao lancado]: #nao-lancado
[0.2.0]: #020---redoubt
[0.1.0]: #010
