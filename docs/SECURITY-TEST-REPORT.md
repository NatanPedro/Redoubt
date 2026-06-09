# Relatório de Pentest — Redoubt

> Red-team adversarial do próprio Redoubt, **autorizado pelo dono**, fim defensivo.
> Cada achado foi **executado de verdade** (comando real + saída real), não só teorizado.

**Data:** 2026-06-08 · **Versão testada:** v0.2.0 → corrigida em **v0.2.1**
**Método:** agente `redoubt-tester` + workflow de 7 frentes de ataque (robustez/crash,
evasão da Sentinela, derrota da Redação, integridade/custódia, extração local via
cmd/PowerShell, rede/telemetria, auditoria de código/RCE) → **59 ataques** gerados,
os de maior impacto reproduzidos na máquina.

---

## Placar

| | Qtd | Resultado |
|---|---|---|
| 🔴 Bugs CRÍTICOS | 2 | **CORRIGIDOS** |
| 🟠 Bugs ALTOS | 2 | **CORRIGIDOS** |
| 🟡 Limitações confirmadas (esperadas pelo threat model) | ~12 | Documentadas (não são bugs) |
| 🟢 Garantias que resistiram | 3 | sem rede · sem RCE · sem autosave residual |

**Veredito:** as fraquezas reais estavam na *implementação* do detector (DoS, um
bypass lógico, crashes) — todas fechadas. As garantias *arquiteturais* (sem rede,
sem execução de código) **resistiram**. As "derrotas" da redação/disco/memória são
exatamente o que `docs/SECURITY.md` já admite — o pentest **confirma a honestidade**
do modelo de ameaça em vez de contradizê-lo.

---

## 1. Bugs corrigidos

### 🔴 CRÍTICA-1 — DoS O(n²) no scanner congela a GUI
- **Ataque:** abrir/colar um arquivo (< 2 MB) com milhares de matches. `_overlaps`
  fazia busca linear numa lista que crescia a cada match → varredura O(n²) na
  thread da GUI (debounce de 300 ms).
- **Prova (antes):** 2000 matches = 0,37 s · 4000 = 1,47 s · 8000 = **7,42 s**
  (≈4× a cada dobro); 46000 ≈ **288 s** projetado → app travado a cada tecla.
- **Correção:** mapa de cobertura `bytearray` O(n) no lugar da busca linear +
  teto `MAX_MATCHES = 2000` (`notepy/secrets.py`).
- **Prova (depois):** 8000 = **0,22 s**; 46000 = **2,0 s** (capado em 2000 matches).

### 🔴 CRÍTICA-2 — "Placeholder-poison" desligava a detecção
- **Ataque:** o filtro global de placeholder rodava como *substring* sobre o match.
  Bastava embutir `dummy`/`xxxx`/`todo`/`your-` **dentro do próprio segredo** para
  ele ser descartado — um *kill-switch* atravessando 3 camadas (provedor, atribuição,
  entropia). Também afeta usuário honesto cujo segredo real contenha esses pedaços.
- **Prova (antes):** `api_key="AK1x7QdummyP0RtZ9KqWeRtY"` → **não detectado**.
- **Correção:** `_is_placeholder` reescrito — só veta exemplo CLARO (template
  `${…}`/`{{…}}`, repetição de 8+ chars iguais, valor-exemplo conhecido, frases
  `your-…`/`…-here`); nunca por substring embutida.
- **Prova (depois):** o mesmo valor → **detectado**; exemplos legítimos
  (`AKIAIOSFODNN7EXAMPLE`, `your-api-key-here`, `${VAR}`, `AKIAXXXX…`) seguem filtrados.
  Corpus de 80 casos manteve **Recall 92% / Precisão 87%** (sem regressão).

### 🟠 ALTA-1 — Crash por surrogate solitário (rescan, custódia, Ctrl+S)
- **Ataque:** colar um surrogate UTF-16 solitário (ex.: `\ud83d`). `encode('utf-8')`
  sem tratamento em `_rescan_secrets` (offset), `content_hash` e `_write` lançava
  `UnicodeEncodeError` na thread da GUI (rescan roda sozinho a cada 300 ms).
- **Correção:** `encode('utf-8', 'surrogatepass')` em offsets e hash; `_write`
  passou a capturar `UnicodeError` (além de `OSError`) e avisar em vez de crashar.
- **Prova (depois):** rescan + hash + save tratados, sem exceção. (Obs.: o
  round-trip do QScintilla já tende a sanitizar surrogates — a correção é defesa extra.)

### 🟠 ALTA-2 — Arquivo > 2 MB desligava a varredura **silenciosamente**
- **Ataque:** inflar o arquivo acima de `_SCAN_LIMIT` (2 MB) com padding; a Sentinela
  parava de varrer e o selo continuava mostrando **`● LIMPO`** — falsa segurança.
- **Correção:** quando a varredura é pulada, o editor sinaliza e o selo mostra
  **`⚠ NÃO VERIFICADO`** (âmbar), nunca `LIMPO`.

---

## 2. Limitações confirmadas (esperadas — **não** são bugs)

O pentest reproduziu, e o threat model em `docs/SECURITY.md` já declara:

- **Modo Redação é visual.** O conteúdo tarjado continua em `editor.text()`,
  no arquivo salvo e no clipboard se copiado. Esconde em screen-share, não protege o dado.
- **Disco em claro.** O arquivo salvo não é cifrado; `Get-Content`/`type` recuperam
  os segredos. (Provado: 5 segredos lidos direto do `.py` salvo.)
- **Memória/processo.** O texto vive em claro na RAM do processo; um atacante local
  com o app aberto pode lê-lo (ReadProcessMemory). Python não zera segredos da RAM.
- **Custódia é best-effort.** SHA-256 sem chave (HMAC), exibido truncado em 8 hex,
  só em memória após salvar; protege contra edição acidental dentro do app, **não**
  contra adulteração deliberada em repouso (qualquer um recalcula o hash).
- **Evasão por ofuscação.** A detecção é por regex sobre texto contíguo: segredo
  quebrado em concatenação/linha, com zero-width chars, homoglifos, ou hex-encodado
  pode escapar. Senha de 1 só classe de caractere e a chave secreta AWS (40 base64)
  podem passar. São o custo de manter a **precisão** alta contra falso-positivo.

> Esses pontos pertencem ao modelo de ameaça: Redoubt é **higiene de tela e de
> commit**, não um cofre. A Fase 3 (cofre `.rdbt` cifrado, burn note) endereça o
> dado em repouso.

---

## 3. Garantias que resistiram 🟢

- **"Tudo local, sem rede".** Auditoria estática: **zero** imports de
  `socket`/`requests`/`urllib`/`http`/`QtNetwork`. Runtime: `netstat` do processo =
  0 conexões. Sem telemetria, sem phone-home.
- **Sem RCE / superfície de execução.** Nenhum `eval`/`exec`/`os.system`/`subprocess`/
  `pickle`; abrir um arquivo malicioso não executa nada; sem injeção via QSS.
- **Sem resíduo extra.** Não há autosave/swap/temp próprios além do arquivo que o
  usuário salva (bom design; só o atalho em "Recentes" do Windows vaza o caminho).

---

## 4. Recomendações (Fase 3+)

1. **Redação real do clipboard:** ao copiar com redação ON, substituir os segredos
   por marcadores no texto que vai pra área de transferência.
2. **Custódia com HMAC + baseline persistida** (e exibir mais que 8 hex) para
   realmente "denunciar adulteração".
3. **Normalização anti-evasão** antes do scan: remover zero-width chars e aplicar
   NFKC (cuidando do mapeamento de offsets) para fechar homoglifo/ZWSP.
4. **Varrer arquivos grandes em pedaços / worker thread**, em vez de simplesmente
   pular acima de 2 MB.
5. **Cofre `.rdbt` cifrado + burn note** para o dado em repouso (já no roadmap).

---

## 5. Pentest da Fase 3 (v0.4.0 → corrigida em v0.4.1)

Segundo pentest, agora sobre as features novas (redação do clipboard, Burn Note,
barra `:`, custódia, Cofre). **35 achados, 4 críticas, 23 bugs** — todos os reais
corrigidos.

### Críticas/Altas corrigidas
- 🔴 **Redação do clipboard furada por todos os caminhos nativos.** O override de
  `copy()`/`cut()`/`keyPressEvent` (camada de método) era ignorado por `SCI_COPY`,
  `SCI_COPYRANGE`, seleção **retangular** (`hasSelectedText()==False`), `Ctrl+Insert`,
  `Shift+Del` e por **cópia parcial** (substring do segredo não casava o regex).
  **Corrigido:** defesa movida para a **camada do clipboard** (`dataChanged`), que
  mascara segredos detectados (inteiros e parciais) em qualquer caminho de cópia,
  sem mexer no clipboard de outros apps.
- 🔴 **scrypt-bomb:** um `.rdbt` malicioso com `log2n` enorme faria o scrypt alocar
  memória astronômica e travar/derrubar o app ao abrir. **Corrigido:** `vault.decrypt`
  valida `n`/`r`/`p` antes de derivar (bloqueio em 0 ms).
- 🔴/🟠 **Custódia confiava em `isModified()`** (forjável com `setModified(False)`) e
  **`:goto`** com número gigante/negativo/dígito-unicode derrubava o app.
  **Corrigido:** `verify_custody` usa o **hash vivo**; `:goto` valida e clampa.
- 🟠 **Burn note:** `Ctrl+Z` reconstruía o conteúdo após o wipe; o clipboard
  sobrevivia ao fechamento; burns não eram apagadas ao fechar o app.
  **Corrigido:** wipe esvazia o UNDO + limpa o clipboard; burns apagadas no `closeEvent`.

### Resistiram (regressão)
Sentinela (recall), Cofre (round-trip + detecção de adulteração GCM), ciclo
travar→destravar (preserva conteúdo) — todos OK após as mudanças.

### Limitações honestas (confirmadas, não são bugs)
- Segredo **sem padrão** (senha genérica) não é mascarado no clipboard — só se
  mascara o que a Sentinela **detecta**.
- Custódia de arquivo **em claro** é best-effort (hash sem chave + baseline em RAM);
  tamper-evidence com chave = **Cofre** (AES-GCM).
- `:open` lê qualquer arquivo (é um editor); adicionado aviso para arquivos >50 MB.

---

## 6. Pentest v0.6 (Localizar/Substituir, Preferências, regressão geral)

**Data:** 2026-06-09 · **Versão testada:** v0.6.0 → corrigida em **v0.6.1**
**Método:** workflow de 4 frentes (Find/Replace · Preferências/config · regressão da
segurança · robustez/crash) → ~20 ataques gerados, os de impacto **reproduzidos na
máquina** (headless `offscreen` + watchdog para detectar travamentos). Foco na
**superfície nova** desde o último pentest + regressão de tudo que já existia.

### Placar

| | Qtd | Resultado |
|---|---|---|
| 🔴 CRÍTICO | 1 | **CORRIGIDO** (loop infinito no `Substituir tudo`) |
| 🟠 ALTO | 1 | **CORRIGIDO** (redação do clipboard furada com 2+ abas) |
| 🟡 MÉDIO | 3 | **CORRIGIDOS** (UTF-16 mojibake · NUL trunca · undo do `lock`) |
| 🔵 BAIXO / endurecimento | 1+ | clamp da config aplicado; demais documentados |
| 🟢 Resistiram (regressão) | muitos | cofre, scrypt-bomb, read-only, :goto, ReDoS, apply_prefs |

### Corrigidos
- 🔴 **`replace_all` com regex de match-vazio (`a*`, `^`, `\b`) → loop infinito**
  que congelava a GUI e crescia o documento até OOM. Confirmado por watchdog (o
  processo não retornava). **Corrigido:** detecção de match de largura zero (avança
  o cursor) + teto `_REPLACE_CAP`. Engine de regex do Scintilla é **não-backtracking**,
  então o ReDoS clássico `(a+)+$` **não** trava — o risco real era só o match-vazio.
- 🟠 **Redação do clipboard contornável com múltiplas abas:** `_sanitize_clipboard`
  decidia pela **aba focada**, não pela dona da cópia — copiar de uma aba redigida
  com outra (sem redação) em foco vazava o segredo inteiro. **Corrigido:** mascara
  com os segredos de **todas** as abas em redação.
- 🟡 **UTF-16/UTF-32 → "LIMPO" falso:** a cadeia `utf-8→cp1252→latin-1` nunca falha,
  então arquivos UTF-16 viravam mojibake e o segredo sumia. **Corrigido:** `read_text`
  detecta os BOMs UTF-16/UTF-32 (UTF-32 **antes** do UTF-16) e decodifica certo.
- 🟡 **NUL embutido → conteúdo truncado:** `SCI_SETTEXT` para no `\x00`, escondendo
  tudo (e qualquer credencial) depois dele com selo "LIMPO". **Corrigido:** `read_text`
  troca `\x00` por `␀` (símbolo visível) — nada é truncado e a Sentinela varre o todo.
- 🟡 **`lock()` não esvaziava o undo:** `Ctrl+Z` reconstruía o texto-claro anterior
  ao travamento. **Corrigido:** `lock()`/`unlock()` chamam `SCI_EMPTYUNDOBUFFER`.
- 🔵 **Config sem clamp:** `tab_width=-5`/`auto_lock_min=-10` gravados direto no
  registro escapavam para o editor/timer. **Corrigido:** `config.get()` clampa os
  inteiros para faixas sãs.

### Resistiram (regressão confirmada)
Cofre selar/lock/unlock (preserva byte-a-byte, esquece a senha), AES-GCM rejeita
senha errada/adulteração, **scrypt-bomb** barrada (valida KDF), **read-only** bloqueia
Find/Replace no cofre travado, `apply_prefs` **preserva** indicadores/redação/mapa de
exposição (não some segredo ao trocar preferência), `auto_lock_min=0` desativa sem
quebrar, `:goto` clampado, 60+ abas estável, surrogate solitário sem crash, linha
gigante → selo "NÃO VERIFICADO" (sem DoS).

### Limitações honestas (confirmadas, não são bugs)
- Token com **8+ caracteres idênticos seguidos** é tratado como placeholder
  (`_REPEAT_RE`): veta corretamente `AKIAXXXX…`/`${...}`; não detectar um token real
  *degenerado* com essa forma é estatisticamente desprezível — trade-off pró-precisão.
- Cópia parcial de segredo com **< 6 caracteres** não é mascarada (piso de projeto).
- `replace_all` em documento gigante roda síncrono (sem barra de progresso/cancelar);
  o `_REPLACE_CAP` limita o runaway, mas a operação ainda bloqueia a thread enquanto roda.

---

*Reproduzir: o agente `redoubt-tester` (em `.claude/agents/`) refaz estas baterias.
Testes do scanner rodam isolados (`from notepy import secrets`); GUI com
`QT_QPA_PLATFORM=offscreen PYTHONIOENCODING=utf-8`.*
