# Custódia assinada + trilha de auditoria

A custódia do Redoubt deixou de ser um SHA-256 nu (que qualquer um recalcula, logo não
*prova* nada) e virou **evidência**: assinatura criptográfica + uma trilha de eventos à
prova de adulteração.

> *Cada arquivo é evidência.*

## Identidade (Ed25519)

Na primeira vez, o Redoubt gera um **par de chaves Ed25519** desta instalação:

- Chave **privada**: `%APPDATA%\Redoubt\Redoubt\identity.ed25519` (PEM, local). Por padrão fica
  **sem senha**; em **Segurança ▸ Proteger identidade com senha** ela é embrulhada num Cofre
  (`identity.rdbt`, o mesmo AES-256-GCM + senha/arquivo-chave do Cofre do app) e o PEM nu é
  apagado — daí só **assinar** pede a credencial (1× por sessão).
- Chave **pública**: exportável (`identity.pub`, em claro) — é o que outra pessoa usa para
  verificar, e por ficar em claro o *fingerprint* e a verificação **não pedem senha**.

Veja o *fingerprint* da sua identidade em **Verificar custódia** (`Ctrl+Shift+H`).

## Assinar um arquivo

**Segurança ▸ Assinar e exportar** (`Ctrl+Shift+G`) grava, ao lado do arquivo:

- `<arquivo>.sig` — a assinatura Ed25519 destacada (base64).
- a chave pública em `%APPDATA%\Redoubt\Redoubt\redoubt-pubkey.txt`.

Isso registra um evento `assinou` na trilha.

## Verificar

**Verificar custódia** (`Ctrl+Shift+H`) mostra:

- SHA-256 do conteúdo atual + comparação com a linha de base do último salvamento;
- se existe um `<arquivo>.sig`: **✓ confere** (não mudou desde que assinou) ou
  **⚠ não confere** (conteúdo mudou, ou o `.sig` é de outro arquivo/chave);
- o *fingerprint* da chave pública;
- o status da **trilha de auditoria** (cadeia íntegra ✓ / quebrada na entrada N).

Verificação programática (qualquer um com a chave pública):

```python
from notepy import custody
ok = custody.verify(conteudo, assinatura_b64, chave_publica_b64)
```

## Selo de proveniência (`.rdbt-seal`)

A assinatura `.sig` é só os bytes crus — você ainda precisa saber *qual* conteúdo e *qual* chave.
O **selo** empacota tudo num artefato **portátil e auto-explicativo**: **Segurança ▸ Selo de
proveniência** grava, ao lado do arquivo, um `<arquivo>.rdbt-seal` (formato **RDBT-SEAL1**) que
liga, **assinado**, o `sha256` do conteúdo + nome + tamanho + timestamp + o **head da trilha de
custódia** no momento do selo (`seq`/`head_hash`) à sua identidade Ed25519.

Entregue o arquivo **+ o `.rdbt-seal`**: qualquer um prova a origem e a integridade **offline e
sem instalar o Redoubt**, com o verificador standalone:

```bash
python verify_seal.py meu-arquivo.txt          # lê meu-arquivo.txt.rdbt-seal ao lado
python verify_seal.py arquivo --pubkey <b64>    # selo de OUTRO autor (chave por canal confiável)
```

Saída: `INTEGRO E AUTENTICO` (a assinatura bate com a chave do autor **embutida no verificador** e
o `sha256` do arquivo confere com o selado) ou `FALHOU`. Como no release, o `verify_seal.py` oficial
**embute a chave pública do autor**, então um selo re-assinado por outra chave é rejeitado.

> **O que o selo prova (e o que não).** A amarra forte é o **conteúdo**: o selo só confere com os
> bytes exatos que foram selados (renomear não quebra — o `name` viaja assinado, mas é informativo,
> e nunca vira caminho de arquivo). O **head da trilha** é uma *asserção assinada*: só quem tem a sua
> `audit.log` cruza com a trilha real — para terceiros é proveniência forense. O selo dá **integridade
> + autenticidade**, não confidencialidade (para esconder conteúdo, use o Cofre).

## Trilha de auditoria (hash-chain)

Eventos de custódia — `abrir`, `salvar`, `selar cofre`, `queimou`, `assinou` — são
anexados a `%APPDATA%\Redoubt\Redoubt\audit.log`, um por linha (JSON). Cada entrada
inclui o **hash da anterior** (`prev`), formando uma cadeia: alterar/remover um evento
passado faz `verify_chain()` apontar exatamente onde a cadeia quebrou.

A trilha guarda **caminho + hash do conteúdo + timestamp** — nunca o conteúdo. Cada entrada nova
carrega `seq` (posição, dentro do hash) e uma `sig` Ed25519 do hash (*best-effort*: vazia se a
identidade estiver protegida e travada — não pede senha só para registrar um evento).

## Âncora anti-reset

A hash-chain prova que a sequência interna não mudou — mas, sozinha, **não detecta reset**: apagar
o `audit.log` e recomeçar do zero gera uma cadeia nova internamente válida. Para fechar isso,
**Segurança ▸ Exportar âncora de custódia** (`export_anchor`) grava um `custody-anchor.json`
assinado com `{seq, head_hash, fingerprint}` do estado atual. **Guarde-o fora da máquina.** Depois,
**Verificar âncora** (`check_anchor`) compara a trilha atual com a âncora e **acusa** reset,
truncamento ou reescrita.

A verificação **amarra a âncora a uma identidade**: a assinatura sozinha não prova autoria (a chave
pública viaja na âncora — um atacante re-assina com a própria chave), então `check_anchor` exige que
o fingerprint derivado da chave bata com o **esperado** (por padrão, a identidade local).

> **Limitação honesta:** o padrão compara com a identidade **local**. Se o atacante tem acesso à
> máquina e **troca a identidade local** antes de forjar a âncora, o `identity_match` local passaria.
> Defesa: (a) **proteja a identidade com senha** (ele não assina como você) e (b) **confira o
> fingerprint da âncora** com o que você conhece do autor, obtido fora da máquina. A âncora que
> **você** guardou sempre detecta o reset pela divergência de `head_hash`/`seq`.

## Honestidade (modelo de ameaça)

- A chave privada é **local**. **Sem proteção**, fica sem senha (usabilidade) e quem tem a
  máquina pode assinar como você. Com **Proteger identidade**, passa a exigir senha (ou
  arquivo-chave) para assinar — *zero-knowledge*, sem backdoor: esqueceu a credencial, perde
  a identidade (mas a pública exportada segue verificando o que já foi assinado). A assinatura
  prova *"veio desta instalação e não mudou"*, desde que a chave não tenha vazado.
- Para confidencialidade **em repouso**, o mecanismo é o **Cofre** (`.rdbt`, AES-256-GCM):
  a custódia assinada é sobre **integridade/autenticidade**, não sobre esconder conteúdo.
- Tudo é **local, sem rede**.
