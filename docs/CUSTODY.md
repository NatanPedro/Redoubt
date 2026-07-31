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

## Backup e rotação da identidade

Esta é a parte que quase todo projeto solo descobre tarde. A identidade é **um arquivo de ~119
bytes** (`identity.ed25519`). Os verificadores standalone (`verify_release.py` / `verify_seal.py`)
têm a **chave pública do autor embutida** — então, se a privada morrer:

| | |
|---|---|
| ✅ Releases e selos **antigos** | continuam verificando (a pública está publicada/embutida) |
| ✅ Scoop | continua instalando (confere SHA-256, não assinatura) |
| ❌ Assinar de novo com aquele *fingerprint* | **impossível** — a privada é a única cópia |
| ❌ Release **novo** | com chave nova, o verificador oficial diz *"assinatura NÃO confere com a chave do autor"* |
| ❌ Provar continuidade | você só pode **afirmar** "sou o mesmo autor, chave nova" — e é exatamente o que um atacante diria |

Perder a chave também custa a chave **X25519 de destinatário** (`recipient.x25519`): sem ela, todo
cofre que alguém selou **para você** fica inacessível.

> Não é hipótese distante: além de falha de disco, reinstalação de Windows ou quarentena de
> antivírus, o próprio passo de *Proteger identidade* já teve um modo de falha que **apagava** o
> arquivo (corrigido; veja o CHANGELOG). Um arquivo único, sem cópia, é um ponto único de falha.

### Fazer o backup

```bash
python tools/backup_identity.py make
```

Gera `redoubt-identity-<fingerprint>-<data>.rdbtbak`: um **Cofre** (AES-256-GCM + Argon2id) com as
privadas Ed25519 **e** X25519 dentro. A senha é pedida sem eco, com confirmação, e o pacote é
**reaberto e verificado** antes de a ferramenta dizer que existe — um backup não verificado é só
uma esperança. O material de chave nunca é impresso na tela.

Opcional (2º fator, recomendado): `--keyfile CAMINHO` exige **senha + arquivo-chave** para abrir.

Depois:

1. **Duas cópias, offline, em lugares diferentes** (ex.: pendrive guardado + outra máquina). Uma
   cópia só no mesmo disco não é backup.
2. **A credencial fora da máquina** (gerenciador de senhas ou papel). É *zero-knowledge*: esquecer
   a senha do backup equivale a não ter backup.
3. **Teste a restauração** num diretório descartável — veja abaixo.

### Conferir e restaurar

```bash
python tools/backup_identity.py check   redoubt-identity-....rdbtbak
python tools/backup_identity.py restore redoubt-identity-....rdbtbak --dir ./teste-restore
```

`check` mostra o que há no pacote (formato, data, *fingerprints*) e se bate com a identidade local.
`restore` grava `identity.ed25519` + `identity.pub` (+ `recipient.x25519`) no diretório de dados
(ou no `--dir` indicado). Sem argumento, o destino é o `%APPDATA%\Redoubt\Redoubt` desta máquina.

Duas proteções deliberadas no `restore`:

- **Recusa sobrescrever** uma identidade existente sem `--force`, mostrando **os dois** *fingerprints*
  — trocar de identidade sem perceber é justamente o acidente que o backup deveria evitar.
- Com `--force`, remove um `identity.rdbt` anterior. Sem isso o app continuaria usando a chave
  **antiga** (a versão protegida vence), e a restauração seria silenciosamente inútil.

A identidade volta na forma **legada** (chave em claro). Proteja-a de novo em *Segurança ▸ Proteger
identidade com senha* — é um passo consciente, não automático.

> Interativo por desenho: a senha é lida do **console**, não de `stdin`. Não há como automatizar o
> backup num script sem expor a credencial — e não deveria haver.

### Rotação assinada (só dá para fazer **antes** de perder a chave)

Trocar de identidade sem quebrar a cadeia de confiança exige usar a chave **antiga** enquanto ela
existe:

1. Gere a identidade nova e anote o *fingerprint* novo.
2. **Com a chave antiga**, assine uma declaração de transição nomeando o *fingerprint* novo
   (`Ctrl+Shift+G` num arquivo `ROTACAO.txt`, ou um `.rdbt-seal`) e publique os dois no repositório.
3. Lance uma versão **ainda verificável pela chave antiga** que anuncie a nova.
4. Só então troque o `AUTHOR_PUBKEY_B64` / `AUTHOR_FINGERPRINT` em `verify_release.py` **e**
   `verify_seal.py`, e atualize o *fingerprint* publicado no README.

Sem o passo 2 — isto é, depois da perda — não existe assinatura capaz de amarrar a chave nova à
antiga. Quem baixa o release não tem como distinguir a sua rotação de um sequestro do repositório.

## Honestidade (modelo de ameaça)

- A chave privada é **local**. **Sem proteção**, fica sem senha (usabilidade) e quem tem a
  máquina pode assinar como você. Com **Proteger identidade**, passa a exigir senha (ou
  arquivo-chave) para assinar — *zero-knowledge*, sem backdoor: esqueceu a credencial, perde
  a identidade (mas a pública exportada segue verificando o que já foi assinado). A assinatura
  prova *"veio desta instalação e não mudou"*, desde que a chave não tenha vazado.
- Para confidencialidade **em repouso**, o mecanismo é o **Cofre** (`.rdbt`, AES-256-GCM):
  a custódia assinada é sobre **integridade/autenticidade**, não sobre esconder conteúdo.
- Além de **confidencialidade**, a chave tem um risco de **disponibilidade**: ela é a âncora de
  confiança de tudo que você já assinou, e vive num arquivo único. O antídoto é o **backup cifrado
  verificado** (seção acima) — e, para trocar de chave sem quebrar a cadeia, a **rotação assinada
  enquanto a chave antiga existe**.
- Tudo é **local, sem rede**.
