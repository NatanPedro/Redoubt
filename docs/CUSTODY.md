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

## Trilha de auditoria (hash-chain)

Eventos de custódia — `abrir`, `salvar`, `selar cofre`, `queimou`, `assinou` — são
anexados a `%APPDATA%\Redoubt\Redoubt\audit.log`, um por linha (JSON). Cada entrada
inclui o **hash da anterior** (`prev`), formando uma cadeia: alterar/remover um evento
passado faz `verify_chain()` apontar exatamente onde a cadeia quebrou.

A trilha guarda **caminho + hash do conteúdo + timestamp** — nunca o conteúdo.

## Honestidade (modelo de ameaça)

- A chave privada é **local**. **Sem proteção**, fica sem senha (usabilidade) e quem tem a
  máquina pode assinar como você. Com **Proteger identidade**, passa a exigir senha (ou
  arquivo-chave) para assinar — *zero-knowledge*, sem backdoor: esqueceu a credencial, perde
  a identidade (mas a pública exportada segue verificando o que já foi assinado). A assinatura
  prova *"veio desta instalação e não mudou"*, desde que a chave não tenha vazado.
- Para confidencialidade **em repouso**, o mecanismo é o **Cofre** (`.rdbt`, AES-256-GCM):
  a custódia assinada é sobre **integridade/autenticidade**, não sobre esconder conteúdo.
- Tudo é **local, sem rede**.
