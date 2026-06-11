# Hook git anti-segredo — a Sentinela fora do editor

O Redoubt não vigia segredos só dentro do editor: a mesma Sentinela (`notepy/secrets.py`)
roda como um **hook `pre-commit`** que **impede você de commitar credencial** em
qualquer repositório.

> *Nada vaza sem você mandar* — agora também no seu `git`.

## Instalar num repositório

```bash
# de dentro da pasta do Redoubt (pra o Python achar o pacote notepy)
python -m notepy.scan_cli --install-hook /caminho/do/seu/repo
```

Isso escreve `.git/hooks/pre-commit` no repo alvo. A partir daí, todo `git commit`
varre o que está no *stage* e **aborta** se achar segredo.

Remover:

```bash
python -m notepy.scan_cli --uninstall-hook /caminho/do/seu/repo
```

(Se já existia um `pre-commit` de outra ferramenta, ele é preservado em
`pre-commit.redoubt-bak` e restaurado ao desinstalar.)

## Varrer na mão (sem hook)

```bash
python -m notepy.scan_cli arquivo1 arquivo2     # varre arquivos
python -m notepy.scan_cli --staged              # varre o stage do repo atual
```

Sai com código **≠ 0** se achar credencial (útil pra encadear em scripts).

## Quando o commit é bloqueado

```
  Redoubt bloqueou o commit — 1 credencial(is) detectada(s):

    config.txt:1:11  [Chave de acesso AWS]  ●●●●●●●●●●●●…

  Remova/cifre o segredo (Selar como cofre no Redoubt) e tente de novo.
  Falso-positivo? Marque a linha com 'redoubt:allow' ou use: git commit --no-verify
```

O relatório **nunca mostra o segredo em claro** — só onde ele está (`arquivo:linha:coluna`),
o tipo e uma prévia mascarada. Assim o próprio log do hook não vira vazamento.

## Escapes

- **Bypass pontual:** `git commit --no-verify` (pula todos os hooks — use consciente).
- **Whitelist por linha:** um comentário com `redoubt:allow` na MESMA linha do achado
  faz a Sentinela ignorá-lo (para falsos-positivos conscientes). Ex.:

  ```python
  EXEMPLO_DOC = "AKIA..............."  # redoubt:allow  (chave de exemplo da doc)
  ```

## Detalhes técnicos

- Varre a versão **em stage** (`git show :arquivo`), não a do *working tree* — é o que
  realmente vai pro commit.
- Pula **binários** (NUL embutido) e arquivos **> 2 MB** (mesmo teto do editor).
- Fora de um repo git, o `--staged` não trava nada (sai 0) — não atrapalha ambientes.
- Mesmas camadas de detecção do editor: provedores (AWS/GitHub/Slack/…), atribuições
  com valor de alta complexidade, CPF/CNPJ/cartão validados, e entropia de Shannon.
