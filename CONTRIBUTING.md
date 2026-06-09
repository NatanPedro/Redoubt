# Contribuindo com o Redoubt

> *Nada vaza sem você mandar.*

Obrigado por querer ajudar o **Redoubt** — o editor que trata cada arquivo como **evidência**. Toda contribuição é bem-vinda: um padrão de segredo novo, um falso-positivo corrigido, um lexer a mais, uma tradução de docstring, ou só um relato de bug. Este guia existe para que você consiga propor mudanças com confiança e sem surpresas.

A regra de ouro do projeto é simples: **a segurança é a identidade do Redoubt**. Mudou algo na Sentinela de Segredos? Então rode os testes antes de abrir o PR. O resto deste documento explica o como.

---

## Sumário

- [Filosofia em uma frase](#filosofia-em-uma-frase)
- [Preparando o ambiente](#preparando-o-ambiente)
- [Anatomia do projeto](#anatomia-do-projeto)
- [Padrão de código](#padrão-de-código)
- [A regra do scanner: `secrets.py`](#a-regra-do-scanner-secretspy)
- [Como propor um novo padrão de segredo](#como-propor-um-novo-padrão-de-segredo)
- [Rodando o app e os testes](#rodando-o-app-e-os-testes)
- [Fluxo de commit e Pull Request](#fluxo-de-commit-e-pull-request)
- [Quem aprova (o workflow do projeto)](#quem-aprova-o-workflow-do-projeto)
- [O que NÃO fazer](#o-que-não-fazer)

---

## Filosofia em uma frase

O Redoubt é um editor de texto/código desktop comum em quase tudo — abas, realce de sintaxe, numeração de linha, folding — exceto numa coisa: ele **vigia** o conteúdo. Cada contribuição deve respeitar três princípios não-negociáveis:

1. **Tudo roda local, sem rede.** A Sentinela de Segredos nunca envia conteúdo para lugar nenhum. Nenhuma dependência de telemetria, nenhuma chamada de rede.
2. **A cor é semântica.** Âmbar = atenção/marca, verde = selado/limpo, vermelho = exposto. Não introduza cores fora da paleta de `theme.py`.
3. **Honestidade sobre limitações.** O Redoubt é uma rede de proteção, não uma garantia. A detecção é best-effort (tem falso-positivo e falso-negativo) e o Modo Redação é **visual** — ele tarja a tela, mas o segredo continua no documento. Nunca documente uma proteção como mais forte do que ela é.

---

## Preparando o ambiente

### Stack

| Item | Versão de referência |
|------|----------------------|
| Python | 3.11.9 |
| PyQt6 | 6.11.0 |
| PyQt6-QScintilla | 2.14.1 (mesmo motor Scintilla do Notepad++) |

Não há outras dependências de runtime. O `requirements.txt` declara apenas:

```
PyQt6>=6.0.3
PyQt6-QScintilla>=2.14
```

### Instalação — atenção ao OneDrive (sem venv)

A pasta do projeto fica **dentro do OneDrive**, que sincroniza tudo para a nuvem. Um `venv` ali dentro vira centenas de arquivos sendo sincronizados sem parar. Por isso, neste projeto, **não criamos virtualenv** — os pacotes são instalados no Python global:

```sh
pip install -r requirements.txt
```

Se você for clonar o Redoubt para **fora** do OneDrive, sinta-se livre para usar um venv normalmente; a recomendação acima é específica do ambiente onde o projeto vive hoje.

> A pasta do projeto se chama `Notepad` (nome histórico) e o pacote Python se chama `notepy/` (também histórico), mas o **produto é o Redoubt**. O nome canônico vem de `notepy/__init__.py` (`APP_NAME = "Redoubt"`). Use sempre "Redoubt" em textos, mensagens de UI e documentação.

---

## Anatomia do projeto

```
main.py              ponto de entrada: aplica o tema e abre os arquivos do argv
run.bat              atalho Windows: abre sem console (pythonw)
requirements.txt     PyQt6 + PyQt6-QScintilla
exemplo_segredos.py  arquivo de DEMONSTRAÇÃO (segredos falsos para testar a Sentinela)
notepy/
  __init__.py        APP_NAME / APP_VERSION / APP_TAGLINE
  secrets.py         a Sentinela de Segredos — scan(text) puro, SEM Qt
  editor.py          CodeEditor (QsciScintilla): vigilância, indicadores, custódia
  theme.py           paleta carbono, QSS do chrome, re-tematização de lexers
  lexers.py          mapa extensão -> lexer QScintilla (~50 linguagens)
  mainwindow.py      janela, abas, barra de custódia e ações de segurança
```

Vale destacar uma propriedade arquitetural importante: **`notepy/secrets.py` não importa Qt.** Ele é Python puro (`math`, `re`, `dataclasses`) e expõe a função `scan(text)` que devolve uma lista de `Match`. Isso é proposital — o coração da segurança é testável de forma isolada, sem instanciar uma `QApplication`. Preserve essa independência ao contribuir.

---

## Padrão de código

Seguimos o estilo que já está no código. Antes de escrever uma linha, leia o módulo que você vai tocar — ele é o melhor guia de estilo que existe.

- **PEP 8.** Indentação de 4 espaços, linhas curtas, nomes em `snake_case` para funções e variáveis, `PascalCase` para classes. Funções e constantes "privadas" do módulo usam prefixo `_` (ex.: `_PATTERNS`, `_valid_cpf`, `_looks_secretish`).
- **`from __future__ import annotations`** no topo de cada módulo (já é o padrão em todos eles).
- **Type hints em tudo.** Assinaturas anotadas, incluindo retornos. Exemplos do código real:
  ```python
  def scan(text: str, *, entropy: bool = True) -> list[Match]:
  def shannon_entropy(s: str) -> float:
  def read_text(path: str) -> tuple[str, str]:
  ```
- **Docstrings em PORTUGUÊS-BR.** É o idioma do projeto. Toda função pública ganha uma docstring curta e direta, no mesmo tom das existentes:
  ```python
  def scan(text: str, *, entropy: bool = True) -> list[Match]:
      """Varre o texto e devolve os segredos encontrados, ordenados por posicao."""
  ```
  Comentários inline também em PT-BR, explicando o *porquê* (não o *o quê*). Repare como o código já comenta as decisões não-óbvias, por exemplo `# md5/sha1/sha256 puro = hash, nao segredo`.
- **Sem dependências novas sem motivo.** O Redoubt orgulha-se de ter pouquíssimas dependências. Adicionar uma biblioteca (ex.: `cryptography` para o futuro cofre `.rdbt`) é uma decisão de arquitetura — proponha e justifique antes, não traga no meio de outro PR.
- **Respeite as camadas.** Lógica de detecção fica em `secrets.py`; aparência/indicadores ficam em `editor.py`; cores ficam em `theme.py`; mapeamento de linguagem fica em `lexers.py`; orquestração de UI fica em `mainwindow.py`. Não espalhe regex de segredo pela `mainwindow`.

---

## A regra do scanner: `secrets.py`

Esta é a regra mais importante deste documento.

> **Toda mudança em `notepy/secrets.py` precisa rodar o teste de regressão e, idealmente, o corpus adversarial antes de abrir o PR.**

Por quê tanto rigor? Porque o scanner já passou por um exercício sério de **red-team**. Um workflow gerou **80 casos adversariais** em 4 lentes (evasão de credenciais cloud/CI, falsos-positivos, PII brasileira, e arquivos reais) e mediu o detector contra eles:

| Versão | Recall | Precisão |
|--------|--------|----------|
| v1 (ingênuo) | 46% | 55% |
| **v2 (endurecido — atual)** | **92%** | **87%** |

O endurecimento que levou a v1 → v2 adicionou: os padrões de Stripe / SendGrid / Twilio / npm / Basic / Bearer / webhook do Slack; detecção de **senha sem aspas**; **CPF/CNPJ sem máscara**; **cartão de crédito** validado por Luhn; e o **filtro global de placeholder**. Também corrigiu um bug em que o regex de entropia incluía o `=` e grudava o nome da variável no valor, furando a exclusão de hashes.

É muito fácil regredir esses números com uma "melhoria" inocente. Um padrão novo amplo demais derruba a precisão; um filtro agressivo demais derruba o recall. Por isso a regra: **não confie no olho, meça.**

### As cinco camadas (mapa mental antes de mexer)

`scan()` aplica detecção em cinco camadas, da maior para a menor confiança, e um `Match` de uma camada de confiança maior **bloqueia** sobreposições nas camadas seguintes (via `_overlaps`):

1. **Padrões de provedor** (`_PATTERNS`) — AWS, JWT, PEM, GitHub, Slack (token e webhook), OpenAI, Stripe, SendGrid, Twilio, npm, Google API, Basic Auth, Bearer, connection strings.
2. **Atribuição `keyword=valor`** (`_ASSIGN_RE`), com e sem aspas, filtrada pela porteira `_looks_like_secret_value` (mínimo 8 chars, ≥2 classes de caractere, não-UUID) e por uma lista de contextos benignos (`_BENIGN_CONTEXT`: csrf, paginação, etc.).
3. **PII brasileira** — CPF/CNPJ com e sem máscara, validados pelos **dígitos verificadores** (`_valid_cpf`, `_valid_cnpj`).
4. **Cartão de crédito** — validado por **Luhn** + comprimento real (13/14/15/16/19) + IIN começando em 2–6.
5. **Rede de entropia de Shannon** (`_TOKEN_RE`, limiar `4.5`) para tokens genéricos ≥32 chars, excluindo hex puro de 32/40/64 (md5/sha1/sha256), data URIs e hashes SRI.

Sobre tudo isso roda o **filtro de placeholder** (`_is_placeholder`): qualquer trecho contendo `example`, `dummy`, `placeholder`, `changeme`, `your-`, `-here`, `xxxx`, `${`, `{{`, `fixme`, `todo`, `redacted`, `lorem`, `<algo>` etc. é descartado. É por isso que a chave-exemplo canônica da AWS (`AKIAIOSFODNN7EXAMPLE`) **não** é marcada — e isso é intencional.

---

## Como propor um novo padrão de segredo

Adicionar um detector novo é a contribuição mais comum e mais valiosa. O fluxo:

### 1. Escolha a camada certa

- Tem um **formato fixo e reconhecível** (prefixo + tamanho, como `ghp_…` ou `AKIA…`)? Vai para `_PATTERNS` em `secrets.py`, com um rótulo legível em PT-BR.
- É um **par chave=valor** genérico (`api_key = …`)? Provavelmente já cai na camada 2; talvez só falte uma keyword nova em `_ASSIGN_RE`.
- É um token **sem formato fixo**, só "parece aleatório"? Aí é a rede de entropia (camada 5) — pense duas vezes, ela é a mais propensa a falso-positivo.

### 2. Escreva o padrão no estilo existente

Siga a convenção de `_PATTERNS`: uma tupla `(rótulo, regex compilado)`, rótulo em PT-BR, regex ancorado com `\b` quando fizer sentido para evitar casamento parcial. Exemplo do código atual:

```python
("Token do GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
```

### 3. OBRIGATÓRIO: traga **um caso positivo e um caso negativo**

Nenhum padrão entra sem prova nos dois sentidos. Você precisa demonstrar que ele:

- **Pega** um segredo real do formato (caso positivo), e
- **Não grita lobo** num trecho parecido mas inofensivo, nem numa string com `example`/`placeholder` (caso negativo).

A forma mais simples de provar isso, já que `secrets.py` é Python puro:

```python
from notepy.secrets import scan

# POSITIVO — deve detectar (exemplo ilustrativo; use um valor falso plausível):
assert any(m.kind == "Meu Provedor X" for m in scan('mpx_AbC123...token_falso_aqui'))

# NEGATIVO — NÃO deve detectar (placeholder e trecho benigno):
assert scan('mpx_your-token-here') == []
assert scan('o produto mpx tem 30 unidades') == []
```

Inclua esses casos na descrição do PR (ou no arquivo de testes, se/quando o suíte de testes versionado existir). Pense também em adicionar uma linha ao **`exemplo_segredos.py`**, que é o arquivo de demonstração vivo do projeto: ele separa explicitamente uma seção "BENIGNO: nada deve ser marcado" de uma seção "SEGREDOS: tudo deve ficar vermelho". Seu padrão novo deve se comportar certo em ambas.

### 4. Cheque a interação com o filtro de placeholder e com `_overlaps`

- O seu segredo de teste contém alguma das palavras de placeholder? Se sim, ele será (corretamente) descartado — use um valor de teste que não esbarre no filtro.
- Seu padrão pode se sobrepor a outro de confiança maior? A primeira camada vence; verifique que isso não muda o rótulo esperado.

### 5. Meça antes de abrir o PR

Rode o caso de demonstração e confirme que nada do que já era detectado parou de ser, e que nada benigno passou a ser marcado. Se você tiver acesso ao corpus adversarial de 80 casos, rode-o e relate Recall/Precisão no PR. **Não baixe os números de v2 (92% / 87%).**

---

## Rodando o app e os testes

### Rodar o app

```sh
python main.py                 # janela vazia
python main.py arquivo.py      # já abrindo um arquivo
python main.py a.py b.js        # várias abas
```

No Windows, **duplo clique em `run.bat`** abre sem janela de console (usa `pythonw`).

### Testar o scanner de forma isolada (sem Qt)

Como `secrets.py` não depende do Qt, você pode exercitá-lo direto no interpretador, sem abrir janela nenhuma:

```sh
python -c "from notepy.secrets import scan; [print(m.kind, repr(m.snippet)) for m in scan(open('exemplo_segredos.py', encoding='utf-8').read())]"
```

Esse é o jeito mais rápido de validar uma mudança no detector.

### Teste headless da UI (offscreen)

Para exercitar o `CodeEditor`/`MainWindow` sem display — útil em CI ou numa sessão remota — use o backend offscreen do Qt e force UTF-8 na saída:

```sh
# Windows (PowerShell)
$env:QT_QPA_PLATFORM = "offscreen"
$env:PYTHONIOENCODING = "utf-8"
python main.py

# Linux / macOS / bash
QT_QPA_PLATFORM=offscreen PYTHONIOENCODING=utf-8 python main.py
```

> **Por que `PYTHONIOENCODING=utf-8`?** Os glifos do selo de estado — `●` (limpo), `▲` (exposto), `■` (redigido) — funcionam perfeitamente dentro do Qt, mas quebram no console `cp1252` padrão do Windows quando algo é impresso no terminal. Forçar UTF-8 evita esse ruído. No Qt em si os glifos estão corretos.

---

## Fluxo de commit e Pull Request

1. **Crie um branch** a partir de `master` (não trabalhe direto em `master`). Um branch por mudança lógica.
2. **Faça commits pequenos e focados.** Mensagem no imperativo e em PT-BR, descrevendo o *porquê* quando não for óbvio. Exemplos no estilo do histórico do projeto: `atualizações SMTP`, `correções`. Para mudanças no scanner, seja específico: `secrets: detecta token Stripe sk_live/test e adiciona caso de teste`.
3. **Antes de abrir o PR**, confira a checklist abaixo.
4. **Abra o PR** com uma descrição que conte: o que muda, por quê, e — se tocou `secrets.py` — os casos positivo/negativo e os números medidos.

### Checklist de PR

- [ ] O código segue PEP 8, tem type hints e docstrings em PT-BR.
- [ ] Nenhuma dependência nova foi adicionada (ou a adição foi justificada e combinada antes).
- [ ] Nenhuma chamada de rede foi introduzida — **tudo continua local**.
- [ ] Cores novas (se houver) vêm de `theme.py` e respeitam a semântica âmbar/verde/vermelho.
- [ ] **Se tocou `secrets.py`:** rodei o caso de demonstração (`exemplo_segredos.py`) e, idealmente, o corpus adversarial; relatei Recall/Precisão; incluí **caso positivo e caso negativo** do padrão.
- [ ] `python main.py` abre e funciona (ou rodei o teste headless offscreen).
- [ ] A documentação afetada (README, este guia, docstrings) foi atualizada.
- [ ] Não exagerei na descrição de nenhuma proteção (limitações honestas mantidas).

---

## Quem aprova (o workflow do projeto)

Hoje o Redoubt é um projeto pessoal do **Natan Lopes**, que é o **único aprovador**. Na prática isso significa:

- Agentes e colaboradores **propõem** mudanças — abrem PRs, sugerem padrões, levantam bugs.
- **Apenas o Natan** aprova merges e altera o status de propostas. Não faça merge por conta própria nem marque uma proposta como aceita.
- O idioma de trabalho do projeto é **PORTUGUÊS-BR**: PRs, issues, commits e docstrings em PT-BR.

Se você é um agente automatizado contribuindo, registre sua proposta no fluxo combinado e aguarde a decisão — você sugere, o Natan decide.

---

## O que NÃO fazer

Para fechar, um lembrete das armadilhas que mais machucam este projeto em específico:

- **Não** adicione rede, telemetria ou "phone home" de qualquer tipo. O Redoubt é local por princípio.
- **Não** mexa em `secrets.py` sem medir. Uma regex larga demais derruba a precisão de 87% num piscar de olhos.
- **Não** trate o Modo Redação como apagamento: ele é **visual** (a tarja é um indicador do Scintilla por cima do texto). O conteúdo real permanece no documento, e copiar ainda traz o segredo. Documente sempre assim.
- **Não** prometa que o "burn"/efêmero zera a RAM. Python não garante isso (strings imutáveis + GC); o que se planeja **reduz** resíduo, não elimina.
- **Não** crie um `venv` dentro da pasta no OneDrive.
- **Não** introduza cores fora da paleta de `theme.py`, nem deixe o lexer herdar as cores-padrão do Scintilla (que são a cara do Notepad++).

---

Bem-vindo ao Redoubt. Escreva código que você confiaria para guardar uma evidência — porque é exatamente isso que ele faz.
