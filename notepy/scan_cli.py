"""CLI da Sentinela — leva a deteccao de segredos para FORA do editor.

Varre arquivos (ou o *stage* do git) reusando `notepy.secrets` (Python puro, sem
Qt). Pensada para rodar num hook **pre-commit**: sai com codigo != 0 se achar
credencial, bloqueando o commit.

Uso:
    python -m notepy.scan_cli [arquivo ...]     # varre arquivos dados
    python -m notepy.scan_cli --staged          # varre o que esta no stage do git
    python -m notepy.scan_cli --install-hook [repo]    # instala o pre-commit
    python -m notepy.scan_cli --uninstall-hook [repo]

Bloqueio:
    - o hook impede o commit se houver segredo no stage;
    - bypass pontual: `git commit --no-verify`;
    - whitelist por linha: um comentario contendo `redoubt:allow` na MESMA linha
      faz a Sentinela ignorar aquele achado (para falsos-positivos conscientes).

DESIGN DE SEGURANCA: a saida NUNCA imprime o segredo em claro — so o tipo, a
posicao (arquivo:linha) e uma previa mascarada. Assim o proprio relatorio do hook
nao vira um vetor de vazamento (logs de terminal/CI).
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass

# Importa o pacote mesmo quando chamado por caminho absoluto (ex.: pelo hook),
# garantindo que a raiz do Redoubt esteja no sys.path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from notepy import secrets as secrets_mod  # noqa: E402

ALLOW_MARKER = "redoubt:allow"
HOOK_MARKER = "redoubt-hook"          # identifica um hook nosso ja instalado
_SCAN_LIMIT = 2_000_000               # mesmo teto do editor; arquivo maior e pulado
_ENCODINGS = ("utf-8", "cp1252", "latin-1")


@dataclass
class Finding:
    path: str
    line: int
    col: int
    kind: str
    masked: str


# --------------------------------------------------------------------------- #
# Varredura
# --------------------------------------------------------------------------- #
def _mostly_text(s: str) -> bool:
    """Heuristica binario/texto: True se >=85% dos chars sao imprimiveis/whitespace."""
    if not s:
        return False
    ok = sum(1 for c in s if c in "\t\n\r" or " " <= c <= "~" or c >= "\xa0")
    return ok / len(s) >= 0.85


def _decode(raw: bytes) -> str | None:
    """Decodifica bytes para varredura; devolve None so se for binario DE VERDADE.

    Espelha editor.read_text: trata BOM UTF-16/UTF-32 e tenta wide-encodings +
    limpeza de NUL ANTES de desistir. Sem isso, um arquivo UTF-16/UTF-32 (cheio de
    NUL) — com ou sem BOM — ou um texto com 1 NUL injetado eram tratados como binario
    e PULADOS, deixando um segredo passar pelo hook (bypass). Binario de verdade
    (denso de bytes nao-texto) continua pulado para nao inundar commits com imagens.
    """
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", "replace")
    # UTF-32 ANTES de UTF-16 (o BOM UTF-32 LE comeca com o BOM UTF-16 LE).
    if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return raw.decode("utf-32", "replace")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", "replace")
    if b"\x00" not in raw:
        for enc in _ENCODINGS:
            try:
                return raw.decode(enc)
            except UnicodeDecodeError:
                continue
        return None
    # Ha NUL e nenhum BOM. A DENSIDADE de NUL distingue os casos: UTF-16/32 (ASCII)
    # tem ~50%/75% de NUL, ~alternados; texto com NUL injetado tem poucos NUL.
    if raw.count(0) / len(raw) >= 0.20:
        # provavelmente wide-encoded sem BOM: tenta utf-16/32
        for enc in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
            try:
                dec = raw.decode(enc)
            except (UnicodeDecodeError, ValueError):
                continue
            if _mostly_text(dec):
                return dec.replace("\x00", "")
        return None                      # denso de NUL mas nao e wide plausivel: binario
    # poucos NUL -> texto com NUL injetado: remove os NUL e varre o restante.
    clean = raw.replace(b"\x00", b"")
    for enc in _ENCODINGS:
        try:
            dec = clean.decode(enc)
        except UnicodeDecodeError:
            continue
        return dec if _mostly_text(dec) else None
    return None


def _mask(snippet: str) -> str:
    """Previa MASCARADA — nunca revela o segredo (no maximo o comprimento)."""
    n = len(snippet.strip())
    return "●" * min(n, 12) + ("…" if n > 12 else "")


def _line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    col = offset - (text.rfind("\n", 0, offset) + 1) + 1
    return line, col


def scan_text(text: str, path: str) -> list[Finding]:
    """Varre um texto e devolve achados, pulando linhas marcadas `redoubt:allow`."""
    if len(text) > _SCAN_LIMIT:
        return []
    lines = text.splitlines()
    out: list[Finding] = []
    for m in secrets_mod.scan(text):
        line, col = _line_col(text, m.start)
        if 1 <= line <= len(lines) and ALLOW_MARKER in lines[line - 1]:
            continue                       # falso-positivo consciente: whitelisted
        out.append(Finding(path, line, col, m.kind, _mask(m.snippet)))
    return out


def scan_paths(paths: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for p in paths:
        try:
            with open(p, "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        text = _decode(raw)
        if text is None:
            continue                       # binario: nada a varrer
        out.extend(scan_text(text, p))
    return out


# --------------------------------------------------------------------------- #
# Integracao com o git (stage)
# --------------------------------------------------------------------------- #
def _git(args: list[str]) -> bytes:
    """Roda um comando git e devolve o stdout (bytes). Levanta em erro."""
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


def staged_files() -> list[str]:
    """Arquivos Adicionados/Copiados/Modificados no stage (caminhos relativos)."""
    raw = _git(["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"])
    return [p for p in raw.decode("utf-8", "surrogatepass").split("\0") if p]


def staged_blob(path: str) -> bytes:
    """Conteudo EXATO que sera commitado (a versao em stage, nao a do working tree)."""
    return _git(["show", f":{path}"])


def _in_git_repo() -> bool:
    try:
        out = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"],
                             capture_output=True).stdout
        return out.strip() == b"true"
    except (OSError, FileNotFoundError):
        return False


def scan_staged() -> list[Finding]:
    out: list[Finding] = []
    for path in staged_files():
        try:
            raw = staged_blob(path)
        except subprocess.CalledProcessError:
            continue
        text = _decode(raw)
        if text is None:
            continue
        if len(text) > _SCAN_LIMIT:
            # nao varremos arquivo enorme (custo), mas NAO ficamos em silencio:
            # avisamos que ele NAO foi verificado (poderia esconder um segredo).
            print(f"  Redoubt: aviso — '{path}' grande demais ({len(text)} chars), "
                  "NAO verificado. Confira manualmente se contem segredo.")
            continue
        out.extend(scan_text(text, path))
    return out


# --------------------------------------------------------------------------- #
# Hook pre-commit
# --------------------------------------------------------------------------- #
def _hook_body() -> str:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    py = sys.executable or "python"
    if "pythonw" in os.path.basename(py).lower():     # hook precisa de console
        py = py.lower().replace("pythonw", "python")
    root_sh = root.replace("\\", "/")
    py_sh = py.replace("\\", "/")
    return (
        "#!/bin/sh\n"
        f"# Redoubt :: Sentinela anti-segredo (pre-commit)  [{HOOK_MARKER}]\n"
        "# Bloqueia o commit se houver credencial no stage.\n"
        "# Bypass pontual: git commit --no-verify\n"
        f'PYTHONPATH="{root_sh}" "{py_sh}" -m notepy.scan_cli --staged\n'
    )


def _hooks_dir(repo: str) -> str:
    try:
        out = subprocess.run(["git", "-C", repo, "rev-parse", "--git-path", "hooks"],
                             check=True, capture_output=True).stdout
        rel = out.decode("utf-8").strip()
        return rel if os.path.isabs(rel) else os.path.join(repo, rel)
    except subprocess.CalledProcessError:
        return os.path.join(repo, ".git", "hooks")


def install_hook(repo: str = ".") -> str:
    """Instala o pre-commit no repo. Faz backup de um hook pre-existente que nao seja nosso."""
    hooks = _hooks_dir(repo)
    if not os.path.isdir(hooks):
        os.makedirs(hooks, exist_ok=True)
    target = os.path.join(hooks, "pre-commit")
    if os.path.exists(target):
        existing = open(target, encoding="utf-8", errors="replace").read()
        if HOOK_MARKER not in existing:                 # nao clobbra hook alheio
            bak = target + ".redoubt-bak"
            os.replace(target, bak)
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(_hook_body())
    try:
        os.chmod(target, 0o755)
    except OSError:
        pass
    return target


def uninstall_hook(repo: str = ".") -> bool:
    """Remove nosso pre-commit (e restaura backup, se houver). Nao mexe em hook alheio."""
    target = os.path.join(_hooks_dir(repo), "pre-commit")
    if not os.path.exists(target):
        return False
    if HOOK_MARKER not in open(target, encoding="utf-8", errors="replace").read():
        return False                                    # nao e nosso: nao toca
    os.remove(target)
    bak = target + ".redoubt-bak"
    if os.path.exists(bak):
        os.replace(bak, target)
    return True


# --------------------------------------------------------------------------- #
# Entrada
# --------------------------------------------------------------------------- #
def _report(findings: list[Finding]) -> None:
    if not findings:
        print("Redoubt: nenhuma credencial detectada no stage. OK para commitar.")
        return
    print(f"\n  Redoubt bloqueou o commit — {len(findings)} credencial(is) detectada(s):\n")
    for f in findings:
        print(f"    {f.path}:{f.line}:{f.col}  [{f.kind}]  {f.masked}")
    print("\n  Remova/cifre o segredo (Selar como cofre no Redoubt) e tente de novo.")
    print(f"  Falso-positivo? Marque a linha com '{ALLOW_MARKER}' ou use: git commit --no-verify\n")


def main(argv: list[str] | None = None) -> int:
    # Saida robusta: o relatorio usa ● … —; num console legado (cp1252, comum no
    # git-bash) um print desses estouraria UnicodeEncodeError no meio do hook.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--install-hook" in argv:
        i = argv.index("--install-hook")
        repo = argv[i + 1] if i + 1 < len(argv) else "."
        path = install_hook(repo)
        print(f"Hook pre-commit instalado em: {path}")
        print("A partir de agora, commits com segredo serao bloqueados neste repo.")
        return 0
    if "--uninstall-hook" in argv:
        i = argv.index("--uninstall-hook")
        repo = argv[i + 1] if i + 1 < len(argv) else "."
        ok = uninstall_hook(repo)
        print("Hook removido." if ok else "Nenhum hook do Redoubt para remover.")
        return 0
    if "--staged" in argv:
        try:
            findings = scan_staged()
        except FileNotFoundError:
            print("Redoubt: git nao encontrado no PATH — nada a verificar.")
            return 0                       # sem git: nao ha o que varrer
        except subprocess.CalledProcessError:
            # DENTRO de um repo mas o git falhou -> fail-CLOSED: nao libera o commit
            # as cegas (uma ferramenta de seguranca nao deve falhar-aberto).
            if _in_git_repo():
                print("Redoubt: falha ao ler o stage do git — commit BLOQUEADO por "
                      "precaucao. Use 'git commit --no-verify' se for intencional.")
                return 1
            print("Redoubt: fora de um repositorio git (nada a verificar).")
            return 0
    else:
        paths = [a for a in argv if not a.startswith("-")]
        if not paths:
            print(__doc__)
            return 0
        findings = scan_paths(paths)
    _report(findings)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
