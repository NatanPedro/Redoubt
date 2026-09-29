"""Testes do CLI/hook da Sentinela (notepy/scan_cli.py) — puro Python, sem Qt."""

import os
import time

import pytest

from notepy import scan_cli, secrets

SEC = "AKIA3FK7XQ2MNP8RTUVW"


def test_scan_text_acha_e_localiza():
    f = scan_cli.scan_text(f"linha1\nkey = {SEC}\n", "x.txt")
    assert len(f) == 1
    assert f[0].kind == "Chave de acesso AWS"
    assert f[0].line == 2                      # segredo na 2a linha


def test_allow_marker_pula():
    assert scan_cli.scan_text(f"k = {SEC}  # redoubt:allow", "x") == []
    assert len(scan_cli.scan_text(f"k = {SEC}", "x")) == 1


def test_mask_nao_revela_o_segredo():
    m = scan_cli._mask(SEC)
    assert "AKIA" not in m and "RTUVW" not in m      # nenhum char real
    assert set(m) <= {"●", "…"}


def test_scan_paths(tmp_path):
    f = tmp_path / "c.txt"
    f.write_text(f"token = {SEC}", encoding="utf-8")
    assert len(scan_cli.scan_paths([str(f)])) == 1


def test_main_exit_codes(tmp_path):
    sujo = tmp_path / "s.txt"; sujo.write_text(f"k = {SEC}", encoding="utf-8")
    limpo = tmp_path / "l.txt"; limpo.write_text("texto comum sem nada", encoding="utf-8")
    assert scan_cli.main([str(sujo)]) == 1           # acha -> bloqueia
    assert scan_cli.main([str(limpo)]) == 0          # limpo -> ok


def test_scan_staged_le_o_stage(monkeypatch):
    def fake_git(args):
        if args[:2] == ["diff", "--cached"]:
            return b"a.txt\x00bin.dat\x00"
        if args == ["show", ":a.txt"]:
            return f"key = {SEC}\n".encode()
        if args == ["show", ":bin.dat"]:
            return b"\x00\x01\x02binario"             # NUL -> pulado
        return b""
    monkeypatch.setattr(scan_cli, "_git", fake_git)
    findings = scan_cli.scan_staged()
    assert len(findings) == 1 and findings[0].path == "a.txt"


# --------------------------------------------------------------------------- #
# Arquivo grande: varredura em janelas (antes, acima de 2 MB o hook so avisava e o CLI
# pulava EM SILENCIO). Tamanhos reduzidos por monkeypatch para os testes serem rapidos e
# para acertar as emendas das janelas com precisao.
# --------------------------------------------------------------------------- #
def _janelas_pequenas(monkeypatch):
    monkeypatch.setattr(scan_cli, "_SCAN_LIMIT", 1_000)
    monkeypatch.setattr(scan_cli, "_WINDOW", 500)
    monkeypatch.setattr(scan_cli, "_OVERLAP", 100)


def _texto_com_segredo_em(offset, total=3_000):
    """Linhas de texto comum, com SEC comecando EXATAMENTE em `offset` (entre espacos, para o
    padrao ter a fronteira de palavra que exige)."""
    base = ("linha comum de texto sem nada\n" * (total // 30 + 1))[:total]
    return base[:offset - 1] + " " + SEC + " " + base[offset - 1:]


def test_arquivo_grande_e_varrido_ate_o_fim(monkeypatch):
    _janelas_pequenas(monkeypatch)
    text = _texto_com_segredo_em(2_800)
    (f,) = scan_cli.scan_text(text, "grande.txt")
    assert f.kind == "Chave de acesso AWS"
    assert f.line == text.count("\n", 0, 2_800) + 1
    assert f.col == 2_800 - (text.rfind("\n", 0, 2_800) + 1) + 1


def test_segredo_na_emenda_das_janelas_aparece_uma_vez_e_inteiro(monkeypatch):
    _janelas_pequenas(monkeypatch)
    for offset in (490, 495, 499, 500, 501, 590, 999, 1_000, 1_495):   # antes, na e depois da emenda
        found = scan_cli.scan_text(_texto_com_segredo_em(offset), "x")
        assert [f.kind for f in found] == ["Chave de acesso AWS"], offset


def test_varredura_em_janelas_igual_a_de_uma_vez(monkeypatch):
    """Mesmo resultado (tipo, linha, coluna) que a varredura unica, com varios achados
    espalhados pelas emendas e um contexto de atribuicao cortado por uma delas."""
    text = ""
    for i in range(12):
        text += "codigo comum " * 7 + "\n"
        text += f"password = \"S3nh4_{i}_Forte\"\n" if i % 2 else f"k{i} = {SEC}\n"
    unica = scan_cli.scan_text(text, "x")
    _janelas_pequenas(monkeypatch)
    janelas = scan_cli.scan_text(text, "x")
    assert len(text) > 1_000 and len(unica) == 12
    assert [(f.kind, f.line, f.col) for f in janelas] == [(f.kind, f.line, f.col) for f in unica]


def test_allow_marker_vale_no_arquivo_grande(monkeypatch):
    _janelas_pequenas(monkeypatch)
    text = _texto_com_segredo_em(2_000)
    fim = text.find("\n", 2_000)
    text = text[:fim] + "  # redoubt:allow" + text[fim:]
    assert scan_cli.scan_text(text, "x") == []


def test_acima_do_teto_avisa_que_nao_verificou(monkeypatch, capsys, tmp_path):
    _janelas_pequenas(monkeypatch)
    monkeypatch.setattr(scan_cli, "_SCAN_CEILING", 2_000)
    f = tmp_path / "enorme.txt"
    f.write_text(_texto_com_segredo_em(100), encoding="utf-8")
    assert scan_cli.scan_paths([str(f)]) == []                 # o CLI antes pulava EM SILENCIO
    assert "NAO verificado" in capsys.readouterr().out


def test_stage_grande_e_varrido_e_avisa_a_demora(monkeypatch, capsys):
    _janelas_pequenas(monkeypatch)
    blob = _texto_com_segredo_em(2_500).encode()

    def fake_git(args):
        if args[:2] == ["diff", "--cached"]:
            return b"dump.sql\x00"
        return blob if args == ["show", ":dump.sql"] else b""
    monkeypatch.setattr(scan_cli, "_git", fake_git)
    findings = scan_cli.scan_staged()
    assert len(findings) == 1 and findings[0].path == "dump.sql"
    assert "varrendo 'dump.sql'" in capsys.readouterr().out


@pytest.mark.slow
def test_arquivo_de_3mb_real_e_minificado_sem_explodir():
    """Tamanhos REAIS: 3 MB com o segredo no fim; e um minificado de UMA linha cheio de achados
    (linha/coluna incrementais + teto de achados: nada de O(n) por achado)."""
    text = "x = 1\n" * 500_000 + f"k = {SEC}\n"
    (f,) = scan_cli.scan_text(text, "x")
    assert f.line == 500_001
    tok = "aB3xZ9qW7eR2tY5uI8oP1aS4dF6gH0jK"
    minified = ";".join(tok + str(i).zfill(8) for i in range(80_000))       # ~3,3 MB, 1 linha
    t = time.time()
    found = scan_cli.scan_text(minified, "bundle.min.js")
    assert len(found) == secrets.MAX_MATCHES and {f.line for f in found} == {1}
    assert time.time() - t < 20


def test_decode_utf16_nao_e_bypass_do_hook(monkeypatch):
    # REGRESSAO (pentest v0.7-v0.10): UTF-16 e cheio de NUL; o _decode antigo
    # tratava como binario e PULAVA -> um segredo num arquivo UTF-16 passava pelo
    # hook (o editor pegava, o hook nao). Agora o BOM UTF-16/32 e decodificado.
    raw16 = (f"senha = {SEC}").encode("utf-16")
    text = scan_cli._decode(raw16)
    assert text is not None and SEC in text

    def fake_git(args):
        if args[:2] == ["diff", "--cached"]:
            return b"creds.txt\x00"
        if args == ["show", ":creds.txt"]:
            return raw16
        return b""
    monkeypatch.setattr(scan_cli, "_git", fake_git)
    assert len(scan_cli.scan_staged()) == 1          # agora o hook PEGA


def test_decode_binario_sem_bom_continua_pulado():
    # binario de verdade (sem BOM de texto, com NUL) segue pulado: nao gera ruido
    assert scan_cli._decode(b"\x89PNG\r\n\x00\x01\x02\x03dados\x07\x08\x0b\x0c") is None


def test_decode_utf16_sem_bom_nao_e_bypass():
    # REGRESSAO: UTF-16-LE SEM BOM tambem e cheio de NUL — nao pode ser pulado.
    text = scan_cli._decode((f"k = {SEC}").encode("utf-16-le"))
    assert text is not None and SEC in text


def test_decode_nul_injetado_nao_e_bypass():
    # REGRESSAO: 1 NUL injetado num texto nao pode desligar a varredura do arquivo.
    text = scan_cli._decode((f"k = {SEC}\n").encode() + b"\x00")
    assert text is not None and SEC in text


def test_install_uninstall_hook(tmp_path, monkeypatch):
    hooks = tmp_path / "hooks"
    monkeypatch.setattr(scan_cli, "_hooks_dir", lambda repo: str(hooks))
    target = scan_cli.install_hook(str(tmp_path))
    assert os.path.exists(target)
    body = open(target, encoding="utf-8").read()
    assert scan_cli.HOOK_MARKER in body and "scan_cli" in body and "--staged" in body
    assert scan_cli.uninstall_hook(str(tmp_path)) is True
    assert not os.path.exists(target)


def test_nao_clobbra_hook_alheio(tmp_path, monkeypatch):
    hooks = tmp_path / "hooks"; hooks.mkdir()
    monkeypatch.setattr(scan_cli, "_hooks_dir", lambda repo: str(hooks))
    pre = hooks / "pre-commit"
    pre.write_text("#!/bin/sh\necho hook de outra ferramenta\n", encoding="utf-8")
    scan_cli.install_hook(str(tmp_path))
    assert (hooks / "pre-commit.redoubt-bak").exists()    # backup do alheio
    assert scan_cli.HOOK_MARKER in pre.read_text(encoding="utf-8")
    scan_cli.uninstall_hook(str(tmp_path))
    assert "outra ferramenta" in pre.read_text(encoding="utf-8")   # restaurou o backup


def test_hook_nao_e_sequestrado_por_pasta_notepy_do_proprio_repo(tmp_path, monkeypatch):
    """Regressao: o hook roda DENTRO do repo e o `python -m` punha o diretorio atual na frente do
    PYTHONPATH — um repo com `notepy/scan_cli.py` proprio executava o codigo dele a cada commit."""
    import shlex
    import subprocess

    evil = tmp_path / "repo"
    (evil / "notepy").mkdir(parents=True)
    (evil / "notepy" / "__init__.py").write_text("")
    (evil / "notepy" / "scan_cli.py").write_text('print("SEQUESTRADO")\n')

    linha = scan_cli._hook_body().strip().splitlines()[-1]         # a linha que o hook executa
    assert linha.startswith("PYTHONPATH=") and " -P -m notepy.scan_cli " in linha
    atrib, *cmd = shlex.split(linha)                                # PYTHONPATH=... python -P -m ...
    env = dict(os.environ, PYTHONPATH=atrib.split("=", 1)[1])
    r = subprocess.run(cmd, cwd=evil, env=env, capture_output=True, text=True, timeout=60)
    assert "SEQUESTRADO" not in r.stdout + r.stderr
