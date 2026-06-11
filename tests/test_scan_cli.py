"""Testes do CLI/hook da Sentinela (notepy/scan_cli.py) — puro Python, sem Qt."""

import os

from notepy import scan_cli

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
