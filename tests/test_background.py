"""Operacoes pesadas sem congelar a janela (bgscan.SlicedJob, fatiado na thread da interface):
a Sentinela do editor em textos grandes, o Substituir tudo e a restauracao da sessao.

Limites reduzidos por monkeypatch: o comportamento e o mesmo dos tamanhos reais, so que rapido."""

import os
import time

import pytest
from PyQt6.QtCore import QSettings

from notepy import bgscan, config, editor as editor_mod, findbar, mainwindow
from notepy import secrets as s

SEC = "AKIA3FK7XQ2MNP8RTUVW"


def _pump(qapp, cond, timeout=15.0):
    fim = time.time() + timeout
    while not cond():
        qapp.processEvents()
        assert time.time() < fim, "tempo esgotado esperando a operacao fatiada"


def _texto(n_linhas=400, segredos_em=(5, 250, 399)):
    linhas = []
    for i in range(n_linhas):
        linhas.append(f"aws = {SEC}" if i in segredos_em else f"linha comum numero {i} sem nada")
    return "\n".join(linhas) + "\n"


@pytest.fixture
def pequeno(monkeypatch):
    """Tudo acima de 1 KB vira 'grande' (fatiado), em janelas de 500 caracteres."""
    monkeypatch.setattr(editor_mod, "_SYNC_SCAN_LIMIT", 1_000)
    monkeypatch.setattr(editor_mod, "_SLICE_WINDOW", 500)


# --------------------------------------------------------------------------- #
# O motor
# --------------------------------------------------------------------------- #
def test_sliced_job_roda_em_fatias_e_devolve_o_resultado(qapp):
    passos = []

    def gen():
        for i in range(5):
            passos.append(i)
            yield (i + 1) / 5
        return "pronto"

    job = bgscan.SlicedJob(gen(), budget_ms=0)       # 1 passo por volta do loop
    prog, fim = [], []
    job.progress.connect(prog.append)
    job.finished.connect(fim.append)
    job.start()
    assert passos == []                              # nada roda antes do loop de eventos
    _pump(qapp, lambda: job.done)
    assert fim == ["pronto"] and prog[-1] == 100 and prog == sorted(prog)


def test_sliced_job_cancelar_para_e_roda_o_finally(qapp):
    estado = []

    def gen():
        try:
            for _ in range(1000):
                yield 0.0
        finally:
            estado.append("finally")

    job = bgscan.SlicedJob(gen(), budget_ms=0)
    fim = []
    job.finished.connect(fim.append)
    job.start()
    qapp.processEvents()
    job.cancel()
    for _ in range(20):
        qapp.processEvents()
    assert estado == ["finally"] and fim == [] and job.cancelled


def test_sliced_job_falha_vira_none_sem_derrubar(qapp):
    def gen():
        yield 0.5
        raise ValueError("quebrou")

    job = bgscan.SlicedJob(gen())
    assert job.run_to_end() is None and job.failed


def test_iter_windows_igual_a_varredura_unica():
    text = _texto()
    unica = [(m.start, m.end, m.kind) for m in s.scan(text)]
    for janela in (300, 777, 5_000):
        fatiada = [(m.start, m.end, m.kind) for _, ms in s.iter_windows(text, janela) for m in ms]
        assert fatiada == unica, janela


# --------------------------------------------------------------------------- #
# Sentinela no editor
# --------------------------------------------------------------------------- #
def test_texto_grande_e_varrido_fatiado_e_chega_ao_mesmo_resultado(win, qapp, pequeno):
    ed = win.current_editor()
    ed.setText(_texto())
    ed.rescan_secrets()
    assert ed.scan_state() == "pending"              # nao congelou: varre aos poucos
    win._update_seal()
    assert win.lbl_seal.text().startswith("VERIFICANDO")
    _pump(qapp, lambda: ed.scan_state() == "done")
    assert len(ed.secret_matches()) == 3 == len(s.scan(ed.text()))
    win._update_seal()
    assert "EXPOSTO" in win.lbl_seal.text()


def test_resultado_de_texto_que_mudou_no_meio_e_descartado(win, qapp, pequeno):
    ed = win.current_editor()
    ed.setText(_texto())
    ed.rescan_secrets()
    velho = ed._scan_job
    ed.setText(_texto(segredos_em=()))               # editou no meio: a varredura e de outro texto
    velho.run_to_end()
    assert ed.secret_matches() == [] or ed.scan_state() != "done"   # nada do texto velho publicado
    ed.rescan_secrets()
    _pump(qapp, lambda: ed.scan_state() == "done")
    assert ed.secret_matches() == []


def test_com_redacao_ligada_ate_2mb_continua_na_hora(win, pequeno):
    """A tarja tem de vir ANTES de o segredo colado aparecer numa transmissao de tela."""
    ed = win.current_editor()
    ed.set_redaction(True)
    ed.setText(_texto())                             # > _SYNC_SCAN_LIMIT, < _SCAN_LIMIT
    assert ed.scan_state() == "done" and len(ed.secret_matches()) == 3


def test_acima_do_teto_fica_nao_verificado(win, monkeypatch):
    monkeypatch.setattr(editor_mod, "_SCAN_CEILING", 1_000)
    ed = win.current_editor()
    ed.setText(_texto())
    ed.rescan_secrets()
    assert ed.scan_skipped() and ed.secret_matches() == []
    win._update_seal()
    assert "NAO VERIFICADO" in win.lbl_seal.text()


def test_edicao_em_lote_varre_uma_vez_so(win, monkeypatch):
    ed = win.current_editor()
    ed.set_redaction(True)                           # o caso que varria a CADA edicao
    chamadas = []
    real = editor_mod.secrets_mod.scan
    monkeypatch.setattr(editor_mod.secrets_mod, "scan", lambda t, **k: chamadas.append(1) or real(t, **k))
    ed.begin_bulk_edit()
    for i in range(30):
        ed.append(f"linha {i}\n")
    assert chamadas == []
    ed.end_bulk_edit()
    assert chamadas == [1]


# --------------------------------------------------------------------------- #
# Substituir tudo
# --------------------------------------------------------------------------- #
def _barra(win, procura, troca):
    fb = win.find_bar
    fb.open_find(replace=True)
    fb.find_edit.setText(procura)
    fb.replace_edit.setText(troca)
    return fb


ORIGINAL = "".join(f"item {i} velho\n" for i in range(300))


def test_substituir_tudo_grande_e_fatiado_e_um_ctrl_z_desfaz(win, qapp, monkeypatch):
    monkeypatch.setattr(findbar, "_REPLACE_SYNC_LIMIT", 100)
    monkeypatch.setattr(findbar, "_FIND_STEP", 7)
    ed = win.current_editor()
    ed.setText(ORIGINAL)
    fb = _barra(win, "velho", "novo")
    assert fb.replace_all() is None                  # rodando fatiado
    assert not ed.isEnabled() and not fb.btn_cancel.isHidden()
    _pump(qapp, lambda: fb._replace_job is None)
    assert ed.isEnabled() and fb.btn_cancel.isHidden()
    assert fb.status.text() == "300 substituida(s)"
    assert "velho" not in ed.text() and ed.text().count("novo") == 300
    ed.undo()
    assert ed.text() == ORIGINAL                     # tudo num passo so de desfazer


def test_cancelar_enquanto_procura_nao_muda_nada(win, qapp, monkeypatch):
    """A rota rapida so toca no documento no fim: cancelar antes nao deixa nada pela metade."""
    monkeypatch.setattr(findbar, "_REPLACE_SYNC_LIMIT", 100)
    monkeypatch.setattr(findbar, "_REPLACE_BUDGET_MS", 0)         # um passo por volta
    monkeypatch.setattr(findbar, "_FIND_STEP", 5)
    ed = win.current_editor()
    ed.setText(ORIGINAL)
    fb = _barra(win, "velho", "novo")
    fb.replace_all()
    qapp.processEvents()
    fb.cancel_replace()
    assert ed.isEnabled() and fb._replace_job is None
    assert fb.status.text().startswith("Cancelado: 0") and ed.text() == ORIGINAL


def test_regex_com_barra_no_substituto_vai_troca_a_troca_e_cancela_no_meio(win, qapp, monkeypatch):
    """`\\t`, `\\1`... o Scintilla expande a cada achado: rota troca a troca, fatiada. Cancelar
    mantem o que ja foi feito, e um Ctrl+Z desfaz."""
    monkeypatch.setattr(findbar, "_REPLACE_SYNC_LIMIT", 100)
    monkeypatch.setattr(findbar, "_REPLACE_BUDGET_MS", 0)         # um passo por volta
    ed = win.current_editor()
    ed.setText(ORIGINAL)
    fb = _barra(win, "velho", "x\\ty")
    fb.cb_regex.setChecked(True)
    fb.replace_all()
    for _ in range(3):
        qapp.processEvents()
    fb.cancel_replace()
    feitas = ed.text().count("x\ty")
    assert feitas == fb._replace_count and 0 < feitas < 300
    ed.undo()
    assert ed.text() == ORIGINAL


@pytest.mark.parametrize("expr,re_,cs,wo,rep", [
    ("velho", False, False, False, "novo"), ("VELHO", False, False, False, "novo"),
    ("velho", False, True, False, "novo"), ("ve", False, False, True, "X"),
    ("v[a-z]+o", True, False, False, "Z"), ("a*", True, False, False, "-"),
    ("ção", False, False, False, "cao"),
])
def test_rota_rapida_da_o_mesmo_resultado_que_trocar_uma_a_uma(win, expr, re_, cs, wo, rep):
    amostra = "".join(f"linha {i} com velho, Velho e VELHO; ve vem; ação e ção\n" for i in range(60))
    fb = win.find_bar
    rapido, lento = editor_mod.CodeEditor(), editor_mod.CodeEditor()
    rapido.setText(amostra)
    lento.setText(amostra)
    n1 = bgscan.SlicedJob(fb._replace_steps_fast(rapido, expr, re_, cs, wo, rep)).run_to_end()
    n2 = bgscan.SlicedJob(fb._replace_steps_one_by_one(lento, expr, re_, cs, wo, rep)).run_to_end()
    assert n1 == n2 and rapido.text() == lento.text()


def test_substituir_tudo_pequeno_segue_na_hora(win):
    ed = win.current_editor()
    ed.setText("a velho b velho")
    assert _barra(win, "velho", "novo").replace_all() == 2
    assert ed.text() == "a novo b novo"


# --------------------------------------------------------------------------- #
# Restaurar a sessao
# --------------------------------------------------------------------------- #
@pytest.fixture
def sessao(win, tmp_path, monkeypatch):
    from notepy import custody
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setattr(custody, "_data_dir", lambda: str(data))
    st = QSettings(str(tmp_path / "prefs.ini"), QSettings.Format.IniFormat)
    monkeypatch.setattr(config, "_s", lambda: st)
    monkeypatch.setattr(mainwindow, "_RESTORE_SYNC_LIMIT", 1_000)
    monkeypatch.setattr(mainwindow, "_RESTORE_WINDOW", 500)
    return tmp_path


def _aba(win, path):
    return next(w for i in range(win.tabs.count())
                if (w := win.tabs.widget(i)).path == os.path.abspath(str(path)))


def test_restaurar_grande_limpo_fica_oculto_ate_verificar_e_aparece(win, qapp, sessao):
    f = sessao / "limpo.txt"
    f.write_text(_texto(segredos_em=()), encoding="utf-8")
    config.save_session([str(f)], 0)
    win.restore_session()
    ed = _aba(win, f)
    assert ed.is_gated() and ed.gate_verifying()
    assert "linha comum" not in ed.text()            # oculto enquanto verifica
    _pump(qapp, lambda: not ed.is_gated())
    assert ed.text().splitlines() == f.read_text(encoding="utf-8").splitlines()
    assert ed.scan_state() == "done"


def test_restaurar_grande_com_segredo_segue_oculto_com_a_contagem(win, qapp, sessao):
    f = sessao / "sujo.txt"
    f.write_text(_texto(), encoding="utf-8")
    config.save_session([str(f)], 0)
    win.restore_session()
    ed = _aba(win, f)
    _pump(qapp, lambda: not ed.gate_verifying())
    assert ed.is_gated() and ed.gated_count() == 3 and SEC not in ed.text()


def test_revelar_no_meio_da_verificacao_para_a_varredura(win, qapp, sessao):
    f = sessao / "x.txt"
    f.write_text(_texto(), encoding="utf-8")
    config.save_session([str(f)], 0)
    win.restore_session()
    ed = _aba(win, f)
    job = ed._gate_job
    win.tabs.setCurrentWidget(ed)
    win.reveal_current()
    assert job.cancelled and not ed.is_gated()


def test_restaurar_incremental_mostra_a_janela_antes_dos_arquivos(win, qapp, sessao):
    arquivos = []
    for i in range(3):
        f = sessao / f"a{i}.txt"
        f.write_text(f"conteudo {i}", encoding="utf-8")
        arquivos.append(str(f))
    config.save_session(arquivos, 0)
    assert win.restore_session(incremental=True) == 3
    assert not any(win.tabs.widget(i).path for i in range(win.tabs.count()))   # ainda nada
    _pump(qapp, lambda: win._restore_job.done)
    abertos = {win.tabs.widget(i).path for i in range(win.tabs.count())}
    assert {os.path.abspath(a) for a in arquivos} <= abertos


def test_restaurar_acima_do_teto_fica_oculto_nao_verificado(win, sessao, monkeypatch):
    monkeypatch.setattr(mainwindow, "_RESTORE_SCAN_CEILING", 1_500)
    f = sessao / "enorme.txt"
    f.write_text(_texto(), encoding="utf-8")
    config.save_session([str(f)], 0)
    win.restore_session()
    ed = _aba(win, f)
    assert ed.is_gated() and not ed.gate_verifying() and ed.gated_count() == 0
