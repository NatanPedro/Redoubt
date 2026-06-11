"""Testes das preferencias (notepy/config.py) e do dialogo (preferences.py)."""

import pytest
from PyQt6.QtCore import QSettings
from PyQt6.QtGui import QFont

from notepy import config


@pytest.fixture
def temp_settings(tmp_path, monkeypatch):
    """Redireciona o QSettings da config para um .ini temporario (sem poluir o registro)."""
    s = QSettings(str(tmp_path / "prefs.ini"), QSettings.Format.IniFormat)
    monkeypatch.setattr(config, "_s", lambda: s)
    return s


def test_defaults(temp_settings):
    assert config.get("auto_lock_min") == 5
    assert config.get("tab_width") == 4
    assert config.get("font_size") == 11


def test_set_get_roundtrip(temp_settings):
    config.set_("auto_lock_min", 15)
    config.set_("tab_width", 2)
    assert config.get("auto_lock_min") == 15
    assert config.get("tab_width") == 2


def test_coercao_de_tipo(temp_settings):
    config.set_("font_size", "14")          # QSettings .ini guarda como string
    assert config.get("font_size") == 14
    assert isinstance(config.get("font_size"), int)


def test_editor_font_pede_monospace(qapp):
    # checa o que a config PEDE (atributo do QFont); o resolvido depende da
    # plataforma (no offscreen o font DB e minimo).
    f = config.editor_font()
    assert f.fixedPitch() is True
    assert f.styleHint() == QFont.StyleHint.Monospace


def test_dialogo_salva(qapp, temp_settings):
    from notepy.preferences import PreferencesDialog
    dlg = PreferencesDialog()
    dlg.sp_lock.setValue(20)
    dlg.sp_size.setValue(13)
    dlg.sp_tab.setValue(2)
    dlg.save()
    assert config.get("auto_lock_min") == 20
    assert config.get("font_size") == 13
    assert config.get("tab_width") == 2


def test_apply_prefs_muda_tab(win, temp_settings):
    config.set_("tab_width", 2)
    ed = win.current_editor()
    ed.apply_prefs()
    assert ed.tabWidth() == 2


def test_clamp_valores_fora_do_range(temp_settings):
    # REGRESSAO (pentest v0.6): o QSettings vive no registro e pode ser editado
    # a mao; valores absurdos nao podem escapar para o editor/timer.
    config.set_("tab_width", -5)
    config.set_("auto_lock_min", -10)
    config.set_("font_size", 9999)
    assert config.get("tab_width") == 1         # clamp para o minimo valido
    assert config.get("auto_lock_min") == 0     # clamp para 0 (= desativado)
    assert config.get("font_size") == 96        # clamp para o teto


def test_valor_nao_inteiro_cai_no_default(temp_settings):
    config.set_("tab_width", "abc")
    assert config.get("tab_width") == 4         # default, sem crash


def test_restore_session_bool(temp_settings):
    assert config.get("restore_session") is True       # default
    config.set_("restore_session", False)
    assert config.get("restore_session") is False      # bool sobrevive ao .ini ("false")


def test_session_roundtrip(temp_settings):
    config.save_session(["/a/b.txt", "/c/d.rdbt"], 1)
    paths, active = config.load_session()
    assert paths == ["/a/b.txt", "/c/d.rdbt"]
    assert active == 1


def test_session_vazia(temp_settings):
    paths, active = config.load_session()               # sem nada salvo
    assert paths == [] and active == 0
