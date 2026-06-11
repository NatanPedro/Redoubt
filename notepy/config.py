"""Preferencias do Redoubt, persistidas via QSettings (entre sessoes).

No Windows isso vai parar no registro (HKCU\\Software\\Redoubt\\Redoubt).
Cada chave tem um default em DEFAULTS; os getters fazem a coercao de tipo.
"""

from __future__ import annotations

from PyQt6.QtCore import QSettings
from PyQt6.QtGui import QFont, QFontDatabase

_ORG, _APP = "Redoubt", "Redoubt"

DEFAULTS = {
    "auto_lock_min": 5,     # minutos de inatividade p/ travar cofres; 0 = desativado
    "font_family": "",      # "" = automatico (1a monoespacada instalada)
    "font_size": 11,
    "tab_width": 4,
    "restore_session": True,  # reabrir os arquivos que estavam abertos ao iniciar
    "theme": "dark",          # 'dark' (carbono) | 'light' (claro)
}

# Preferencia de fontes monoespacadas (a 1a instalada vence).
_MONO_PREFS = ("JetBrains Mono", "Cascadia Mono", "Cascadia Code",
               "Consolas", "DejaVu Sans Mono", "Courier New")


# Limites sãos para os valores inteiros. Os spinboxes da tela de Preferencias
# ja restringem o UX, mas o QSettings vive no registro (HKCU) e pode ser
# editado a mao ou corrompido — sem isto um tab_width negativo ou um
# auto_lock_min absurdo escapariam direto para o editor/timer.
_BOUNDS = {
    "auto_lock_min": (0, 1440),   # 0 = desativado; teto 24h
    "font_size": (6, 96),
    "tab_width": (1, 16),
}


def _s() -> QSettings:
    return QSettings(_ORG, _APP)


def get(key: str):
    d = DEFAULTS[key]
    val = _s().value(key, d)
    # bool ANTES de int (em Python bool e subclasse de int). O QSettings .ini
    # devolve "true"/"false" como string; o registro pode devolver 0/1 ou bool.
    if isinstance(d, bool):
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("true", "1", "yes", "on")
    if isinstance(d, int):
        try:
            ival = int(val)
        except (ValueError, TypeError):
            return d
        lo, hi = _BOUNDS.get(key, (None, None))
        if lo is not None:
            ival = max(lo, min(hi, ival))
        return ival
    return val if val is not None else d


def set_(key: str, value) -> None:
    _s().setValue(key, value)


def monospace_family() -> str | None:
    """Primeira fonte monoespacada da lista de preferencia que esteja instalada."""
    fams = set(QFontDatabase.families())
    for cand in _MONO_PREFS:
        if cand in fams:
            return cand
    return None


def editor_font() -> QFont:
    """QFont do editor conforme as preferencias (com fallback p/ monospace instalada)."""
    size = get("font_size")
    fam = get("font_family")
    fams = set(QFontDatabase.families())
    chosen = fam if (fam and fam in fams) else monospace_family()
    font = QFont(chosen, size) if chosen else QFont("", size)
    font.setFixedPitch(True)
    font.setStyleHint(QFont.StyleHint.Monospace)
    return font


# --------------------------------------------------------------------------- #
# Sessao: APENAS os caminhos dos arquivos abertos — NUNCA o conteudo.
# Notas de queima e buffers sem titulo nao tem caminho/sao efemeros e por isso
# JAMAIS entram aqui (nada de texto possivelmente secreto vai para o registro).
# Cofres guardam so o caminho (o .rdbt no disco ja e cifrado; a senha nunca e
# persistida — zero-knowledge).
# --------------------------------------------------------------------------- #
def save_session(paths: list[str], active: int = 0) -> None:
    s = _s()
    s.setValue("session/paths", list(paths))
    s.setValue("session/active", int(active))


def load_session() -> tuple[list[str], int]:
    s = _s()
    raw = s.value("session/paths", [])
    if raw is None:
        paths: list[str] = []
    elif isinstance(raw, str):
        paths = [raw] if raw else []     # QSettings devolve str se a lista tinha 1 item
    else:
        paths = [str(p) for p in raw]
    try:
        active = int(s.value("session/active", 0))
    except (ValueError, TypeError):
        active = 0
    return paths, active
