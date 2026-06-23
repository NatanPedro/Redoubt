"""Detecção da linguagem (lexer do QScintilla) a partir do arquivo.

O QScintilla traz dezenas de "lexers" prontos (o mesmo motor Scintilla que o
Notepad++ usa). Aqui mapeamos extensões/nomes de arquivo para esses lexers e
devolvemos uma instância já com a fonte aplicada — ou None para texto puro.
"""

from __future__ import annotations

import os

from PyQt6 import Qsci

# Extensão (em minúsculo) -> nome da classe de lexer no módulo PyQt6.Qsci.
_EXT_LEXER: dict[str, str] = {
    # Python
    ".py": "QsciLexerPython", ".pyw": "QsciLexerPython", ".pyi": "QsciLexerPython",
    # Web / JS
    ".js": "QsciLexerJavaScript", ".mjs": "QsciLexerJavaScript",
    ".cjs": "QsciLexerJavaScript", ".jsx": "QsciLexerJavaScript",
    ".ts": "QsciLexerJavaScript", ".tsx": "QsciLexerJavaScript",
    ".coffee": "QsciLexerCoffeeScript",
    ".json": "QsciLexerJSON",
    ".html": "QsciLexerHTML", ".htm": "QsciLexerHTML", ".xhtml": "QsciLexerHTML",
    ".vue": "QsciLexerHTML",
    ".xml": "QsciLexerXML", ".xsd": "QsciLexerXML", ".xsl": "QsciLexerXML",
    ".svg": "QsciLexerXML",
    ".css": "QsciLexerCSS", ".scss": "QsciLexerCSS", ".less": "QsciLexerCSS",
    # C / C++ / família
    ".c": "QsciLexerCPP", ".h": "QsciLexerCPP",
    ".cpp": "QsciLexerCPP", ".cxx": "QsciLexerCPP", ".cc": "QsciLexerCPP",
    ".hpp": "QsciLexerCPP", ".hxx": "QsciLexerCPP", ".ino": "QsciLexerCPP",
    ".cs": "QsciLexerCSharp",
    ".java": "QsciLexerJava",
    ".d": "QsciLexerD",
    # Scripts / shell
    ".sh": "QsciLexerBash", ".bash": "QsciLexerBash", ".zsh": "QsciLexerBash",
    # O QScintilla nao traz lexer de PowerShell; o Bash e o mais proximo
    # (comentario "#", "$variavel" e strings batem) — melhor que texto puro.
    ".ps1": "QsciLexerBash", ".psm1": "QsciLexerBash", ".psd1": "QsciLexerBash",
    ".bat": "QsciLexerBatch", ".cmd": "QsciLexerBatch",
    ".pl": "QsciLexerPerl", ".pm": "QsciLexerPerl",
    ".rb": "QsciLexerRuby",
    ".lua": "QsciLexerLua",
    ".tcl": "QsciLexerTCL",
    # Dados / config
    ".sql": "QsciLexerSQL",
    ".yaml": "QsciLexerYAML", ".yml": "QsciLexerYAML",
    ".ini": "QsciLexerProperties", ".cfg": "QsciLexerProperties",
    ".conf": "QsciLexerProperties", ".properties": "QsciLexerProperties",
    ".toml": "QsciLexerProperties", ".env": "QsciLexerProperties",
    # Texto / docs
    ".md": "QsciLexerMarkdown", ".markdown": "QsciLexerMarkdown",
    ".tex": "QsciLexerTeX",
    ".diff": "QsciLexerDiff", ".patch": "QsciLexerDiff",
    # Engenharia / outros
    ".cmake": "QsciLexerCMake",
    ".f": "QsciLexerFortran77", ".for": "QsciLexerFortran77",
    ".f90": "QsciLexerFortran", ".f95": "QsciLexerFortran",
    ".m": "QsciLexerMatlab",
    ".pas": "QsciLexerPascal",
    ".v": "QsciLexerVerilog", ".vhd": "QsciLexerVHDL", ".vhdl": "QsciLexerVHDL",
    ".asm": "QsciLexerAsm", ".s": "QsciLexerAsm",
    ".po": "QsciLexerPO", ".pot": "QsciLexerPO",
}

# Nomes de arquivo sem extensão (em minúsculo) que conhecemos.
_NAME_LEXER: dict[str, str] = {
    "makefile": "QsciLexerMakefile",
    "gnumakefile": "QsciLexerMakefile",
    "cmakelists.txt": "QsciLexerCMake",
    ".gitignore": "QsciLexerProperties",
    ".editorconfig": "QsciLexerProperties",
}


# Menu "Linguagem": grupos ordenados de (rotulo, classe-do-lexer | None) para o
# usuario FORCAR o realce manualmente, sobrepondo a auto-deteccao por extensao.
# Os rotulos sao UNICOS — a checkmark do menu casa por rotulo. Repare que PowerShell
# e Shell/Bash compartilham o mesmo QsciLexerBash (o QScintilla nao traz lexer de PS),
# por isso o estado e guardado por rotulo, nao pela classe.
LANGUAGE_GROUPS: list[list[tuple[str, str | None]]] = [
    [("Python", "QsciLexerPython"),
     ("JavaScript / TypeScript", "QsciLexerJavaScript"),
     ("JSON", "QsciLexerJSON"),
     ("HTML", "QsciLexerHTML"), ("XML", "QsciLexerXML"), ("CSS", "QsciLexerCSS")],
    [("C / C++", "QsciLexerCPP"), ("C#", "QsciLexerCSharp"),
     ("Java", "QsciLexerJava"), ("D", "QsciLexerD")],
    [("PowerShell", "QsciLexerBash"), ("Shell / Bash", "QsciLexerBash"),
     ("Batch", "QsciLexerBatch"), ("Perl", "QsciLexerPerl"),
     ("Ruby", "QsciLexerRuby"), ("Lua", "QsciLexerLua"), ("TCL", "QsciLexerTCL")],
    [("SQL", "QsciLexerSQL"), ("YAML", "QsciLexerYAML"),
     ("INI / Properties", "QsciLexerProperties"),
     ("Makefile", "QsciLexerMakefile"), ("CMake", "QsciLexerCMake")],
    [("Markdown", "QsciLexerMarkdown"), ("TeX", "QsciLexerTeX"),
     ("Diff / Patch", "QsciLexerDiff")],
    [("Fortran", "QsciLexerFortran"), ("Matlab", "QsciLexerMatlab"),
     ("Pascal", "QsciLexerPascal"), ("Verilog", "QsciLexerVerilog"),
     ("VHDL", "QsciLexerVHDL"), ("Assembly", "QsciLexerAsm")],
]

# Rotulo de texto puro (sem realce) — distinto de "Auto (pela extensao)".
PLAIN_TEXT_LABEL = "Texto puro"

_LABEL_TO_CLASS: dict[str, str | None] = {PLAIN_TEXT_LABEL: None}
for _grp in LANGUAGE_GROUPS:
    for _label, _cls in _grp:
        _LABEL_TO_CLASS[_label] = _cls


def make_lexer(class_name: str | None, font, parent=None):
    """Instancia o lexer pela classe do QScintilla (ou None p/ texto puro)."""
    if not class_name:
        return None
    lexer_cls = getattr(Qsci, class_name, None)
    if lexer_cls is None:  # versão do QScintilla não tem esse lexer
        return None
    lexer = lexer_cls(parent)
    # Aplica a fonte monoespaçada a todos os estilos do lexer.
    lexer.setDefaultFont(font)
    try:
        lexer.setFont(font)
    except Exception:
        pass
    return lexer


def lexer_for_path(path: str | None, font, parent=None):
    """Devolve um lexer configurado para `path`, ou None (texto puro)."""
    if not path:
        return None
    base = os.path.basename(path).lower()
    name = _NAME_LEXER.get(base)
    if name is None:
        ext = os.path.splitext(base)[1]
        name = _EXT_LEXER.get(ext)
    return make_lexer(name, font, parent)


def make_lexer_for_label(label: str | None, font, parent=None):
    """Instancia o lexer escolhido no menu Linguagem (por rotulo de LANGUAGE_GROUPS)."""
    return make_lexer(_LABEL_TO_CLASS.get(label), font, parent)
