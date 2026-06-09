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


def lexer_for_path(path: str | None, font, parent=None):
    """Devolve um lexer configurado para `path`, ou None (texto puro)."""
    if not path:
        return None

    base = os.path.basename(path).lower()
    name = _NAME_LEXER.get(base)
    if name is None:
        ext = os.path.splitext(base)[1]
        name = _EXT_LEXER.get(ext)
    if name is None:
        return None

    lexer_cls = getattr(Qsci, name, None)
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
