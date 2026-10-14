"""DPAPI do Windows (CryptProtectData / CryptUnprotectData, escopo do USUARIO) via ctypes — sem
dependencia nova.

O que o DPAPI faz: cifra bytes com uma chave que o Windows deriva das credenciais da CONTA. So
essa conta, nesta maquina (ou no perfil movel dela), consegue decifrar. Uma copia do arquivo em
outro PC, num backup ou num disco roubado nao abre.

O que NAO faz: qualquer programa rodando COMO voce decifra sem pedir nada. E se um administrador
REDEFINIR a senha da conta (diferente de voce troca-la), o Windows perde as chaves do DPAPI dela:
o que estava protegido assim deixa de abrir. Por isso o Redoubt so usa o DPAPI como destravador A
MAIS, opcional, ao lado de senha/arquivo-chave e do backup cifrado.

`entropy` amarra o blob a um uso: o mesmo blob nao abre com outra entropia.
"""

from __future__ import annotations

import sys


def available() -> bool:
    return sys.platform == "win32"


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _PBLOB = ctypes.POINTER(_Blob)
    _crypt32.CryptProtectData.argtypes = [_PBLOB, wintypes.LPCWSTR, _PBLOB, ctypes.c_void_p,
                                          ctypes.c_void_p, wintypes.DWORD, _PBLOB]
    _crypt32.CryptProtectData.restype = wintypes.BOOL
    _crypt32.CryptUnprotectData.argtypes = [_PBLOB, ctypes.c_void_p, _PBLOB, ctypes.c_void_p,
                                            ctypes.c_void_p, wintypes.DWORD, _PBLOB]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _UI_FORBIDDEN = 0x1                 # nunca abre dialogo do Windows: falha em vez de perguntar

    def _blob(data: bytes) -> tuple[_Blob, ctypes.Array]:
        buf = ctypes.create_string_buffer(data, len(data))
        return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def _take(out: _Blob) -> bytes:
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))

    def protect(data: bytes, entropy: bytes) -> bytes:
        """Cifra `data` para a conta atual. OSError se o Windows recusar."""
        din, _keep1 = _blob(data)
        dent, _keep2 = _blob(entropy)
        dout = _Blob()
        if not _crypt32.CryptProtectData(ctypes.byref(din), "Redoubt", ctypes.byref(dent), None,
                                         None, _UI_FORBIDDEN, ctypes.byref(dout)):
            raise OSError(ctypes.get_last_error(), "o Windows recusou proteger (CryptProtectData)")
        return _take(dout)

    def unprotect(blob: bytes, entropy: bytes) -> bytes:
        """Decifra um blob desta conta. OSError se for de outra conta/maquina, de outra entropia,
        adulterado, ou se o Windows perdeu as chaves (senha redefinida por administrador)."""
        din, _keep1 = _blob(blob)
        dent, _keep2 = _blob(entropy)
        dout = _Blob()
        if not _crypt32.CryptUnprotectData(ctypes.byref(din), None, ctypes.byref(dent), None,
                                           None, _UI_FORBIDDEN, ctypes.byref(dout)):
            raise OSError(ctypes.get_last_error(), "o Windows recusou abrir (CryptUnprotectData)")
        return _take(dout)

else:
    def protect(data: bytes, entropy: bytes) -> bytes:
        raise OSError("o DPAPI so existe no Windows")

    def unprotect(blob: bytes, entropy: bytes) -> bytes:
        raise OSError("o DPAPI so existe no Windows")
