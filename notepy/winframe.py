"""Moldura propria no Windows: a barra superior do Redoubt vira a barra de titulo.

Sem dependencia nova (so ctypes). A janela fica sem a moldura nativa desenhada, mas mantem os
ESTILOS nativos (WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU), e e
isso que preserva o que o usuario espera do Windows: arrastar, Aero Snap, Snap Layouts do
Windows 11 no hover do maximizar, sombra, cantos arredondados, Alt+Espaco, duplo clique
maximiza e clique direito abre o menu de sistema.

Duas mensagens fazem o trabalho:

  - WM_NCCALCSIZE: a area cliente passa a ser a janela inteira (a barra do app ocupa o lugar do
    titulo). Maximizada, o Windows empurra a janela alem da tela pela espessura da borda
    invisivel; a area cliente e recuada por essa espessura para a barra nao ser cortada;
  - WM_NCHITTEST: diz ao Windows o que e cada ponto: borda de redimensionar, HTCAPTION (espaco
    vazio da barra: arrastar/duplo clique/menu de sistema), HTSYSMENU (icone), HTMAXBUTTON
    (maximizar: e o que liga os Snap Layouts) ou HTCLIENT (menus, paleta, botoes).

`hit_test` e pura (sem Qt, sem Windows) para ser testada em qualquer plataforma.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence

# Codigos de hit-test do Windows (WinUser.h).
HTCLIENT = 1
HTCAPTION = 2
HTSYSMENU = 3
HTMAXBUTTON = 9
HTLEFT, HTRIGHT, HTTOP = 10, 11, 12
HTTOPLEFT, HTTOPRIGHT = 13, 14
HTBOTTOM, HTBOTTOMLEFT, HTBOTTOMRIGHT = 15, 16, 17

Rect = tuple[int, int, int, int]      # x, y, largura, altura (pixels FISICOS, relativos a janela)


def _inside(px: int, py: int, r: Rect) -> bool:
    x, y, w, h = r
    return x <= px < x + w and y <= py < y + h


def hit_test(px: int, py: int, width: int, height: int, *, border: int, top_border: int,
             caption_height: int, maximized: bool, max_button: Rect | None = None,
             sys_icon: Rect | None = None, interactive: Sequence[Rect] = ()) -> int:
    """O que o ponto (px, py) da janela e, para o Windows.

    Ordem: bordas de redimensionar (so fora de maximizada; a borda de cima vale ATE sobre a
    barra), depois a barra: maximizar, icone, controles interativos, e o resto e arrasto."""
    if not maximized:
        on_left, on_right = px < border, px >= width - border
        on_top, on_bottom = py < top_border, py >= height - border
        c = max(border, top_border) * 2               # cantos mais faceis de pegar que as bordas
        near_left, near_right = px < c, px >= width - c
        near_top, near_bottom = py < c, py >= height - c
        if (on_top and near_left) or (on_left and near_top):
            return HTTOPLEFT
        if (on_top and near_right) or (on_right and near_top):
            return HTTOPRIGHT
        if (on_bottom and near_left) or (on_left and near_bottom):
            return HTBOTTOMLEFT
        if (on_bottom and near_right) or (on_right and near_bottom):
            return HTBOTTOMRIGHT
        if on_top:
            return HTTOP
        if on_bottom:
            return HTBOTTOM
        if on_left:
            return HTLEFT
        if on_right:
            return HTRIGHT
    if py < caption_height:
        if max_button is not None and _inside(px, py, max_button):
            return HTMAXBUTTON
        if sys_icon is not None and _inside(px, py, sys_icon):
            return HTSYSMENU
        if any(_inside(px, py, r) for r in interactive):
            return HTCLIENT
        return HTCAPTION
    return HTCLIENT


# --------------------------------------------------------------------------- #
# Windows (ctypes). Nada abaixo roda fora do win32.
# --------------------------------------------------------------------------- #
WM_NCCALCSIZE = 0x0083
WM_NCHITTEST = 0x0084
WM_NCMOUSEMOVE = 0x00A0
WM_NCLBUTTONDOWN = 0x00A1
WM_NCLBUTTONUP = 0x00A2
WM_NCLBUTTONDBLCLK = 0x00A3
WM_NCMOUSELEAVE = 0x02A2
WM_MOUSEMOVE = 0x0200

_WS_CAPTION = 0x00C00000
_WS_THICKFRAME = 0x00040000
_WS_MINIMIZEBOX = 0x00020000
_WS_MAXIMIZEBOX = 0x00010000
_WS_SYSMENU = 0x00080000
_GWL_STYLE = -16
_SWP_FLAGS = 0x0001 | 0x0002 | 0x0004 | 0x0020 | 0x0200   # NOSIZE|NOMOVE|NOZORDER|FRAMECHANGED|NOOWNERZORDER
_SM_CXSIZEFRAME = 32
_SM_CXPADDEDBORDER = 92


if sys.platform == "win32":        # a classe so existe onde ha API do Windows (e o mypy entende)
    class WinFrame:
        """Liga a moldura propria numa janela Qt no Windows.

        `regions()` e chamada a cada hit-test e devolve, em pixels LOGICOS relativos a janela:
        {'caption_height', 'max_button', 'sys_icon', 'interactive'}. `on_max_hover(bool)` e
        `on_max_click()` cuidam do botao maximizar, que o Windows passa a tratar como nao-cliente."""

        def __init__(self, window, regions: Callable[[], dict],
                     on_max_hover: Callable[[bool], None], on_max_click: Callable[[], None]):
            import ctypes
            from ctypes import wintypes

            self._ctypes = ctypes
            self._wt = wintypes
            self.window = window
            self.regions = regions
            self.on_max_hover = on_max_hover
            self.on_max_click = on_max_click
            self.hwnd = 0
            self._u32 = ctypes.windll.user32
            self._u32.GetWindowLongPtrW.restype = ctypes.c_ssize_t
            self._u32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
            self._u32.SetWindowLongPtrW.restype = ctypes.c_ssize_t
            self._u32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t]
            self._hover = False

            class _NCCALCSIZE_PARAMS(ctypes.Structure):
                _fields_ = [("rgrc", wintypes.RECT * 3), ("lppos", ctypes.c_void_p)]

            class _MARGINS(ctypes.Structure):
                _fields_ = [("l", ctypes.c_int), ("r", ctypes.c_int),
                            ("t", ctypes.c_int), ("b", ctypes.c_int)]

            self._NCCALCSIZE_PARAMS = _NCCALCSIZE_PARAMS
            self._MARGINS = _MARGINS

        # ---------------------------------------------------------------- setup
        def attach(self) -> None:
            """Chame depois que a janela tem handle nativo (winId). Devolve os estilos nativos que o
            FramelessWindowHint tirou e pede ao Windows para recalcular a moldura."""
            self.hwnd = int(self.window.winId())
            style = self._u32.GetWindowLongPtrW(self.hwnd, _GWL_STYLE)
            style |= _WS_CAPTION | _WS_THICKFRAME | _WS_MINIMIZEBOX | _WS_MAXIMIZEBOX | _WS_SYSMENU
            self._u32.SetWindowLongPtrW(self.hwnd, _GWL_STYLE, style)
            try:                                    # sombra e borda do DWM (sem ela a janela fica "chapada")
                m = self._MARGINS(1, 1, 1, 1)
                self._ctypes.windll.dwmapi.DwmExtendFrameIntoClientArea(self.hwnd, self._ctypes.byref(m))
            except Exception:
                pass
            self._u32.SetWindowPos(self.hwnd, 0, 0, 0, 0, 0, _SWP_FLAGS)

        def thickness(self) -> int:
            """Espessura (px fisicos) da borda invisivel de redimensionar, no DPI da janela."""
            try:
                dpi = self._u32.GetDpiForWindow(self.hwnd) or 96
                f = self._u32.GetSystemMetricsForDpi
                return f(_SM_CXSIZEFRAME, dpi) + f(_SM_CXPADDEDBORDER, dpi)
            except Exception:
                return self._u32.GetSystemMetrics(_SM_CXSIZEFRAME) + self._u32.GetSystemMetrics(_SM_CXPADDEDBORDER)

        def is_maximized(self) -> bool:
            return bool(self._u32.IsZoomed(self.hwnd))

        # ---------------------------------------------------------------- mensagens
        def handle(self, event_type, message) -> tuple[bool, int] | None:
            if event_type != b"windows_generic_MSG" or not self.hwnd:
                return None
            msg = self._wt.MSG.from_address(int(message))
            m = msg.message
            if m == WM_NCCALCSIZE and msg.wParam:
                if self.is_maximized():
                    t = self.thickness()
                    p = self._NCCALCSIZE_PARAMS.from_address(msg.lParam)
                    r = p.rgrc[0]
                    r.left += t
                    r.top += t
                    r.right -= t
                    r.bottom -= t
                return True, 0                      # area cliente = janela inteira (sem titulo nativo)
            if m == WM_NCHITTEST:
                ht = self._hit(msg.lParam)
                self._set_hover(ht == HTMAXBUTTON)
                return True, ht
            if m in (WM_NCMOUSELEAVE, WM_MOUSEMOVE):
                self._set_hover(False)
                return None
            if m in (WM_NCLBUTTONDOWN, WM_NCLBUTTONDBLCLK) and msg.wParam == HTMAXBUTTON:
                return True, 0                      # engole: o Windows desenharia o botao classico
            if m == WM_NCLBUTTONUP and msg.wParam == HTMAXBUTTON:
                self.on_max_click()
                return True, 0
            return None

        def _set_hover(self, on: bool) -> None:
            if on != self._hover:
                self._hover = on
                self.on_max_hover(on)

        def _hit(self, lparam: int) -> int:
            ct = self._ctypes
            x = ct.c_short(lparam & 0xFFFF).value
            y = ct.c_short((lparam >> 16) & 0xFFFF).value
            wr = self._wt.RECT()
            self._u32.GetWindowRect(self.hwnd, ct.byref(wr))
            px, py = x - wr.left, y - wr.top
            width, height = wr.right - wr.left, wr.bottom - wr.top
            maximized = self.is_maximized()
            off = self.thickness() if maximized else 0   # maximizada: a area cliente comeca depois da borda
            dpr = self.window.devicePixelRatioF() or 1.0
            reg = self.regions()

            def phys(r):
                if r is None:
                    return None
                x0, y0, w0, h0 = r
                return (int(x0 * dpr) + off, int(y0 * dpr) + off, int(w0 * dpr) + 1, int(h0 * dpr) + 1)

            t = self.thickness()
            return hit_test(px, py, width, height,
                            border=max(4, int(t * 0.75)), top_border=max(3, int(t * 0.5)),
                            caption_height=int(reg["caption_height"] * dpr) + off,
                            maximized=maximized,
                            max_button=phys(reg.get("max_button")),
                            sys_icon=phys(reg.get("sys_icon")),
                            interactive=[phys(r) for r in reg.get("interactive", [])])


def supported(app) -> bool:
    """So no Windows de verdade (o Qt offscreen/minimal dos testes nao tem mensagens nativas)."""
    return sys.platform == "win32" and app is not None and app.platformName() == "windows"
