"""Icones de traco do Redoubt, desenhados com QPainter.

Sem SVG de proposito: o modulo QtSvg e opcional em varias distros Linux (no Arch e um
pacote a parte), e um icone que some por falta de plugin e pior que nenhum. Cada icone e uma
lista de primitivas numa grade 24x24 (a mesma do prototipo), escalada para o tamanho pedido.
"""

from __future__ import annotations

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap


def _poly(path: QPainterPath, *pts: tuple[float, float]) -> None:
    path.moveTo(*pts[0])
    for p in pts[1:]:
        path.lineTo(*p)


def _shield(p: QPainterPath) -> None:
    p.moveTo(12, 3); p.lineTo(19, 6); p.lineTo(19, 12)
    p.cubicTo(19, 16.5, 16, 19.5, 12, 21)
    p.cubicTo(8, 19.5, 5, 16.5, 5, 12)
    p.lineTo(5, 6); p.closeSubpath()


def _build(name: str) -> QPainterPath:
    p = QPainterPath()
    if name == "shield":
        _shield(p)
    elif name == "shieldcheck":
        _shield(p); _poly(p, (9, 12), (11, 14), (15, 10))
    elif name == "search":
        p.addEllipse(QPointF(11, 11), 7, 7); _poly(p, (20, 20), (16.5, 16.5))
    elif name == "lock":
        p.addRoundedRect(QRectF(5, 11, 14, 10), 2, 2)
        p.moveTo(8, 11); p.lineTo(8, 8); p.arcTo(QRectF(8, 4, 8, 8), 180, -180); p.lineTo(16, 11)
    elif name == "key":
        p.addEllipse(QPointF(8, 15), 4, 4); _poly(p, (11, 12), (19, 4)); _poly(p, (16, 7), (19, 10))
    elif name == "finger":
        p.moveTo(6, 12); p.arcTo(QRectF(6, 6, 12, 12), 180, -180); p.lineTo(18, 14)
        p.moveTo(9, 12); p.arcTo(QRectF(9, 9, 6, 6), 180, -180); p.lineTo(15, 16)
        _poly(p, (12, 12), (12, 19)); _poly(p, (6, 16), (6, 17))
        p.moveTo(18, 17); p.cubicTo(18, 18, 17.5, 19, 17, 20)
    elif name == "diff":
        p.addRoundedRect(QRectF(3, 4, 8, 16), 1, 1); p.addRoundedRect(QRectF(13, 4, 8, 16), 1, 1)
    elif name == "sliders":
        _poly(p, (4, 7), (14, 7)); _poly(p, (18, 7), (20, 7))
        _poly(p, (4, 17), (8, 17)); _poly(p, (12, 17), (20, 17))
        p.addEllipse(QPointF(16, 7), 2, 2); p.addEllipse(QPointF(10, 17), 2, 2)
    elif name == "x":
        _poly(p, (6, 6), (18, 18)); _poly(p, (18, 6), (6, 18))
    elif name == "alert":
        p.moveTo(12, 4); p.lineTo(21, 20); p.lineTo(3, 20); p.closeSubpath()
        _poly(p, (12, 10), (12, 14)); _poly(p, (12, 17), (12, 17.5))
    elif name == "check":
        _poly(p, (5, 12), (10, 17), (19, 7))
    elif name == "eyeoff":
        p.moveTo(3, 12); p.quadTo(12, 3, 21, 12); p.quadTo(12, 21, 3, 12)
        p.addEllipse(QPointF(12, 12), 3, 3); _poly(p, (4, 4), (20, 20))
    elif name == "eye":
        p.moveTo(3, 12); p.quadTo(12, 3, 21, 12); p.quadTo(12, 21, 3, 12)
        p.addEllipse(QPointF(12, 12), 3, 3)
    elif name == "flame":
        p.moveTo(12, 3); p.cubicTo(13, 7, 17, 8, 17, 13); p.arcTo(QRectF(7, 8, 10, 10), 0, -180)
        p.cubicTo(7, 11, 8, 10, 9, 9); p.cubicTo(9, 11, 10, 12, 11, 12); p.cubicTo(11, 9, 10, 7, 12, 3)
    elif name == "cmd":
        _poly(p, (5, 8), (9, 12), (5, 16)); _poly(p, (12, 16), (19, 16))
    elif name == "file":
        _poly(p, (7, 3), (14, 3), (19, 8), (19, 21), (7, 21), (7, 3)); _poly(p, (14, 3), (14, 8), (19, 8))
    elif name == "copy":
        p.addRoundedRect(QRectF(8, 8, 12, 12), 2, 2); _poly(p, (16, 8), (16, 4), (4, 4), (4, 16), (8, 16))
    elif name == "plus":
        _poly(p, (12, 5), (12, 19)); _poly(p, (5, 12), (19, 12))
    elif name == "user":
        p.addEllipse(QPointF(12, 8), 4, 4); p.moveTo(4, 21); p.cubicTo(5, 17, 8, 15, 12, 15)
        p.cubicTo(16, 15, 19, 17, 20, 21)
    elif name == "anchor":
        p.addEllipse(QPointF(12, 5), 2, 2); _poly(p, (12, 7), (12, 21))
        p.moveTo(5, 13); p.arcTo(QRectF(5, 6, 14, 14), 180, 180); _poly(p, (8, 11), (16, 11))
    elif name == "clock":
        p.addEllipse(QPointF(12, 12), 8, 8); _poly(p, (12, 8), (12, 12), (15, 14))
    elif name == "seal":
        p.addEllipse(QPointF(12, 10), 6, 6); _poly(p, (9, 15), (7, 21), (12, 19), (17, 21), (15, 15))
    elif name == "chev":
        _poly(p, (6, 9), (12, 15), (18, 9))
    elif name == "chevup":
        _poly(p, (6, 15), (12, 9), (18, 15))
    elif name == "git":
        p.addEllipse(QPointF(6, 6), 2, 2); p.addEllipse(QPointF(6, 18), 2, 2)
        p.addEllipse(QPointF(18, 8), 2, 2); _poly(p, (6, 8), (6, 16))
        p.moveTo(18, 10); p.cubicTo(18, 14, 12, 13, 8, 16)
    elif name == "unlock":
        p.addRoundedRect(QRectF(5, 11, 14, 10), 2, 2)
        p.moveTo(8, 11); p.lineTo(8, 8); p.arcTo(QRectF(8, 4, 8, 8), 180, -150)
    else:
        raise KeyError(name)
    return p


NAMES = ("shield", "shieldcheck", "search", "lock", "unlock", "key", "finger", "diff", "sliders",
         "x", "alert", "check", "eyeoff", "eye", "flame", "cmd", "file", "copy", "plus", "user",
         "anchor", "clock", "seal", "chev", "chevup", "git")


def pixmap(name: str, color: str, size: int = 18, stroke: float = 1.8, dpr: float = 2.0) -> QPixmap:
    """O icone `name` na cor `color`, com `size` px logicos (desenhado em `dpr`x para HiDPI)."""
    px = QPixmap(int(size * dpr), int(size * dpr))
    px.fill(Qt.GlobalColor.transparent)
    px.setDevicePixelRatio(dpr)
    painter = QPainter(px)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    scale = size / 24.0
    painter.scale(scale, scale)
    pen = QPen(QColor(color), stroke)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawPath(_build(name))
    painter.end()
    return px


def icon(name: str, color: str, size: int = 18, stroke: float = 1.8) -> QIcon:
    return QIcon(pixmap(name, color, size, stroke))
