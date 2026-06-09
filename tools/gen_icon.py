"""Gera o icone do Redoubt (escudo ambar com fechadura sobre tile carbono).

Uso:  python tools/gen_icon.py     (requer Pillow)
Saida: assets/redoubt.ico e assets/redoubt.png
"""
import os

from PIL import Image, ImageDraw

ASSETS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")
os.makedirs(ASSETS, exist_ok=True)

CARBON = (14, 17, 22, 255)      # #0E1116
PANEL = (33, 38, 45, 255)       # borda sutil
AMBER = (232, 163, 61, 255)     # #E8A33D

S = 512
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# tile carbono arredondado + borda
d.rounded_rectangle([8, 8, S - 8, S - 8], radius=96, fill=CARBON, outline=PANEL, width=6)

# escudo (reduto) ambar
d.polygon([(150, 150), (362, 150), (362, 262), (256, 398), (150, 262)], fill=AMBER)

# fechadura recortada em carbono: circulo + haste trapezoidal
cx, cy, r = 256, 232, 34
d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=CARBON)
d.polygon([(cx - 18, cy + 6), (cx + 18, cy + 6), (cx + 30, cy + 96), (cx - 30, cy + 96)], fill=CARBON)

img.save(os.path.join(ASSETS, "redoubt.png"))
img.save(os.path.join(ASSETS, "redoubt.ico"),
         sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("icone gerado em", ASSETS)
