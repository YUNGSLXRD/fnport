#!/usr/bin/env python3
# Generates the README diagrams (docs/img/*.svg). Run: python3 docs/img/make_diagrams.py
import os
from xml.sax.saxutils import escape

OUT = os.path.dirname(os.path.abspath(__file__))
FONT = "-apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"

# own light card background, so the pictures read the same in GitHub light and dark themes
STYLE = {
    "node": ("#f6f8fa", "#8c959f", "#1f2328"),
    "fnport": ("#dafbe1", "#1a7f37", "#0f3d1e"),
    "isp": ("#eaeef2", "#57606a", "#1f2328"),
    "question": ("#fff8c5", "#9a6700", "#3d2a00"),
    "option": ("#ddf4ff", "#0969da", "#0a2f5c"),
}


class Svg:
    def __init__(self, w, h):
        self.w, self.h, self.parts = w, h, []

    def box(self, x, y, w, h, lines, kind="node", pill=False):
        fill, stroke, color = STYLE[kind]
        r = h / 2 if pill else 8
        self.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" '
                          f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>')
        lh = 18
        y0 = y + h / 2 - (len(lines) - 1) * lh / 2
        for i, line in enumerate(lines):
            bold = line.startswith("**")
            text = line.strip("*")
            weight = ' font-weight="600"' if bold else ""
            self.parts.append(f'<text x="{x + w / 2}" y="{y0 + i * lh}" text-anchor="middle" '
                              f'dominant-baseline="central" font-size="14"{weight} fill="{color}">'
                              f'{escape(text)}</text>')
        return (x, y, w, h)

    def arrow(self, x1, y1, x2, y2, dashed=False, label=None, at=0.5, above=False):
        dash = ' stroke-dasharray="6 5"' if dashed else ""
        self.parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#57606a" '
                          f'stroke-width="1.6"{dash} marker-end="url(#arrow)"/>')
        if label:
            lines = label if isinstance(label, list) else [label]
            lx, ly = x1 + (x2 - x1) * at, y1 + (y2 - y1) * at
            lh = 15
            w = max(len(l) for l in lines) * 6.6 + 14
            h = len(lines) * lh + 8
            if above:  # short horizontal arrows: keep the line visible
                ly -= h / 2 + 5
            self.parts.append(f'<rect x="{lx - w / 2}" y="{ly - h / 2}" width="{w}" height="{h}" rx="4" '
                              f'fill="#ffffff" stroke="#d0d7de"/>')
            y0 = ly - (len(lines) - 1) * lh / 2
            for i, line in enumerate(lines):
                self.parts.append(f'<text x="{lx}" y="{y0 + i * lh}" text-anchor="middle" '
                                  f'dominant-baseline="central" font-size="12" fill="#57606a">'
                                  f'{escape(line)}</text>')

    def group(self, x, y, w, h, title):
        self.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="none" '
                          f'stroke="#8c959f" stroke-width="1.5" stroke-dasharray="4 4"/>')
        self.parts.append(f'<text x="{x + 14}" y="{y + 18}" font-size="13" font-weight="600" '
                          f'fill="#57606a">{escape(title)}</text>')

    def save(self, name, title):
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" '
               f'viewBox="0 0 {self.w} {self.h}" font-family="{FONT}" role="img">'
               f'<title>{escape(title)}</title>'
               '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" '
               'markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#57606a"/>'
               '</marker></defs>'
               f'<rect x="0.5" y="0.5" width="{self.w - 1}" height="{self.h - 1}" rx="12" '
               'fill="#ffffff" stroke="#d0d7de"/>'
               + "".join(self.parts) + "</svg>\n")
        with open(os.path.join(OUT, name), "w") as f:
            f.write(svg)


def right(b):
    return (b[0] + b[2], b[1] + b[3] / 2)


def left(b):
    return (b[0], b[1] + b[3] / 2)


def top(b):
    return (b[0] + b[2] / 2, b[1])


def bottom(b):
    return (b[0] + b[2] / 2, b[1] + b[3])


# 1. which option fits
s = Svg(780, 400)
q1 = s.box(270, 24, 240, 50, ["Есть роутер с OpenWrt?"], "question")
ok = s.box(560, 24, 196, 50, ["**Ставьте fnport**", "раздел «Установка»"], "fnport")
q2 = s.box(270, 140, 240, 58, ["Ваш роутер есть", "в списке OpenWrt?"], "question")
v1 = s.box(24, 312, 220, 64, ["**Вариант 1**", "прошить свой роутер"], "option")
v2 = s.box(280, 312, 220, 64, ["**Вариант 2**", "добавить устройство с OpenWrt"], "option")
v3 = s.box(536, 312, 220, 64, ["**Вариант 3**", "OpenWrt в виртуальной машине"], "option")
s.arrow(*right(q1), *left(ok), label="Да", above=True)
s.arrow(*bottom(q1), *top(q2), label="Нет")
s.arrow(*bottom(q2), *top(v1), label=["Да, и не страшно", "его перепрошить"], at=0.6)
s.arrow(*bottom(q2), *top(v2), label=["Нет, или это Keenetic,", "или роутер провайдера"], at=0.5)
s.arrow(*bottom(q2), *top(v3), label=["Роутера нет,", "только ПК"], at=0.6)
s.save("no-openwrt-choose.svg", "Какой вариант выбрать без роутера с OpenWrt")

# 2. option 1: flash your router
s = Svg(780, 190)
isp = s.box(24, 70, 130, 46, ["Провайдер"], "isp", pill=True)
r = s.box(230, 64, 210, 58, ["**Ваш роутер**", "OpenWrt + fnport"], "fnport")
pc = s.box(540, 24, 210, 46, ["Игровой ПК"])
ph = s.box(540, 116, 210, 46, ["Телефоны, ноутбуки"])
s.arrow(*right(isp), *left(r))
s.arrow(r[0] + r[2], r[1] + 18, *left(pc), label="кабель", at=0.55)
s.arrow(r[0] + r[2], r[1] + 40, *left(ph), dashed=True, label="Wi-Fi", at=0.55)
s.save("no-openwrt-option1.svg", "Вариант 1: свой роутер прошит в OpenWrt")

# 3. option 2a: OpenWrt is the main router, the old one gives Wi-Fi
s = Svg(780, 230)
isp = s.box(24, 70, 120, 46, ["Провайдер"], "isp", pill=True)
ow = s.box(200, 64, 190, 58, ["**Роутер с OpenWrt**", "+ fnport (главный)"], "fnport")
pc = s.box(470, 24, 150, 58, ["Игровой ПК", "(лучше кабелем)"])
old = s.box(470, 132, 150, 64, ["**Старый роутер**", "режим точки", "доступа"])
ph = s.box(672, 136, 92, 56, ["Телефоны,", "ноутбуки"])
s.arrow(*right(isp), *left(ow), label="кабель", above=True)
s.arrow(ow[0] + ow[2], ow[1] + 18, *left(pc))
s.arrow(ow[0] + ow[2], ow[1] + 42, *left(old), label="LAN", at=0.5)
s.arrow(*right(old), *left(ph), dashed=True, label="Wi-Fi", above=True)
s.save("no-openwrt-option2a.svg", "Вариант 2а: OpenWrt главный, старый роутер раздаёт Wi-Fi")

# 4. option 2b: OpenWrt behind the old router
s = Svg(780, 140)
isp = s.box(24, 46, 120, 46, ["Провайдер"], "isp", pill=True)
old = s.box(196, 40, 150, 58, ["**Старый роутер**", "(как сейчас)"])
ow = s.box(446, 40, 170, 58, ["**Роутер с OpenWrt**", "+ fnport"], "fnport")
pc = s.box(660, 46, 100, 46, ["Игровой ПК"])
s.arrow(*right(isp), *left(old))
s.arrow(*right(old), *left(ow), label="LAN → WAN", above=True)
s.arrow(*right(ow), *left(pc))
s.save("no-openwrt-option2b.svg", "Вариант 2б: роутер с OpenWrt за старым роутером")

# 5. option 3: OpenWrt in a VM on the PC
s = Svg(780, 170)
s.group(20, 20, 420, 130, "Игровой ПК")
g = s.box(44, 66, 130, 50, ["Fortnite"])
vm = s.box(220, 60, 196, 62, ["**Виртуальная машина**", "OpenWrt + fnport"], "fnport")
r = s.box(480, 64, 130, 54, ["Ваш роутер"])
isp = s.box(650, 68, 110, 46, ["Провайдер"], "isp", pill=True)
s.arrow(*right(g), *left(vm))
s.arrow(*right(vm), *left(r))
s.arrow(*right(r), *left(isp))
s.save("no-openwrt-option3.svg", "Вариант 3: OpenWrt в виртуальной машине на игровом ПК")

print("ok")
