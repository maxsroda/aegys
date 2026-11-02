"""Write assets/agy-window.svg: a mock macOS terminal window with agy's start screen, its
aegys status chip, and the aegys shield (assets/logo.svg) pointing at the chip.

Run: python3 assets/make-agy-window.py"""
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "agy-window.svg"
LOGO_SVG = (HERE / "logo.svg").read_text(encoding="utf-8")

# agy's pixel logo, 12 columns x 10 rows, colours sampled from a screenshot of agy 1.4.12 ('......' = empty).
LOGO = [
    "...... ...... ...... ...... ...... e69743 e27a44 ...... ...... ...... ...... ......",
    "...... ...... ...... ...... d6b24a ea9643 e57b45 e06444 ...... ...... ...... ......",
    "...... ...... ...... a6c158 b6b351 d99c4d e88244 e87442 df614a ...... ...... ......",
    "...... ...... ...... 94c35e 83b268 c59758 e18051 d36e58 d25b5c ...... ...... ......",
    "...... ...... 8cbf60 84bf68 6ea791 6790b0 8075ac 7271be 9162a4 946094 ...... ......",
    "...... ...... 90c363 6eb586 5596d9 ...... ...... 537fde 6f70c9 8968b0 ...... ......",
    "...... ...... 7ac083 60acab ...... ...... ...... ...... 5481e4 6c75d2 ...... ......",
    "...... 82c398 76b8d3 5fa7d8 ...... ...... ...... ...... 4d89f4 5482e9 677bdb ......",
    "...... 81c4a6 76b5f1 ...... ...... ...... ...... ...... ...... 4987f4 5282ed ......",
    "79b8f0 76b5f1 ...... ...... ...... ...... ...... ...... ...... ...... 4884f2 4c86f5",
]

BLUE, GRAY, GREEN, CHIP_BLUE, RULE = "#406bc0", "#606368", "#3c7d40", "#235faa", "#dbdce0"
FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"

canvas_w, canvas_h = 960, 340
win_x, win_y, win_w, win_h = 160, 34, 760, 262
bar_h = 30
pad = 22
font_size = 13
line_h = 19

parts = []
add = parts.append
add(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {canvas_w} {canvas_h}" width="{canvas_w}" height="{canvas_h}" role="img" aria-label="agy in a terminal window, with the aegys status chip under the prompt">')
add('<defs>')
add('<linearGradient id="desk" x1="0" y1="0" x2="1" y2="1">'
    '<stop offset="0" stop-color="#7f9cf5"/><stop offset="0.5" stop-color="#b38bd9"/><stop offset="1" stop-color="#f4a6a0"/></linearGradient>')
add('<filter id="shadow" x="-10%" y="-10%" width="120%" height="130%">'
    '<feGaussianBlur stdDeviation="12"/></filter>')
add(f'<clipPath id="win"><rect x="{win_x}" y="{win_y}" width="{win_w}" height="{win_h}" rx="10"/></clipPath>')
add('</defs>')

# Desktop backdrop.
add(f'<rect width="{canvas_w}" height="{canvas_h}" rx="14" fill="url(#desk)"/>')

# Window body and title bar.
add(f'<rect x="{win_x}" y="{win_y + 10}" width="{win_w}" height="{win_h}" rx="10" fill="#1a1440" fill-opacity="0.35" filter="url(#shadow)"/>')
add(f'<rect x="{win_x}" y="{win_y}" width="{win_w}" height="{win_h}" rx="10" fill="#ffffff"/>')
add(f'<g clip-path="url(#win)">'
    f'<rect x="{win_x}" y="{win_y}" width="{win_w}" height="{bar_h}" fill="#ececee"/>'
    f'<line x1="{win_x}" y1="{win_y + bar_h}" x2="{win_x + win_w}" y2="{win_y + bar_h}" stroke="#d6d6d9"/></g>')
for i, colour in enumerate(("#ff5f57", "#febc2e", "#28c840")):
    add(f'<circle cx="{win_x + 18 + i * 20}" cy="{win_y + bar_h / 2}" r="6" fill="{colour}"/>')
add(f'<text x="{win_x + win_w / 2}" y="{win_y + bar_h / 2 + 4.5}" text-anchor="middle" '
    f'font-family="-apple-system, BlinkMacSystemFont, \'Segoe UI\', Helvetica, Arial, sans-serif" '
    f'font-size="12.5" fill="#6e6e73">agy — ~/projects/aegys</text>')

# Terminal content.
left = win_x + pad
right = win_x + win_w - pad
top = win_y + bar_h + 18

cell = 7
for r, row in enumerate(LOGO):
    for c, colour in enumerate(row.split()):
        if colour != "......":
            add(f'<rect x="{left + 4 + c * cell}" y="{top + r * cell}" width="{cell}" height="{cell}" fill="#{colour}"/>')

def text(x, y, content, fill, weight="normal", anchor="start"):
    add(f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{font_size}" font-weight="{weight}" '
        f'fill="{fill}" text-anchor="{anchor}" xml:space="preserve">{content}</text>')

info_x = left + 4 + 12 * cell + 28
info_y = top + 11
text(info_x, info_y, "Antigravity CLI 1.4.12", BLUE, weight="bold")
text(info_x, info_y + line_h, "you@example.com (Google AI Pro)", GRAY)
text(info_x, info_y + 2 * line_h, "Gemini 3.8 Flash (Medium)", GRAY)
text(info_x, info_y + 3 * line_h, "~/projects/aegys", GRAY)

rule1 = top + 10 * cell + 22
add(f'<line x1="{left}" y1="{rule1}" x2="{right}" y2="{rule1}" stroke="{RULE}" stroke-width="1.5"/>')
prompt_y = rule1 + 26
add(f'<text x="{left}" y="{prompt_y}" font-family="{FONT}" font-size="{font_size}" xml:space="preserve">'
    f'<tspan fill="{BLUE}">&gt;</tspan><tspan fill="{GRAY}"> Accept-edits mode: file edits auto-approved (shift+tab to cycle)</tspan></text>')
rule2 = prompt_y + 16
add(f'<line x1="{left}" y1="{rule2}" x2="{right}" y2="{rule2}" stroke="{RULE}" stroke-width="1.5"/>')

foot_y = rule2 + 24
text(left, foot_y, "? for shortcuts", GRAY)
add(f'<text x="{right}" y="{foot_y}" font-family="{FONT}" font-size="{font_size}" text-anchor="end" xml:space="preserve">'
    f'<tspan fill="{GREEN}">accept-edits</tspan><tspan fill="{GRAY}"> · Gemini 3.8 Flash · medium</tspan></text>')
text(left, foot_y + line_h, "aegys ● a:0 d:0", CHIP_BLUE)

# The aegys shield on the desktop, left of the window, with an arrow to the chip.
body = re.sub(r"(?s)^.*?<svg[^>]*>|</svg>\s*$|<title>.*?</title>", "", LOGO_SVG)
for name in set(re.findall(r'id="([^"]+)"', body)):
    body = body.replace(f'id="{name}"', f'id="logo-{name}"').replace(f"url(#{name})", f"url(#logo-{name})")
shield = 96
chip_mid_y = foot_y + line_h - 4.5
shield_x, shield_y = 28, chip_mid_y - shield / 2 - 6
add(f'<svg x="{shield_x}" y="{shield_y}" width="{shield}" height="{shield}" viewBox="0 0 64 64">{body}</svg>')
start_x, end_x = shield_x + shield - 14, left - 9
add(f'<defs><marker id="head" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="4" markerHeight="4" orient="auto-start-reverse">'
    f'<path d="M0 0 L10 5 L0 10 Z" fill="{CHIP_BLUE}"/></marker></defs>')
arrow = f"M{start_x} {chip_mid_y + 16} C {start_x + 30} {chip_mid_y + 18}, {end_x - 26} {chip_mid_y + 2}, {end_x} {chip_mid_y}"
add(f'<path d="{arrow}" fill="none" stroke="#ffffff" stroke-width="6" stroke-linecap="round"/>')
add(f'<path d="{arrow}" fill="none" stroke="{CHIP_BLUE}" stroke-width="2.5" stroke-linecap="round" marker-end="url(#head)"/>')

add('</svg>')
OUT.write_text("\n".join(parts) + "\n", encoding="utf-8")
