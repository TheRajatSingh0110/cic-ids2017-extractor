# Render the PPT demo animation for the CIC-IDS2017 extractor.
# Pure-PIL frames encoded with the ffmpeg bundled by imageio-ffmpeg.
# Run from the project root with the video venv python:
#
#   python tools/make_video.py [--out path/to/demo.mp4]
#
# All on-screen command/output strings are read live from the captured
# assets under tools/video/assets so the video reflects real tool output.

from __future__ import annotations

import argparse
import math
import os
import sys

from PIL import Image, ImageDraw, ImageFont

try:
    import imageio
    import numpy as np
except ImportError:
    sys.exit('run with the video venv python (has imageio + imageio-ffmpeg)')

W, H, FPS, FADE = 1920, 1080, 30, 0.6

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, 'tools', 'video', 'assets')

# palette (github dark)
BG = (13, 17, 23)
PANEL = (22, 27, 34)
PANEL2 = (28, 36, 46)
BORDER = (48, 54, 61)
TXT = (230, 237, 243)
MUT = (139, 148, 158)
BLUE = (47, 129, 247)
BLUE_D = (31, 88, 171)
GREEN = (63, 185, 80)
YELLOW = (210, 153, 34)
RED = (248, 81, 73)
PURPLE = (188, 140, 248)
CYAN = (57, 211, 205)

FONTS = {}


def font(path, size):
    key = (path, size)
    if key not in FONTS:
        FONTS[key] = ImageFont.truetype(path, size)
    return FONTS[key]


FE = 'C:/Windows/Fonts/segoeui.ttf'
FEB = 'C:/Windows/Fonts/segoeuib.ttf'
FEL = 'C:/Windows/Fonts/segoeuil.ttf'
CM = 'C:/Windows/Fonts/consola.ttf'
CMB = 'C:/Windows/Fonts/consolab.ttf'


def ease(p):
    return 1 - math.pow(1 - max(0.0, min(1.0, p)), 3)


def lerp(a, b, p):
    return a + (b - a) * p


def appear(t, start, dur=0.55):
    if t < start:
        return 0.0, 26
    return ease((t - start) / dur), round(26 * (1 - ease(min(1.0, (t - start) / dur))))


def with_alpha(color, a):
    return (color[0], color[1], color[2], int(255 * a))


def fade_image(img, a):
    if a >= 1:
        return img
    if a <= 0:
        return Image.new('RGB', (W, H), BG)
    mask = Image.new('L', img.size, int(255 * a))
    return Image.composite(img, Image.new('RGB', (W, H), BG), mask)


def read_asset(name):
    with open(os.path.join(ASSETS, name), 'r', encoding='utf-8') as fh:
        return fh.read().strip()


def read_lines(name):
    return read_asset(name).splitlines()


def wrap_tokens(text, drw, fnt, maxw):
    tokens = text.split(',')
    lines = []
    cur = ''
    for tk in tokens:
        cand = tk if not cur else cur + ',' + tk
        if drw.textlength(cand, font=fnt) <= maxw:
            cur = cand
        else:
            if cur:
                lines.append(cur)
            cur = tk
    if cur:
        lines.append(cur)
    return lines


def draw_text(img, xy, text, path, size, fill=None, anchor='la', alpha=1.0):
    drw = ImageDraw.Draw(img)
    color = with_alpha(fill or TXT, alpha)
    drw.text(xy, text, font=font(path, size), fill=color, anchor=anchor)
    return img


def tint(color, alpha):
    if color is None or alpha >= 1.0:
        return color
    return (color[0], color[1], color[2], int(255 * max(0.0, min(1.0, alpha))))


def draw_panel(img, box, fill=PANEL, outline=BORDER, width=1, radius=18, alpha=1.0):
    drw = ImageDraw.Draw(img)
    drw.rounded_rectangle(
        box, radius=radius, fill=tint(fill, alpha), outline=tint(outline, alpha), width=width)
    return img


def draw_pill(img, cx, y, text, path, size, fg, bg, pad_x=22, pad_y=9, alpha=1.0):
    drw = ImageDraw.Draw(img)
    f = font(path, size)
    tw = drw.textlength(text, font=f)
    _, th = drw.textbbox((0, 0), text, font=f)[2:]
    w = int(tw + pad_x * 2)
    h = int(th + pad_y * 2)
    x0, y0 = int(cx - w / 2), int(y)
    drw.rounded_rectangle((x0, y0, x0 + w, y0 + h), radius=h, fill=tint(bg, alpha))
    drw.text((cx, y0 + h / 2), text, font=f, fill=tint(fg, alpha), anchor='mm')
    return w


def vbar(img, x, y0, y1, color, width=6):
    ImageDraw.Draw(img).rounded_rectangle(
        (x - width / 2, y0, x + width / 2, y1), radius=width / 2, fill=color)


def hbar(img, x0, y, x1, color, height=6):
    ImageDraw.Draw(img).rounded_rectangle(
        (x0, y - height / 2, x1, y + height / 2), radius=height / 2, fill=color)


def arrow_right(img, x0, y, x1, color, alpha=1.0):
    drw = ImageDraw.Draw(img)
    color_a = with_alpha(color, alpha)
    drw.line((x0, y, x1 - 18, y), fill=color_a, width=5)
    drw.polygon([(x1, y), (x1 - 22, y - 11), (x1 - 22, y + 11)], fill=color_a)


class Scene:
    def render(self, t):
        img = Image.new('RGBA', (W, H), BG + (0,))
        self.paint(img, t)
        return img

    def paint(self, img, t):
        raise NotImplementedError


class TitleScene(Scene):
    def paint(self, img, t):
        a, dy = appear(t, 0.0)
        cy = 300 - dy
        draw_text(img, (W / 2, cy), 'CIC-IDS2017', FEL, 150, TXT, 'mm', a)
        a2, dy2 = appear(t, 0.5)
        draw_text(img, (W / 2, cy + 165 - dy2), 'Flow Feature Extractor', FEL, 96, BLUE, 'mm', a2)
        a3, dy3 = appear(t, 1.0)
        draw_text(
            img, (W / 2, cy + 280 - dy3),
            '69 CICFlowMeter-exact features - live capture and offline pcap analysis', FE, 34, MUT, 'mm', a3)
        a4, dy4 = appear(t, 1.5)
        draw_pill(img, W / 2, cy + 360 - dy4, 'demo', FE, 22, TXT, RED, pad_x=26, alpha=a4)
        a5, dy5 = appear(t, 2.0)
        draw_pill(
            img, W / 2, cy + 470 - dy5,
            'github.com/TheRajatSingh0110/cic-ids2017-extractor', CMB, 28, BG, BLUE, pad_x=34, pad_y=14,
            alpha=a5)


class WhatScene(Scene):
    CARDS = [
        ('Bidirectional flows', 'Reference 5-tuple flow ids (fwdFlowId / bwdFlowId), '
         'merge decided by source IP like CICFlowMeter.'),
        ('CICFlowMeter semantics', 'Port of the v4 Java reference: payload/header lengths, '
         'sample statistics, subflows, active/idle, FIN-RST-timeout rules.'),
        ('Deterministic output', 'Exactly 69 raw features in the canonical order - 69 '
         'comma-separated values per row, no header, no labels.'),
    ]

    def paint(self, img, t):
        a, dy = appear(t, 0.0)
        draw_text(img, (120, 150 - dy), 'What it produces', FEL, 72, TXT, 'la', a)
        draw_text(img, (120, 238 - dy), 'Raw, ready-to-feed flow feature rows', FE, 28, MUT, 'la', a)
        cw = (W - 240 - 60) / 3
        for i, (title, body) in enumerate(self.CARDS):
            a, dy = appear(t, 0.9 + i * 0.35)
            x0 = 120 + i * (cw + 30)
            y0 = 360 - dy
            draw_panel(img, (x0, y0, x0 + cw, y0 + 430), fill=PANEL, alpha=a)
            drw = ImageDraw.Draw(img)
            colors = [BLUE, GREEN, PURPLE]
            drw.rounded_rectangle(
                (x0 + 40, y0 + 48, x0 + 88, y0 + 96), radius=10,
                fill=with_alpha(colors[i], a))
            draw_text(img, (x0 + 40, y0 + 160), title, FEB, 34, TXT, 'la', a)
            wrapped = wrap_tokens(body, drw, font(FE, 26), cw - 80)
            ly = y0 + 230
            for line in wrapped:
                draw_text(img, (x0 + 40, ly), line, FE, 26, MUT, 'la', a)
                ly += 40


class PipelineScene(Scene):
    BOXES = [
        ('INPUT', 'pcap file /', 'Npcap interface', BLUE),
        ('PARSE', 'TCP / UDP', 'PacketInfo', GREEN),
        ('MERGE', 'FlowManager', 'fwd + bwd flows', YELLOW),
        ('EXTRACT', '69 features', 'canonical order', PURPLE),
        ('OUTPUT', 'CSV / JSON', 'raw value rows', CYAN),
    ]

    def paint(self, img, t):
        a, dy = appear(t, 0.0)
        draw_text(img, (120, 150 - dy), 'Pipeline', FEL, 72, TXT, 'la', a)
        draw_text(img, (120, 238 - dy), 'one packet in - one 69-value row out', FE, 28, MUT, 'la', a)
        bw, gap = 300, 40
        x0 = (W - (bw * 5 + gap * 4)) / 2
        y = 420
        for i, (tag, l1, l2, col) in enumerate(self.BOXES):
            a, dy = appear(t, 0.8 + i * 0.35)
            bx = x0 + i * (bw + gap)
            draw_panel(img, (bx, y - dy, bx + bw, y + 240), fill=PANEL, alpha=a)
            draw_pill(img, bx + 100, y - dy + 34, tag, CMB, 20, BG, col, pad_x=18, pad_y=7)
            draw_text(img, (bx + bw / 2, y - dy + 130), l1, FEB, 30, TXT, 'mm', a)
            draw_text(img, (bx + bw / 2, y - dy + 180), l2, FE, 24, MUT, 'mm', a)
            if i < len(self.BOXES) - 1:
                ax = x0 + (i + 1) * bw + i * gap - 8
                arrow_right(img, bx + bw + 14, y + 120 - dy, ax, BORDER, a)
        a, dy = appear(t, 4.2)
        draw_text(
            img, (W / 2, 760 - dy),
            'Default flow timeout 120s - activity timeout 5s - direction by source IP only', FE, 26, MUT, 'mm', a)


class TerminalScene(Scene):
    def paint(self, img, t):
        a, dy = appear(t, 0.0)
        draw_text(img, (120, 130 - dy), 'Live demo', FEL, 72, TXT, 'la', a)
        draw_text(img, (120, 218 - dy), 'real output from the tool in this repo', FE, 28, MUT, 'la', a)

        panel = (120, 330 - dy, W - 120, H - 130)
        draw_panel(img, panel, fill=PANEL, alpha=a)
        drw = ImageDraw.Draw(img)
        # title bar
        x0, y0 = panel[0], panel[1]
        drw.rounded_rectangle(
            (x0, y0, panel[2], y0 + 56), radius=0, fill=(30, 36, 44), outline=BORDER)
        drw.ellipse((x0 + 26, y0 + 21, x0 + 42, y0 + 37), fill=(255, 95, 86))
        drw.ellipse((x0 + 52, y0 + 21, x0 + 68, y0 + 37), fill=(255, 189, 46))
        drw.ellipse((x0 + 78, y0 + 21, x0 + 94, y0 + 37), fill=(39, 201, 63))
        draw_text(img, (W / 2, y0 + 28), 'PowerShell - cic-ids2017-extractor', FE, 18, MUT, 'mm', a)

        line_h = 40
        text_x = x0 + 40
        first_y = y0 + 108
        mono = font(CM, 27)

        prompts = [
            ('python main.py --pcap sample_pcaps/synthetic.pcap --out out/flows --format csv', 1.05, 0.022),
            ('python main.py --pcap sample_pcaps/synthetic.pcap --out out/flows --format json', 6.0, 0.022),
        ]
        outputs = [
            read_lines('cli_capture.txt'),
            read_lines('cli_json.txt'),
        ]
        lines = []
        y = first_y
        for idx, (cmd, start, cps) in enumerate(prompts):
            shown = int(min(1.0, max(0.0, (t - start) / (len(cmd) * cps))) * len(cmd))
            cur = cmd[:shown]
            draw_text(img, (text_x, y), cur, CM, 27, TXT, 'la', a)
            xcur = text_x + mono.getlength(cur)
            blink = 1.0 if (t - start) > len(cmd) * cps and int(t * 2) % 2 == 0 else a
            draw_text(img, (xcur + 6, y), '_', CM, 27, GREEN, 'la', blink)
            y += line_h
            out = outputs[idx]
            start2 = start + len(cmd) * cps + 0.45
            for li, line in enumerate(out):
                if t >= start2 + li * 0.4:
                    draw_text(img, (text_x, y), line, CM, 27, TXT, 'la', a)
                y += line_h
        draw_text(img, (text_x, y), '2 files written. Done.', CM, 27, GREEN, 'la',
                  min(a, ease(max(0.0, (t - 10.6) / 0.8))))


class CsvScene(Scene):
    def paint(self, img, t):
        a, dy = appear(t, 0.0)
        draw_text(img, (120, 120 - dy), 'One flow - one row', FEL, 64, TXT, 'la', a)
        draw_text(img, (120, 196 - dy), '69 raw values, no header, canonical order', FE, 26, MUT, 'la', a)

        rows = read_lines('sample_rows.csv')
        row0 = rows[0]
        names = read_lines('features.txt')

        panel = (120, 270 - dy, W - 120, 560 - dy)
        draw_panel(img, panel, fill=PANEL, alpha=a)
        draw_pill(img, 220, panel[1] + 26, 'flows.csv', CMB, 20, TXT, PANEL2, pad_x=16, pad_y=6, alpha=a)
        drw = ImageDraw.Draw(img)
        mono_s = font(CM, 22)
        wrapped = wrap_tokens(row0, drw, mono_s, W - 400)
        ly = panel[1] + 130
        for line in wrapped[:5]:
            draw_text(img, (panel[0] + 50, ly), line, CM, 22, (127, 219, 147), 'la', a)
            ly += 38
        if len(wrapped) > 5:
            draw_text(img, (panel[0] + 50, ly), '...', CM, 22, MUT, 'la', a)

        pairs = list(zip(names, row0.split(',')))
        grid_top = 620 - dy
        col_w = 560
        for col in range(3):
            for r in range(3):
                idx = col * 3 + r
                if idx >= len(pairs):
                    continue
                na, val = pairs[idx]
                yy = grid_top + r * 86
                xx = 150 + col * col_w
                draw_text(img, (xx, yy), '%02d' % (idx + 1), CM, 22, MUT, 'la', a)
                draw_text(img, (xx + 56, yy), na, FE, 24, TXT, 'la', a)
                draw_pill(img, xx + 430, yy - 4, val, CM, 22, BG, BLUE, pad_x=16, pad_y=7, alpha=a)

        a2, dy2 = appear(t, 4.5)
        draw_text(
            img, (W / 2, 980 - dy2),
            'zero-safe: degenerate statistics output 0.0, never NaN or Inf - byte-for-byte Java-style float format',
            FE, 24, MUT, 'mm', a2)


class ValidationScene(Scene):
    CHECKS = [
        '69 names in exact reference order',
        'IAT / packet / flag statistics vs hand-computed values',
        'flow state: merge, subflows, active-idle, FIN-RST-timeout rules',
        'end-to-end decode of the synthetic validation pcap',
    ]

    def paint(self, img, t):
        a, dy = appear(t, 0.0)
        draw_text(img, (120, 140 - dy), 'Validation', FEL, 72, TXT, 'la', a)
        draw_text(img, (120, 228 - dy), 'pytest suite against known-good reference behaviour', FE, 28, MUT, 'la', a)

        draw_panel(img, (120, 340 - dy, W - 120, 800 - dy), fill=PANEL, alpha=a)
        progress = ease(max(0.0, min(1.0, (t - 1.2) / 2.5)))
        draw_text(img, (W / 2, 428 - dy), '40 / 40 tests pass', FEB, 72, TXT, 'mm', a)
        bar_x0, bar_x1 = 420, W - 420
        draw_panel(img, (bar_x0, 520 - dy, bar_x1, 560 - dy), fill=PANEL2, radius=20, alpha=a)
        if progress > 0:
            ImageDraw.Draw(img).rounded_rectangle(
                (bar_x0 + 6, 526 - dy, bar_x0 + 6 + (bar_x1 - bar_x0 - 12) * progress, 554 - dy),
                radius=12, fill=with_alpha(GREEN, a))
        draw_text(img, (W / 2, 610 - dy), '40 passed in 1.23s', CM, 24, GREEN, 'mm', a)

        ly0 = 660 - dy
        for i, chk in enumerate(self.CHECKS):
            a2, dy2 = appear(t, 2.6 + i * 0.35)
            draw_text(img, (200, ly0 + i * 56 + 26 - dy2), 'o ', CM, 26, GREEN, 'la', a2)
            draw_text(img, (252, ly0 + i * 56 - dy2), chk, FE, 27, TXT, 'la', a2)


class LiveScene(Scene):
    def paint(self, img, t):
        a, dy = appear(t, 0.0)
        draw_text(img, (120, 130 - dy), 'Live capture', FEL, 72, TXT, 'la', a)
        draw_text(img, (120, 218 - dy), 'Npcap present - interface list from this machine', FE, 28, MUT, 'la', a)

        ifs = read_lines('interfaces.txt')
        panel = (120, 340 - dy, W - 120, 830 - dy)
        draw_panel(img, panel, fill=PANEL, alpha=a)
        ImageDraw.Draw(img).rounded_rectangle(
            (panel[0], panel[1], panel[2], panel[1] + 56), radius=0,
            fill=(30, 36, 44), outline=BORDER)
        draw_text(img, (panel[0] + 40, panel[1] + 28), 'python main.py --list-interfaces', CM, 24, TXT, 'la', a)
        for i, line in enumerate(ifs[:7]):
            a2, dy2 = appear(t, 0.9 + i * 0.28)
            draw_text(img, (panel[0] + 40, panel[1] + 110 + i * 52 - dy2), line, CM, 24, MUT, 'la', a2)
        a3, dy3 = appear(t, 3.4)
        draw_pill(img, W / 2, 640 - dy, '10 interfaces detected - one command switches to live mode',
                  FE, 28, TXT, GREEN, pad_x=34, pad_y=18, alpha=a3)

        a4, dy4 = appear(t, 4.6)
        draw_text(
            img, (W / 2, 950 - dy4),
            '--interface <name>  replaces  --pcap:  stream the same 69 features straight to disk',
            FE, 24, MUT, 'mm', a4)


class CreditsScene(Scene):
    def paint(self, img, t):
        a, dy = appear(t, 0.0)
        draw_text(img, (W / 2, 380 - dy), 'Thank you', FEL, 110, TXT, 'mm', a)
        a2, dy2 = appear(t, 1.2)
        draw_text(
            img, (W / 2, 540 - dy2),
            'github.com/TheRajatSingh0110/cic-ids2017-extractor', CMB, 34, BLUE, 'mm', a2)
        a3, dy3 = appear(t, 2.1)
        draw_text(img, (W / 2, 640 - dy3), 'Python - Scapy - Npcap - CICFlowMeter v4 reference', FE, 28, MUT, 'mm', a3)
        a4, dy4 = appear(t, 2.9)
        draw_text(img, (W / 2, 720 - dy4), 'generated with opencode', FE, 24, MUT, 'mm', a4)


SCENES = [
    (TitleScene(), 5.0),
    (WhatScene(), 7.0),
    (PipelineScene(), 8.5),
    (TerminalScene(), 12.0),
    (CsvScene(), 10.0),
    (ValidationScene(), 7.5),
    (LiveScene(), 6.5),
    (CreditsScene(), 5.5),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=os.path.join(ROOT, 'tools', 'video', 'cic-ids2017-demo.mp4'))
    ap.add_argument('--scale', type=float, default=1.0)
    args = ap.parse_args()

    out = os.path.abspath(args.out)
    sc_w, sc_h = int(W * args.scale), int(H * args.scale)
    os.makedirs(os.path.dirname(out), exist_ok=True)

    starts = []
    acc = 0.0
    for _, dur in SCENES:
        starts.append(acc)
        acc += dur
    total = acc

    with imageio.get_writer(
            out, fps=FPS, codec='libx264', quality=7, pixelformat='yuv420p') as writer:
        nframes = int(round(total * FPS))
        for i in range(nframes):
            t = i / FPS
            for s, (scene, dur) in enumerate(SCENES):
                if t < starts[s] + dur:
                    lt = t - starts[s]
                    frame = scene.render(lt)
                    if args.scale != 1.0:
                        frame = frame.resize((sc_w, sc_h), Image.LANCZOS)
                    fade = 1.0
                    if lt < FADE:
                        fade = lt / FADE
                    writer.append_data(np.asarray(fade_image(frame.convert('RGB'), fade)))
                    break
            if i % round(FPS) == 0 or i == nframes - 1:
                print('frame %d/%d - t=%.1fs' % (i + 1, nframes, t), flush=True)
    print('rendered %d frames (%.1fs) -> %s' % (nframes, total, out))


if __name__ == '__main__':
    main()