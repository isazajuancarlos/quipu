#!/usr/bin/env python3
"""Exploración generativa de glifos (vía CPU, sin GPU).

Implementa un DECODIFICADOR LATENTE -> GLIFO: un vector latente continuo z se
mapea a curvas Bézier suaves. Es un stand-in de un VAE/difusión (que APRENDERÍA
ese decodificador de un dataset). Aquí el decodificador está hecho a mano, pero
el resto del pipeline (muestrear latentes -> rasterizar -> glyphopt) es idéntico
al que usaría un modelo entrenado. Produce glifos más ORGÁNICOS (curvos) que la
versión geométrica de líneas rectas.

    python scripts/glyph_generative.py
"""

import math
import random
import struct
import zlib

import quipu  # glyphopt de Rust (select_separable, glyph_min_distance)

SIZE = 16
LATENT_DIM = 12
N_CANDIDATES = 1500
K_SELECT = 94


# ------------------------- decodificador latente -> glifo -------------------------
def cubic_bezier(p, t):
    mt = 1 - t
    x = (mt**3 * p[0][0] + 3 * mt**2 * t * p[1][0]
         + 3 * mt * t**2 * p[2][0] + t**3 * p[3][0])
    y = (mt**3 * p[0][1] + 3 * mt**2 * t * p[1][1]
         + 3 * mt * t**2 * p[2][1] + t**3 * p[3][1])
    return x, y


def draw_bezier(g, pts, steps=48):
    for i in range(steps + 1):
        x, y = cubic_bezier(pts, i / steps)
        xi, yi = int(round(x)), int(round(y))
        if 0 <= xi < SIZE and 0 <= yi < SIZE:
            g[yi][xi] = 1


def decode(z):
    """Decodifica un vector latente z en un bitmap 16x16 (curvas suaves)."""
    g = [[0] * SIZE for _ in range(SIZE)]
    nstrokes = 2 + (1 if z[0] > 0 else 0)
    for k in range(nstrokes):
        pts = []
        for j in range(4):
            a = z[(k * 3 + j) % LATENT_DIM]
            b = z[(k * 3 + j + 5) % LATENT_DIM]
            x = 8 + 5.5 * math.sin(math.pi * a + 0.8 * j + k)
            y = 8 + 5.5 * math.cos(math.pi * b + 0.6 * j + 1.3 * k)
            pts.append((x, y))
        draw_bezier(g, pts)
    return g


def fingerprint(g):
    bits = [g[y][x] for y in range(SIZE) for x in range(SIZE)]
    out = bytearray()
    for i in range(0, SIZE * SIZE, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)
    return bytes(out)


def sample_candidates():
    random.seed(7)
    cands = {}
    attempts = 0
    while len(cands) < N_CANDIDATES and attempts < N_CANDIDATES * 20:
        attempts += 1
        z = [random.uniform(-1, 1) for _ in range(LATENT_DIM)]
        g = decode(z)
        filled = sum(sum(r) for r in g)
        if filled < 8 or filled > 110:
            continue
        fp = fingerprint(g)
        if fp not in cands:
            cands[fp] = g
    return list(cands.keys()), list(cands.values())


# ------------------------- salida -------------------------
def write_png(path, width, height, pixels):
    def chunk(typ, data):
        body = typ + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        raw.extend(pixels[y * width:(y + 1) * width])
    idat = zlib.compress(bytes(raw), 9)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(chunk(b"IHDR", ihdr))
        f.write(chunk(b"IDAT", idat))
        f.write(chunk(b"IEND", b""))


def sheet_png(path, grids, cols=10):
    pad = 1
    cell = SIZE + 2 * pad
    rows = (len(grids) + cols - 1) // cols
    W, H = cols * cell, rows * cell
    px = bytearray([255]) * (W * H)
    for idx, g in enumerate(grids):
        gx = (idx % cols) * cell + pad
        gy = (idx // cols) * cell + pad
        for y in range(SIZE):
            for x in range(SIZE):
                if g[y][x]:
                    px[(gy + y) * W + (gx + x)] = 0
    write_png(path, W, H, px)
    return W, H


def ascii_row(grids):
    lines = []
    for y in range(SIZE):
        parts = ["".join("#" if g[y][x] else " " for x in range(SIZE)) for g in grids]
        lines.append("  ".join(parts))
    return "\n".join(lines)


def main():
    fps, grids = sample_candidates()
    print(f"Glifos muestreados del espacio latente (únicos): {len(fps)}")

    idx = quipu.select_separable(fps, K_SELECT)
    sel_fps = [fps[i] for i in idx]
    sel_grids = [grids[i] for i in idx]

    baseline = quipu.glyph_min_distance(fps[:K_SELECT])
    optimized = quipu.glyph_min_distance(sel_fps)
    print(f"Alfabeto generativo: {len(sel_fps)} glifos curvos (orgánicos)")
    print(f"Distancia mínima  -  sin optimizar: {baseline}  |  optimizada: {optimized}")
    print(f"Mejora de separabilidad: x{optimized / max(baseline, 1):.1f}\n")

    print("Muestra (8 glifos generativos, lado a lado):\n")
    print(ascii_row(sel_grids[:8]))

    out = "/mnt/data/decod/glyph_generative.png"
    w, h = sheet_png(out, sel_grids)
    print(f"\nAlfabeto generativo ({len(sel_grids)} glifos): {out} ({w}x{h})")
    print("\nNOTA: el decodificador latente está hecho a mano. Un VAE/difusión")
    print("ENTRENADO reemplazaría `decode(z)` aprendiéndolo de datos; el resto")
    print("del pipeline (muestrear -> glyphopt -> font) no cambia.")


if __name__ == "__main__":
    main()
