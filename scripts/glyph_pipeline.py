#!/usr/bin/env python3
"""Pipeline de generación de glifos para Quipu (sin dependencias externas).

Genera glifos candidatos por combinación de primitivas geométricas, calcula su
huella (bitmap 16x16 -> 32 bytes), y usa el glyphopt REAL de Rust (vía el módulo
`quipu`) para seleccionar el subconjunto más separable. Renderiza una muestra en
ASCII y escribe una hoja PNG con todos los glifos elegidos.

    python scripts/glyph_pipeline.py
"""

import random
import struct
import zlib

import quipu  # binding Rust (glyphopt)

SIZE = 16          # lado del glifo en píxeles
ANCHORS = [(x, y) for x in (2, 6, 9, 13) for y in (2, 6, 9, 13)]
N_CANDIDATES = 1500
K_SELECT = 94      # = nº de símbolos ASCII imprimibles (mapeo 1:1 con quipu.encode)


# ----------------------------- rasterización -----------------------------
def new_grid():
    return [[0] * SIZE for _ in range(SIZE)]


def draw_line(g, x0, y0, x1, y1):
    dx, dy = abs(x1 - x0), -abs(y1 - y0)
    sx = 1 if x0 < x1 else -1
    sy = 1 if y0 < y1 else -1
    err = dx + dy
    while True:
        if 0 <= x0 < SIZE and 0 <= y0 < SIZE:
            g[y0][x0] = 1
        if x0 == x1 and y0 == y1:
            break
        e2 = 2 * err
        if e2 >= dy:
            err += dy
            x0 += sx
        if e2 <= dx:
            err += dx
            y0 += sy


def draw_circle(g, cx, cy, r):
    x, y, err = r, 0, 0
    while x >= y:
        for px, py in [
            (cx + x, cy + y), (cx + y, cy + x), (cx - y, cy + x), (cx - x, cy + y),
            (cx - x, cy - y), (cx - y, cy - x), (cx + y, cy - x), (cx + x, cy - y),
        ]:
            if 0 <= px < SIZE and 0 <= py < SIZE:
                g[py][px] = 1
        y += 1
        err += 1 + 2 * y
        if 2 * (err - x) + 1 > 0:
            x -= 1
            err += 1 - 2 * x


def fingerprint(g):
    """Empaqueta el bitmap 16x16 (256 bits) en 32 bytes."""
    bits = [g[y][x] for y in range(SIZE) for x in range(SIZE)]
    out = bytearray()
    for i in range(0, SIZE * SIZE, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)
    return bytes(out)


# ----------------------------- generación -----------------------------
def generate_candidates():
    random.seed(42)  # determinista
    cands = {}
    attempts = 0
    while len(cands) < N_CANDIDATES and attempts < N_CANDIDATES * 20:
        attempts += 1
        g = new_grid()
        for _ in range(random.randint(2, 4)):
            a, b = random.sample(ANCHORS, 2)
            draw_line(g, a[0], a[1], b[0], b[1])
        if random.random() < 0.4:
            draw_circle(g, random.choice([7, 8]), random.choice([7, 8]),
                        random.choice([3, 4, 5]))
        filled = sum(sum(r) for r in g)
        if filled < 6 or filled > 120:  # ni vacío ni saturado
            continue
        fp = fingerprint(g)
        if fp not in cands:
            cands[fp] = g
    return list(cands.keys()), list(cands.values())


# ----------------------------- salida -----------------------------
def ascii_row(grids):
    """Renderiza una fila de glifos lado a lado en ASCII."""
    lines = []
    for y in range(SIZE):
        parts = ["".join("#" if g[y][x] else " " for x in range(SIZE)) for g in grids]
        lines.append("  ".join(parts))
    return "\n".join(lines)


def write_png(path, width, height, pixels):
    """Escribe un PNG en escala de grises (8 bits), solo con la stdlib."""
    def chunk(typ, data):
        body = typ + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filtro None por scanline
        raw.extend(pixels[y * width:(y + 1) * width])
    idat = zlib.compress(bytes(raw), 9)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(chunk(b"IHDR", ihdr))
        f.write(chunk(b"IDAT", idat))
        f.write(chunk(b"IEND", b""))


def grid_sheet_png(path, grids, cols=8):
    pad = 1
    cell = SIZE + 2 * pad
    rows = (len(grids) + cols - 1) // cols
    W, H = cols * cell, rows * cell
    px = bytearray([255]) * (W * H)  # fondo blanco
    for idx, g in enumerate(grids):
        gx = (idx % cols) * cell + pad
        gy = (idx // cols) * cell + pad
        for y in range(SIZE):
            for x in range(SIZE):
                if g[y][x]:
                    px[(gy + y) * W + (gx + x)] = 0  # trazo negro
    write_png(path, W, H, px)
    return W, H


# ----------------------------- main -----------------------------
def render_message_png(path, sel_grids, symbols, cols=24):
    """Pinta un mensaje cifrado (cadena de símbolos ASCII) como glifos."""
    pad = 1
    cell = SIZE + 2 * pad
    n = len(symbols)
    rows = (n + cols - 1) // cols
    W, H = cols * cell, rows * cell
    px = bytearray([255]) * (W * H)
    for i, ch in enumerate(symbols):
        gi = ord(ch) - 0x21          # mapeo símbolo ASCII -> índice de glifo
        if gi < 0 or gi >= len(sel_grids):
            continue
        g = sel_grids[gi]
        gx = (i % cols) * cell + pad
        gy = (i // cols) * cell + pad
        for y in range(SIZE):
            for x in range(SIZE):
                if g[y][x]:
                    px[(gy + y) * W + (gx + x)] = 0
    write_png(path, W, H, px)
    return W, H


def main():
    fps, grids = generate_candidates()
    print(f"Glifos candidatos generados (únicos): {len(fps)}")

    idx = quipu.select_separable(fps, K_SELECT)
    sel_fps = [fps[i] for i in idx]
    sel_grids = [grids[i] for i in idx]

    baseline = quipu.glyph_min_distance(fps[:K_SELECT])   # primeros K (sin optimizar)
    optimized = quipu.glyph_min_distance(sel_fps)          # los K elegidos
    print(f"Alfabeto seleccionado: {len(sel_fps)} glifos (= símbolos ASCII)")
    print(f"Distancia mínima  -  sin optimizar: {baseline} bits  |  optimizada: {optimized} bits")
    print(f"Mejora de separabilidad: x{optimized / max(baseline,1):.1f}\n")

    print("Muestra (8 glifos del alfabeto, lado a lado):\n")
    print(ascii_row(sel_grids[:8]))

    sheet = "/mnt/data/decod/glyph_alphabet.png"
    w, h = grid_sheet_png(sheet, sel_grids, cols=10)
    print(f"\nAlfabeto completo ({len(sel_grids)} glifos): {sheet} ({w}x{h})")

    # --- Cierre del círculo: cifrar un mensaje y pintarlo con estos glifos ---
    secreto = b"Mensaje secreto pintado con glifos propios generados por IA."
    symbols = quipu.encode(secreto, "mi-passphrase")   # cifrado real (base-94)
    # Verifica que descifra:
    assert quipu.decode(symbols, "mi-passphrase") == secreto
    msg_png = "/mnt/data/decod/secreto_en_glifos.png"
    w2, h2 = render_message_png(msg_png, sel_grids, symbols)
    print(f"\nMensaje cifrado ({len(symbols)} glifos) pintado en: {msg_png} ({w2}x{h2})")
    print("(cada glifo = un símbolo del texto cifrado; round-trip verificado OK)")


if __name__ == "__main__":
    main()
