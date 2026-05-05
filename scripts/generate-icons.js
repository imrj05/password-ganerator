#!/usr/bin/env node
/**
 * Generates PNG icon files for the extension at 16, 32, 48, and 128 px.
 * The icon is a dark rounded square with a bold white "P" — no external deps,
 * only Node built-ins (zlib, fs, path).
 */

import zlib from 'zlib'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const OUT_DIR = path.join(__dirname, '..', 'icons')

// ── PNG helpers ────────────────────────────────────────────────────────────
function crc32(buf) {
  const table = crc32.table || (crc32.table = (() => {
    const t = new Uint32Array(256)
    for (let i = 0; i < 256; i++) {
      let c = i
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1)
      t[i] = c
    }
    return t
  })())
  let crc = 0xffffffff
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

function chunk(type, data) {
  const typeBytes = Buffer.from(type, 'ascii')
  const len = Buffer.alloc(4)
  len.writeUInt32BE(data.length, 0)
  const crcInput = Buffer.concat([typeBytes, data])
  const crcBuf = Buffer.alloc(4)
  crcBuf.writeUInt32BE(crc32(crcInput), 0)
  return Buffer.concat([len, typeBytes, data, crcBuf])
}

function encodePNG(width, height, pixels /* Uint8Array RGBA flat */) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])

  // IHDR
  const ihdrData = Buffer.alloc(13)
  ihdrData.writeUInt32BE(width, 0)
  ihdrData.writeUInt32BE(height, 4)
  ihdrData[8] = 8   // bit depth
  ihdrData[9] = 2   // color type: RGB  (we'll use RGBA → type 6)
  ihdrData[9] = 6   // RGBA
  ihdrData[10] = 0  // compression
  ihdrData[11] = 0  // filter
  ihdrData[12] = 0  // interlace
  const ihdr = chunk('IHDR', ihdrData)

  // Raw image data: filter byte (0) + RGBA per row
  const rowSize = width * 4
  const raw = Buffer.alloc((1 + rowSize) * height)
  for (let y = 0; y < height; y++) {
    raw[y * (rowSize + 1)] = 0 // filter type None
    for (let x = 0; x < width; x++) {
      const src = (y * width + x) * 4
      const dst = y * (rowSize + 1) + 1 + x * 4
      raw[dst]     = pixels[src]
      raw[dst + 1] = pixels[src + 1]
      raw[dst + 2] = pixels[src + 2]
      raw[dst + 3] = pixels[src + 3]
    }
  }

  const compressed = zlib.deflateSync(raw, { level: 9 })
  const idat = chunk('IDAT', compressed)
  const iend = chunk('IEND', Buffer.alloc(0))

  return Buffer.concat([signature, ihdr, idat, iend])
}

// ── Drawing primitives ─────────────────────────────────────────────────────
function createCanvas(w, h) {
  const pixels = new Uint8Array(w * h * 4) // all transparent
  const set = (x, y, r, g, b, a) => {
    if (x < 0 || x >= w || y < 0 || y >= h) return
    const i = (y * w + x) * 4
    // simple alpha blending over existing
    const srcA = a / 255
    const dstA = pixels[i + 3] / 255
    const outA = srcA + dstA * (1 - srcA)
    if (outA === 0) return
    pixels[i]     = Math.round((r * srcA + pixels[i]     * dstA * (1 - srcA)) / outA)
    pixels[i + 1] = Math.round((g * srcA + pixels[i + 1] * dstA * (1 - srcA)) / outA)
    pixels[i + 2] = Math.round((b * srcA + pixels[i + 2] * dstA * (1 - srcA)) / outA)
    pixels[i + 3] = Math.round(outA * 255)
  }
  return { w, h, pixels, set }
}

/** Anti-aliased filled circle */
function fillCircleAA(ctx, cx, cy, r, R, G, B, A) {
  const { set } = ctx
  const r2 = r * r
  for (let y = Math.floor(cy - r) - 1; y <= Math.ceil(cy + r) + 1; y++) {
    for (let x = Math.floor(cx - r) - 1; x <= Math.ceil(cx + r) + 1; x++) {
      const dx = x - cx, dy = y - cy
      const dist = Math.sqrt(dx * dx + dy * dy)
      const alpha = Math.max(0, Math.min(1, r - dist + 0.5))
      if (alpha > 0) set(x, y, R, G, B, Math.round(A * alpha))
    }
  }
}

/** Filled rectangle with AA at corners */
function fillRect(ctx, x, y, w, h, R, G, B, A) {
  for (let py = y; py < y + h; py++)
    for (let px = x; px < x + w; px++)
      ctx.set(px, py, R, G, B, A)
}

/** Rounded rectangle (filled, AA) */
function fillRoundRect(ctx, x, y, w, h, r, R, G, B, A) {
  // fill body minus corners
  fillRect(ctx, x + r, y, w - 2 * r, h, R, G, B, A)
  fillRect(ctx, x, y + r, r, h - 2 * r, R, G, B, A)
  fillRect(ctx, x + w - r, y + r, r, h - 2 * r, R, G, B, A)
  // four corner arcs
  const corners = [
    [x + r,     y + r],
    [x + w - r, y + r],
    [x + r,     y + h - r],
    [x + w - r, y + h - r],
  ]
  for (const [cx, cy] of corners) {
    // only paint the quadrant
    for (let py = cy - r - 1; py <= cy + r + 1; py++) {
      for (let px = cx - r - 1; px <= cx + r + 1; px++) {
        if (px < x || px >= x + w || py < y || py >= y + h) continue
        const dx = px - cx, dy = py - cy
        const dist = Math.sqrt(dx * dx + dy * dy)
        const alpha = Math.max(0, Math.min(1, r - dist + 0.5))
        if (alpha > 0) ctx.set(px, py, R, G, B, Math.round(A * alpha))
      }
    }
  }
}

// ── "P" glyph renderer ─────────────────────────────────────────────────────
/**
 * Draws a bold geometric "P" into the canvas.
 * All measurements are relative to the canvas size.
 *
 * Strategy:
 *   1. Vertical stem: a thick rounded rectangle on the left side.
 *   2. Bowl: a filled half-circle on the right side of the top half.
 *   3. Subtract the inner hollow of the bowl with the background colour.
 */
function drawP(ctx, size) {
  const S = size
  // colour palette
  const BG  = [22,  22,  26,  255]  // near-black #16161a
  const FG  = [255, 255, 255, 255]  // white

  // background rounded square
  const radius = Math.round(S * 0.18)
  fillRoundRect(ctx, 0, 0, S, S, radius, ...BG)

  // --- Glyph geometry (tuned for visual balance) ---
  const padL  = Math.round(S * 0.22)   // left edge of stem
  const padT  = Math.round(S * 0.15)   // top of P
  const padB  = Math.round(S * 0.15)   // bottom of P
  const stemW = Math.round(S * 0.18)   // width of vertical stem
  const glyphH = S - padT - padB

  // Outer bowl: semicircle centred on the right of the top half
  const bowlCY  = padT + Math.round(glyphH * 0.30)
  const bowlR   = Math.round(glyphH * 0.295)
  const bowlCX  = padL + stemW          // centre X at stem right edge

  // 1. Draw full outer bowl (solid white circle, right half)
  for (let py = padT; py <= bowlCY + bowlR + 1; py++) {
    for (let px = bowlCX; px <= bowlCX + bowlR + 1; px++) {
      const dx = px - bowlCX, dy = py - bowlCY
      const dist = Math.sqrt(dx * dx + dy * dy)
      const alpha = Math.max(0, Math.min(1, bowlR - dist + 0.5))
      if (alpha > 0) ctx.set(px, py, ...FG.slice(0, 3), Math.round(255 * alpha))
    }
  }

  // 2. Fill the rectangle bridging stem to bowl centre (top chunk)
  fillRect(ctx, padL, padT, stemW + 1, bowlR * 2 + 1, ...FG)

  // 3. Hollow: inner bowl (background colour)
  const holeR  = Math.round(bowlR * 0.52)
  for (let py = padT; py <= bowlCY + bowlR + 1; py++) {
    for (let px = bowlCX; px <= bowlCX + bowlR + 1; px++) {
      const dx = px - bowlCX, dy = py - bowlCY
      const dist = Math.sqrt(dx * dx + dy * dy)
      const alpha = Math.max(0, Math.min(1, holeR - dist + 0.5))
      if (alpha > 0) ctx.set(px, py, ...BG.slice(0, 3), Math.round(255 * alpha))
    }
  }

  // 4. Vertical stem (drawn last so it's always solid)
  const stemR = Math.round(stemW * 0.5)
  fillRoundRect(ctx, padL, padT, stemW, glyphH, stemR, ...FG)
}

// ── Main ───────────────────────────────────────────────────────────────────
const SIZES = [16, 32, 48, 128]

fs.mkdirSync(OUT_DIR, { recursive: true })

for (const size of SIZES) {
  const ctx = createCanvas(size, size)
  drawP(ctx, size)
  const png = encodePNG(size, size, ctx.pixels)
  const outPath = path.join(OUT_DIR, `icon${size}.png`)
  fs.writeFileSync(outPath, png)
  console.log(`✓ ${outPath}  (${png.length} bytes)`)
}

console.log('\nAll icons generated.')
