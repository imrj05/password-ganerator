#!/usr/bin/env node
/**
 * process-logo.js
 *
 * 1. Reads icons/icon128.png
 * 2. Strips the cream/white background (flood-fill from corners → alpha = 0)
 * 3. Writes the transparent version back to icons/icon128.png
 * 4. Produces downscaled copies at 16, 32, 48 px (nearest-neighbour, then box filter)
 * 5. Prints the base64 data-URL of the 128 px transparent icon to stdout so the
 *    caller can embed it in contentScript.js
 *
 * Pure Node.js – only built-in modules (zlib, fs, path, url).
 */

import zlib from 'zlib'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ICONS_DIR = path.join(__dirname, '..', 'icons')

// ─── CRC32 ────────────────────────────────────────────────────────────────────
const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1)
    t[i] = c
  }
  return t
})()
function crc32(buf) {
  let crc = 0xffffffff
  for (let i = 0; i < buf.length; i++) crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

// ─── PNG chunk builder ────────────────────────────────────────────────────────
function buildChunk(type, data) {
  const tb = Buffer.from(type, 'ascii')
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0)
  const crcIn = Buffer.concat([tb, data])
  const crcBuf = Buffer.alloc(4); crcBuf.writeUInt32BE(crc32(crcIn), 0)
  return Buffer.concat([len, tb, data, crcBuf])
}

// ─── PNG encoder ──────────────────────────────────────────────────────────────
function encodePNG(w, h, rgba /* Uint8Array RGBA flat */) {
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])
  const ihdrData = Buffer.alloc(13)
  ihdrData.writeUInt32BE(w, 0); ihdrData.writeUInt32BE(h, 4)
  ihdrData[8] = 8; ihdrData[9] = 6 // 8-bit RGBA
  const rowSize = w * 4
  const raw = Buffer.alloc((1 + rowSize) * h)
  for (let y = 0; y < h; y++) {
    raw[y * (rowSize + 1)] = 0 // filter None
    for (let x = 0; x < w; x++) {
      const s = (y * w + x) * 4, d = y * (rowSize + 1) + 1 + x * 4
      raw[d] = rgba[s]; raw[d+1] = rgba[s+1]; raw[d+2] = rgba[s+2]; raw[d+3] = rgba[s+3]
    }
  }
  return Buffer.concat([
    sig,
    buildChunk('IHDR', ihdrData),
    buildChunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    buildChunk('IEND', Buffer.alloc(0)),
  ])
}

// ─── PNG decoder ──────────────────────────────────────────────────────────────
function decodePNG(buf) {
  // verify signature
  if (buf.readUInt32BE(0) !== 0x89504e47) throw new Error('Not a PNG')

  // parse chunks
  let pos = 8
  const chunks = {}
  const idatBuffers = []
  while (pos < buf.length) {
    const len = buf.readUInt32BE(pos); pos += 4
    const type = buf.toString('ascii', pos, pos + 4); pos += 4
    const data = buf.slice(pos, pos + len); pos += len
    pos += 4 // skip CRC
    if (type === 'IHDR') chunks.IHDR = data
    else if (type === 'IDAT') idatBuffers.push(data)
  }

  const ihdr = chunks.IHDR
  const w = ihdr.readUInt32BE(0)
  const h = ihdr.readUInt32BE(4)
  const bitDepth = ihdr[8]
  const colorType = ihdr[9]
  if (bitDepth !== 8) throw new Error(`Unsupported bit depth: ${bitDepth}`)
  // colorType: 2=RGB, 6=RGBA
  const hasAlpha = colorType === 6
  const channels = hasAlpha ? 4 : 3

  const compressed = Buffer.concat(idatBuffers)
  const raw = zlib.inflateSync(compressed)

  // reconstruct pixels with PNG filters
  const rowBytes = w * channels
  const pixels = new Uint8Array(w * h * 4) // always output RGBA
  let prev = new Uint8Array(rowBytes)

  for (let y = 0; y < h; y++) {
    const rowStart = y * (rowBytes + 1)
    const filter = raw[rowStart]
    const row = new Uint8Array(rowBytes)

    for (let i = 0; i < rowBytes; i++) {
      const x = raw[rowStart + 1 + i]
      const a = i >= channels ? row[i - channels] : 0
      const b = prev[i]
      const c = i >= channels ? prev[i - channels] : 0
      switch (filter) {
        case 0: row[i] = x; break
        case 1: row[i] = (x + a) & 0xff; break
        case 2: row[i] = (x + b) & 0xff; break
        case 3: row[i] = (x + Math.floor((a + b) / 2)) & 0xff; break
        case 4: {
          const p = a + b - c
          const pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c)
          row[i] = (x + (pa <= pb && pa <= pc ? a : pb <= pc ? b : c)) & 0xff
          break
        }
        default: throw new Error(`Unknown filter: ${filter}`)
      }
    }

    for (let x = 0; x < w; x++) {
      const src = x * channels
      const dst = (y * w + x) * 4
      pixels[dst]   = row[src]
      pixels[dst+1] = row[src+1]
      pixels[dst+2] = row[src+2]
      pixels[dst+3] = hasAlpha ? row[src+3] : 255
    }
    prev = row
  }

  return { w, h, pixels }
}

// ─── Background removal (flood-fill from corners) ─────────────────────────────
function removeBackground(pixels, w, h, tolerance = 30) {
  // Sample background colour from the four corners
  const corners = [
    pixels.slice(0, 4),
    pixels.slice((w - 1) * 4, w * 4),
    pixels.slice((h - 1) * w * 4, (h - 1) * w * 4 + 4),
    pixels.slice(((h - 1) * w + w - 1) * 4, ((h - 1) * w + w - 1) * 4 + 4),
  ]
  // average of the four corners
  const bgR = Math.round(corners.reduce((s, c) => s + c[0], 0) / 4)
  const bgG = Math.round(corners.reduce((s, c) => s + c[1], 0) / 4)
  const bgB = Math.round(corners.reduce((s, c) => s + c[2], 0) / 4)

  const result = new Uint8Array(pixels)
  const visited = new Uint8Array(w * h)

  function colorDist(i) {
    const dr = result[i] - bgR, dg = result[i+1] - bgG, db = result[i+2] - bgB
    return Math.sqrt(dr*dr + dg*dg + db*db)
  }

  // BFS flood fill from all four corners
  const queue = []
  const seedPoints = [
    0, w - 1, (h - 1) * w, h * w - 1
  ]
  for (const p of seedPoints) {
    if (!visited[p] && colorDist(p * 4) <= tolerance) {
      queue.push(p)
      visited[p] = 1
    }
  }

  while (queue.length) {
    const idx = queue.shift()
    result[idx * 4 + 3] = 0 // make transparent

    const x = idx % w, y = Math.floor(idx / w)
    const neighbors = []
    if (x > 0)     neighbors.push(idx - 1)
    if (x < w - 1) neighbors.push(idx + 1)
    if (y > 0)     neighbors.push(idx - w)
    if (y < h - 1) neighbors.push(idx + w)

    for (const n of neighbors) {
      if (!visited[n] && colorDist(n * 4) <= tolerance) {
        visited[n] = 1
        queue.push(n)
      }
    }
  }

  return result
}

// ─── Downscale (box filter average) ─────────────────────────────────────────
function downscale(src, srcW, srcH, dstW, dstH) {
  const dst = new Uint8Array(dstW * dstH * 4)
  const scaleX = srcW / dstW, scaleY = srcH / dstH

  for (let dy = 0; dy < dstH; dy++) {
    for (let dx = 0; dx < dstW; dx++) {
      const x0 = dx * scaleX, x1 = x0 + scaleX
      const y0 = dy * scaleY, y1 = y0 + scaleY
      let r = 0, g = 0, b = 0, a = 0, n = 0
      for (let sy = Math.floor(y0); sy < Math.ceil(y1) && sy < srcH; sy++) {
        for (let sx = Math.floor(x0); sx < Math.ceil(x1) && sx < srcW; sx++) {
          const i = (sy * srcW + sx) * 4
          r += src[i]; g += src[i+1]; b += src[i+2]; a += src[i+3]
          n++
        }
      }
      const di = (dy * dstW + dx) * 4
      dst[di] = r/n; dst[di+1] = g/n; dst[di+2] = b/n; dst[di+3] = a/n
    }
  }
  return dst
}

// ─── Main ─────────────────────────────────────────────────────────────────────
const srcPath = path.join(ICONS_DIR, 'icon128.png')
const raw128 = fs.readFileSync(srcPath)

const { w, h, pixels } = decodePNG(raw128)
console.error(`Decoded ${srcPath}: ${w}×${h}`)

const transparent = removeBackground(pixels, w, h, 35)

// Write 128 px transparent version
const png128 = encodePNG(w, h, transparent)
fs.writeFileSync(srcPath, png128)
console.error(`✓ icons/icon128.png  (transparent, ${png128.length} bytes)`)

// Write smaller sizes
for (const size of [16, 32, 48]) {
  const scaled = downscale(transparent, w, h, size, size)
  const png = encodePNG(size, size, scaled)
  const p = path.join(ICONS_DIR, `icon${size}.png`)
  fs.writeFileSync(p, png)
  console.error(`✓ icons/icon${size}.png  (${png.length} bytes)`)
}

// Output base64 data-URL of the 128 px icon to stdout
const b64 = png128.toString('base64')
process.stdout.write(`data:image/png;base64,${b64}`)
