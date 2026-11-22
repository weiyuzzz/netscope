// 生成 NetScope 图标源图（1024x1024 RGBA PNG）。
// 仅使用 Node 内置 zlib，无第三方依赖。生成后由 `pnpm tauri icon` 产出全套平台图标。
import { deflateSync } from 'node:zlib'
import { writeFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const SIZE = 1024

// ---- 调色板（与前端深色主题一致）----
const BG = [11, 18, 32, 255] // #0B1220 深夜蓝
const RING_OUT = [34, 211, 238, 255] // #22D3EE 青
const RING_MID = [59, 130, 246, 255] // #3B82F6 蓝
const NODE = [167, 139, 250, 255] // #A78BFA 紫
const CORE = [34, 211, 238, 255] // 中心节点

const cx = SIZE / 2
const cy = SIZE / 2

// 外环与中环之间的 6 个拓扑节点（圆周均布，顶部起始）
const dots = Array.from({ length: 6 }, (_, i) => {
  const a = (Math.PI * 2 * i) / 6 - Math.PI / 2
  return [cx + Math.cos(a) * 375, cy + Math.sin(a) * 375]
})

function px(x, y) {
  const d = Math.hypot(x - cx, y - cy)
  if (Math.abs(d - 445) <= 32) return RING_OUT
  if (Math.abs(d - 290) <= 16) return RING_MID
  if (d <= 56) return CORE
  for (const [dx, dy] of dots) {
    if (Math.hypot(x - dx, y - dy) <= 44) return NODE
  }
  return BG
}

// ---- PNG 编码（CRC32 + zlib deflate）----
const crcTable = (() => {
  const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    t[n] = c >>> 0
  }
  return t
})()

function crc32(buf) {
  let c = 0xffffffff
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

function chunk(type, data) {
  const len = Buffer.alloc(4)
  len.writeUInt32BE(data.length)
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data])
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(crc32(body))
  return Buffer.concat([len, body, crc])
}

// 每行扫描线前加 1 字节 filter（0 = none）
const raw = Buffer.alloc(SIZE * (SIZE * 4 + 1))
let o = 0
for (let y = 0; y < SIZE; y++) {
  raw[o++] = 0
  for (let x = 0; x < SIZE; x++) {
    const [r, g, b, a] = px(x, y)
    raw[o++] = r
    raw[o++] = g
    raw[o++] = b
    raw[o++] = a
  }
}

const ihdr = Buffer.alloc(13)
ihdr.writeUInt32BE(SIZE, 0)
ihdr.writeUInt32BE(SIZE, 4)
ihdr[8] = 8 // bit depth
ihdr[9] = 6 // color type: RGBA

const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
])

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
mkdirSync(join(root, 'assets'), { recursive: true })
mkdirSync(join(root, 'public'), { recursive: true })
writeFileSync(join(root, 'assets', 'icon-source.png'), png)
writeFileSync(join(root, 'public', 'icon.png'), png)
console.log('icon generated:', join(root, 'assets', 'icon-source.png'))
