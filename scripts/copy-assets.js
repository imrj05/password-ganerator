import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const root = process.cwd()
const dist = path.join(root, 'dist')

function copyFile(src, dest) {
  fs.mkdirSync(path.dirname(dest), { recursive: true })
  fs.copyFileSync(src, dest)
}

try {
  // Copy manifest
  const manifestSrc = path.join(root, 'manifest.json')
  const manifestDest = path.join(dist, 'manifest.json')
  if (fs.existsSync(manifestSrc)) copyFile(manifestSrc, manifestDest)



  // Copy contentScript.js
  const contentScriptSrc = path.join(root, 'contentScript.js')
  const contentScriptDest = path.join(dist, 'contentScript.js')
  if (fs.existsSync(contentScriptSrc)) copyFile(contentScriptSrc, contentScriptDest)

  // Copy icons folder if present
  const iconsSrc = path.join(root, 'icons')
  const iconsDest = path.join(dist, 'icons')
  if (fs.existsSync(iconsSrc)) {
    fs.mkdirSync(iconsDest, { recursive: true })
    const items = fs.readdirSync(iconsSrc)
    for (const item of items) {
      const s = path.join(iconsSrc, item)
      const d = path.join(iconsDest, item)
      copyFile(s, d)
    }
  }

  console.log('Assets copied to dist/')
} catch (err) {
  console.error('Failed to copy assets:', err)
  process.exit(1)
}
