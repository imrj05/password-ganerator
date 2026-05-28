// WebAuthn helpers for platform authenticator re-auth
// Stores credential ID in chrome.storage.local and keeps a short in-memory auth window

const WA_KEYS = {
  CRED_ID: 'webauthn_platform_cred_id',
}

let lastAuthAt = 0
const AUTH_WINDOW_MS = 60_000 // 60 seconds

function toB64url(buf) {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)))
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function fromB64url(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b64url.length + 3) % 4)
  const bin = atob(b64)
  const arr = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i)
  return arr.buffer
}

export async function getCredentialId() {
  return new Promise((resolve) => {
    try { chrome.storage.local.get([WA_KEYS.CRED_ID], (res) => resolve(res[WA_KEYS.CRED_ID] || null)) } catch { resolve(null) }
  })
}

export async function setCredentialId(idB64url) {
  return new Promise((resolve) => {
    try { chrome.storage.local.set({ [WA_KEYS.CRED_ID]: idB64url }, resolve) } catch { resolve() }
  })
}

export function isAuthWindowValid() {
  return Date.now() - lastAuthAt < AUTH_WINDOW_MS
}

export function markAuthWindow() {
  lastAuthAt = Date.now()
}

export function clearAuthWindow() {
  lastAuthAt = 0
}

export async function enrollPlatformCredential() {
  if (!('credentials' in navigator)) throw new Error('WebAuthn not supported')
  const userId = crypto.getRandomValues(new Uint8Array(16))
  const publicKey = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: 'SecurePass Generator' },
    user: { id: userId, name: 'user@local', displayName: 'SecurePass User' },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },   // ES256
      { type: 'public-key', alg: -257 }  // RS256
    ],
    authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' },
    timeout: 60000,
  }
  const cred = await navigator.credentials.create({ publicKey })
  const idB64url = toB64url(cred.rawId)
  await setCredentialId(idB64url)
  return idB64url
}

export async function verifyPlatformCredential() {
  if (!('credentials' in navigator)) return false
  const id = await getCredentialId()
  if (!id) return false
  const allowCredentials = [{ id: fromB64url(id), type: 'public-key' }]
  const publicKey = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials,
    userVerification: 'required',
    timeout: 60000,
  }
  try {
    const assertion = await navigator.credentials.get({ publicKey })
    if (assertion && assertion.response && assertion.rawId) {
      markAuthWindow()
      return true
    }
  } catch (e) {
    return false
  }
  return false
}

export default {
  getCredentialId, setCredentialId,
  enrollPlatformCredential, verifyPlatformCredential,
  isAuthWindowValid, markAuthWindow, clearAuthWindow,
}

