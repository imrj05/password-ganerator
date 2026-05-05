// Content script for SecurePass Generator
// Provides in-page password suggestions plus a lightweight local credential vault flow.
const extensionChrome = typeof chrome !== 'undefined' ? chrome : null
const DEFAULT_PASSWORD_OPTIONS = {
  length: 20,
  includeUppercase: true,
  includeLowercase: true,
  includeNumbers: true,
  includeSymbols: true,
  symbolSet: 'basic',
  customSymbols: '',
  excludeAmbiguous: false,
  ensureComplexity: true
}
const STORAGE_KEYS = {
  PASSWORD_HISTORY: 'passwordHistory',
  HISTORY_ENABLED: 'historyEnabled',
  SAVED_CREDENTIALS: 'savedCredentials',
  CREDENTIALS_ENABLED: 'credentialsEnabled',
  CREDENTIAL_NEVER_SAVE_DOMAINS: 'credentialNeverSaveDomains',
  WRAPPING_JWK: 'crypto_wrapping_jwk_v1',
  PENDING_CREDENTIAL_PROMPT: 'pendingCredentialPrompt'
}
const SYMBOL_SETS = {
  basic: '!@#$%^&*',
  extended: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  safe: '!@#$%*+-=?'
}
const UI = {
  suggestionRoot: null,
  suggestionCard: null,
  passwordText: null,
  suggestionSubtitle: null,
  suggestionActions: null,
  triggerRoot: null,
  triggerButton: null,
  fillButton: null,
  copyButton: null,
  refreshButton: null,
  dismissButton: null,
  feedback: null,
  saveRoot: null,
  saveCard: null,
  saveMessage: null,
  saveDetails: null,
  saveButton: null,
  neverButton: null,
  laterButton: null
}
let activeField = null
let activePassword = ''
let feedbackTimer = null
let repositionFrame = null
let autoShowTimer = null
let observer = null
let activeCredential = null
let triggerField = null
let pendingSavePayload = null
let initialized = false
let generatedPasswordField = null
const dismissedFields = new WeakSet()
const submittedForms = new WeakMap()
const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder()
const PENDING_PROMPT_MAX_AGE_MS = 10 * 60 * 1000
const WA_KEYS = {
  CRED_ID: 'webauthn_platform_cred_id'
}
function toB64(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index])
  }
  return btoa(binary)
}
function fromB64(value) {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes.buffer
}
async function getStorageValue(key, fallback) {
  if (extensionChrome?.storage?.local) {
    try {
      const result = await extensionChrome.storage.local.get(key)
      if (result[key] !== undefined) {
        return result[key]
      }
    } catch (error) {
      // Fall through to localStorage fallback.
    }
  }
  try {
    const raw = localStorage.getItem(key)
    return raw === null ? fallback : JSON.parse(raw)
  } catch (error) {
    return fallback
  }
}
async function setStorageValue(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value))
  } catch (error) {
    // ignore localStorage failures
  }
  if (extensionChrome?.storage?.local) {
    try {
      await extensionChrome.storage.local.set({ [key]: value })
    } catch (error) {
      // ignore extension storage failures
    }
  }
}
function normalizeDomain(value = '') {
  if (!value) return ''
  try {
    return new URL(value).hostname.toLowerCase()
  } catch (error) {
    return String(value).trim().toLowerCase()
  }
}
function normalizeOrigin(value = '') {
  if (!value) return ''
  try {
    return new URL(value).origin.toLowerCase()
  } catch (error) {
    return ''
  }
}
function maskUsername(username = '') {
  const value = String(username).trim()
  if (!value) return 'Unknown account'
  const [localPart, domainPart] = value.split('@')
  if (domainPart) {
    const visible = localPart.slice(0, 2)
    return `${visible}${localPart.length > 2 ? '***' : '*'}@${domainPart}`
  }
  if (value.length <= 3) return `${value[0] || ''}**`
  return `${value.slice(0, 2)}***${value.slice(-1)}`
}
async function getOrCreateWrappingKey() {
  const jwk = await getStorageValue(STORAGE_KEYS.WRAPPING_JWK, null)
  if (jwk) {
    try {
      return await crypto.subtle.importKey('jwk', jwk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
    } catch (error) {
      // Regenerate on invalid key material.
    }
  }
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
  const exported = await crypto.subtle.exportKey('jwk', key)
  await setStorageValue(STORAGE_KEYS.WRAPPING_JWK, exported)
  return key
}
async function encryptText(plaintext) {
  const key = await getOrCreateWrappingKey()
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, textEncoder.encode(plaintext))
  return { ivB64: toB64(iv), ctB64: toB64(ciphertext) }
}
function toB64url(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let index = 0; index < bytes.length; index += 1) {
    binary += String.fromCharCode(bytes[index])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function fromB64url(value) {
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4)
  return fromB64(b64)
}
async function getCredentialId() {
  return getStorageValue(WA_KEYS.CRED_ID, null)
}
async function setCredentialId(value) {
  await setStorageValue(WA_KEYS.CRED_ID, value)
}
async function enrollPlatformCredential() {
  if (!navigator.credentials) return false
  const userId = crypto.getRandomValues(new Uint8Array(16))
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: 'SecurePass Generator' },
      user: { id: userId, name: 'user@local', displayName: 'SecurePass User' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required' },
      timeout: 60000,
    }
  })
  if (!credential?.rawId) return false
  await setCredentialId(toB64url(credential.rawId))
  return true
}
async function ensureCredentialVerification() {
  if (!navigator.credentials) return true
  const credentialId = await getCredentialId()
  if (!credentialId) {
    const enrolled = await enrollPlatformCredential().catch(() => false)
    if (!enrolled) return false
  }
  const savedCredentialId = await getCredentialId()
  if (!savedCredentialId) return false
  try {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ id: fromB64url(savedCredentialId), type: 'public-key' }],
        userVerification: 'required',
        timeout: 60000,
      }
    })
    return !!(assertion && assertion.rawId)
  } catch (error) {
    return false
  }
}
async function decryptText(enc) {
  if (!enc?.ivB64 || !enc?.ctB64) return ''
  const key = await getOrCreateWrappingKey()
  const iv = new Uint8Array(fromB64(enc.ivB64))
  const ciphertext = fromB64(enc.ctB64)
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext)
  return textDecoder.decode(plaintext)
}
function getSecureRandomInt(max) {
  if (!Number.isInteger(max) || max <= 0) {
    throw new Error('Invalid max value for secure random integer')
  }
  const randomValues = new Uint32Array(1)
  const limit = Math.floor(0x100000000 / max) * max
  while (true) {
    crypto.getRandomValues(randomValues)
    const value = randomValues[0]
    if (value < limit) {
      return value % max
    }
  }
}
function getSymbolChars(symbolSet, customSymbols) {
  if (symbolSet === 'custom') {
    return customSymbols || SYMBOL_SETS.basic
  }
  return SYMBOL_SETS[symbolSet] || SYMBOL_SETS.basic
}
function buildCharset(options) {
  let charset = ''
  if (options.includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  if (options.includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz'
  if (options.includeNumbers) charset += '0123456789'
  if (options.includeSymbols) charset += getSymbolChars(options.symbolSet, options.customSymbols)
  if (!charset) charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
  return charset
}
function generatePassword(options = DEFAULT_PASSWORD_OPTIONS) {
  const charset = buildCharset(options)
  const requiredSets = []
  if (options.includeUppercase) requiredSets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
  if (options.includeLowercase) requiredSets.push('abcdefghijklmnopqrstuvwxyz')
  if (options.includeNumbers) requiredSets.push('0123456789')
  if (options.includeSymbols) requiredSets.push(getSymbolChars(options.symbolSet, options.customSymbols))
  const passwordChars = []
  requiredSets.forEach(set => {
    passwordChars.push(set[getSecureRandomInt(set.length)])
  })
  while (passwordChars.length < options.length) {
    passwordChars.push(charset[getSecureRandomInt(charset.length)])
  }
  for (let index = passwordChars.length - 1; index > 0; index -= 1) {
    const swapIndex = getSecureRandomInt(index + 1)
    const temp = passwordChars[index]
    passwordChars[index] = passwordChars[swapIndex]
    passwordChars[swapIndex] = temp
  }
  return passwordChars.join('')
}
function isVisibleField(field) {
  if (!field || !(field instanceof HTMLInputElement)) return false
  if (field.disabled || field.readOnly || field.type === 'hidden') return false
  if (field.hidden || field.closest('[hidden]')) return false
  const style = window.getComputedStyle(field)
  if (style.display === 'none' || style.visibility === 'hidden') return false
  const clientRects = typeof field.getClientRects === 'function' ? field.getClientRects().length : 0
  return clientRects > 0 || field.isConnected
}
function isPasswordField(field) {
  if (!isVisibleField(field)) return false
  const attrText = [
    field.type,
    field.autocomplete,
    field.name,
    field.id,
    field.className,
    field.placeholder,
    field.getAttribute('aria-label') || ''
  ].join(' ').toLowerCase()
  return field.type === 'password' || attrText.includes('password')
}
function isUsernameField(field) {
  if (!isVisibleField(field)) return false
  if (field.type === 'password') return false
  const type = (field.type || '').toLowerCase()
  if (['email', 'text', 'tel', 'search', 'url'].includes(type)) {
    const attrText = [
      field.autocomplete,
      field.name,
      field.id,
      field.className,
      field.placeholder,
      field.getAttribute('aria-label') || ''
    ].join(' ').toLowerCase()
    return (
      type === 'email' ||
      attrText.includes('user') ||
      attrText.includes('email') ||
      attrText.includes('login') ||
      attrText.includes('account') ||
      attrText.includes('phone')
    )
  }
  return false
}
function isEligibleSuggestionField(field) {
  return isPasswordField(field) && !field.value && !dismissedFields.has(field)
}
function isEligibleTriggerField(field) {
  return isPasswordField(field) && !field.value
}
function getPasswordFields(root = document) {
  return Array.from(root.querySelectorAll('input')).filter(isPasswordField)
}
function getEligibleSuggestionFields(root = document) {
  return getPasswordFields(root).filter(isEligibleSuggestionField)
}
function getUsernameFields(root = document) {
  return Array.from(root.querySelectorAll('input')).filter(isUsernameField)
}
function getFieldIdentifier(field) {
  return field.name || field.id || field.autocomplete || field.placeholder || field.type || 'field'
}
function getFieldDescription(field) {
  const label = field?.labels?.[0]?.textContent?.trim()
  if (label) return label
  if (field?.placeholder) return field.placeholder
  if (field?.name) return field.name
  if (field?.id) return field.id
  return 'password field'
}
function getSameFormTargets(field) {
  if (!field) return []
  const form = field.form
  const source = form || document
  const fields = getPasswordFields(source)
  const targets = fields.filter(candidate => {
    if (!isVisibleField(candidate)) return false
    if (candidate.disabled || candidate.readOnly) return false
    if (candidate === field) return true
    return !candidate.value
  })
  return targets.includes(field) ? targets : [field, ...targets]
}
function setNativeValue(field, value) {
  const previousValue = field.value
  const descriptor = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')
  descriptor?.set?.call(field, value)
  if (!descriptor?.set) {
    field.value = value
  }
  if (field._valueTracker) {
    field._valueTracker.setValue(previousValue)
  }
}
function triggerInputEvents(field) {
  field.dispatchEvent(new Event('input', { bubbles: true }))
  field.dispatchEvent(new Event('change', { bubbles: true }))
}
function highlightField(field, color = 'rgba(34, 197, 94, 0.85)') {
  const previousBoxShadow = field.style.boxShadow
  const previousTransition = field.style.transition
  field.style.boxShadow = `0 0 0 2px ${color}`
  field.style.transition = 'box-shadow 0.2s ease'
  window.setTimeout(() => {
    if (field.isConnected) {
      field.style.boxShadow = previousBoxShadow
      field.style.transition = previousTransition
    }
  }, 1600)
}
function fillPasswordFields(password, sourceField = activeField) {
  const fields = sourceField ? getSameFormTargets(sourceField) : getPasswordFields().filter(field => !field.value)
  if (!fields.length) {
    return {
      success: false,
      message: 'No empty password fields found on this page',
      fieldsCount: 0,
      domain: location.hostname,
      fields: []
    }
  }
  const filledFields = []
  fields.forEach(field => {
    field.focus()
    setNativeValue(field, password)
    triggerInputEvents(field)
    highlightField(field)
    filledFields.push(getFieldIdentifier(field))
  })
  return {
    success: true,
    message: `Password filled in ${filledFields.length} field${filledFields.length === 1 ? '' : 's'}`,
    fieldsCount: filledFields.length,
    domain: location.hostname,
    fields: filledFields
  }
}
function getUsernameTarget(passwordField) {
  const form = passwordField?.form
  const searchRoot = form || document
  const fields = getUsernameFields(searchRoot)
  return fields[0] || null
}
function fillSavedCredential({ username = '', password = '' }, sourceField = activeField) {
  const passwordField = sourceField && isPasswordField(sourceField)
    ? sourceField
    : getPasswordFields().find(field => !field.disabled && !field.readOnly)
  if (!passwordField) {
    return {
      success: false,
      message: 'No sign-in form found on this page',
      domain: location.hostname,
      fields: []
    }
  }
  const usernameField = getUsernameTarget(passwordField)
  const filledFields = []
  if (usernameField && username) {
    usernameField.focus()
    setNativeValue(usernameField, username)
    triggerInputEvents(usernameField)
    highlightField(usernameField, 'rgba(59, 130, 246, 0.8)')
    filledFields.push(getFieldIdentifier(usernameField))
  }
  const passwordResult = fillPasswordFields(password, passwordField)
  filledFields.push(...(passwordResult.fields || []))
  return {
    success: passwordResult.success,
    message: passwordResult.success
      ? `Filled ${usernameField && username ? 'username and password' : 'password'} for sign-in`
      : passwordResult.message,
    domain: location.hostname,
    fields: filledFields
  }
}
function setFeedback(message, tone = 'neutral') {
  if (!UI.feedback) return
  UI.feedback.textContent = message
  UI.feedback.dataset.tone = tone
  UI.feedback.style.display = message ? 'block' : 'none'
  UI.feedback.style.color = tone === 'success'
    ? '#34d399'
    : tone === 'error'
      ? '#f87171'
      : '#8b8d98'
  if (feedbackTimer) {
    clearTimeout(feedbackTimer)
  }
  feedbackTimer = window.setTimeout(() => {
    if (UI.feedback) {
      UI.feedback.textContent = ''
      UI.feedback.dataset.tone = 'neutral'
      UI.feedback.style.display = 'none'
    }
  }, 1800)
}
function setSuggestionSubtitle(text = '') {
  if (!UI.suggestionSubtitle) return
  UI.suggestionSubtitle.textContent = text
  UI.suggestionSubtitle.style.display = text ? 'block' : 'none'
}
function getPasswordCharColor(char, index) {
  if (/\d/.test(char)) {
    return index % 2 === 0 ? '#38bdf8' : '#22d3ee'
  }
  if (/[^A-Za-z0-9]/.test(char)) {
    return '#f59e0b'
  }
  if (/[A-Z]/.test(char)) {
    return '#f4f4f5'
  }
  return '#d4d4d8'
}
function setSuggestionPasswordText(value = '', colorize = false) {
  if (!UI.passwordText) return
  UI.passwordText.textContent = ''
  if (!colorize) {
    UI.passwordText.textContent = value
    return
  }
  Array.from(value).forEach((char, index) => {
    const span = document.createElement('span')
    span.textContent = char
    span.style.color = getPasswordCharColor(char, index)
    UI.passwordText.appendChild(span)
  })
}
function applyButtonStyles(button, styles, options = {}) {
  const {
    stretch = true,
    height = '36px',
    padding = '0 12px',
    borderRadius = '8px',
    fontSize = '12px'
  } = options
  button.style.flex = stretch ? '1' : '0 0 auto'
  button.style.height = height
  button.style.padding = padding
  button.style.borderRadius = borderRadius
  button.style.display = 'inline-flex'
  button.style.alignItems = 'center'
  button.style.justifyContent = 'center'
  button.style.cursor = 'pointer'
  button.style.fontSize = fontSize
  button.style.fontWeight = '600'
  button.style.transition = 'opacity 0.15s ease, background-color 0.15s ease, border-color 0.15s ease, color 0.15s ease'
  button.style.outline = 'none'
  button.style.boxSizing = 'border-box'
  button.style.whiteSpace = 'nowrap'
  button.style.appearance = 'none'
  button.style.webkitAppearance = 'none'
  Object.assign(button.style, styles)
  button.addEventListener('mouseenter', () => {
    button.style.opacity = '0.92'
  })
  button.addEventListener('mouseleave', () => {
    button.style.opacity = '1'
  })
}
function ensureUi() {
  if (UI.suggestionRoot && UI.saveRoot && UI.triggerRoot) return
  const suggestionRoot = document.createElement('div')
  suggestionRoot.id = 'securepass-suggestion-root'
  suggestionRoot.style.position = 'absolute'
  suggestionRoot.style.zIndex = '2147483647'
  suggestionRoot.style.display = 'none'
  suggestionRoot.style.fontFamily = 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif'
  const triggerRoot = document.createElement('div')
  triggerRoot.id = 'securepass-trigger-root'
  triggerRoot.style.position = 'absolute'
  triggerRoot.style.zIndex = '2147483646'
  triggerRoot.style.display = 'none'
  triggerRoot.style.fontFamily = 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif'
  const triggerButton = document.createElement('button')
  triggerButton.type = 'button'
  triggerButton.setAttribute('aria-label', 'Show SecurePass suggestion')
  triggerButton.style.width = '28px'
  triggerButton.style.height = '28px'
  triggerButton.style.border = 'none'
  triggerButton.style.borderRadius = '8px'
  triggerButton.style.background = 'transparent'
  triggerButton.style.color = '#a1a1aa'
  triggerButton.style.cursor = 'pointer'
  triggerButton.style.display = 'inline-flex'
  triggerButton.style.alignItems = 'center'
  triggerButton.style.justifyContent = 'center'
  triggerButton.style.padding = '0'
  triggerButton.style.margin = '0'
  triggerButton.style.appearance = 'none'
  triggerButton.style.webkitAppearance = 'none'
  triggerButton.style.boxSizing = 'border-box'
  triggerButton.style.transition = 'background-color 0.15s ease, color 0.15s ease, opacity 0.15s ease'
  const triggerGlyph = document.createElement('img')
  triggerGlyph.src = 'data:image/png;base64,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'
  triggerGlyph.alt = ''
  triggerGlyph.width = 22
  triggerGlyph.height = 22
  triggerGlyph.style.display = 'block'
  triggerGlyph.style.flexShrink = '0'
  triggerGlyph.style.pointerEvents = 'none'
  triggerButton.appendChild(triggerGlyph)
  triggerButton.addEventListener('mouseenter', () => {
    triggerButton.style.background = 'rgba(255, 255, 255, 0.08)'
    triggerButton.style.color = '#f4f4f5'
  })
  triggerButton.addEventListener('mouseleave', () => {
    triggerButton.style.background = 'transparent'
    triggerButton.style.color = '#a1a1aa'
  })
  triggerButton.addEventListener('pointerdown', (event) => {
    event.preventDefault()
    event.stopPropagation()
  })
  triggerButton.addEventListener('click', handleTriggerClick)
  triggerRoot.appendChild(triggerButton)
  const suggestionCard = document.createElement('div')
  suggestionCard.setAttribute('role', 'dialog')
  suggestionCard.setAttribute('aria-live', 'polite')
  suggestionCard.style.minWidth = '300px'
  suggestionCard.style.maxWidth = '420px'
  suggestionCard.style.padding = '10px'
  suggestionCard.style.borderRadius = '10px'
  suggestionCard.style.border = '1px solid rgba(255, 255, 255, 0.08)'
  suggestionCard.style.background = '#111216'
  suggestionCard.style.boxShadow = '0 14px 30px rgba(0, 0, 0, 0.3)'
  suggestionCard.style.color = '#f3f4f6'
  const title = document.createElement('div')
  title.textContent = 'Suggested password'
  title.style.fontSize = '10px'
  title.style.fontWeight = '600'
  title.style.letterSpacing = '0.16em'
  title.style.textTransform = 'uppercase'
  title.style.color = '#8b8d98'
  const suggestionSubtitle = document.createElement('div')
  suggestionSubtitle.textContent = 'Generated locally for this site.'
  suggestionSubtitle.style.marginTop = '4px'
  suggestionSubtitle.style.fontSize = '11px'
  suggestionSubtitle.style.lineHeight = '1.45'
  suggestionSubtitle.style.color = '#a1a1aa'
  const passwordText = document.createElement('div')
  passwordText.style.marginTop = '8px'
  passwordText.style.padding = '9px 10px'
  passwordText.style.borderRadius = '8px'
  passwordText.style.border = '1px solid rgba(255, 255, 255, 0.06)'
  passwordText.style.background = '#0b0c0f'
  passwordText.style.fontSize = '13px'
  passwordText.style.lineHeight = '1.5'
  passwordText.style.fontWeight = '600'
  passwordText.style.letterSpacing = '-0.02em'
  passwordText.style.fontFamily = 'JetBrains Mono, Geist Mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace'
  passwordText.style.wordBreak = 'break-all'
  passwordText.style.color = '#fafafa'
  const suggestionActions = document.createElement('div')
  suggestionActions.style.display = 'grid'
  suggestionActions.style.gridTemplateColumns = 'repeat(3, minmax(0, 1fr)) auto'
  suggestionActions.style.columnGap = '6px'
  suggestionActions.style.marginTop = '8px'
  suggestionActions.style.alignItems = 'center'
  suggestionActions.style.width = '100%'
  const fillButton = document.createElement('button')
  fillButton.type = 'button'
  fillButton.textContent = 'Fill'
  applyButtonStyles(fillButton, {
    background: '#22C55E',
    color: '#052e16',
    border: '1px solid rgba(34, 197, 94, 0.7)'
  }, { stretch: true, height: '32px', padding: '0 12px', borderRadius: '8px', fontSize: '12px' })
  fillButton.style.minWidth = '0'
  fillButton.style.width = '100%'
  const copyButton = document.createElement('button')
  copyButton.type = 'button'
  copyButton.textContent = 'Copy'
  applyButtonStyles(copyButton, {
    background: '#18181b',
    color: '#e4e4e7',
    border: '1px solid rgba(255, 255, 255, 0.08)'
  }, { stretch: false, height: '32px', padding: '0 10px', borderRadius: '8px', fontSize: '12px' })
  copyButton.style.flex = '0 0 auto'
  copyButton.style.minWidth = '0'
  copyButton.style.width = '100%'
  const refreshButton = document.createElement('button')
  refreshButton.type = 'button'
  refreshButton.textContent = 'Refresh'
  applyButtonStyles(refreshButton, {
    background: '#18181b',
    color: '#e4e4e7',
    border: '1px solid rgba(255, 255, 255, 0.08)'
  }, { stretch: false, height: '32px', padding: '0 10px', borderRadius: '8px', fontSize: '12px' })
  refreshButton.style.flex = '0 0 auto'
  refreshButton.style.minWidth = '0'
  refreshButton.style.width = '100%'
  const dismissButton = document.createElement('button')
  dismissButton.type = 'button'
  dismissButton.textContent = 'Later'
  applyButtonStyles(dismissButton, {
    background: 'transparent',
    color: '#8b8d98',
    border: '1px solid rgba(255, 255, 255, 0.06)'
  }, { stretch: false, height: '32px', padding: '0 4px', borderRadius: '8px', fontSize: '12px' })
  dismissButton.style.border = 'none'
  dismissButton.style.background = 'transparent'
  dismissButton.style.padding = '0 2px'
  dismissButton.style.height = '32px'
  dismissButton.style.fontWeight = '500'
  dismissButton.style.color = '#8b8d98'
  dismissButton.style.marginLeft = 'auto'
  const feedback = document.createElement('div')
  feedback.style.marginTop = '6px'
  feedback.style.fontSize = '11px'
  feedback.style.display = 'none'
  feedback.style.lineHeight = '1.4'
  feedback.style.color = '#8b8d98'
  fillButton.addEventListener('click', handleSuggestionPrimaryClick)
  copyButton.addEventListener('click', handleSuggestionSecondaryClick)
  refreshButton.addEventListener('click', handleSuggestionRefreshClick)
  dismissButton.addEventListener('click', handleDismissClick)
  suggestionActions.append(fillButton, copyButton, refreshButton, dismissButton)
  suggestionCard.append(title, suggestionSubtitle, passwordText, suggestionActions, feedback)
  suggestionRoot.appendChild(suggestionCard)
  const saveRoot = document.createElement('div')
  saveRoot.id = 'securepass-save-root'
  saveRoot.style.position = 'fixed'
  saveRoot.style.right = '16px'
  saveRoot.style.bottom = '16px'
  saveRoot.style.zIndex = '2147483647'
  saveRoot.style.display = 'none'
  saveRoot.style.fontFamily = 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif'
  const saveCard = document.createElement('div')
  saveCard.style.width = '288px'
  saveCard.style.maxWidth = 'calc(100vw - 32px)'
  saveCard.style.padding = '12px'
  saveCard.style.borderRadius = '12px'
  saveCard.style.border = '1px solid rgba(148, 163, 184, 0.22)'
  saveCard.style.background = 'rgba(15, 23, 42, 0.985)'
  saveCard.style.boxShadow = '0 10px 28px rgba(15, 23, 42, 0.2)'
  saveCard.style.color = '#f8fafc'
  const saveMessage = document.createElement('div')
  saveMessage.textContent = 'Save login for this site?'
  saveMessage.style.fontSize = '13px'
  saveMessage.style.fontWeight = '600'
  const saveDetails = document.createElement('div')
  saveDetails.style.marginTop = '6px'
  saveDetails.style.fontSize = '11px'
  saveDetails.style.color = '#94a3b8'
  saveDetails.style.lineHeight = '1.45'
  const saveActions = document.createElement('div')
  saveActions.style.display = 'flex'
  saveActions.style.gap = '6px'
  saveActions.style.marginTop = '10px'
  saveActions.style.flexWrap = 'wrap'
  saveActions.style.justifyContent = 'flex-end'
  const saveButton = document.createElement('button')
  saveButton.type = 'button'
  saveButton.textContent = 'Save'
  applyButtonStyles(saveButton, {
    background: '#e2e8f0',
    color: '#0f172a',
    border: '1px solid rgba(226, 232, 240, 0.72)'
  }, { stretch: false, height: '30px', padding: '0 10px', borderRadius: '7px', fontSize: '12px' })
  const neverButton = document.createElement('button')
  neverButton.type = 'button'
  neverButton.textContent = 'Never'
  applyButtonStyles(neverButton, {
    background: 'transparent',
    color: '#cbd5e1',
    border: '1px solid rgba(148, 163, 184, 0.22)'
  }, { stretch: false, height: '30px', padding: '0 10px', borderRadius: '7px', fontSize: '12px' })
  const laterButton = document.createElement('button')
  laterButton.type = 'button'
  laterButton.textContent = 'Later'
  applyButtonStyles(laterButton, {
    background: 'transparent',
    color: '#94a3b8',
    border: '1px solid rgba(148, 163, 184, 0.16)'
  }, { stretch: false, height: '30px', padding: '0 10px', borderRadius: '7px', fontSize: '12px' })
  saveButton.addEventListener('click', handleSaveCredentialConfirm)
  neverButton.addEventListener('click', handleNeverSaveDomain)
  laterButton.addEventListener('click', hideSavePrompt)
  saveActions.append(saveButton, neverButton, laterButton)
  saveCard.append(saveMessage, saveDetails, saveActions)
  saveRoot.appendChild(saveCard)
  document.documentElement.appendChild(suggestionRoot)
  document.documentElement.appendChild(triggerRoot)
  document.documentElement.appendChild(saveRoot)
  UI.suggestionRoot = suggestionRoot
  UI.suggestionCard = suggestionCard
  UI.passwordText = passwordText
  UI.suggestionSubtitle = suggestionSubtitle
  UI.suggestionActions = suggestionActions
  UI.triggerRoot = triggerRoot
  UI.triggerButton = triggerButton
  UI.fillButton = fillButton
  UI.copyButton = copyButton
  UI.refreshButton = refreshButton
  UI.dismissButton = dismissButton
  UI.feedback = feedback
  UI.saveRoot = saveRoot
  UI.saveCard = saveCard
  UI.saveMessage = saveMessage
  UI.saveDetails = saveDetails
  UI.saveButton = saveButton
  UI.neverButton = neverButton
  UI.laterButton = laterButton
}
function updateCardPosition() {
  if (!UI.suggestionRoot || !activeField || !activeField.isConnected) return
  const rect = activeField.getBoundingClientRect()
  const scrollX = window.scrollX || window.pageXOffset
  const scrollY = window.scrollY || window.pageYOffset
  const viewportWidth = document.documentElement.clientWidth
  const viewportHeight = document.documentElement.clientHeight
  const desiredWidth = Math.max(320, Math.min(viewportWidth - 24, Math.round(rect.width)))
  if (UI.suggestionCard) {
    UI.suggestionCard.style.width = `${desiredWidth}px`
  }
  const cardWidth = UI.suggestionCard?.offsetWidth || desiredWidth
  let left = rect.left + scrollX
  let top = rect.bottom + scrollY + 8
  if (left + cardWidth > scrollX + viewportWidth - 12) {
    left = Math.max(scrollX + 12, scrollX + viewportWidth - cardWidth - 12)
  }
  if (top + 210 > scrollY + viewportHeight) {
    top = Math.max(scrollY + 12, rect.top + scrollY - 218)
  }
  UI.suggestionRoot.style.left = `${left}px`
  UI.suggestionRoot.style.top = `${top}px`
}
function updateTriggerPosition() {
  if (!UI.triggerRoot || !triggerField || !triggerField.isConnected || !isEligibleTriggerField(triggerField)) {
    hideTrigger()
    return
  }
  const rect = triggerField.getBoundingClientRect()
  const scrollX = window.scrollX || window.pageXOffset
  const scrollY = window.scrollY || window.pageYOffset
  const left = Math.max(scrollX + 8, rect.right + scrollX - 36)
  const top = rect.top + scrollY + Math.max(0, (rect.height - 28) / 2)
  UI.triggerRoot.style.left = `${left}px`
  UI.triggerRoot.style.top = `${top}px`
}
function showTriggerForField(field) {
  ensureUi()
  if (!isEligibleTriggerField(field)) {
    hideTrigger()
    return
  }
  triggerField = field
  UI.triggerRoot.style.display = 'block'
  updateTriggerPosition()
}
function hideTrigger() {
  if (UI.triggerRoot) {
    UI.triggerRoot.style.display = 'none'
  }
  triggerField = null
}
function scheduleReposition() {
  if (repositionFrame) {
    cancelAnimationFrame(repositionFrame)
  }
  repositionFrame = requestAnimationFrame(() => {
    repositionFrame = null
    updateCardPosition()
    updateTriggerPosition()
  })
}
function getPreferredSuggestionField() {
  if (isEligibleSuggestionField(document.activeElement)) {
    return document.activeElement
  }
  if (isEligibleSuggestionField(activeField)) {
    return activeField
  }
  const [firstEligibleField] = getEligibleSuggestionFields()
  return firstEligibleField || null
}
async function getSavedCredentials(domain = location.hostname) {
  const enabled = await getStorageValue(STORAGE_KEYS.CREDENTIALS_ENABLED, true)
  if (enabled === false) return []
  const credentials = await getStorageValue(STORAGE_KEYS.SAVED_CREDENTIALS, [])
  const normalizedDomain = normalizeDomain(domain)
  return (Array.isArray(credentials) ? credentials : []).filter(entry => entry.domain === normalizedDomain)
}
async function showCredentialSuggestion(field, credentials) {
  ensureUi()
  if (!credentials.length) return false
  activeField = field
  activeCredential = credentials[0]
  activePassword = ''
  generatedPasswordField = null
  setSuggestionPasswordText(activeCredential.usernamePreview || 'Saved account', false)
  setSuggestionSubtitle(credentials.length > 1
    ? `Saved login for ${activeCredential.domain}. Use the popup vault to choose another account.`
    : `Saved login for ${activeCredential.domain}. Device verification is required before fill.`)
  UI.fillButton.textContent = 'Fill login'
  UI.copyButton.textContent = 'Copy user'
  if (UI.suggestionActions) {
    UI.suggestionActions.style.gridTemplateColumns = 'repeat(2, minmax(0, 1fr)) auto'
  }
  if (UI.refreshButton) {
    UI.refreshButton.style.display = 'none'
  }
  UI.dismissButton.textContent = 'Dismiss'
  UI.suggestionRoot.style.display = 'block'
  setFeedback('', 'neutral')
  scheduleReposition()
  return true
}
function showGeneratedSuggestion(field) {
  ensureUi()
  if (!isEligibleSuggestionField(field)) {
    hideSuggestion()
    return false
  }
  activeField = field
  activeCredential = null
  const shouldReusePassword = generatedPasswordField === field && activePassword
  if (!shouldReusePassword) {
    activePassword = generatePassword(DEFAULT_PASSWORD_OPTIONS)
    generatedPasswordField = field
  }
  setSuggestionPasswordText(activePassword, true)
  setSuggestionSubtitle('')
  UI.fillButton.textContent = 'Fill'
  UI.copyButton.textContent = 'Copy'
  if (UI.suggestionActions) {
    UI.suggestionActions.style.gridTemplateColumns = 'repeat(3, minmax(0, 1fr)) auto'
  }
  if (UI.refreshButton) {
    UI.refreshButton.style.display = 'inline-flex'
  }
  UI.dismissButton.textContent = 'Later'
  UI.suggestionRoot.style.display = 'block'
  setFeedback('', 'neutral')
  scheduleReposition()
  return true
}
async function showSuggestionForFirstEligibleField() {
  const field = getPreferredSuggestionField()
  if (!field) {
    hideSuggestion()
    return null
  }
  const credentials = await getSavedCredentials(location.hostname)
  const isSignInContext = getPasswordFields(field.form || document).length === 1
  if (isSignInContext && credentials.length) {
    await showCredentialSuggestion(field, credentials)
    return field
  }
  showGeneratedSuggestion(field)
  return field
}
function scheduleAutoShow(delay = 0) {
  if (typeof window === 'undefined') {
    return
  }
  if (autoShowTimer) {
    clearTimeout(autoShowTimer)
  }
  autoShowTimer = window.setTimeout(() => {
    autoShowTimer = null
    const shouldKeepCurrent = activeField && UI.suggestionRoot?.style.display === 'block' && isPasswordField(activeField)
    if (shouldKeepCurrent) {
      scheduleReposition()
      return
    }
    showSuggestionForFirstEligibleField()
  }, delay)
}
function hideSuggestion() {
  if (UI.suggestionRoot) {
    UI.suggestionRoot.style.display = 'none'
  }
  activeField = null
  activeCredential = null
}
function handleSuggestionRefreshClick(event) {
  event.preventDefault()
  if (!activeField || activeCredential) return
  activePassword = generatePassword(DEFAULT_PASSWORD_OPTIONS)
  generatedPasswordField = activeField
  setSuggestionPasswordText(activePassword, true)
  setFeedback('Password refreshed', 'success')
  scheduleReposition()
}
function showSavePrompt(payload) {
  ensureUi()
  pendingSavePayload = payload
  UI.saveMessage.textContent = `Save login for ${payload.domain}?`
  UI.saveDetails.textContent = `Username: ${maskUsername(payload.username)}${payload.isSignup ? ' • Looks like a sign-up form' : ' • Looks like a sign-in form'}`
  UI.saveRoot.style.display = 'block'
}
async function persistPendingSavePrompt(payload) {
  if (!payload) return
  const promptPayload = {
    ...payload,
    createdAt: payload.createdAt || new Date().toISOString()
  }
  pendingSavePayload = promptPayload
  await setStorageValue(STORAGE_KEYS.PENDING_CREDENTIAL_PROMPT, promptPayload)
}
async function clearPendingSavePrompt() {
  pendingSavePayload = null
  await setStorageValue(STORAGE_KEYS.PENDING_CREDENTIAL_PROMPT, null)
}
async function restorePendingSavePrompt() {
  const savedPrompt = await getStorageValue(STORAGE_KEYS.PENDING_CREDENTIAL_PROMPT, null)
  if (!savedPrompt?.username || !savedPrompt?.password || !savedPrompt?.domain) {
    return null
  }
  const createdAt = new Date(savedPrompt.createdAt || 0).getTime()
  if (!createdAt || Date.now() - createdAt > PENDING_PROMPT_MAX_AGE_MS) {
    await clearPendingSavePrompt()
    return null
  }
  showSavePrompt(savedPrompt)
  return savedPrompt
}
async function hideSavePrompt() {
  if (UI.saveRoot) {
    UI.saveRoot.style.display = 'none'
  }
  await clearPendingSavePrompt()
}
async function writeClipboardText(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text)
    return
  }
  const area = document.createElement('textarea')
  area.value = text
  area.setAttribute('readonly', 'readonly')
  area.style.position = 'fixed'
  area.style.opacity = '0'
  document.body.appendChild(area)
  area.select()
  document.execCommand('copy')
  document.body.removeChild(area)
}
async function getHistory() {
  const history = await getStorageValue(STORAGE_KEYS.PASSWORD_HISTORY, [])
  return Array.isArray(history) ? history : []
}
async function setHistory(entries) {
  await setStorageValue(STORAGE_KEYS.PASSWORD_HISTORY, entries)
}
async function addPasswordHistory(action, password) {
  const historyEnabled = await getStorageValue(STORAGE_KEYS.HISTORY_ENABLED, true)
  if (historyEnabled === false) return
  const history = await getHistory()
  const entry = {
    id: Date.now() + Math.random(),
    action,
    passwordType: 'random',
    website: location.href,
    passwordLength: password.length,
    timestamp: new Date().toISOString(),
    domain: location.hostname,
    passwordEnc: null
  }
  await setHistory([entry, ...history].slice(0, 100))
}
async function updateSavedCredentialUsage(entryId) {
  const savedCredentials = await getStorageValue(STORAGE_KEYS.SAVED_CREDENTIALS, [])
  const now = new Date().toISOString()
  const nextCredentials = (Array.isArray(savedCredentials) ? savedCredentials : []).map(entry => (
    entry.id === entryId ? { ...entry, lastUsedAt: now, updatedAt: now } : entry
  ))
  await setStorageValue(STORAGE_KEYS.SAVED_CREDENTIALS, nextCredentials)
}
async function handleSuggestionPrimaryClick(event) {
  event.preventDefault()
  if (activeCredential) {
    const verified = await ensureCredentialVerification()
    if (!verified) {
      setFeedback('Verification failed', 'error')
      return
    }
    const username = activeCredential.usernameEnc ? await decryptText(activeCredential.usernameEnc) : ''
    const password = activeCredential.passwordEnc ? await decryptText(activeCredential.passwordEnc) : ''
    const result = fillSavedCredential({ username, password }, activeField)
    if (result.success) {
      await updateSavedCredentialUsage(activeCredential.id)
      setFeedback(result.message, 'success')
      window.setTimeout(() => hideSuggestion(), 320)
    } else {
      setFeedback(result.message, 'error')
    }
    return
  }
  if (!activePassword || !activeField) return
  const result = fillPasswordFields(activePassword, activeField)
  if (result.success) {
    try {
      await writeClipboardText(activePassword)
    } catch (error) {
      // Keep fill successful even if clipboard write fails.
    }
    await addPasswordHistory('autofill', activePassword)
    setFeedback(`${result.message} Copied to clipboard.`, 'success')
    window.setTimeout(() => hideSuggestion(), 320)
  } else {
    setFeedback(result.message, 'error')
  }
}
async function handleSuggestionSecondaryClick(event) {
  event.preventDefault()
  try {
    if (activeCredential) {
      const username = activeCredential.usernameEnc ? await decryptText(activeCredential.usernameEnc) : ''
      if (!username) {
        setFeedback('No saved username', 'error')
        return
      }
      await writeClipboardText(username)
      setFeedback('Username copied', 'success')
      return
    }
    if (!activePassword) return
    await writeClipboardText(activePassword)
    await addPasswordHistory('copy', activePassword)
    setFeedback('Password copied', 'success')
  } catch (error) {
    setFeedback('Copy failed', 'error')
  }
}
function handleDismissClick(event) {
  event.preventDefault()
  if (activeField) {
    dismissedFields.add(activeField)
    showTriggerForField(activeField)
  }
  hideSuggestion()
  scheduleAutoShow(0)
}
async function handleTriggerClick(event) {
  event.preventDefault()
  event.stopPropagation()
  const field = triggerField
  if (!field || !isEligibleTriggerField(field)) {
    hideTrigger()
    return
  }
  dismissedFields.delete(field)
  activeField = field
  const credentials = await getSavedCredentials(location.hostname)
  const isSignInContext = getPasswordFields(field.form || document).length === 1
  if (isSignInContext && credentials.length) {
    await showCredentialSuggestion(field, credentials)
  } else {
    showGeneratedSuggestion(field)
  }
  showTriggerForField(field)
}
function handlePointerDown(event) {
  if (UI.suggestionRoot?.style.display === 'block') {
    const target = event.target
    if (!UI.suggestionRoot.contains(target) && !UI.triggerRoot?.contains(target) && target !== activeField) {
      hideSuggestion()
    }
  }
}
async function handleFocusIn(event) {
  const field = event.target
  if (!isPasswordField(field)) {
    return
  }
  showTriggerForField(field)
  const credentials = await getSavedCredentials(location.hostname)
  const isSignInContext = getPasswordFields(field.form || document).length === 1
  if (isSignInContext && credentials.length) {
    await showCredentialSuggestion(field, credentials)
    return
  }
  if (isEligibleSuggestionField(field)) {
    showGeneratedSuggestion(field)
  }
}
function handleInput(event) {
  if (!activeField || event.target !== activeField) return
  if (activeCredential) {
    if (activeField.value) {
      hideSuggestion()
      hideTrigger()
    }
    return
  }
  if (activeField.value) {
    hideSuggestion()
    hideTrigger()
    scheduleAutoShow(0)
  } else if (isEligibleSuggestionField(activeField)) {
    showTriggerForField(activeField)
    showGeneratedSuggestion(activeField)
  }
}
function handleScrollOrResize() {
  if (UI.suggestionRoot?.style.display === 'block') {
    scheduleReposition()
  } else if (UI.triggerRoot?.style.display === 'block') {
    scheduleReposition()
  }
}
function getCredentialPayloadFromForm(form) {
  if (!form) return null
  const passwordFields = getPasswordFields(form)
  if (!passwordFields.length) return null
  const usernameField = getUsernameTarget(passwordFields[0])
  const username = usernameField?.value?.trim() || ''
  const password = passwordFields[0]?.value || ''
  const isSignup = passwordFields.length > 1
  if (!username || !password) return null
  return {
    origin: normalizeOrigin(location.href),
    domain: normalizeDomain(location.hostname),
    username,
    password,
    isSignup
  }
}
async function shouldSaveCredentialForCurrentSite() {
  const enabled = await getStorageValue(STORAGE_KEYS.CREDENTIALS_ENABLED, true)
  if (enabled === false) return false
  const deniedDomains = await getStorageValue(STORAGE_KEYS.CREDENTIAL_NEVER_SAVE_DOMAINS, [])
  return !(Array.isArray(deniedDomains) && deniedDomains.includes(normalizeDomain(location.hostname)))
}
async function shouldPromptForCredential(payload) {
  if (!payload?.domain || !payload?.username || !payload?.password) {
    return false
  }
  const savedCredentials = await getSavedCredentials(payload.domain)
  if (!savedCredentials.length) {
    return true
  }
  for (const entry of savedCredentials) {
    if (!entry?.usernameEnc || !entry?.passwordEnc) {
      continue
    }
    try {
      const savedUsername = await decryptText(entry.usernameEnc)
      if (savedUsername !== payload.username) {
        continue
      }
      const savedPassword = await decryptText(entry.passwordEnc)
      return savedPassword !== payload.password
    } catch (error) {
      return true
    }
  }
  return true
}
function handleFormSubmit(event) {
  const form = event.target
  if (!(form instanceof HTMLFormElement)) return
  const payload = getCredentialPayloadFromForm(form)
  if (!payload) return
  submittedForms.set(form, payload)
  window.setTimeout(async () => {
    const latestPayload = submittedForms.get(form)
    if (!latestPayload) return
    const shouldPrompt = await shouldSaveCredentialForCurrentSite()
    const shouldPromptForEntry = shouldPrompt ? await shouldPromptForCredential(latestPayload) : false
    if (shouldPrompt && shouldPromptForEntry) {
      await persistPendingSavePrompt(latestPayload)
      showSavePrompt(latestPayload)
    }
    submittedForms.delete(form)
  }, 600)
}
async function saveCredentialPayload(payload) {
  const savedCredentials = await getStorageValue(STORAGE_KEYS.SAVED_CREDENTIALS, [])
  const usernameEnc = await encryptText(payload.username)
  const passwordEnc = await encryptText(payload.password)
  const nextEntry = {
    id: Date.now() + Math.random(),
    origin: payload.origin,
    domain: payload.domain,
    usernamePreview: maskUsername(payload.username),
    usernameEnc,
    passwordEnc,
    label: payload.isSignup ? 'Sign-up' : 'Sign-in',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    lastUsedAt: null
  }
  const currentEntries = Array.isArray(savedCredentials) ? savedCredentials : []
  const remainingEntries = []
  for (const entry of currentEntries) {
    if (entry.domain !== payload.domain || !entry.usernameEnc) {
      remainingEntries.push(entry)
      continue
    }
    try {
      const decryptedUsername = await decryptText(entry.usernameEnc)
      if (decryptedUsername !== payload.username) {
        remainingEntries.push(entry)
      }
    } catch (error) {
      remainingEntries.push(entry)
    }
  }
  await setStorageValue(STORAGE_KEYS.SAVED_CREDENTIALS, [nextEntry, ...remainingEntries])
  return nextEntry
}
async function handleSaveCredentialConfirm(event) {
  event.preventDefault()
  if (!pendingSavePayload) return
  try {
    await saveCredentialPayload(pendingSavePayload)
    await hideSavePrompt()
  } catch (error) {
    console.error('Failed to save credential:', error)
  }
}
async function handleNeverSaveDomain(event) {
  event.preventDefault()
  if (!pendingSavePayload?.domain) {
    await hideSavePrompt()
    return
  }
  const deniedDomains = await getStorageValue(STORAGE_KEYS.CREDENTIAL_NEVER_SAVE_DOMAINS, [])
  const nextDomains = Array.from(new Set([...(Array.isArray(deniedDomains) ? deniedDomains : []), pendingSavePayload.domain]))
  await setStorageValue(STORAGE_KEYS.CREDENTIAL_NEVER_SAVE_DOMAINS, nextDomains)
  await hideSavePrompt()
}
function watchDomChanges() {
  if (observer) return
  observer = new MutationObserver(() => {
    if (activeField && (!activeField.isConnected || !isPasswordField(activeField))) {
      hideSuggestion()
    }
    if (triggerField && (!triggerField.isConnected || !isEligibleTriggerField(triggerField))) {
      hideTrigger()
    }
    scheduleAutoShow(0)
  })
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['style', 'class', 'type', 'disabled', 'readonly', 'value']
  })
}
function findPasswordFields() {
  return getPasswordFields()
}
async function initializeAutoSuggestion() {
  if (initialized) return
  initialized = true
  ensureUi()
  await restorePendingSavePrompt()
  scheduleAutoShow(0)
}
if (extensionChrome?.runtime?.onMessage) {
  extensionChrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'fillPassword') {
      const password = request.password || activePassword || generatePassword(DEFAULT_PASSWORD_OPTIONS)
      const result = fillPasswordFields(password, activeField)
      if (result.success) {
        addPasswordHistory('autofill', password)
      }
      sendResponse(result)
      return true
    }
    if (request.action === 'fillSavedCredential') {
      ensureCredentialVerification().then((verified) => {
        if (!verified) {
          sendResponse({ success: false, message: 'Verification failed' })
          return
        }
        const result = fillSavedCredential(request.credential || {}, activeField)
        if (result.success && request.credential?.id) {
          updateSavedCredentialUsage(request.credential.id)
        }
        sendResponse(result)
      })
      return true
    }
    if (request.action === 'findPasswordFields') {
      const fields = findPasswordFields()
      sendResponse({
        success: true,
        fieldsCount: fields.length,
        message: `Found ${fields.length} password field${fields.length === 1 ? '' : 's'}`
      })
      return true
    }
    return false
  })
}
document.addEventListener('focusin', handleFocusIn, true)
document.addEventListener('pointerdown', handlePointerDown, true)
document.addEventListener('input', handleInput, true)
document.addEventListener('submit', handleFormSubmit, true)
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    scheduleAutoShow(0)
  }
})
window.addEventListener('scroll', handleScrollOrResize, true)
window.addEventListener('resize', handleScrollOrResize)
window.addEventListener('load', () => {
  scheduleAutoShow(0)
})
watchDomChanges()
initializeAutoSuggestion()
console.log('SecurePass Generator: In-page password suggestions and vault prompts enabled')
globalThis.__SECUREPASS_CONTENT_SCRIPT__ = {
  DEFAULT_PASSWORD_OPTIONS,
  decryptText,
  encryptText,
  fillPasswordFields,
  fillSavedCredential,
  findPasswordFields,
  generatePassword,
  getCredentialPayloadFromForm,
  getEligibleSuggestionFields,
  getPreferredSuggestionField,
  getStorageValue,
  getSavedCredentials,
  getSameFormTargets,
  getUsernameTarget,
  isEligibleSuggestionField,
  isPasswordField,
  isUsernameField,
  maskUsername,
  persistPendingSavePrompt,
  restorePendingSavePrompt,
  saveCredentialPayload,
  shouldPromptForCredential,
  showSuggestionForFirstEligibleField
}
