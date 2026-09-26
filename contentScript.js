// Content script for SecurePass Generator
// Provides in-page password suggestions plus a lightweight local credential vault flow.
const extensionChrome = typeof chrome !== 'undefined' ? chrome : null
const DEFAULT_PASSWORD_OPTIONS = {
  length: 20,
  includeUppercase: true,
  includeLowercase: true,
  includeNumbers: true,
  includeSymbols: false,
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
  PENDING_CREDENTIAL_PROMPT: 'pendingCredentialPrompt',
  SUGGESTION_ENABLED: 'suggestionEnabled',
  LENGTH: 'length',
  INCLUDE_UPPERCASE: 'includeUppercase',
  INCLUDE_LOWERCASE: 'includeLowercase',
  INCLUDE_NUMBERS: 'includeNumbers',
  INCLUDE_SYMBOLS: 'includeSymbols',
  SYMBOL_SET: 'symbolSet',
  CUSTOM_SYMBOLS: 'customSymbols',
  EXCLUDE_AMBIGUOUS: 'excludeAmbiguous'
}
const SYMBOL_SETS = {
  basic: '!@#$%&*+-=?',
  extended: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  safe: '!@#$%&*+-=?.',
  brackets: '()[]{}',
  punctuation: '!@#$%&*+-=?:;,.',
  math: '+-=*%^',
  dbsafe: '_.-~*+',
  custom: ''
}
const AMBIGUOUS_CHARS = 'il1Lo0O'
const GENERATOR_SETTING_KEYS = [
  STORAGE_KEYS.LENGTH,
  STORAGE_KEYS.INCLUDE_UPPERCASE,
  STORAGE_KEYS.INCLUDE_LOWERCASE,
  STORAGE_KEYS.INCLUDE_NUMBERS,
  STORAGE_KEYS.INCLUDE_SYMBOLS,
  STORAGE_KEYS.SYMBOL_SET,
  STORAGE_KEYS.CUSTOM_SYMBOLS,
  STORAGE_KEYS.EXCLUDE_AMBIGUOUS
]
const UI = {
  suggestionRoot: null,
  suggestionCard: null,
  title: null,
  passwordText: null,
  suggestionSubtitle: null,
  cardHeader: null,
  strengthBadge: null,
  credentialSelect: null,
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
  laterButton: null,
  tooltipRoot: null,
  tooltipBubble: null
}
const THEME_KEY = 'theme'
let activeThemeMode = 'light'
let activeField = null
let activePassword = ''
let feedbackTimer = null
let repositionFrame = null
let autoShowTimer = null
let observer = null
let activeCredential = null
let activeCredentialList = []
let activePasswordOptions = null
let activeStrengthText = ''
let activeStrengthTone = 'neutral'
let triggerField = null
let pendingSavePayload = null
let initialized = false
let generatedPasswordField = null
let cachedPasswordOptions = null
const dismissedFields = new WeakSet()
let isCurrentDomainDismissed = false
const DISMISSED_DOMAINS_KEY = 'dismissedSuggestionDomains'
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
function normalizeLength(value) {
  const length = Number(value)
  return Number.isInteger(length) && length >= 4 && length <= 128
    ? length
    : DEFAULT_PASSWORD_OPTIONS.length
}
async function getPasswordOptions() {
  if (cachedPasswordOptions) return cachedPasswordOptions
  const [length, includeUppercase, includeLowercase, includeNumbers, includeSymbols, symbolSet, customSymbols, excludeAmbiguous] = await Promise.all([
    getStorageValue(STORAGE_KEYS.LENGTH, DEFAULT_PASSWORD_OPTIONS.length),
    getStorageValue(STORAGE_KEYS.INCLUDE_UPPERCASE, DEFAULT_PASSWORD_OPTIONS.includeUppercase),
    getStorageValue(STORAGE_KEYS.INCLUDE_LOWERCASE, DEFAULT_PASSWORD_OPTIONS.includeLowercase),
    getStorageValue(STORAGE_KEYS.INCLUDE_NUMBERS, DEFAULT_PASSWORD_OPTIONS.includeNumbers),
    getStorageValue(STORAGE_KEYS.INCLUDE_SYMBOLS, DEFAULT_PASSWORD_OPTIONS.includeSymbols),
    getStorageValue(STORAGE_KEYS.SYMBOL_SET, DEFAULT_PASSWORD_OPTIONS.symbolSet),
    getStorageValue(STORAGE_KEYS.CUSTOM_SYMBOLS, DEFAULT_PASSWORD_OPTIONS.customSymbols),
    getStorageValue(STORAGE_KEYS.EXCLUDE_AMBIGUOUS, DEFAULT_PASSWORD_OPTIONS.excludeAmbiguous)
  ])
  cachedPasswordOptions = {
    length: normalizeLength(length),
    includeUppercase: includeUppercase !== false,
    includeLowercase: includeLowercase !== false,
    includeNumbers: includeNumbers !== false,
    includeSymbols: includeSymbols === true,
    symbolSet: typeof symbolSet === 'string' && SYMBOL_SETS[symbolSet] !== undefined ? symbolSet : 'basic',
    customSymbols: typeof customSymbols === 'string' ? customSymbols : '',
    excludeAmbiguous: excludeAmbiguous === true
  }
  return cachedPasswordOptions
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
function getPreferredTheme(themeSetting) {
  if (themeSetting === 'dark' || themeSetting === 'light') return themeSetting
  if (typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: dark)').matches) {
    return 'dark'
  }
  return 'light'
}
function getThemePalette(mode = activeThemeMode) {
  if (mode === 'dark') {
    return {
      triggerBackground: 'rgba(24, 28, 36, 0.98)',
      triggerBorder: 'rgba(74, 85, 104, 0.55)',
      triggerColor: '#a6adbb',
      triggerHoverBackground: 'rgba(24, 42, 34, 0.98)',
      triggerHoverBorder: 'rgba(115, 226, 160, 0.28)',
      triggerHoverColor: '#73e2a0',
      cardBackground: 'rgba(31, 35, 43, 0.985)',
      cardBorder: 'rgba(74, 85, 104, 0.52)',
      cardColor: '#f2f5f7',
      shadow: '0 24px 48px -28px rgba(2, 6, 23, 0.54), 0 8px 18px -12px rgba(2, 6, 23, 0.32)',
      eyebrow: '#8f98a8',
      mutedText: '#9aa4b2',
      panelBackground: 'linear-gradient(180deg, rgba(18, 22, 28, 0.98) 0%, rgba(24, 29, 36, 0.98) 100%)',
      panelBorder: 'rgba(74, 85, 104, 0.42)',
      panelText: '#f8fafc',
      primaryBackground: 'rgba(115, 226, 160, 0.2)',
      primaryBorder: 'rgba(115, 226, 160, 0.38)',
      primaryColor: '#8af0b4',
      neutralBackground: 'rgba(39, 44, 55, 0.98)',
      neutralBorder: 'rgba(74, 85, 104, 0.46)',
      neutralColor: '#edf2f7',
      tertiaryColor: '#9aa4b2',
    }
  }

  return {
    triggerBackground: 'rgba(255, 255, 255, 0.98)',
    triggerBorder: 'rgba(53, 66, 87, 0.18)',
    triggerColor: '#6b7280',
    triggerHoverBackground: 'rgba(236, 253, 245, 0.98)',
    triggerHoverBorder: 'rgba(34, 197, 94, 0.28)',
    triggerHoverColor: '#166534',
    cardBackground: 'rgba(255, 255, 255, 0.985)',
    cardBorder: 'rgba(53, 66, 87, 0.14)',
    cardColor: '#1f2937',
    shadow: '0 24px 48px -28px rgba(40, 48, 67, 0.22), 0 8px 18px -12px rgba(40, 48, 67, 0.1)',
    eyebrow: '#6b7280',
    mutedText: '#6b7280',
    panelBackground: 'linear-gradient(180deg, rgba(248, 250, 252, 0.98) 0%, rgba(244, 247, 249, 0.98) 100%)',
    panelBorder: 'rgba(53, 66, 87, 0.12)',
    panelText: '#111827',
    primaryBackground: 'rgba(115, 226, 160, 0.22)',
    primaryBorder: 'rgba(34, 197, 94, 0.42)',
    primaryColor: '#14532d',
    neutralBackground: 'rgba(255, 255, 255, 0.82)',
    neutralBorder: 'rgba(53, 66, 87, 0.12)',
    neutralColor: '#1f2937',
    tertiaryColor: '#6b7280',
  }
}
function applyCurrentThemeToUi() {
  const palette = getThemePalette(activeThemeMode)

  if (UI.triggerButton) {
    UI.triggerButton.style.background = palette.triggerBackground
    UI.triggerButton.style.borderColor = palette.triggerBorder
    UI.triggerButton.style.color = palette.triggerColor
  }
  if (UI.suggestionCard) {
    UI.suggestionCard.style.background = palette.cardBackground
    UI.suggestionCard.style.borderColor = palette.cardBorder
    UI.suggestionCard.style.boxShadow = palette.shadow
    UI.suggestionCard.style.color = palette.cardColor
  }
  if (UI.title) {
    UI.title.style.color = palette.eyebrow
  }
  if (UI.tooltipBubble) {
    UI.tooltipBubble.style.background = palette.cardBackground
    UI.tooltipBubble.style.borderColor = palette.cardBorder
    UI.tooltipBubble.style.color = palette.cardColor
  }
  if (UI.passwordText) {
    UI.passwordText.style.background = palette.panelBackground
    UI.passwordText.style.borderColor = palette.panelBorder
    UI.passwordText.style.color = palette.panelText
  }
  if (!activeCredential && activePassword) {
    setSuggestionPasswordText(activePassword, true)
  }
  if (UI.suggestionSubtitle) {
    UI.suggestionSubtitle.style.color = palette.mutedText
  }
  if (UI.strengthBadge) {
    UI.strengthBadge.style.background = palette.neutralBackground
    UI.strengthBadge.style.borderColor = palette.neutralBorder
    UI.strengthBadge.style.color = palette.tertiaryColor
  }
  if (UI.credentialSelect) {
    UI.credentialSelect.style.background = palette.neutralBackground
    UI.credentialSelect.style.borderColor = palette.neutralBorder
    UI.credentialSelect.style.color = palette.neutralColor
  }
  if (activeStrengthText) {
    setStrengthBadge(activeStrengthText, activeStrengthTone)
  }
  if (UI.feedback) {
    UI.feedback.style.color = palette.mutedText
  }
  if (UI.fillButton) {
    UI.fillButton.style.background = palette.primaryBackground
    UI.fillButton.style.borderColor = palette.primaryBorder
    UI.fillButton.style.color = palette.primaryColor
  }
  if (UI.copyButton) {
    UI.copyButton.style.background = palette.neutralBackground
    UI.copyButton.style.borderColor = palette.neutralBorder
    UI.copyButton.style.color = palette.neutralColor
  }
  if (UI.refreshButton) {
    UI.refreshButton.style.background = palette.neutralBackground
    UI.refreshButton.style.borderColor = palette.neutralBorder
    UI.refreshButton.style.color = palette.neutralColor
  }
  if (UI.dismissButton) {
    UI.dismissButton.style.color = palette.tertiaryColor
  }
  if (UI.saveCard) {
    UI.saveCard.style.background = palette.cardBackground
    UI.saveCard.style.borderColor = palette.cardBorder
    UI.saveCard.style.boxShadow = palette.shadow
    UI.saveCard.style.color = palette.cardColor
  }
  if (UI.saveDetails) {
    UI.saveDetails.style.color = palette.mutedText
  }
  if (UI.saveButton) {
    UI.saveButton.style.background = palette.primaryBackground
    UI.saveButton.style.borderColor = palette.primaryBorder
    UI.saveButton.style.color = palette.primaryColor
  }
  if (UI.neverButton) {
    UI.neverButton.style.background = palette.neutralBackground
    UI.neverButton.style.borderColor = palette.neutralBorder
    UI.neverButton.style.color = palette.neutralColor
  }
  if (UI.laterButton) {
    UI.laterButton.style.color = palette.tertiaryColor
  }
}
async function syncUiTheme() {
  const storedTheme = await getStorageValue(THEME_KEY, 'system')
  activeThemeMode = getPreferredTheme(storedTheme)
  applyCurrentThemeToUi()
}
async function loadDismissalState() {
  const dismissed = await getStorageValue(DISMISSED_DOMAINS_KEY, [])
  isCurrentDomainDismissed = Array.isArray(dismissed) && dismissed.includes(location.hostname)
}
async function addDomainToDismissed() {
  const dismissed = await getStorageValue(DISMISSED_DOMAINS_KEY, [])
  const list = Array.isArray(dismissed) ? dismissed : []
  if (!list.includes(location.hostname)) {
    list.push(location.hostname)
    await setStorageValue(DISMISSED_DOMAINS_KEY, list)
  }
}
async function removeDomainFromDismissed() {
  const dismissed = await getStorageValue(DISMISSED_DOMAINS_KEY, [])
  const list = Array.isArray(dismissed) ? dismissed : []
  const filtered = list.filter(d => d !== location.hostname)
  await setStorageValue(DISMISSED_DOMAINS_KEY, filtered)
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
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256
        { type: 'public-key', alg: -257 }  // RS256
      ],
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
function removeAmbiguousChars(charset) {
  return charset.split('').filter(char => !AMBIGUOUS_CHARS.includes(char)).join('')
}
function getRequiredSets(options) {
  const sets = []
  if (options.includeUppercase) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
  if (options.includeLowercase) sets.push('abcdefghijklmnopqrstuvwxyz')
  if (options.includeNumbers) sets.push('0123456789')
  if (options.includeSymbols) sets.push(getSymbolChars(options.symbolSet, options.customSymbols))
  return options.excludeAmbiguous ? sets.map(removeAmbiguousChars).filter(Boolean) : sets
}
function buildCharset(options) {
  let charset = ''
  if (options.includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  if (options.includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz'
  if (options.includeNumbers) charset += '0123456789'
  if (options.includeSymbols) charset += getSymbolChars(options.symbolSet, options.customSymbols)
  if (options.excludeAmbiguous) charset = removeAmbiguousChars(charset)
  if (!charset) {
    const fallback = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    charset = options.excludeAmbiguous ? removeAmbiguousChars(fallback) : fallback
  }
  return charset
}
function generatePassword(options = DEFAULT_PASSWORD_OPTIONS) {
  const charset = buildCharset(options)
  const requiredSets = getRequiredSets(options)
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
  return isPasswordField(field) && !field.value && !dismissedFields.has(field) && !isCurrentDomainDismissed
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
function setStrengthBadge(text = '', tone = 'neutral') {
  activeStrengthText = text
  activeStrengthTone = tone
  if (!UI.strengthBadge) return
  if (!text) {
    UI.strengthBadge.style.display = 'none'
    return
  }
  const palette = getThemePalette(activeThemeMode)
  UI.strengthBadge.textContent = text
  UI.strengthBadge.style.display = 'inline-flex'
  if (tone === 'strong') {
    UI.strengthBadge.style.background = palette.primaryBackground
    UI.strengthBadge.style.borderColor = palette.primaryBorder
    UI.strengthBadge.style.color = palette.primaryColor
  } else {
    UI.strengthBadge.style.background = palette.neutralBackground
    UI.strengthBadge.style.borderColor = palette.neutralBorder
    UI.strengthBadge.style.color = palette.tertiaryColor
  }
}
function getPasswordStrengthInfo(password = '', options = null) {
  if (!password || !options) return { text: '', tone: 'neutral' }
  const charsetSize = Math.max(1, buildCharset(options).length)
  const entropy = password.length * Math.log2(charsetSize)
  const label = entropy >= 80 ? 'Strong' : entropy >= 60 ? 'Good' : entropy >= 40 ? 'Fair' : 'Weak'
  return { text: `${label} · ${password.length} chars`, tone: entropy >= 80 ? 'strong' : 'neutral' }
}
function applyPasswordStrengthBadge(password, options) {
  const info = getPasswordStrengthInfo(password, options)
  setStrengthBadge(info.text, info.tone)
}
function handleCredentialSelectChange(event) {
  const index = Number(event.target.value)
  const credential = activeCredentialList[index]
  if (!credential) return
  activeCredential = credential
  setSuggestionPasswordText(credential.usernamePreview || 'Saved account', false)
  setFeedback('', 'neutral')
}
function getPasswordCharColor(char, index, mode = activeThemeMode) {
  const dark = mode === 'dark'
  if (/\d/.test(char)) {
    if (dark) return index % 2 === 0 ? '#38bdf8' : '#22d3ee'
    return index % 2 === 0 ? '#0369a1' : '#0e7490'
  }
  if (/[^A-Za-z0-9]/.test(char)) {
    return dark ? '#f59e0b' : '#b45309'
  }
  if (/[A-Z]/.test(char)) {
    return dark ? '#f4f4f5' : '#111827'
  }
  return dark ? '#d4d4d8' : '#374151'
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
  button.style.gap = '6px'
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
function hideTooltip() {
  if (UI.tooltipRoot) {
    UI.tooltipRoot.style.display = 'none'
  }
}
function showTooltip(target, label) {
  if (!target || !label || !UI.tooltipRoot || !UI.tooltipBubble) return

  UI.tooltipBubble.textContent = label
  UI.tooltipRoot.style.display = 'block'

  const rect = target.getBoundingClientRect()
  const bubbleRect = UI.tooltipBubble.getBoundingClientRect()
  const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0

  let left = rect.left + (rect.width / 2) - (bubbleRect.width / 2)
  left = Math.max(8, Math.min(left, viewportWidth - bubbleRect.width - 8))

  const top = Math.max(8, rect.top - bubbleRect.height - 8)
  UI.tooltipRoot.style.left = `${left}px`
  UI.tooltipRoot.style.top = `${top}px`
}
function attachTooltip(button, label) {
  const show = () => showTooltip(button, label)
  const hide = () => hideTooltip()

  button.addEventListener('mouseenter', show)
  button.addEventListener('mouseleave', hide)
  button.addEventListener('focus', show)
  button.addEventListener('blur', hide)
  button.addEventListener('pointerdown', hide)
}
const BUTTON_ICONS = {
  fill: [
    ['path', { d: 'M5 4h1a3 3 0 0 1 3 3 3 3 0 0 1 3-3h1' }],
    ['path', { d: 'M13 20h-1a3 3 0 0 1-3-3 3 3 0 0 1-3 3H5' }],
    ['path', { d: 'M5 16H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2h1' }],
    ['path', { d: 'M13 8h7a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-7' }],
    ['path', { d: 'M9 7v10' }],
  ],
  copy: [
    ['rect', { x: 8, y: 8, width: 14, height: 14, rx: 2 }],
    ['path', { d: 'M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2' }],
  ],
  refresh: [
    ['path', { d: 'M21 12a9 9 0 1 1-3-6.7L21 8' }],
    ['path', { d: 'M21 3v5h-5' }],
  ],
  dismiss: [
    ['path', { d: 'M18 6 6 18' }],
    ['path', { d: 'm6 6 12 12' }],
  ],
  save: [
    ['path', { d: 'M15.2 3a2 2 0 0 1 1.4.6l3.8 3.8a2 2 0 0 1 .6 1.4V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z' }],
    ['path', { d: 'M17 21v-7a1 1 0 0 0-1-1H8a1 1 0 0 0-1 1v7' }],
    ['path', { d: 'M7 3v4a1 1 0 0 0 1 1h7' }],
  ],
  never: [
    ['circle', { cx: 12, cy: 12, r: 10 }],
    ['path', { d: 'm4.9 4.9 14.2 14.2' }],
  ],
  later: [
    ['circle', { cx: 12, cy: 12, r: 10 }],
    ['path', { d: 'M12 6v6l4 2' }],
  ],
  key: [
    ['circle', { cx: 7.5, cy: 15.5, r: 5.5 }],
    ['path', { d: 'm21 2-9.6 9.6' }],
    ['path', { d: 'm15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4' }],
  ],
}
function createButtonIcon(name, size = 15) {
  const svgNs = 'http://www.w3.org/2000/svg'
  const svg = document.createElementNS(svgNs, 'svg')
  svg.setAttribute('viewBox', '0 0 24 24')
  svg.setAttribute('width', String(size))
  svg.setAttribute('height', String(size))
  svg.setAttribute('fill', 'none')
  svg.setAttribute('stroke', 'currentColor')
  svg.setAttribute('stroke-width', '2')
  svg.setAttribute('stroke-linecap', 'round')
  svg.setAttribute('stroke-linejoin', 'round')
  svg.setAttribute('aria-hidden', 'true')
  svg.style.display = 'block'
  svg.style.flexShrink = '0'
  svg.style.pointerEvents = 'none'

  const shapes = BUTTON_ICONS[name] || BUTTON_ICONS.dismiss
  shapes.forEach(([tag, attrs]) => {
    const node = document.createElementNS(svgNs, tag)
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, String(value)))
    svg.appendChild(node)
  })

  return svg
}
function setButtonIcon(button, iconName, label) {
  button.textContent = ''
  button.setAttribute('aria-label', label)
  button.title = label
  button.appendChild(createButtonIcon(iconName))
}
function setButtonContent(button, iconName, text, ariaLabel = text) {
  button.textContent = ''
  button.setAttribute('aria-label', ariaLabel)
  button.title = ariaLabel
  button.appendChild(createButtonIcon(iconName))
  const label = document.createElement('span')
  label.textContent = text
  button.appendChild(label)
}
function ensureUi() {
  if (UI.suggestionRoot && UI.saveRoot && UI.triggerRoot) return
  const sansFont = 'Alan Sans, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif'
  const monoFont = 'Geist Mono, SFMono-Regular, ui-monospace, Menlo, Monaco, Consolas, monospace'
  const suggestionRoot = document.createElement('div')
  suggestionRoot.id = 'securepass-suggestion-root'
  suggestionRoot.style.position = 'absolute'
  suggestionRoot.style.zIndex = '2147483647'
  suggestionRoot.style.display = 'none'
  suggestionRoot.style.fontFamily = sansFont
  const tooltipRoot = document.createElement('div')
  tooltipRoot.id = 'securepass-tooltip-root'
  tooltipRoot.style.position = 'fixed'
  tooltipRoot.style.zIndex = '2147483647'
  tooltipRoot.style.display = 'none'
  tooltipRoot.style.pointerEvents = 'none'
  tooltipRoot.style.fontFamily = sansFont
  const tooltipBubble = document.createElement('div')
  tooltipBubble.style.border = '1px solid rgba(53, 66, 87, 0.14)'
  tooltipBubble.style.borderRadius = '2px'
  tooltipBubble.style.background = 'rgba(255, 255, 255, 0.985)'
  tooltipBubble.style.color = '#1f2937'
  tooltipBubble.style.boxShadow = '0 12px 28px -18px rgba(40, 48, 67, 0.14), 0 2px 6px -4px rgba(40, 48, 67, 0.08)'
  tooltipBubble.style.padding = '6px 8px'
  tooltipBubble.style.fontSize = '11px'
  tooltipBubble.style.fontWeight = '600'
  tooltipBubble.style.lineHeight = '1'
  tooltipBubble.style.whiteSpace = 'nowrap'
  tooltipRoot.appendChild(tooltipBubble)
  const triggerRoot = document.createElement('div')
  triggerRoot.id = 'securepass-trigger-root'
  triggerRoot.style.position = 'absolute'
  triggerRoot.style.zIndex = '2147483646'
  triggerRoot.style.display = 'none'
  triggerRoot.style.fontFamily = sansFont
  const triggerButton = document.createElement('button')
  triggerButton.type = 'button'
  triggerButton.setAttribute('aria-label', 'Show SecurePass suggestion')
  triggerButton.style.width = '32px'
  triggerButton.style.height = '32px'
  triggerButton.style.border = '1px solid rgba(53, 66, 87, 0.18)'
  triggerButton.style.borderRadius = '2px'
  triggerButton.style.background = 'rgba(255, 255, 255, 0.98)'
  triggerButton.style.color = '#6b7280'
  triggerButton.style.cursor = 'pointer'
  triggerButton.style.display = 'inline-flex'
  triggerButton.style.alignItems = 'center'
  triggerButton.style.justifyContent = 'center'
  triggerButton.style.padding = '0'
  triggerButton.style.margin = '0'
  triggerButton.style.appearance = 'none'
  triggerButton.style.webkitAppearance = 'none'
  triggerButton.style.boxSizing = 'border-box'
  triggerButton.style.boxShadow = '0 12px 28px -18px rgba(40, 48, 67, 0.14), 0 2px 6px -4px rgba(40, 48, 67, 0.08)'
  triggerButton.style.backdropFilter = 'blur(12px)'
  triggerButton.style.transition = 'background-color 0.15s ease, color 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease, opacity 0.15s ease'
  const triggerGlyph = createButtonIcon('key', 17)
  triggerButton.appendChild(triggerGlyph)
  triggerButton.addEventListener('mouseenter', () => {
    const palette = getThemePalette(activeThemeMode)
    triggerButton.style.background = palette.triggerHoverBackground
    triggerButton.style.borderColor = palette.triggerHoverBorder
    triggerButton.style.color = palette.triggerHoverColor
    triggerButton.style.boxShadow = '0 18px 36px -22px rgba(40, 48, 67, 0.18), 0 4px 12px -8px rgba(40, 48, 67, 0.08)'
  })
  triggerButton.addEventListener('mouseleave', () => {
    const palette = getThemePalette(activeThemeMode)
    triggerButton.style.background = palette.triggerBackground
    triggerButton.style.borderColor = palette.triggerBorder
    triggerButton.style.color = palette.triggerColor
    triggerButton.style.boxShadow = '0 12px 28px -18px rgba(40, 48, 67, 0.14), 0 2px 6px -4px rgba(40, 48, 67, 0.08)'
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
  suggestionCard.style.minWidth = '316px'
  suggestionCard.style.maxWidth = '420px'
  suggestionCard.style.padding = '14px'
  suggestionCard.style.borderRadius = '2px'
  suggestionCard.style.border = '1px solid rgba(53, 66, 87, 0.14)'
  suggestionCard.style.background = 'rgba(255, 255, 255, 0.985)'
  suggestionCard.style.backdropFilter = 'blur(18px)'
  suggestionCard.style.boxShadow = '0 24px 48px -28px rgba(40, 48, 67, 0.22), 0 8px 18px -12px rgba(40, 48, 67, 0.1)'
  suggestionCard.style.color = '#1f2937'
  const title = document.createElement('div')
  title.textContent = 'Suggested password'
  title.style.fontSize = '10px'
  title.style.fontWeight = '600'
  title.style.letterSpacing = '0.2em'
  title.style.textTransform = 'uppercase'
  title.style.color = '#6b7280'
  const suggestionSubtitle = document.createElement('div')
  suggestionSubtitle.textContent = 'Generated locally for this site.'
  suggestionSubtitle.style.marginTop = '4px'
  suggestionSubtitle.style.fontSize = '11px'
  suggestionSubtitle.style.lineHeight = '1.45'
  suggestionSubtitle.style.color = '#6b7280'
  const cardHeader = document.createElement('div')
  cardHeader.style.display = 'flex'
  cardHeader.style.alignItems = 'center'
  cardHeader.style.justifyContent = 'space-between'
  cardHeader.style.gap = '8px'
  const strengthBadge = document.createElement('div')
  strengthBadge.style.display = 'none'
  strengthBadge.style.alignItems = 'center'
  strengthBadge.style.padding = '2px 7px'
  strengthBadge.style.borderRadius = '2px'
  strengthBadge.style.border = '1px solid rgba(53, 66, 87, 0.12)'
  strengthBadge.style.background = 'rgba(255, 255, 255, 0.82)'
  strengthBadge.style.color = '#6b7280'
  strengthBadge.style.fontSize = '10px'
  strengthBadge.style.fontWeight = '600'
  strengthBadge.style.whiteSpace = 'nowrap'
  cardHeader.append(title, strengthBadge)
  const credentialSelect = document.createElement('select')
  credentialSelect.style.display = 'none'
  credentialSelect.style.marginTop = '10px'
  credentialSelect.style.width = '100%'
  credentialSelect.style.height = '32px'
  credentialSelect.style.padding = '0 8px'
  credentialSelect.style.borderRadius = '2px'
  credentialSelect.style.border = '1px solid rgba(53, 66, 87, 0.12)'
  credentialSelect.style.background = 'rgba(255, 255, 255, 0.82)'
  credentialSelect.style.color = '#1f2937'
  credentialSelect.style.fontSize = '12px'
  credentialSelect.style.fontFamily = sansFont
  credentialSelect.style.boxSizing = 'border-box'
  credentialSelect.setAttribute('aria-label', 'Choose saved account')
  credentialSelect.addEventListener('change', handleCredentialSelectChange)
  const passwordText = document.createElement('div')
  passwordText.style.marginTop = '10px'
  passwordText.style.padding = '12px 13px'
  passwordText.style.borderRadius = '2px'
  passwordText.style.border = '1px solid rgba(53, 66, 87, 0.12)'
  passwordText.style.background = 'linear-gradient(180deg, rgba(248, 250, 252, 0.98) 0%, rgba(244, 247, 249, 0.98) 100%)'
  passwordText.style.fontSize = '13px'
  passwordText.style.lineHeight = '1.6'
  passwordText.style.fontWeight = '600'
  passwordText.style.letterSpacing = '-0.03em'
  passwordText.style.fontFamily = monoFont
  passwordText.style.wordBreak = 'break-all'
  passwordText.style.color = '#111827'
  const suggestionActions = document.createElement('div')
  suggestionActions.style.display = 'flex'
  suggestionActions.style.gap = '6px'
  suggestionActions.style.marginTop = '10px'
  suggestionActions.style.alignItems = 'center'
  suggestionActions.style.width = '100%'
  const fillButton = document.createElement('button')
  fillButton.type = 'button'
  setButtonContent(fillButton, 'fill', 'Fill', 'Fill password')
  applyButtonStyles(fillButton, {
    background: 'rgba(115, 226, 160, 0.22)',
    color: '#14532d',
    border: '1px solid rgba(34, 197, 94, 0.42)'
  }, { stretch: false, height: '34px', padding: '0 10px', borderRadius: '2px', fontSize: '12px' })
  const copyButton = document.createElement('button')
  copyButton.type = 'button'
  setButtonContent(copyButton, 'copy', 'Copy', 'Copy password')
  applyButtonStyles(copyButton, {
    background: 'rgba(255, 255, 255, 0.82)',
    color: '#1f2937',
    border: '1px solid rgba(53, 66, 87, 0.12)'
  }, { stretch: false, height: '34px', padding: '0 10px', borderRadius: '2px', fontSize: '12px' })
  const refreshButton = document.createElement('button')
  refreshButton.type = 'button'
  setButtonIcon(refreshButton, 'refresh', 'Refresh password')
  applyButtonStyles(refreshButton, {
    background: 'rgba(255, 255, 255, 0.82)',
    color: '#1f2937',
    border: '1px solid rgba(53, 66, 87, 0.12)'
  }, { stretch: false, height: '34px', padding: '0', borderRadius: '2px', fontSize: '12px' })
  refreshButton.style.width = '34px'
  refreshButton.style.minWidth = '34px'
  const dismissButton = document.createElement('button')
  dismissButton.type = 'button'
  setButtonIcon(dismissButton, 'dismiss', 'Dismiss suggestion')
  applyButtonStyles(dismissButton, {
    background: 'transparent',
    color: '#6b7280',
    border: '1px solid transparent'
  }, { stretch: false, height: '34px', padding: '0', borderRadius: '2px', fontSize: '12px' })
  dismissButton.style.border = 'none'
  dismissButton.style.background = 'transparent'
  dismissButton.style.padding = '0'
  dismissButton.style.height = '34px'
  dismissButton.style.width = '34px'
  dismissButton.style.minWidth = '34px'
  dismissButton.style.fontWeight = '500'
  dismissButton.style.color = '#6b7280'
  dismissButton.style.marginLeft = 'auto'
  const feedback = document.createElement('div')
  feedback.style.marginTop = '8px'
  feedback.style.fontSize = '11px'
  feedback.style.display = 'none'
  feedback.style.lineHeight = '1.4'
  feedback.style.color = '#6b7280'
  fillButton.addEventListener('click', handleSuggestionPrimaryClick)
  copyButton.addEventListener('click', handleSuggestionSecondaryClick)
  refreshButton.addEventListener('click', handleSuggestionRefreshClick)
  dismissButton.addEventListener('click', handleDismissClick)
  attachTooltip(refreshButton, 'Refresh password')
  attachTooltip(dismissButton, 'Dismiss suggestion')
  suggestionActions.append(fillButton, copyButton, refreshButton, dismissButton)
  suggestionCard.append(cardHeader, suggestionSubtitle, credentialSelect, passwordText, suggestionActions, feedback)
  suggestionRoot.appendChild(suggestionCard)
  const saveRoot = document.createElement('div')
  saveRoot.id = 'securepass-save-root'
  saveRoot.style.position = 'fixed'
  saveRoot.style.right = '16px'
  saveRoot.style.bottom = '16px'
  saveRoot.style.zIndex = '2147483647'
  saveRoot.style.display = 'none'
  saveRoot.style.fontFamily = sansFont
  const saveCard = document.createElement('div')
  saveCard.style.width = '304px'
  saveCard.style.maxWidth = 'calc(100vw - 32px)'
  saveCard.style.padding = '14px'
  saveCard.style.borderRadius = '2px'
  saveCard.style.border = '1px solid rgba(53, 66, 87, 0.14)'
  saveCard.style.background = 'rgba(255, 255, 255, 0.985)'
  saveCard.style.backdropFilter = 'blur(18px)'
  saveCard.style.boxShadow = '0 24px 48px -28px rgba(40, 48, 67, 0.22), 0 8px 18px -12px rgba(40, 48, 67, 0.1)'
  saveCard.style.color = '#1f2937'
  const saveMessage = document.createElement('div')
  saveMessage.textContent = 'Save login for this site?'
  saveMessage.style.fontSize = '14px'
  saveMessage.style.fontWeight = '600'
  saveMessage.style.letterSpacing = '-0.01em'
  const saveDetails = document.createElement('div')
  saveDetails.style.marginTop = '6px'
  saveDetails.style.fontSize = '11px'
  saveDetails.style.color = '#6b7280'
  saveDetails.style.lineHeight = '1.45'
  const saveActions = document.createElement('div')
  saveActions.style.display = 'flex'
  saveActions.style.gap = '6px'
  saveActions.style.marginTop = '12px'
  saveActions.style.flexWrap = 'wrap'
  saveActions.style.justifyContent = 'flex-end'
  const saveButton = document.createElement('button')
  saveButton.type = 'button'
  setButtonContent(saveButton, 'save', 'Save', 'Save login')
  applyButtonStyles(saveButton, {
    background: 'rgba(115, 226, 160, 0.22)',
    color: '#14532d',
    border: '1px solid rgba(34, 197, 94, 0.42)'
  }, { stretch: false, height: '34px', padding: '0 10px', borderRadius: '2px', fontSize: '12px' })
  const neverButton = document.createElement('button')
  neverButton.type = 'button'
  setButtonContent(neverButton, 'never', 'Never', 'Never save for this site')
  applyButtonStyles(neverButton, {
    background: 'rgba(255, 255, 255, 0.82)',
    color: '#1f2937',
    border: '1px solid rgba(53, 66, 87, 0.12)'
  }, { stretch: false, height: '34px', padding: '0 10px', borderRadius: '2px', fontSize: '12px' })
  const laterButton = document.createElement('button')
  laterButton.type = 'button'
  setButtonContent(laterButton, 'later', 'Later', 'Decide later')
  applyButtonStyles(laterButton, {
    background: 'transparent',
    color: '#6b7280',
    border: '1px solid transparent'
  }, { stretch: false, height: '34px', padding: '0 10px', borderRadius: '2px', fontSize: '12px' })
  saveButton.addEventListener('click', handleSaveCredentialConfirm)
  neverButton.addEventListener('click', handleNeverSaveDomain)
  laterButton.addEventListener('click', hideSavePrompt)
  saveActions.append(saveButton, neverButton, laterButton)
  saveCard.append(saveMessage, saveDetails, saveActions)
  saveRoot.appendChild(saveCard)
  document.documentElement.appendChild(tooltipRoot)
  document.documentElement.appendChild(suggestionRoot)
  document.documentElement.appendChild(triggerRoot)
  document.documentElement.appendChild(saveRoot)
  UI.suggestionRoot = suggestionRoot
  UI.suggestionCard = suggestionCard
  UI.title = title
  UI.passwordText = passwordText
  UI.suggestionSubtitle = suggestionSubtitle
  UI.cardHeader = cardHeader
  UI.strengthBadge = strengthBadge
  UI.credentialSelect = credentialSelect
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
  UI.tooltipRoot = tooltipRoot
  UI.tooltipBubble = tooltipBubble
  applyCurrentThemeToUi()
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
  activeCredentialList = credentials
  activePassword = ''
  activePasswordOptions = null
  generatedPasswordField = null
  setStrengthBadge('')
  setSuggestionPasswordText(activeCredential.usernamePreview || 'Saved account', false)
  setSuggestionSubtitle(credentials.length > 1
    ? `Saved logins for ${activeCredential.domain}. Choose an account above.`
    : `Saved login for ${activeCredential.domain}. Device verification is required before fill.`)
  if (UI.credentialSelect) {
    while (UI.credentialSelect.firstChild) UI.credentialSelect.removeChild(UI.credentialSelect.firstChild)
    credentials.forEach((credential, index) => {
      const option = document.createElement('option')
      option.value = String(index)
      option.textContent = credential.usernamePreview || credential.domain || `Account ${index + 1}`
      UI.credentialSelect.appendChild(option)
    })
    UI.credentialSelect.value = '0'
    UI.credentialSelect.style.display = credentials.length > 1 ? 'block' : 'none'
  }
  setButtonContent(UI.fillButton, 'fill', 'Fill login', 'Fill login')
  setButtonContent(UI.copyButton, 'copy', 'Copy username', 'Copy username')
  if (UI.refreshButton) {
    UI.refreshButton.style.display = 'none'
  }
  UI.dismissButton.textContent = 'Dismiss'
  UI.suggestionRoot.style.display = 'block'
  setFeedback('', 'neutral')
  scheduleReposition()
  return true
}
async function showGeneratedSuggestion(field) {
  ensureUi()
  if (!isEligibleSuggestionField(field)) {
    hideSuggestion()
    return false
  }
  activeField = field
  activeCredential = null
  activeCredentialList = []
  const shouldReusePassword = generatedPasswordField === field && activePassword
  if (!shouldReusePassword) {
    const options = await getPasswordOptions()
    if (activeField !== field || activeCredential) return false
    activePassword = generatePassword(options)
    activePasswordOptions = options
    generatedPasswordField = field
  }
  if (UI.credentialSelect) UI.credentialSelect.style.display = 'none'
  setSuggestionPasswordText(activePassword, true)
  setSuggestionSubtitle('')
  applyPasswordStrengthBadge(activePassword, activePasswordOptions)
  setButtonContent(UI.fillButton, 'fill', 'Fill', 'Fill password')
  setButtonContent(UI.copyButton, 'copy', 'Copy', 'Copy password')
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
  // Respect the user's "Password Suggestion" toggle from Settings
  const suggestionEnabled = await getStorageValue(STORAGE_KEYS.SUGGESTION_ENABLED, true)
  if (suggestionEnabled === false) {
    hideSuggestion()
    return null
  }
  const field = getPreferredSuggestionField()
  if (!field) {
    hideSuggestion()
    return null
  }
  const credentials = await getSavedCredentials(location.hostname)
  const isSignInContext = getPasswordFields(field.form || document).length === 1
  if (isSignInContext && credentials.length) {
    if (!dismissedFields.has(field)) {
      await showCredentialSuggestion(field, credentials)
      return field
    }
  }
  await showGeneratedSuggestion(field)
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
  activeCredentialList = []
}
async function handleSuggestionRefreshClick(event) {
  event.preventDefault()
  if (!activeField || activeCredential) return
  const field = activeField
  const options = await getPasswordOptions()
  if (activeField !== field || activeCredential) return
  activePassword = generatePassword(options)
  activePasswordOptions = options
  generatedPasswordField = field
  setSuggestionPasswordText(activePassword, true)
  applyPasswordStrengthBadge(activePassword, activePasswordOptions)
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
  isCurrentDomainDismissed = true
  addDomainToDismissed()
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
  isCurrentDomainDismissed = false
  removeDomainFromDismissed()
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
    if (!dismissedFields.has(field)) {
      await showCredentialSuggestion(field, credentials)
      return
    }
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
  await syncUiTheme()
  await loadDismissalState()
  await restorePendingSavePrompt()
  scheduleAutoShow(0)
}
if (extensionChrome?.storage?.onChanged?.addListener) {
  extensionChrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== 'local') return
    if (changes[THEME_KEY]) {
      const nextTheme = changes[THEME_KEY].newValue
      activeThemeMode = getPreferredTheme(nextTheme)
      applyCurrentThemeToUi()
    }
    if (GENERATOR_SETTING_KEYS.some(key => changes[key])) {
      cachedPasswordOptions = null
    }
    if (changes[DISMISSED_DOMAINS_KEY]) {
      loadDismissalState()
    }
  })
}
if (typeof window !== 'undefined' && window.matchMedia) {
  const systemThemeQuery = window.matchMedia('(prefers-color-scheme: dark)')
  const handleSystemThemeChange = async () => {
    const storedTheme = await getStorageValue(THEME_KEY, 'system')
    if (storedTheme === 'system' || storedTheme == null) {
      activeThemeMode = getPreferredTheme(storedTheme)
      applyCurrentThemeToUi()
    }
  }
  if (typeof systemThemeQuery.addEventListener === 'function') {
    systemThemeQuery.addEventListener('change', handleSystemThemeChange)
  } else if (typeof systemThemeQuery.addListener === 'function') {
    systemThemeQuery.addListener(handleSystemThemeChange)
  }
}
if (extensionChrome?.runtime?.onMessage) {
  extensionChrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'fillPassword') {
      const password = request.password || activePassword
      if (password) {
        sendResponse(fillPasswordFields(password, activeField))
        return true
      }
      // History for popup-triggered autofill is recorded by the popup, which
      // can include the encrypted password and password type.
      getPasswordOptions().then((options) => {
        sendResponse(fillPasswordFields(generatePassword(options), activeField))
      })
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
function handleKeyDown(event) {
  if (event.key !== 'Escape') return

  let handled = false

  if (UI.saveRoot?.style.display === 'block') {
    hideSavePrompt()
    handled = true
  }

  if (UI.suggestionRoot?.style.display === 'block') {
    hideSuggestion()
    hideTrigger()
    handled = true
  }

  if (handled) {
    event.preventDefault()
    event.stopPropagation()
  }
}
document.addEventListener('focusin', handleFocusIn, true)
document.addEventListener('pointerdown', handlePointerDown, true)
document.addEventListener('input', handleInput, true)
document.addEventListener('submit', handleFormSubmit, true)
document.addEventListener('keydown', handleKeyDown, true)
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
  buildCharset,
  decryptText,
  encryptText,
  fillPasswordFields,
  fillSavedCredential,
  findPasswordFields,
  generatePassword,
  getCredentialPayloadFromForm,
  getEligibleSuggestionFields,
  getPreferredSuggestionField,
  getPasswordOptions,
  getPasswordCharColor,
  getPasswordStrengthInfo,
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
  showCredentialSuggestion,
  showSuggestionForFirstEligibleField
}
