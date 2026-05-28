import React, { useCallback, useEffect, useRef, useState } from 'react'
import { History, Info, KeyRound, Settings, Wand2, Moon, Sun, ShieldCheck } from 'lucide-react'

import { storageManager, STORAGE_KEYS } from './storageUtils'
import SecurePasswordGenerator from './securePasswordGenerator'
import MemorablePasswordGenerator from './memorablePasswordGenerator'
import { PASSWORD_TEMPLATES } from './passwordTemplates'
import { generatePasswordBatch } from './batchPasswordGenerator'
import { PASSWORD_POLICIES, validatePasswordPolicy } from './passwordPolicies'
import { GENERATOR_SHORTCUTS, getGeneratorShortcutAction } from './keyboardShortcuts'
import { encryptForHistory, decryptText } from './lib/crypto'
import { enrollPlatformCredential, isAuthWindowValid, verifyPlatformCredential } from './lib/webauthn'
import logoUrl from '../icons/icon48.png'
import manifest from '../manifest.json'
import pkg from '../package.json'

import PasswordControls from './components/PasswordControls'
import GeneratedPasswordCard from './components/GeneratedPasswordCard'
import ActionButtons from './components/ActionButtons'
import HistoryPanel from './components/HistoryPanel'
import VaultPanel from './components/VaultPanel'
import SettingsPanel from './components/SettingsPanel'
import { Slider } from './components/ui/slider'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './components/ui/select'
import { Badge } from './components/ui/badge'

const secureGen = new SecurePasswordGenerator()
const memorableGen = new MemorablePasswordGenerator()
const SYMBOL_SETS = secureGen.getSymbolSets()

// ---------- helpers ----------

function generatePasswordForTab(tab, opts) {
  if (tab === 'memorable') {
    return memorableGen.generateMemorablePassword({
      wordCount: opts.wordCount,
      includeCapitalization: opts.includeCapitalization,
    })
  }
  if (tab === 'pin') {
    const chars = '0123456789'
    const arr = new Uint32Array(opts.pinLength)
    crypto.getRandomValues(arr)
    return Array.from(arr).map(v => chars[v % chars.length]).join('')
  }
  if (tab === 'hex') {
    const chars = '0123456789abcdef'
    const arr = new Uint32Array(opts.hexLength)
    crypto.getRandomValues(arr)
    return Array.from(arr).map(v => chars[v % chars.length]).join('')
  }
  return secureGen.generateSecurePassword({
    length: opts.length,
    includeUppercase: opts.includeUppercase,
    includeLowercase: opts.includeLowercase,
    includeNumbers: opts.includeNumbers,
    includeSymbols: opts.includeSymbols,
    symbolSet: opts.symbolSet,
    customSymbols: opts.customSymbols,
    excludeAmbiguous: opts.excludeAmbiguous,
  })
}

function formatTimestamp(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  const now = new Date()
  const diffMins = Math.floor((now - d) / 60000)
  if (diffMins < 1) return 'Just now'
  if (diffMins < 60) return `${diffMins}m ago`
  const diffHrs = Math.floor(diffMins / 60)
  if (diffHrs < 24) return `${diffHrs}h ago`
  return d.toLocaleDateString()
}

function getPasswordTypeIcon(type) {
  if (type === 'memorable') return <Wand2 size={14} />
  if (type === 'pin') return <ShieldCheck size={14} />
  return <KeyRound size={14} />
}

const SliderField = ({
  label,
  min,
  max,
  value,
  onChange,
  dragging,
  setDragging,
  ariaLabel
}) => (
  <div className="space-y-4">
    <div className="flex items-baseline justify-between gap-3">
      <label className="text-sm font-medium text-foreground">{label} <span className="text-muted-foreground">({min}-{max})</span></label>
      <span className="text-sm text-foreground font-semibold">{value} {ariaLabel.toLowerCase()}</span>
    </div>
    <div
      className="relative"
      onMouseDown={() => setDragging(true)}
      onMouseUp={() => setDragging(false)}
      onMouseLeave={() => setDragging(false)}
      onTouchStart={() => setDragging(true)}
      onTouchEnd={() => setDragging(false)}
    >
      <Slider
        value={[value]}
        min={min}
        max={max}
        onValueChange={(val) => onChange(val[0])}
        aria-label={ariaLabel}
      />
      <div
        className="absolute -top-8 translate-x-[-50%] rounded-sm border border-border/60 bg-popover px-2 py-0.5 text-[10px] text-popover-foreground shadow-sm transition-all duration-150 ease-out"
        style={{ left: `${Math.min(100, Math.max(0, ((value - min) / (max - min)) * 100))}%` }}
        data-active={dragging ? 'true' : 'false'}
      >
        {value}
      </div>
    </div>
  </div>
)

const PasswordTemplates = ({ onApplyTemplate }) => (
  <div className="rounded-sm border border-border/80 bg-card/80 px-4 py-3.5 shadow-none">
    <div className="mb-3 flex items-start justify-between gap-3">
      <div>
        <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Templates</div>
        <div className="mt-1 text-xs text-muted-foreground">Apply secure presets for common use cases</div>
      </div>
    </div>
    <div className="grid grid-cols-2 gap-2">
      {PASSWORD_TEMPLATES.map(template => (
        <button
          key={template.id}
          type="button"
          onClick={() => onApplyTemplate(template)}
          className="rounded-sm border border-border/70 bg-background/35 px-3 py-2 text-left transition-colors hover:border-primary/50 hover:bg-primary/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <div className="text-xs font-medium text-foreground">{template.name}</div>
          <div className="mt-1 text-[11px] leading-4 text-muted-foreground">{template.description}</div>
        </button>
      ))}
    </div>
  </div>
)

const PasswordBatchPanel = ({ passwords, onGenerateBatch, onCopyPassword, disabled }) => (
  <div className="rounded-sm border border-border/80 bg-card/80 px-4 py-3.5 shadow-none">
    <div className="mb-3 flex items-start justify-between gap-3">
      <div>
        <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Batch</div>
        <div className="mt-1 text-xs text-muted-foreground">Generate multiple options with current settings</div>
      </div>
      <button
        type="button"
        onClick={onGenerateBatch}
        disabled={disabled}
        className="inline-flex items-center gap-1.5 rounded-sm border border-border/80 bg-background/45 px-3 py-1.5 text-[11px] font-medium text-foreground transition-colors hover:bg-primary/10 disabled:cursor-not-allowed disabled:opacity-50"
      >
        <span>Generate 5</span>
        <Badge variant="outline" className="rounded-sm px-1.5 py-0 text-[10px] leading-4 text-muted-foreground" aria-hidden="true">
          B
        </Badge>
      </button>
    </div>

    {passwords.length > 0 ? (
      <div className="space-y-2">
        {passwords.map((item, index) => (
          <div key={`${item}-${index}`} className="flex items-center gap-2 rounded-sm border border-border/60 bg-background/35 px-3 py-2">
            <div className="min-w-0 flex-1 truncate font-mono text-xs text-foreground">{item}</div>
            <button
              type="button"
              onClick={() => onCopyPassword(item)}
              className="shrink-0 rounded-sm border border-border/70 px-2 py-1 text-[11px] font-medium text-muted-foreground transition-colors hover:text-foreground"
            >
              Copy
            </button>
          </div>
        ))}
      </div>
    ) : (
      <div className="rounded-sm border border-dashed border-border/70 bg-background/25 px-3 py-3 text-xs text-muted-foreground">
        No batch generated yet. Use this when you want to compare several candidates before copying one.
      </div>
    )}
  </div>
)

const PasswordPolicyPanel = ({ password, policyId, onPolicyChange }) => {
  const result = validatePasswordPolicy(password, policyId)

  return (
    <div className="rounded-sm border border-border/80 bg-card/80 px-4 py-3.5 shadow-none">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Policy check</div>
          <div className="mt-1 text-xs text-muted-foreground">Validate the current password against common requirements</div>
        </div>
        <div className={`rounded-sm border px-2 py-1 text-[11px] font-medium ${result.passed ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400'}`}>
          {result.passedCount}/{result.totalCount}
        </div>
      </div>

      <Select value={policyId} onValueChange={onPolicyChange}>
        <SelectTrigger className="h-9 text-xs" aria-label="Password policy">
          <SelectValue placeholder="Choose policy" />
        </SelectTrigger>
        <SelectContent>
          {PASSWORD_POLICIES.map(policy => (
            <SelectItem key={policy.id} value={policy.id}>{policy.name}</SelectItem>
          ))}
        </SelectContent>
      </Select>

      <div className="mt-3 text-[11px] leading-4 text-muted-foreground">
        {result.policy.description}
      </div>

      <div className="mt-3 grid grid-cols-1 gap-1.5">
        {result.checks.map(check => (
          <div key={check.id} className="flex items-center justify-between gap-2 rounded-sm border border-border/60 bg-background/35 px-3 py-1.5 text-[11px]">
            <span className="text-muted-foreground">{check.label}</span>
            <span className={check.passed ? 'font-medium text-emerald-600 dark:text-emerald-400' : 'font-medium text-amber-600 dark:text-amber-400'}>
              {check.passed ? 'Pass' : 'Missing'}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

const KeyboardShortcutsPanel = () => (
  <div className="rounded-sm border border-border/80 bg-card/80 px-4 py-3.5 shadow-none">
    <div className="mb-3">
      <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Shortcuts</div>
      <div className="mt-1 text-xs text-muted-foreground">Use these keys while the generator is open</div>
    </div>
    <div className="grid grid-cols-3 gap-2">
      {GENERATOR_SHORTCUTS.map(shortcut => (
        <div key={shortcut.key} className="rounded-sm border border-border/60 bg-background/35 px-2.5 py-2 text-center">
          <div className="mx-auto flex h-6 w-6 items-center justify-center rounded-sm border border-border/70 bg-background text-xs font-semibold text-foreground">
            {shortcut.label}
          </div>
          <div className="mt-1.5 text-[10px] leading-3 text-muted-foreground">{shortcut.description}</div>
        </div>
      ))}
    </div>
  </div>
)

const AboutPanel = () => (
  <div className="space-y-3">
    <div className="rounded-sm border border-border/80 bg-card/80 px-5 py-6 text-center shadow-none">
      <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-sm border border-border/80 bg-background shadow-sm">
        <img src={logoUrl} alt="SecurePass logo" className="h-9 w-9 object-contain" />
      </div>
      <h2 className="mt-4 text-base font-semibold tracking-tight">{manifest.name}</h2>
      <p className="mt-1 text-xs text-muted-foreground">Version {manifest.version}</p>
      <p className="mx-auto mt-4 max-w-[280px] text-sm leading-6 text-muted-foreground">
        {manifest.description}
      </p>
    </div>

    <div className="rounded-sm border border-border/70 bg-background/55 px-4 py-3 text-xs leading-5 text-muted-foreground">
      <h3 className="mb-2 text-sm font-medium text-foreground">What it does</h3>
      <div className="grid grid-cols-2 gap-2">
        <div className="rounded-sm border border-border/60 bg-card/55 px-3 py-2">Random passwords</div>
        <div className="rounded-sm border border-border/60 bg-card/55 px-3 py-2">Memorable passphrases</div>
        <div className="rounded-sm border border-border/60 bg-card/55 px-3 py-2">PIN generation</div>
        <div className="rounded-sm border border-border/60 bg-card/55 px-3 py-2">Hexadecimal secrets</div>
      </div>
    </div>

    <div className="rounded-sm border border-border/70 bg-background/55 px-4 py-3 text-xs leading-5 text-muted-foreground">
      <h3 className="mb-2 text-sm font-medium text-foreground">Privacy & security</h3>
      <div className="space-y-1.5">
        <div>Passwords are generated locally on your device.</div>
        <div>History and saved logins are stored locally using extension storage.</div>
        <div>Saved secrets require device verification before reveal or copy.</div>
        <div>No account, sync service, or remote server is required.</div>
      </div>
    </div>

    <div className="rounded-sm border border-border/70 bg-background/55 px-4 py-3 text-xs leading-5 text-muted-foreground">
      <h3 className="mb-2 text-sm font-medium text-foreground">Extension permissions</h3>
      <div className="space-y-1.5">
        <div><span className="font-medium text-foreground">Storage:</span> save settings, history, and encrypted login data.</div>
        <div><span className="font-medium text-foreground">Clipboard:</span> copy generated passwords when requested.</div>
        <div><span className="font-medium text-foreground">Active tab:</span> autofill passwords into the current page.</div>
      </div>
    </div>

    <div className="rounded-sm border border-border/70 bg-background/55 px-4 py-3 text-xs leading-5 text-muted-foreground">
      <div className="flex items-center justify-between gap-3">
        <span>Extension version</span>
        <span className="font-medium text-foreground">v{manifest.version}</span>
      </div>
      <div className="mt-2 flex items-center justify-between gap-3">
        <span>Package version</span>
        <span className="font-medium text-foreground">v{pkg.version}</span>
      </div>
      <div className="mt-2 flex items-center justify-between gap-3">
        <span>Data model</span>
        <span className="font-medium text-foreground">Local only</span>
      </div>
    </div>
  </div>
)

// ---------- simple inline toast ----------

function useToast() {
  const [msg, setMsg] = useState(null) // { text, type }
  const timerRef = useRef(null)

  const toast = useCallback((text, type = 'success') => {
    if (timerRef.current) clearTimeout(timerRef.current)
    setMsg({ text, type })
    timerRef.current = setTimeout(() => setMsg(null), 2200)
  }, [])

  useEffect(() => () => { if (timerRef.current) clearTimeout(timerRef.current) }, [])

  const ToastUI = msg ? (
    <div
      className={`fixed bottom-4 left-1/2 z-50 -translate-x-1/2 whitespace-nowrap rounded-sm px-4 py-2 text-xs font-medium shadow-lg ${
        msg.type === 'error' ? 'bg-rose-600 text-white' : 'bg-emerald-600 text-white'
      }`}
    >
      {msg.text}
    </div>
  ) : null

  return { toast, ToastUI }
}

// ---------- nav ----------

const NAV_TABS = [
  { id: 'generator', label: 'Generator', icon: Wand2 },
  { id: 'history',   label: 'History',   icon: History },
  { id: 'vault',     label: 'Vault',     icon: KeyRound },
  { id: 'settings',  label: 'Settings',  icon: Settings },
]

// ---------- component ----------

export default function PopupApp() {
  const { toast, ToastUI } = useToast()

  // ── theme ──
  const [isDark, setIsDark] = useState(() =>
    document.documentElement.classList.contains('dark')
  )
  const toggleTheme = () => {
    const next = isDark ? 'light' : 'dark'
    document.documentElement.classList.remove('light', 'dark')
    document.documentElement.classList.add(next)
    document.documentElement.setAttribute('data-theme', next)
    localStorage.setItem('vite-ui-theme', next)
    setIsDark(next === 'dark')
    storageManager.setSetting(STORAGE_KEYS.THEME, next)
  }

  // ── navigation ──
  const [activeView, setActiveView] = useState('generator')

  // ── generator controls ──
  const [activeTab, setActiveTab] = useState('random')
  const [length, setLength] = useState(20)
  const [includeNumbers, setIncludeNumbers] = useState(true)
  const [includeSymbols, setIncludeSymbols] = useState(false)
  const [symbolSet, setSymbolSet] = useState('basic')
  const [customSymbols, setCustomSymbols] = useState('')
  const [wordCount, setWordCount] = useState(3)
  const [includeCapitalization, setIncludeCapitalization] = useState(true)
  const [pinLength, setPinLength] = useState(4)
  const [includeUppercase, setIncludeUppercase] = useState(true)
  const [includeLowercase, setIncludeLowercase] = useState(true)
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(false)
  const [hexLength, setHexLength] = useState(64)

  // ── generated password ──
  const [password, setPassword] = useState('')
  const [batchPasswords, setBatchPasswords] = useState([])
  const [policyId, setPolicyId] = useState('standard')

  // ── history ──
  const [historyData, setHistoryData] = useState([])
  const [historyStats, setHistoryStats] = useState(null)
  const [historyEnabled, setHistoryEnabledState] = useState(true)
  const [historyClearOnClose, setHistoryClearOnCloseState] = useState(false)
  const [showConfirmModal, setShowConfirmModal] = useState(false)
  const [confirmModalMode, setConfirmModalMode] = useState(null)

  // ── vault ──
  const [credentialsData, setCredentialsData] = useState([])
  const [credentialsEnabled, setCredentialsEnabledState] = useState(true)

  // ── settings ──
  const [suggestionEnabled, setSuggestionEnabledState] = useState(true)

  // ── dragging states ──
  const [draggingLen, setDraggingLen] = useState(false)
  const [draggingWords, setDraggingWords] = useState(false)
  const [draggingPin, setDraggingPin] = useState(false)
  const [draggingHex, setDraggingHex] = useState(false)

  // ── boot: load from storage ──
  useEffect(() => {
    storageManager.getAllSettings().then(s => {
      setActiveTab(s[STORAGE_KEYS.ACTIVE_TAB] || 'random')
      setLength(s[STORAGE_KEYS.LENGTH] ?? 20)
      setIncludeNumbers(s[STORAGE_KEYS.INCLUDE_NUMBERS] ?? true)
      setIncludeSymbols(s[STORAGE_KEYS.INCLUDE_SYMBOLS] ?? false)
      setSymbolSet(s[STORAGE_KEYS.SYMBOL_SET] || 'basic')
      setCustomSymbols(s[STORAGE_KEYS.CUSTOM_SYMBOLS] || '')
      setWordCount(s[STORAGE_KEYS.WORD_COUNT] ?? 3)
      setIncludeCapitalization(s[STORAGE_KEYS.INCLUDE_CAPITALIZATION] ?? true)
      setPinLength(s[STORAGE_KEYS.PIN_LENGTH] ?? 4)
      setHistoryEnabledState(s[STORAGE_KEYS.HISTORY_ENABLED] ?? true)
      setHistoryClearOnCloseState(s[STORAGE_KEYS.HISTORY_CLEAR_ON_CLOSE] ?? false)
      setCredentialsEnabledState(s[STORAGE_KEYS.CREDENTIALS_ENABLED] ?? true)
      setSuggestionEnabledState(s[STORAGE_KEYS.SUGGESTION_ENABLED] ?? true)
      setIncludeUppercase(s[STORAGE_KEYS.INCLUDE_UPPERCASE] ?? true)
      setIncludeLowercase(s[STORAGE_KEYS.INCLUDE_LOWERCASE] ?? true)
      setExcludeAmbiguous(s[STORAGE_KEYS.EXCLUDE_AMBIGUOUS] ?? false)
      setHexLength(s[STORAGE_KEYS.HEX_LENGTH] ?? 64)
    })
    refreshHistory()
    refreshCredentials()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // persist generator settings to storage
  useEffect(() => { storageManager.setSetting(STORAGE_KEYS.ACTIVE_TAB, activeTab) }, [activeTab])
  useEffect(() => { storageManager.setSetting(STORAGE_KEYS.LENGTH, length) }, [length])
  useEffect(() => { storageManager.setSetting(STORAGE_KEYS.INCLUDE_NUMBERS, includeNumbers) }, [includeNumbers])
  useEffect(() => { storageManager.setSetting(STORAGE_KEYS.INCLUDE_SYMBOLS, includeSymbols) }, [includeSymbols])
  useEffect(() => { storageManager.setSetting(STORAGE_KEYS.SYMBOL_SET, symbolSet) }, [symbolSet])
  useEffect(() => { storageManager.setSetting(STORAGE_KEYS.CUSTOM_SYMBOLS, customSymbols) }, [customSymbols])
  useEffect(() => { storageManager.setSetting(STORAGE_KEYS.WORD_COUNT, wordCount) }, [wordCount])
  useEffect(() => { storageManager.setSetting(STORAGE_KEYS.INCLUDE_CAPITALIZATION, includeCapitalization) }, [includeCapitalization])
  useEffect(() => { storageManager.setSetting(STORAGE_KEYS.PIN_LENGTH, pinLength) }, [pinLength])
  useEffect(() => { storageManager.setSetting(STORAGE_KEYS.INCLUDE_UPPERCASE, includeUppercase) }, [includeUppercase])
  useEffect(() => { storageManager.setSetting(STORAGE_KEYS.INCLUDE_LOWERCASE, includeLowercase) }, [includeLowercase])
  useEffect(() => { storageManager.setSetting(STORAGE_KEYS.EXCLUDE_AMBIGUOUS, excludeAmbiguous) }, [excludeAmbiguous])
  useEffect(() => { storageManager.setSetting(STORAGE_KEYS.HEX_LENGTH, hexLength) }, [hexLength])

  // ── auto-regenerate password ──
  const refreshPassword = useCallback(() => {
    const p = generatePasswordForTab(activeTab, {
      length, includeNumbers, includeSymbols, symbolSet, customSymbols,
      wordCount, includeCapitalization, pinLength,
      includeUppercase, includeLowercase, excludeAmbiguous, hexLength,
    })
    setPassword(p)
  }, [activeTab, length, includeNumbers, includeSymbols, symbolSet, customSymbols,
      wordCount, includeCapitalization, pinLength,
      includeUppercase, includeLowercase, excludeAmbiguous, hexLength])

  useEffect(() => { refreshPassword() }, [refreshPassword])

  useEffect(() => { setBatchPasswords([]) }, [refreshPassword])

  // ── safe toggle handlers ──
  const handleToggleUppercase = (val) => {
    if (!val && !includeLowercase && !includeNumbers && !includeSymbols) {
      toast('At least one character type must be selected', 'error')
      return
    }
    setIncludeUppercase(val)
  }

  const handleToggleLowercase = (val) => {
    if (!val && !includeUppercase && !includeNumbers && !includeSymbols) {
      toast('At least one character type must be selected', 'error')
      return
    }
    setIncludeLowercase(val)
  }

  const handleToggleNumbers = (val) => {
    if (!val && !includeUppercase && !includeLowercase && !includeSymbols) {
      toast('At least one character type must be selected', 'error')
      return
    }
    setIncludeNumbers(val)
  }

  const handleToggleSymbols = (val) => {
    if (!val && !includeUppercase && !includeLowercase && !includeNumbers) {
      toast('At least one character type must be selected', 'error')
      return
    }
    setIncludeSymbols(val)
  }

  const applyPasswordTemplate = useCallback((template) => {
    const s = template.settings

    setActiveTab(s.activeTab)

    if (s.length !== undefined) setLength(s.length)
    if (s.includeLowercase !== undefined) setIncludeLowercase(s.includeLowercase)
    if (s.includeUppercase !== undefined) setIncludeUppercase(s.includeUppercase)
    if (s.includeNumbers !== undefined) setIncludeNumbers(s.includeNumbers)
    if (s.includeSymbols !== undefined) setIncludeSymbols(s.includeSymbols)
    if (s.symbolSet !== undefined) setSymbolSet(s.symbolSet)
    if (s.customSymbols !== undefined) setCustomSymbols(s.customSymbols)
    if (s.excludeAmbiguous !== undefined) setExcludeAmbiguous(s.excludeAmbiguous)
    if (s.wordCount !== undefined) setWordCount(s.wordCount)
    if (s.includeCapitalization !== undefined) setIncludeCapitalization(s.includeCapitalization)
    if (s.pinLength !== undefined) setPinLength(s.pinLength)
    if (s.hexLength !== undefined) setHexLength(s.hexLength)

    toast(`${template.name} template applied`)
  }, [toast])

  // ── history helpers ──
  async function refreshHistory() {
    const data = await storageManager.getPasswordHistory(50)
    const stats = await storageManager.getPasswordHistoryStats()
    setHistoryData(data)
    setHistoryStats(stats)
  }

  async function exportHistory() {
    const data = await storageManager.getPasswordHistory(100)
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'password-history.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  async function clearHistory() {
    await storageManager.clearPasswordHistory()
    refreshHistory()
    toast('History cleared')
  }

  async function removeHistoryEntry(id) {
    await storageManager.removePasswordHistoryEntry(id)
    refreshHistory()
  }

  // ── vault helpers ──
  async function refreshCredentials() {
    const data = await storageManager.getSavedCredentials()
    setCredentialsData(data)
  }

  async function ensureVerified() {
    try {
      if (isAuthWindowValid()) return true
      let ok = await verifyPlatformCredential()
      if (ok) return true
      await enrollPlatformCredential()
      ok = await verifyPlatformCredential()
      return ok
    } catch { return false }
  }

  async function onCopyField(entry, field) {
    const ok = await ensureVerified()
    if (!ok) { toast('Verification failed', 'error'); return }
    try {
      const plain = await decryptText(field === 'username' ? entry.usernameEnc : entry.passwordEnc)
      await navigator.clipboard.writeText(plain)
      toast(`${field === 'username' ? 'Username' : 'Password'} copied`)
    } catch { toast('Unable to copy', 'error') }
  }

  async function onFillCredential(entry) {
    const ok = await ensureVerified()
    if (!ok) { toast('Verification failed', 'error'); return }
    try {
      const username = await decryptText(entry.usernameEnc)
      const pw = await decryptText(entry.passwordEnc)
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      if (!tab?.id) { toast('No active tab found', 'error'); return }
      const result = await chrome.tabs.sendMessage(tab.id, {
        action: 'fillSavedCredential',
        credential: { username, password: pw, id: entry.id },
      })
      if (result?.success) {
        await storageManager.touchSavedCredentialUsage(entry.id)
        refreshCredentials()
        toast('Login filled on page')
      } else {
        toast(result?.message || 'Could not fill on page', 'error')
      }
    } catch { toast('Could not fill on page', 'error') }
  }

  async function onRemoveCredential(id) {
    await storageManager.removeSavedCredential(id)
    refreshCredentials()
    toast('Login removed')
  }

  async function onUpdateCredentialLabel(id, label) {
    const updated = await storageManager.updateSavedCredentialLabel(id, label)
    if (!updated) {
      toast('Unable to update label', 'error')
      return
    }

    refreshCredentials()
    toast(updated.label ? 'Label updated' : 'Label cleared')
  }

  // ── settings toggle helpers ──
  const setHistoryEnabled = async (val) => {
    setHistoryEnabledState(val)
    await storageManager.setSetting(STORAGE_KEYS.HISTORY_ENABLED, val)
    toast(val ? 'History enabled' : 'History disabled')
  }

  const setHistoryClearOnClose = async (val) => {
    setHistoryClearOnCloseState(val)
    await storageManager.setSetting(STORAGE_KEYS.HISTORY_CLEAR_ON_CLOSE, val)
    toast(val ? 'Clear on close enabled' : 'Clear on close disabled')
  }

  const setCredentialsEnabled = async (val) => {
    setCredentialsEnabledState(val)
    await storageManager.setSetting(STORAGE_KEYS.CREDENTIALS_ENABLED, val)
    toast(val ? 'Saved logins enabled' : 'Saved logins disabled')
  }

  const setSuggestionEnabled = async (val) => {
    setSuggestionEnabledState(val)
    await storageManager.setSetting(STORAGE_KEYS.SUGGESTION_ENABLED, val)
    toast(val ? 'Password suggestion enabled' : 'Password suggestion disabled')
  }

  // ── copy & autofill ──
  async function handleCopy() {
    if (!password) return
    await navigator.clipboard.writeText(password)
    toast('Password copied')
    if (historyEnabled) {
      const enc = await encryptForHistory(password)
      await storageManager.addPasswordHistory('copy', activeTab, '', password.length, enc)
      refreshHistory()
    }
  }

  function handleGenerateBatch() {
    const batch = generatePasswordBatch(() => generatePasswordForTab(activeTab, {
      length, includeNumbers, includeSymbols, symbolSet, customSymbols,
      wordCount, includeCapitalization, pinLength,
      includeUppercase, includeLowercase, excludeAmbiguous, hexLength,
    }), 5)
    setBatchPasswords(batch)
    toast('Batch generated')
  }

  async function handleCopyBatchPassword(value) {
    if (!value) return
    await navigator.clipboard.writeText(value)
    toast('Password copied')
    if (historyEnabled) {
      const enc = await encryptForHistory(value)
      await storageManager.addPasswordHistory('copy', activeTab, '', value.length, enc)
      refreshHistory()
    }
  }

  async function handleAutofill() {
    if (!password) return
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      if (!tab?.id) { toast('No active tab found', 'error'); return }
      const result = await chrome.tabs.sendMessage(tab.id, {
        action: 'fillPassword',
        password,
      })
      if (result?.success) {
        toast(`Filled ${result.fieldsCount} field${result.fieldsCount !== 1 ? 's' : ''}`)
        if (historyEnabled) {
          const enc = await encryptForHistory(password)
          await storageManager.addPasswordHistory('autofill', activeTab, tab.url || '', password.length, enc)
          refreshHistory()
        }
      } else {
        toast(result?.message || 'No password field found', 'error')
      }
    } catch { toast('Could not reach the current page', 'error') }
  }

  useEffect(() => {
    if (activeView !== 'generator') return undefined

    const onKeyDown = (event) => {
      const action = getGeneratorShortcutAction(event)
      if (!action) return

      event.preventDefault()

      if (action === 'refresh') refreshPassword()
      if (action === 'copy') handleCopy()
      if (action === 'batch') handleGenerateBatch()
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [activeView, refreshPassword, password, historyEnabled, activeTab, length, includeNumbers, includeSymbols, symbolSet, customSymbols, wordCount, includeCapitalization, pinLength, includeUppercase, includeLowercase, excludeAmbiguous, hexLength])

  // ── clear-on-close confirmation callback ──
  const confirmClearOnClose = (enable) => {
    setHistoryClearOnCloseState(enable)
    storageManager.setSetting(STORAGE_KEYS.HISTORY_CLEAR_ON_CLOSE, enable)
    if (enable) storageManager.setSetting(STORAGE_KEYS.HISTORY_PENDING_CLEAR, true)
  }

  // ── render ──
  return (
    <div className="flex h-full min-h-[520px] w-[380px] flex-col bg-background text-foreground">
      {/* ── Header ── */}
      <header className="flex shrink-0 items-center justify-between border-b border-border/80 px-4 py-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-sm border border-border/80 bg-card shadow-sm">
            <img src={logoUrl} alt="SecurePass logo" className="h-5 w-5 object-contain" />
          </div>
          <span className="text-sm font-semibold tracking-tight">SecurePass</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setActiveView('about')}
            className={`inline-flex h-8 w-8 items-center justify-center rounded-sm border border-border/80 bg-card transition-colors hover:text-foreground ${activeView === 'about' ? 'text-primary' : 'text-muted-foreground'}`}
            aria-label="About SecurePass"
          >
            <Info size={15} />
          </button>
          <button
            type="button"
            onClick={toggleTheme}
            className="inline-flex h-8 w-8 items-center justify-center rounded-sm border border-border/80 bg-card text-muted-foreground transition-colors hover:text-foreground"
            aria-label="Toggle theme"
          >
            {isDark ? <Sun size={15} /> : <Moon size={15} />}
          </button>
        </div>
      </header>

      {/* ── Nav tabs ── */}
      <nav className="flex shrink-0 items-center gap-0.5 border-b border-border/80 bg-card/50 px-2 py-1.5">
        {NAV_TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            id={`nav-${id}`}
            onClick={() => setActiveView(id)}
            className={`flex flex-1 items-center justify-center gap-1.5 rounded-sm px-2 py-1.5 text-[11px] font-medium transition-colors ${
              activeView === id
                ? 'bg-primary/10 text-primary'
                : 'text-muted-foreground hover:bg-background/60 hover:text-foreground'
            }`}
          >
            <Icon size={13} />
            {label}
          </button>
        ))}
      </nav>

      {/* ── Main content ── */}
      <main className="flex-1 overflow-y-auto p-3">
        {/* Generator */}
        {activeView === 'generator' && (
          <div className="space-y-3">
            <div className="rounded-sm border border-border/80 bg-card/80 px-4 py-3.5 shadow-none space-y-4">
              <GeneratedPasswordCard password={password} />
              
              {/* Dynamic Length Slider */}
              <div className="border-t border-border/80 pt-4 pb-1">
                {activeTab === 'random' && (
                  <SliderField
                    label="Length"
                    min={4}
                    max={50}
                    value={length}
                    onChange={setLength}
                    dragging={draggingLen}
                    setDragging={setDraggingLen}
                    ariaLabel="Characters"
                  />
                )}
                {activeTab === 'memorable' && (
                  <SliderField
                    label="Word Count"
                    min={2}
                    max={6}
                    value={wordCount}
                    onChange={setWordCount}
                    dragging={draggingWords}
                    setDragging={setDraggingWords}
                    ariaLabel="Words"
                  />
                )}
                {activeTab === 'pin' && (
                  <SliderField
                    label="Digits"
                    min={4}
                    max={12}
                    value={pinLength}
                    onChange={setPinLength}
                    dragging={draggingPin}
                    setDragging={setDraggingPin}
                    ariaLabel="Digits"
                  />
                )}
                {activeTab === 'hex' && (
                  <SliderField
                    label="Length"
                    min={8}
                    max={128}
                    value={hexLength}
                    onChange={setHexLength}
                    dragging={draggingHex}
                    setDragging={setDraggingHex}
                    ariaLabel="Characters"
                  />
                )}
              </div>
            </div>
            
            <ActionButtons
              onCopy={handleCopy}
              onAutofill={handleAutofill}
              onRefresh={refreshPassword}
              disabled={!password}
            />

            <PasswordTemplates onApplyTemplate={applyPasswordTemplate} />

            <PasswordPolicyPanel
              password={password}
              policyId={policyId}
              onPolicyChange={setPolicyId}
            />

            <PasswordBatchPanel
              passwords={batchPasswords}
              onGenerateBatch={handleGenerateBatch}
              onCopyPassword={handleCopyBatchPassword}
              disabled={!password}
            />

            <KeyboardShortcutsPanel />

            <PasswordControls
              activeTab={activeTab}
              setActiveTab={setActiveTab}
              includeLowercase={includeLowercase} setIncludeLowercase={handleToggleLowercase}
              includeUppercase={includeUppercase} setIncludeUppercase={handleToggleUppercase}
              includeNumbers={includeNumbers} setIncludeNumbers={handleToggleNumbers}
              includeSymbols={includeSymbols} setIncludeSymbols={handleToggleSymbols}
              excludeAmbiguous={excludeAmbiguous} setExcludeAmbiguous={setExcludeAmbiguous}
              symbolSet={symbolSet} setSymbolSet={setSymbolSet}
              customSymbols={customSymbols} setCustomSymbols={setCustomSymbols}
              symbolSets={SYMBOL_SETS}
              includeCapitalization={includeCapitalization} setIncludeCapitalization={setIncludeCapitalization}
            />
          </div>
        )}

        {/* History */}
        {activeView === 'history' && (
          <HistoryPanel
            showHistory
            setShowHistory={() => {}}
            onBack={() => setActiveView('generator')}
            historyData={historyData}
            historyStats={historyStats}
            exportHistory={exportHistory}
            clearHistory={clearHistory}
            removeHistoryEntry={removeHistoryEntry}
            formatTimestamp={formatTimestamp}
            getPasswordTypeIcon={getPasswordTypeIcon}
            showConfirmModal={showConfirmModal}
            setShowConfirmModalLocal={setShowConfirmModal}
            confirmModalMode={confirmModalMode}
            onConfirmClearOnClose={confirmClearOnClose}
          />
        )}

        {/* Vault */}
        {activeView === 'vault' && (
          <VaultPanel
            credentialsData={credentialsData}
            onCopyField={onCopyField}
            onFillCredential={onFillCredential}
            onRemoveCredential={onRemoveCredential}
            onUpdateCredentialLabel={onUpdateCredentialLabel}
            formatTimestamp={formatTimestamp}
          />
        )}

        {/* Settings */}
        {activeView === 'settings' && (
          <SettingsPanel
            suggestionEnabled={suggestionEnabled}
            setSuggestionEnabled={setSuggestionEnabled}
            credentialsEnabled={credentialsEnabled}
            setCredentialsEnabled={setCredentialsEnabled}
            historyEnabled={historyEnabled}
            setHistoryEnabled={setHistoryEnabled}
            historyClearOnClose={historyClearOnClose}
            setHistoryClearOnClose={setHistoryClearOnClose}
          />
        )}

        {/* About */}
        {activeView === 'about' && <AboutPanel />}
      </main>

      {/* Toast notification */}
      {ToastUI}
    </div>
  )
}
