import React, { useState, useCallback, useMemo, useEffect } from 'react'
import { Shuffle, Lightbulb, Hash, Copy, Moon, Sun, Send, History, Clock, Globe, Trash2, X, Download, Lock, Github, Star, Mail, KeyRound, MessageSquareText, Ellipsis, CircleHelp, Plus } from 'lucide-react'
import SecurePasswordGenerator from './securePasswordGenerator.js'
import MemorablePasswordGenerator from './memorablePasswordGenerator.js'
import storageManager, { STORAGE_KEYS } from './storageUtils.js'
import { decryptText, encryptForHistory } from './lib/crypto.js'
import { Dialog, DialogContent, DialogTitle } from './components/ui/dialog'
import { Button } from './components/ui/button'
import { Select } from './components/ui/select'
import { Switch } from './components/ui/switch'
import { Card } from './components/ui/card'
import { Input } from './components/ui/input'
import PasswordTypeTabs from './components/PasswordTypeTabs'
import PasswordControls from './components/PasswordControls'
import GeneratedPasswordCard from './components/GeneratedPasswordCard'
import ActionButtons from './components/ActionButtons'
import HistoryPanel from './components/HistoryPanel'
import VaultPanel from './components/VaultPanel'
import { Toaster, toast } from 'sonner'
import manifest from '../manifest.json'
import pkg from '../package.json'
import { enrollPlatformCredential, isAuthWindowValid, verifyPlatformCredential } from './lib/webauthn'

const App = () => {
  const [password, setPassword] = useState('')
  const [activeTab, setActiveTab] = useState('random')
  const [copied, setCopied] = useState(false)
  const [isDarkMode, setIsDarkMode] = useState(false)
  const [autoFilled, setAutoFilled] = useState(false)
  const [autoFillMessage, setAutoFillMessage] = useState('')
  const [showHistory, setShowHistory] = useState(false)
  const [historyData, setHistoryData] = useState([])
  const [historyStats, setHistoryStats] = useState(null)
  const [historyEnabled, setHistoryEnabled] = useState(true)
  const [historyClearOnClose, setHistoryClearOnClose] = useState(false)
  const [credentialsEnabled, setCredentialsEnabled] = useState(true)
  const [vaultData, setVaultData] = useState([])
  const [showConfirmModal, setShowConfirmModal] = useState(false)
  const [confirmModalMode, setConfirmModalMode] = useState('') // 'enable' | 'close'

  // Random password settings
  const [length, setLength] = useState(20)
  const [includeNumbers, setIncludeNumbers] = useState(true)
  const [includeSymbols, setIncludeSymbols] = useState(false)
  const [symbolSet, setSymbolSet] = useState('basic')
  const [customSymbols, setCustomSymbols] = useState('')
  const [showSymbolOptions, setShowSymbolOptions] = useState(false)

  // Memorable password settings
  const [wordCount, setWordCount] = useState(3)
  const [includeCapitalization, setIncludeCapitalization] = useState(true)

  // PIN settings
  const [pinLength, setPinLength] = useState(4)

  const passwordGenerator = useMemo(() => new SecurePasswordGenerator(), [])
  const memorableGenerator = useMemo(() => new MemorablePasswordGenerator(), [])
  const symbolSets = useMemo(() => passwordGenerator.getSymbolSets(), [passwordGenerator])

  // Load saved preferences on app start
  useEffect(() => {
    const loadPreferences = async () => {
      try {
        const settings = await storageManager.getAllSettings()

        // Set all preferences from storage
        setActiveTab(settings[STORAGE_KEYS.ACTIVE_TAB])
        setLength(settings[STORAGE_KEYS.LENGTH])
        setIncludeNumbers(settings[STORAGE_KEYS.INCLUDE_NUMBERS])
        setIncludeSymbols(settings[STORAGE_KEYS.INCLUDE_SYMBOLS])
        setSymbolSet(settings[STORAGE_KEYS.SYMBOL_SET])
        setCustomSymbols(settings[STORAGE_KEYS.CUSTOM_SYMBOLS])
        setWordCount(settings[STORAGE_KEYS.WORD_COUNT])
        setIncludeCapitalization(settings[STORAGE_KEYS.INCLUDE_CAPITALIZATION])
        setPinLength(settings[STORAGE_KEYS.PIN_LENGTH])
        setHistoryEnabled(settings[STORAGE_KEYS.HISTORY_ENABLED])
        setCredentialsEnabled(settings[STORAGE_KEYS.CREDENTIALS_ENABLED])
        const clearOnClose = settings[STORAGE_KEYS.HISTORY_CLEAR_ON_CLOSE]
        setHistoryClearOnClose(clearOnClose)
        // If a pending clear was set from previous unload, clear history now
        try {
          const pending = await storageManager.getSetting(STORAGE_KEYS.HISTORY_PENDING_CLEAR)
          if (pending) {
            await storageManager.clearPasswordHistory()
            await storageManager.setSetting(STORAGE_KEYS.HISTORY_PENDING_CLEAR, false)
          }
        } catch (e) {
          // ignore
        }

        // Handle theme preference
        const savedTheme = settings[STORAGE_KEYS.THEME]
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches

        let shouldBeDark = false
        if (savedTheme === 'dark') {
          shouldBeDark = true
        } else if (savedTheme === 'light') {
          shouldBeDark = false
        } else {
          shouldBeDark = prefersDark
        }

        setIsDarkMode(shouldBeDark)

        if (shouldBeDark) {
          document.documentElement.setAttribute('data-theme', 'dark')
        } else {
          document.documentElement.removeAttribute('data-theme')
        }

        // Generate initial password after preferences are loaded
        setTimeout(() => {
          generatePassword()
        }, 100)
      } catch (error) {
        console.error('Error loading preferences:', error)
      }
    }

    loadPreferences()
  }, [])

  const toggleDarkMode = useCallback(() => {
    const newDarkMode = !isDarkMode
    setIsDarkMode(newDarkMode)

    if (newDarkMode) {
      document.documentElement.setAttribute('data-theme', 'dark')
      storageManager.setSetting(STORAGE_KEYS.THEME, 'dark')
    } else {
      document.documentElement.removeAttribute('data-theme')
      storageManager.setSetting(STORAGE_KEYS.THEME, 'light')
    }
  }, [isDarkMode])

  useEffect(() => {
    storageManager.setSetting(STORAGE_KEYS.HISTORY_ENABLED, historyEnabled)
  }, [historyEnabled])

  useEffect(() => {
    storageManager.setSetting(STORAGE_KEYS.CREDENTIALS_ENABLED, credentialsEnabled)
  }, [credentialsEnabled])

  useEffect(() => {
    storageManager.setSetting(STORAGE_KEYS.HISTORY_CLEAR_ON_CLOSE, historyClearOnClose)
  }, [historyClearOnClose])

  // Clear history when popup unloads if the setting is enabled.
  // Show a browser confirmation prompt before clearing by using beforeunload.
  useEffect(() => {
    // Use beforeunload to mark pending clear synchronously via localStorage
    const beforeUnloadHandler = () => {
      try {
        const shouldClear = localStorage.getItem(STORAGE_KEYS.HISTORY_CLEAR_ON_CLOSE)
        if (shouldClear && JSON.parse(shouldClear) === true) {
          // mark pending clear so next open can clear from async chrome.storage
          localStorage.setItem(STORAGE_KEYS.HISTORY_PENDING_CLEAR, JSON.stringify(true))
        }
      } catch (e) {
        // ignore
      }
    }

    window.addEventListener('beforeunload', beforeUnloadHandler)
    return () => {
      window.removeEventListener('beforeunload', beforeUnloadHandler)
    }
  }, [historyClearOnClose])

  // Save preferences when they change
  useEffect(() => {
    storageManager.setSetting(STORAGE_KEYS.ACTIVE_TAB, activeTab)
  }, [activeTab])

  useEffect(() => {
    storageManager.setSetting(STORAGE_KEYS.LENGTH, length)
  }, [length])

  useEffect(() => {
    storageManager.setSetting(STORAGE_KEYS.INCLUDE_NUMBERS, includeNumbers)
  }, [includeNumbers])

  useEffect(() => {
    storageManager.setSetting(STORAGE_KEYS.INCLUDE_SYMBOLS, includeSymbols)
  }, [includeSymbols])

  useEffect(() => {
    storageManager.setSetting(STORAGE_KEYS.SYMBOL_SET, symbolSet)
  }, [symbolSet])

  useEffect(() => {
    storageManager.setSetting(STORAGE_KEYS.CUSTOM_SYMBOLS, customSymbols)
  }, [customSymbols])

  useEffect(() => {
    storageManager.setSetting(STORAGE_KEYS.WORD_COUNT, wordCount)
  }, [wordCount])

  useEffect(() => {
    storageManager.setSetting(STORAGE_KEYS.INCLUDE_CAPITALIZATION, includeCapitalization)
  }, [includeCapitalization])

  useEffect(() => {
    storageManager.setSetting(STORAGE_KEYS.PIN_LENGTH, pinLength)
  }, [pinLength])

  const generatePassword = useCallback(() => {
    try {
      let generatedPassword = ''

      if (activeTab === 'random') {
        const options = {
          length,
          includeUppercase: true,
          includeLowercase: true,
          includeNumbers,
          includeSymbols,
          symbolSet,
          customSymbols,
          excludeAmbiguous: false,
          ensureComplexity: true
        }

        const validation = passwordGenerator.validateOptions(options)
        if (!validation.isValid) {
          alert(validation.errors.join('\n'))
          return
        }

        generatedPassword = passwordGenerator.generateSecurePassword(options)
      } else if (activeTab === 'memorable') {
        const options = {
          wordCount,
          includeNumbers: true,
          includeCapitalization,
          separatorType: 'random',
          minLength: 8,
          maxLength: 50
        }

        generatedPassword = memorableGenerator.generateMemorablePassword(options)
      } else if (activeTab === 'pin') {
        generatedPassword = generatePIN(pinLength)
      }

      setPassword(generatedPassword)
      setCopied(false)
    } catch (error) {
      console.error('Password generation error:', error)
      alert('Failed to generate password. Please try again.')
    }
  }, [activeTab, length, includeNumbers, includeSymbols, wordCount, includeCapitalization, pinLength, passwordGenerator, memorableGenerator, symbolSet, customSymbols])

  // Generate password when tab changes
  useEffect(() => {
    generatePassword()
  }, [activeTab, generatePassword])

  // Load history data
  const loadHistoryData = useCallback(async () => {
    try {
      const history = await storageManager.getPasswordHistory(20)
      const stats = await storageManager.getPasswordHistoryStats()
      setHistoryData(history)
      setHistoryStats(stats)
    } catch (error) {
      console.error('Failed to load history:', error)
    }
  }, [])

  const loadVaultData = useCallback(async () => {
    try {
      const credentials = await storageManager.getSavedCredentials()
      setVaultData(credentials)
    } catch (error) {
      console.error('Failed to load saved credentials:', error)
    }
  }, [])

  // Load history when component mounts or when history panel is opened
  useEffect(() => {
    if (showHistory) {
      loadHistoryData()
    }
  }, [showHistory, loadHistoryData])

  useEffect(() => {
    if (activeTab === 'vault') {
      loadVaultData()
    }
  }, [activeTab, loadVaultData])

  // Also refresh history when switching to the History tab
  useEffect(() => {
    if (activeTab === 'history') {
      loadHistoryData()
    }
  }, [activeTab, loadHistoryData])

  useEffect(() => {
    if (historyEnabled && activeTab === 'history') {
      loadHistoryData()
    }
    if (!historyEnabled) {
      setHistoryData([])
      setHistoryStats(null)
    }
  }, [historyEnabled, activeTab, loadHistoryData])

  useEffect(() => {
    if (credentialsEnabled && activeTab === 'vault') {
      loadVaultData()
    }
    if (!credentialsEnabled) {
      setVaultData([])
    }
  }, [credentialsEnabled, activeTab, loadVaultData])

  useEffect(() => {
    setShowHistory(activeTab === 'history')
  }, [activeTab])

  const clearHistory = async () => {
    try {
      await storageManager.clearPasswordHistory()
      setHistoryData([])
      setHistoryStats(null)
      await loadHistoryData()
    } catch (error) {
      console.error('Failed to clear history:', error)
    }
  }

  const removeHistoryEntry = async (entryId) => {
    try {
      await storageManager.removePasswordHistoryEntry(entryId)
      await loadHistoryData()
    } catch (error) {
      console.error('Failed to remove history entry:', error)
    }
  }

  const ensureVerified = useCallback(async () => {
    try {
      if (isAuthWindowValid()) return true
      let ok = await verifyPlatformCredential()
      if (ok) return true
      await enrollPlatformCredential()
      ok = await verifyPlatformCredential()
      return ok
    } catch (error) {
      return false
    }
  }, [])

  const copySavedCredentialField = useCallback(async (entry, field) => {
    try {
      const ok = await ensureVerified()
      if (!ok) {
        toast.error('Verification failed')
        return
      }

      const encryptedValue = field === 'username' ? entry.usernameEnc : entry.passwordEnc
      if (!encryptedValue) {
        toast.error(`No ${field} available`)
        return
      }

      const plaintext = await decryptText(encryptedValue)
      await navigator.clipboard.writeText(plaintext)
      toast.success(`${field === 'username' ? 'Username' : 'Password'} copied`, { duration: 1800 })
    } catch (error) {
      toast.error(`Unable to copy ${field}`)
    }
  }, [ensureVerified])

  const fillSavedCredential = useCallback(async (entry) => {
    try {
      const ok = await ensureVerified()
      if (!ok) {
        toast.error('Verification failed')
        return
      }

      const username = entry.usernameEnc ? await decryptText(entry.usernameEnc) : ''
      const passwordValue = entry.passwordEnc ? await decryptText(entry.passwordEnc) : ''

      if (!passwordValue) {
        toast.error('Saved password is missing')
        return
      }

      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      const response = await chrome.tabs.sendMessage(tab.id, {
        action: 'fillSavedCredential',
        credential: {
          id: entry.id,
          username,
          password: passwordValue,
          domain: entry.domain
        }
      })

      if (response?.success) {
        await storageManager.touchSavedCredentialUsage(entry.id)
        await loadVaultData()
        toast.success('Saved login filled', { description: response.message, duration: 2400 })
      } else {
        toast.error('Fill failed', { description: response?.message || 'No suitable sign-in fields found', duration: 2600 })
      }
    } catch (error) {
      console.error('Failed to fill saved credential:', error)
      toast.error('Unable to fill saved login')
    }
  }, [ensureVerified, loadVaultData])

  const removeSavedCredential = useCallback(async (entryId) => {
    try {
      await storageManager.removeSavedCredential(entryId)
      await loadVaultData()
      toast.success('Saved login removed', { duration: 1800 })
    } catch (error) {
      console.error('Failed to remove saved credential:', error)
      toast.error('Unable to remove saved login')
    }
  }, [loadVaultData])

  const exportHistory = async () => {
    try {
      // Confirm history export when history is disabled
      const enabled = await storageManager.getSetting(STORAGE_KEYS.HISTORY_ENABLED)
      if (!enabled) {
        alert('History is disabled. Enable history in settings to export.')
        return
      }
      const history = await storageManager.getPasswordHistory()
      const stats = await storageManager.getPasswordHistoryStats()

      const exportData = {
        exportedAt: new Date().toISOString(),
        stats,
        history: history.map(entry => ({
          ...entry,
          // Remove sensitive data if any
          id: entry.id,
          action: entry.action,
          passwordType: entry.passwordType,
          domain: entry.domain,
          passwordLength: entry.passwordLength,
          timestamp: entry.timestamp
        }))
      }

      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `password-history-${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to export history:', error)
    }
  }

  const generatePIN = (length) => {
    const array = new Uint32Array(length)
    crypto.getRandomValues(array)

    let pin = ''
    for (let i = 0; i < length; i++) {
      pin += (array[i] % 10).toString()
    }

    return pin
  }

  const copyToClipboard = async () => {
    if (!password) return

    try {
      await navigator.clipboard.writeText(password)
      setCopied(true)
      try {
        toast.success('Password copied', { description: 'Saved to clipboard', duration: 1800 })
      } catch(e) {}
      setTimeout(() => setCopied(false), 2000)

      // Track copy action in history
      try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
        const website = tab?.url || ''
        const passwordEnc = await encryptForHistory(password)
        await storageManager.addPasswordHistory('copy', activeTab, website, password.length, passwordEnc)
        if (activeTab === 'history') {
          await loadHistoryData()
        }
      } catch (historyError) {
        console.error('Failed to track copy action:', historyError)
      }
    } catch (err) {
      console.error('Failed to copy password:', err)
    }
  }

  const autoFillPassword = async () => {
    if (!password) return

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })

      const response = await chrome.tabs.sendMessage(tab.id, {
        action: 'fillPassword',
        password: password
      })

      if (response?.success) {
        setAutoFilled(true)
        setAutoFillMessage(response.message)
        try {
          const host = new URL(tab.url).hostname
          const fieldHint = Array.isArray(response.fields) && response.fields.length ? ` • field: ${response.fields[0]}` : ''
          toast.success('Auto-filled', { description: `${response.message} • ${host}${fieldHint}`, duration: 2800 })
        } catch(e) {}
        setTimeout(() => {
          setAutoFilled(false)
          setAutoFillMessage('')
        }, 3000)

        // Track autofill action in history
        try {
          const website = tab?.url || ''
          const passwordEnc = await encryptForHistory(password)
          await storageManager.addPasswordHistory('autofill', activeTab, website, password.length, passwordEnc)
        } catch (historyError) {
          console.error('Failed to track autofill action:', historyError)
        }
      } else if (response) {
        setAutoFillMessage(response.message)
        try {
          const host = response.domain || (tab?.url ? new URL(tab.url).hostname : '')
          const fieldHint = Array.isArray(response.fields) && response.fields.length ? ` • field: ${response.fields[0]}` : ''
          const desc = host ? `${response.message} • ${host}${fieldHint}` : `${response.message}${fieldHint}`
          toast.error('Auto-fill failed', { description: desc, duration: 3000 })
        } catch(e) {}
        setTimeout(() => setAutoFillMessage(''), 3000)
      } else {
        try { toast.error('Auto-fill failed', { duration: 3000 }) } catch(e) {}
      }
    } catch (err) {
      console.error('Failed to auto-fill password:', err)
      setAutoFillMessage('Failed to auto-fill password')
      try { toast.error('Auto-fill failed', { duration: 3000 }) } catch(e) {}
      setTimeout(() => setAutoFillMessage(''), 3000)
    }
  }

  const getStrengthForCurrentType = () => {
    if (!password) return { score: 0, label: 'None', entropy: 0 }

    if (activeTab === 'random') {
      const options = {
        length,
        includeUppercase: true,
        includeLowercase: true,
        includeNumbers,
        includeSymbols,
        symbolSet,
        customSymbols,
        excludeAmbiguous: false
      }

      // Pass the exact generation options so strength uses same charset
      return passwordGenerator.assessPasswordStrength(password, options)
    } else if (activeTab === 'memorable') {
      return memorableGenerator.assessMemorableStrength(password)
    } else if (activeTab === 'pin') {
      const entropy = pinLength * Math.log2(10)
      let score = 1
      if (entropy >= 20) score = 2
      if (entropy >= 30) score = 3
      if (entropy >= 40) score = 4
      if (entropy >= 50) score = 5

      const labels = ['None', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong']
      return { score, label: labels[score], entropy: Math.round(entropy) }
    }

    return { score: 0, label: 'None', entropy: 0 }
  }

  const strength = useMemo(() => getStrengthForCurrentType(), [
    password, activeTab, includeNumbers, includeSymbols, pinLength, passwordGenerator, memorableGenerator
  ])

  const renderTabContent = () => {
    if (activeTab === 'random') {
      return (
        <>
          <div className="slider-group">
            <label className="slider-label">Characters</label>
            <div className="slider-container">
              <input
                type="range"
                min="4"
                max="50"
                value={length}
                onChange={(e) => setLength(parseInt(e.target.value))}
                className="slider"
              />
              <div className="slider-value">{length}</div>
            </div>
          </div>

          <div className="toggle-group">
            <div className="toggle-item">
              <label className="toggle-label">Numbers</label>
              <Switch checked={includeNumbers} onCheckedChange={setIncludeNumbers} />
            </div>

            <div className="toggle-item">
              <label className="toggle-label">Symbols</label>
              <Switch checked={includeSymbols} onCheckedChange={setIncludeSymbols} />
            </div>
          </div>

          {includeSymbols && (
            <div className="symbol-options">
              <div className="symbol-selector">
                <label className="symbol-selector-label">Symbol Set</label>
                <Select
                  label={null}
                  value={symbolSet}
                  onChange={(v) => setSymbolSet(v)}
                  options={Object.entries(symbolSets).map(([key, set]) => ({ value: key, label: set.name, preview: set.symbols }))}
                />
              </div>

              {symbolSet === 'custom' && (
                <div className="custom-symbols">
                  <label className="custom-symbols-label">Custom Symbols</label>
                  <Input
                    placeholder="Enter custom symbols"
                    value={customSymbols}
                    onChange={(event) => setCustomSymbols(event.target.value)}
                    className="custom-symbols-input"
                  />
                </div>
              )}

              <div className="symbol-preview">
                <span className="symbol-preview-label">Using: </span>
                <span className="symbol-preview-text">
                  {symbolSet === 'custom' ? customSymbols || 'No custom symbols' : symbolSets[symbolSet]?.symbols}
                </span>
              </div>
            </div>
          )}
        </>
      )
    } else if (activeTab === 'memorable') {
      return (
        <>
          <div className="slider-group">
            <label className="slider-label">Words</label>
            <div className="slider-container">
              <input
                type="range"
                min="2"
                max="6"
                value={wordCount}
                onChange={(e) => setWordCount(parseInt(e.target.value))}
                className="slider"
              />
              <div className="slider-value">{wordCount}</div>
            </div>
          </div>

          <div className="toggle-group">
            <div className="toggle-item">
              <label className="toggle-label">Capitalization</label>
              <Switch checked={includeCapitalization} onCheckedChange={setIncludeCapitalization} />
            </div>
          </div>
        </>
      )
    } else if (activeTab === 'pin') {
      return (
        <div className="slider-group">
          <label className="slider-label">Digits</label>
          <div className="slider-container">
            <input
              type="range"
              min="4"
              max="12"
              value={pinLength}
              onChange={(e) => setPinLength(parseInt(e.target.value))}
              className="slider"
            />
            <div className="slider-value">{pinLength}</div>
          </div>
        </div>
      )
      }
    else if (activeTab === 'about') {
      return (
        <div className="space-y-3">
          <Card className="border border-white/10 bg-background/70 p-4">
            <div className="flex items-start justify-between gap-4">
              <div className="flex items-start gap-3">
                <div className="flex h-12 w-12 shrink-0 items-center justify-center overflow-hidden rounded-2xl border border-primary/15 bg-primary/10 shadow-sm">
                  <img src="icons/icon128.png" alt="app icon" className="h-9 w-9 object-contain" />
                </div>
                <div className="space-y-1">
                  <div className="text-sm font-semibold">{manifest?.name || 'SecurePass Generator'}</div>
                  {manifest?.description && <p className="text-sm leading-relaxed text-muted-foreground">{manifest.description}</p>}
                </div>
              </div>

              <div className="flex items-center gap-2">
                <a href={manifest?.homepage_url || 'https://github.com/work-rjkashyap/password-ganerator'} target="_blank" rel="noopener noreferrer" className="rounded-xl border border-border/60 bg-background/65 p-2 text-muted-foreground transition-colors hover:bg-accent/70 hover:text-foreground">
                  <Github size={16} />
                </a>
                <a href="https://chromewebstore.google.com/detail/securepass-generator/iillkojencnommaljcgiommobneopafa" target="_blank" rel="noopener noreferrer" className="rounded-xl border border-border/60 bg-background/65 p-2 text-amber-500 transition-colors hover:bg-accent/70">
                  <Star size={16} />
                </a>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-2 gap-3 text-sm">
              <div className="rounded-2xl border border-border/60 bg-background/55 p-3">
                <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-primary/80">Version</div>
                <div className="mt-1 text-sm font-medium">{manifest?.version || pkg?.version}</div>
              </div>
              <div className="rounded-2xl border border-border/60 bg-background/55 p-3">
                <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-primary/80">License</div>
                <div className="mt-1 text-sm font-medium">{pkg?.license || 'MIT'}</div>
              </div>
              <div className="rounded-2xl border border-border/60 bg-background/55 p-3">
                <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-primary/80">Permissions</div>
                <div className="mt-1 text-sm font-medium">{manifest?.permissions ? manifest.permissions.join(', ') : 'storage, clipboardWrite'}</div>
              </div>
              <div className="rounded-2xl border border-border/60 bg-background/55 p-3">
                <div className="text-[11px] font-semibold uppercase tracking-[0.14em] text-primary/80">Developer</div>
                <div className="mt-1 text-sm font-medium">Rajeshwar Kashyap</div>
              </div>
            </div>

            <div className="mt-4 space-y-3">
              <div className="rounded-[20px] border border-border/60 bg-background/55 p-4">
                <div className="mb-2 flex items-center gap-2 text-primary">
                  <Lock size={18} />
                  <div className="text-sm font-semibold text-foreground">Security</div>
                </div>
                <div className="text-sm leading-relaxed text-muted-foreground">All password generation runs locally in your browser using the Web Crypto API (<code>crypto.getRandomValues()</code>) with rejection sampling to avoid statistical bias. The extension does not transmit generated passwords or form data to external servers. Preferences are stored via Chrome Storage; history entries (if enabled) are encrypted before saving.</div>
              </div>

              <div className="rounded-[20px] border border-border/60 bg-background/55 p-4">
                <div className="mb-2 flex items-center gap-2 text-primary">
                  <Mail size={18} />
                  <div className="text-sm font-semibold text-foreground">Support</div>
                </div>
                <div className="text-sm leading-relaxed text-muted-foreground">For bugs or feature requests, open an issue on the <a className="text-primary underline" href="https://github.com/work-rjkashyap/password-ganerator" target="_blank" rel="noopener noreferrer">GitHub repository</a>. For direct support, email <code>rajeshwarkashyap5@gmail.com</code> and include the extension version plus reproduction steps.</div>
              </div>
            </div>
          </Card>
        </div>
      )
    }
  }

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp)
    const now = new Date()
    const diffInMinutes = Math.floor((now - date) / (1000 * 60))

    if (diffInMinutes < 1) return 'Just now'
    if (diffInMinutes < 60) return `${diffInMinutes}m ago`
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h ago`
    if (diffInMinutes < 10080) return `${Math.floor(diffInMinutes / 1440)}d ago`

    return date.toLocaleDateString()
  }

  const getPasswordTypeIcon = (type) => {
    switch (type) {
      case 'random': return <Shuffle size={14} />
      case 'memorable': return <Lightbulb size={14} />
      case 'pin': return <Hash size={14} />
      default: return <Copy size={14} />
    }
  }

  const primarySection = ['random', 'memorable', 'pin'].includes(activeTab) ? 'generator' : activeTab

  const renderHistoryPanel = () => {
    if (!showHistory) return null

    return (
      <>
      <div className="history-panel">
        <div className="history-header">
          <div className="history-title">
            <History size={16} />
            <span>Password History</span>
          </div>
          <div className="history-actions">
            <div className="history-toggle">
              <Button
                variant={historyEnabled ? 'default' : 'default'}
                className={`history-enabled-btn ${historyEnabled ? 'enabled' : 'disabled'}`}
                onClick={() => setHistoryEnabled(!historyEnabled)}
                title={historyEnabled ? 'Disable history' : 'Enable history'}
              >
                <Lock size={14} />
              </Button>
            </div>
            <div className="history-clear-on-close">
              <label className="history-clear-label">Clear on close</label>
              <div>
                <Button
                  className={`ml-2 ${historyClearOnClose ? 'bg-blue-600 text-white' : 'bg-gray-200'}`}
                  onClick={() => {
                    setConfirmModalMode(historyClearOnClose ? 'disable' : 'enable')
                    setShowConfirmModal(true)
                  }}
                >
                  {historyClearOnClose ? 'Enabled' : 'Disabled'}
                </Button>
              </div>
            </div>
            {historyData.length > 0 && (
              <>
                <button className="export-history-btn" onClick={exportHistory} title="Export history">
                  <Download size={14} />
                </button>
                <button className="clear-history-btn" onClick={clearHistory} title="Clear all history">
                  <Trash2 size={14} />
                </button>
              </>
            )}
            <button className="close-history-btn" onClick={() => setShowHistory(false)} title="Close history">
              <X size={14} />
            </button>
          </div>
        </div>

        {historyStats && (
          <Card className="history-stats">
            <div className="stat-item">
              <span className="stat-label">Total Actions:</span>
              <span className="stat-value">{historyStats.total}</span>
            </div>
            <div className="stat-item">
              <span className="stat-label">Last 7 Days:</span>
              <span className="stat-value">{historyStats.lastSevenDays}</span>
            </div>
            <div className="stat-row">
              <div className="stat-item">
                <Copy size={12} />
                <span className="stat-value">{historyStats.copyCount}</span>
              </div>
              <div className="stat-item">
                <Send size={12} />
                <span className="stat-value">{historyStats.autofillCount}</span>
              </div>
            </div>
          </Card>
        )}

        <div className="history-list">
          {historyData.length === 0 ? (
            <div className="empty-history">
              <History size={32} />
              <p>No password history yet</p>
              <p>Your copy and autofill actions will appear here</p>
            </div>
          ) : (
            historyData.map((entry) => (
              <div key={entry.id} className="history-item">
                <div className="history-item-icon">
                  {getPasswordTypeIcon(entry.passwordType)}
                </div>
                <div className="history-item-content">
                  <div className="history-item-main">
                    <div className="history-item-action">
                      <span className={`action-badge ${entry.action}`}>
                        {entry.action === 'copy' ? <Copy size={12} /> : <Send size={12} />}
                        {entry.action === 'copy' ? 'Copied' : 'Auto-filled'}
                      </span>
                      <span className="password-type">{entry.passwordType}</span>
                      <span className="password-length">({entry.passwordLength} chars)</span>
                    </div>
                    <div className="history-item-website">
                      {entry.domain ? (
                        <div className="website-info">
                          <Globe size={12} />
                          <span>{entry.domain}</span>
                        </div>
                      ) : (
                        <span className="no-website">Extension popup</span>
                      )}
                    </div>
                  </div>
                  <div className="history-item-meta">
                    <div className="history-item-time">
                      <Clock size={12} />
                      <span>{formatTimestamp(entry.timestamp)}</span>
                    </div>
                    <button
                      className="remove-entry-btn"
                      onClick={() => removeHistoryEntry(entry.id)}
                      title="Remove this entry"
                    >
                      <X size={12} />
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Confirmation dialog for toggling clear-on-close */}
      <Dialog open={showConfirmModal} onOpenChange={(v) => setShowConfirmModal(v)}>
        <DialogContent>
          <DialogTitle>{confirmModalMode === 'enable' ? 'Enable Clear on Close' : 'Disable Clear on Close'}</DialogTitle>
          <p className="text-sm mb-4">Are you sure you want to {confirmModalMode === 'enable' ? 'enable' : 'disable'} clearing history when the popup closes?</p>
          <div className="flex justify-end gap-2">
            <Button onClick={() => setShowConfirmModal(false)}>Cancel</Button>
            <Button
              variant="primary"
              onClick={async () => {
                setShowConfirmModal(false)
                if (confirmModalMode === 'enable') setHistoryClearOnClose(true)
                else setHistoryClearOnClose(false)
                // Persist immediately
                await storageManager.setSetting(STORAGE_KEYS.HISTORY_CLEAR_ON_CLOSE, confirmModalMode === 'enable')
              }}
            >
              Confirm
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
    )
  }

  return (
    <div className="mx-auto flex min-h-screen w-full max-w-sm flex-col bg-background text-foreground">
      <Toaster position="top-center" richColors closeButton duration={2500} />

      <div className="border-b border-border/80 bg-card px-4 py-3">
        <div className="grid grid-cols-4 gap-1.5 text-center text-[12px] text-muted-foreground">
          <button className={`flex flex-col items-center gap-2 px-2 py-2.5 ${primarySection === 'vault' ? 'rounded-sm border border-border/80 bg-background/40 text-foreground' : ''}`} onClick={() => setActiveTab('vault')}>
            <KeyRound size={22} />
            <span>Vault</span>
          </button>
          <button className={`flex flex-col items-center gap-2 px-2 py-2.5 ${primarySection === 'history' ? 'rounded-sm border border-border/80 bg-background/40 text-foreground' : ''}`} onClick={() => { setShowHistory(true); setActiveTab('history') }}>
            <History size={22} />
            <span>History</span>
          </button>
          <button className={`flex flex-col items-center gap-2 px-2 py-2.5 ${primarySection === 'generator' ? 'rounded-sm border border-border/80 bg-background/40 text-foreground' : ''}`} onClick={() => setActiveTab('random')}>
            <MessageSquareText size={22} />
            <span>Generator</span>
          </button>
          <button className={`flex flex-col items-center gap-2 px-2 py-2.5 ${primarySection === 'about' ? 'rounded-sm border border-border/80 bg-background/40 text-foreground' : ''}`} onClick={() => setActiveTab('about')}>
            <Ellipsis size={22} />
            <span>More</span>
          </button>
        </div>
      </div>

      <div className="flex-1 space-y-4 px-3 py-4">
        {primarySection === 'history' ? (
          <HistoryPanel
            showHistory={true}
            setShowHistory={setShowHistory}
            historyData={historyData}
            historyStats={historyStats}
            historyEnabled={historyEnabled}
            setHistoryEnabled={setHistoryEnabled}
            historyClearOnClose={historyClearOnClose}
            setConfirmModalMode={setConfirmModalMode}
            setShowConfirmModal={setShowConfirmModal}
            exportHistory={exportHistory}
            clearHistory={clearHistory}
            removeHistoryEntry={removeHistoryEntry}
            formatTimestamp={formatTimestamp}
            getPasswordTypeIcon={getPasswordTypeIcon}
            showConfirmModal={showConfirmModal}
            setShowConfirmModalLocal={setShowConfirmModal}
            confirmModalMode={confirmModalMode}
            onConfirmClearOnClose={async (enable) => {
              setHistoryClearOnClose(enable)
              try {
                await storageManager.setSetting(STORAGE_KEYS.HISTORY_CLEAR_ON_CLOSE, enable)
                toast.success(enable ? 'Enabled: clear on close' : 'Disabled: clear on close', { duration: 2000 })
              } catch (e) {}
            }}
          />
        ) : primarySection === 'vault' ? (
          <VaultPanel
            credentialsEnabled={credentialsEnabled}
            setCredentialsEnabled={setCredentialsEnabled}
            credentialsData={vaultData}
            onCopyField={copySavedCredentialField}
            onFillCredential={fillSavedCredential}
            onRemoveCredential={removeSavedCredential}
            formatTimestamp={formatTimestamp}
          />
        ) : primarySection === 'about' ? (
          <div className="space-y-4">{renderTabContent()}</div>
        ) : (
          <>
            <Card className="border border-border/80 bg-card px-4 py-4 shadow-none">
              <div className="space-y-4">
                <GeneratedPasswordCard password={password} />
                <ActionButtons onCopy={copyToClipboard} onAutofill={autoFillPassword} onRefresh={generatePassword} disabled={!password} />
              </div>
            </Card>

            <PasswordControls
              activeTab={activeTab}
              setActiveTab={setActiveTab}
              length={length} setLength={setLength}
              includeNumbers={includeNumbers} setIncludeNumbers={setIncludeNumbers}
              includeSymbols={includeSymbols} setIncludeSymbols={setIncludeSymbols}
              symbolSet={symbolSet} setSymbolSet={setSymbolSet}
              customSymbols={customSymbols} setCustomSymbols={setCustomSymbols}
              symbolSets={symbolSets}
              wordCount={wordCount} setWordCount={setWordCount}
              includeCapitalization={includeCapitalization} setIncludeCapitalization={setIncludeCapitalization}
              pinLength={pinLength} setPinLength={setPinLength}
            />

            {copied && <div className="rounded-sm border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">Password copied to clipboard.</div>}
            {autoFilled && <div className="rounded-sm border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">{autoFillMessage}</div>}
            {!autoFilled && autoFillMessage && <div className="rounded-sm border border-rose-500/20 bg-rose-500/10 px-3 py-2 text-sm text-rose-300">{autoFillMessage}</div>}
          </>
        )}
      </div>

      <div className="mt-auto flex items-center justify-between border-t border-border/80 bg-card px-4 py-3 text-muted-foreground">
        <a
          className="flex items-center gap-2 text-sm text-foreground"
          href="https://github.com/work-rjkashyap/password-ganerator"
          target="_blank"
          rel="noopener noreferrer"
        >
          <img src="icons/icon128.png" alt="SecurePass" className="h-5 w-5 object-contain opacity-80" />
          <span>Open the web app</span>
        </a>

        <div className="flex items-center gap-4">
          <button className="text-muted-foreground hover:text-foreground" title="Generate" onClick={generatePassword}><Plus size={20} /></button>
          <button className="text-muted-foreground hover:text-foreground" title="Help" onClick={() => setActiveTab('about')}><CircleHelp size={20} /></button>
          <button className="text-muted-foreground hover:text-foreground" title="Theme" onClick={() => {
            const current = document.documentElement.classList.contains('dark') ? 'dark' : (document.documentElement.classList.contains('light') ? 'light' : 'system')
            const next = current === 'dark' ? 'light' : 'dark'
            try { localStorage.setItem('vite-ui-theme', next) } catch (e) {}
            document.documentElement.classList.remove('light', 'dark')
            document.documentElement.classList.add(next)
            setIsDarkMode(next === 'dark')
          }}>{isDarkMode ? <Sun size={20} /> : <Moon size={20} />}</button>
        </div>
      </div>
    </div>
  )
}

export default App
