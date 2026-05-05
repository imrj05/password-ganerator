/**
 * Chrome Storage utilities for password generator settings
 */

import { decryptText } from './lib/crypto.js'

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

  if (value.length <= 3) {
    return `${value[0] || ''}**`
  }

  return `${value.slice(0, 2)}***${value.slice(-1)}`
}

const STORAGE_KEYS = {
  THEME: 'theme',
  ACTIVE_TAB: 'activeTab',
  LENGTH: 'length',
  INCLUDE_NUMBERS: 'includeNumbers',
  INCLUDE_SYMBOLS: 'includeSymbols',
  SYMBOL_SET: 'symbolSet',
  CUSTOM_SYMBOLS: 'customSymbols',
  WORD_COUNT: 'wordCount',
  INCLUDE_CAPITALIZATION: 'includeCapitalization',
  PIN_LENGTH: 'pinLength',
  PASSWORD_HISTORY: 'passwordHistory',
  HISTORY_ENABLED: 'historyEnabled',
  HISTORY_CLEAR_ON_CLOSE: 'historyClearOnClose',
  HISTORY_PENDING_CLEAR: 'historyPendingClear',
  SAVED_CREDENTIALS: 'savedCredentials',
  CREDENTIALS_ENABLED: 'credentialsEnabled',
  CREDENTIAL_NEVER_SAVE_DOMAINS: 'credentialNeverSaveDomains'
}

const DEFAULT_SETTINGS = {
  [STORAGE_KEYS.THEME]: 'system',
  [STORAGE_KEYS.ACTIVE_TAB]: 'random',
  [STORAGE_KEYS.LENGTH]: 20,
  [STORAGE_KEYS.INCLUDE_NUMBERS]: true,
  [STORAGE_KEYS.INCLUDE_SYMBOLS]: false,
  [STORAGE_KEYS.SYMBOL_SET]: 'basic',
  [STORAGE_KEYS.CUSTOM_SYMBOLS]: '',
  [STORAGE_KEYS.WORD_COUNT]: 3,
  [STORAGE_KEYS.INCLUDE_CAPITALIZATION]: true,
  [STORAGE_KEYS.PIN_LENGTH]: 4,
  [STORAGE_KEYS.PASSWORD_HISTORY]: [],
  [STORAGE_KEYS.HISTORY_ENABLED]: true,
  [STORAGE_KEYS.HISTORY_CLEAR_ON_CLOSE]: false,
  [STORAGE_KEYS.HISTORY_PENDING_CLEAR]: false,
  [STORAGE_KEYS.SAVED_CREDENTIALS]: [],
  [STORAGE_KEYS.CREDENTIALS_ENABLED]: true,
  [STORAGE_KEYS.CREDENTIAL_NEVER_SAVE_DOMAINS]: []
}

class StorageManager {
  constructor() {
    this.storage = chrome?.storage?.local || null
  }

  /**
   * Check if Chrome storage is available
   */
  isAvailable() {
    return this.storage !== null
  }

  /**
   * Get a single setting value
   * @param {string} key - Storage key
   * @returns {Promise<any>} - Setting value or default
   */
  async getSetting(key) {
    // Prefer chrome.storage when available but fall back to localStorage synchronously
    if (!this.isAvailable()) {
      try {
        const raw = localStorage.getItem(key)
        return raw !== null ? JSON.parse(raw) : DEFAULT_SETTINGS[key]
      } catch (e) {
        return DEFAULT_SETTINGS[key]
      }
    }

    try {
      const result = await this.storage.get(key)
      if (result[key] !== undefined) return result[key]
      // If chrome storage didn't return a value, fall back to localStorage if present
      try {
        const raw = localStorage.getItem(key)
        return raw !== null ? JSON.parse(raw) : DEFAULT_SETTINGS[key]
      } catch (e) {
        return DEFAULT_SETTINGS[key]
      }
    } catch (error) {
      console.error('Error getting setting:', error)
      try {
        const raw = localStorage.getItem(key)
        return raw !== null ? JSON.parse(raw) : DEFAULT_SETTINGS[key]
      } catch (e) {
        return DEFAULT_SETTINGS[key]
      }
    }
  }

  /**
   * Get multiple settings
   * @param {string[]} keys - Array of storage keys
   * @returns {Promise<Object>} - Settings object
   */
  async getSettings(keys) {
    if (!this.isAvailable()) {
      const settings = {}
      keys.forEach(key => {
        settings[key] = DEFAULT_SETTINGS[key]
      })
      return settings
    }

    try {
      const result = await this.storage.get(keys)
      const settings = {}
      keys.forEach(key => {
        settings[key] = result[key] !== undefined ? result[key] : DEFAULT_SETTINGS[key]
      })
      return settings
    } catch (error) {
      console.error('Error getting settings:', error)
      const settings = {}
      keys.forEach(key => {
        settings[key] = DEFAULT_SETTINGS[key]
      })
      return settings
    }
  }

  /**
   * Get all settings
   * @returns {Promise<Object>} - All settings
   */
  async getAllSettings() {
    return this.getSettings(Object.keys(DEFAULT_SETTINGS))
  }

  /**
   * Set a single setting value
   * @param {string} key - Storage key
   * @param {any} value - Value to store
   */
  async setSetting(key, value) {
    // Always mirror to localStorage so we have a synchronous copy usable during unload
    try {
      localStorage.setItem(key, JSON.stringify(value))
    } catch (e) {
      // ignore localStorage errors
    }

    if (!this.isAvailable()) {
      console.warn('Chrome storage not available, using localStorage fallback')
      return
    }

    try {
      await this.storage.set({ [key]: value })
    } catch (error) {
      console.error('Error setting value in chrome.storage:', error)
    }
  }

  /**
   * Set multiple settings
   * @param {Object} settings - Settings object to store
   */
  async setSettings(settings) {
    // Mirror to localStorage synchronously
    try {
      Object.entries(settings).forEach(([key, value]) => {
        localStorage.setItem(key, JSON.stringify(value))
      })
    } catch (e) {
      // ignore
    }

    if (!this.isAvailable()) {
      console.warn('Chrome storage not available, using localStorage fallback')
      return
    }

    try {
      await this.storage.set(settings)
    } catch (error) {
      console.error('Error setting settings in chrome.storage:', error)
    }
  }

  /**
   * Remove a setting
   * @param {string} key - Storage key to remove
   */
  async removeSetting(key) {
    if (!this.isAvailable()) {
      localStorage.removeItem(key)
      return
    }

    try {
      await this.storage.remove(key)
    } catch (error) {
      console.error('Error removing setting:', error)
      localStorage.removeItem(key)
    }
  }

  /**
   * Clear all settings
   */
  async clearAll() {
    if (!this.isAvailable()) {
      Object.keys(DEFAULT_SETTINGS).forEach(key => {
        localStorage.removeItem(key)
      })
      return
    }

    try {
      await this.storage.clear()
    } catch (error) {
      console.error('Error clearing storage:', error)
      Object.keys(DEFAULT_SETTINGS).forEach(key => {
        localStorage.removeItem(key)
      })
    }
  }

  /**
   * Listen for storage changes
   * @param {Function} callback - Callback function for changes
   */
  onChanged(callback) {
    if (!this.isAvailable()) {
      return
    }

    chrome.storage.onChanged.addListener((changes, namespace) => {
      if (namespace === 'local') {
        callback(changes)
      }
    })
  }

  /**
   * Add a password action to history
   * @param {string} action - Action type ('copy' or 'autofill')
   * @param {string} passwordType - Type of password ('random', 'memorable', 'pin')
   * @param {string} website - Website URL where action occurred
   * @param {number} passwordLength - Length of the password
   */
  async addPasswordHistory(action, passwordType, website = '', passwordLength = 0, passwordEnc = null) {
    try {
      // Respect user privacy setting: don't store history if disabled
      const historyEnabled = await this.getSetting(STORAGE_KEYS.HISTORY_ENABLED)
      if (historyEnabled === false) return null

      const currentHistory = await this.getSetting(STORAGE_KEYS.PASSWORD_HISTORY)
      const historyEntry = {
        id: Date.now() + Math.random(), // Unique ID
        action,
        passwordType,
        website,
        passwordLength,
        timestamp: new Date().toISOString(),
        domain: website ? new URL(website).hostname : '',
        passwordEnc: passwordEnc || null
      }

      // Add to beginning of array and limit to 100 entries
      const updatedHistory = [historyEntry, ...currentHistory].slice(0, 100)

      await this.setSetting(STORAGE_KEYS.PASSWORD_HISTORY, updatedHistory)
      return historyEntry
    } catch (error) {
      console.error('Error adding password history:', error)
      return null
    }
  }

  /**
   * Get password history
   * @param {number} limit - Maximum number of entries to return
   * @returns {Promise<Array>} - Array of history entries
   */
  async getPasswordHistory(limit = 50) {
    try {
      const history = await this.getSetting(STORAGE_KEYS.PASSWORD_HISTORY)
      return Array.isArray(history) ? history.slice(0, limit) : []
    } catch (error) {
      console.error('Error getting password history:', error)
      return []
    }
  }

  /**
   * Clear password history
   */
  async clearPasswordHistory() {
    try {
      await this.setSetting(STORAGE_KEYS.PASSWORD_HISTORY, [])
    } catch (error) {
      console.error('Error clearing password history:', error)
    }
  }

  /**
   * Remove a specific history entry
   * @param {string|number} entryId - ID of the entry to remove
   */
  async removePasswordHistoryEntry(entryId) {
    try {
      const currentHistory = await this.getSetting(STORAGE_KEYS.PASSWORD_HISTORY)
      const updatedHistory = currentHistory.filter(entry => entry.id !== entryId)
      await this.setSetting(STORAGE_KEYS.PASSWORD_HISTORY, updatedHistory)
    } catch (error) {
      console.error('Error removing password history entry:', error)
    }
  }

  /**
   * Get password history statistics
   * @returns {Promise<Object>} - Statistics object
   */
  async getPasswordHistoryStats() {
    try {
      const history = await this.getSetting(STORAGE_KEYS.PASSWORD_HISTORY)
      const stats = {
        total: history.length,
        copyCount: 0,
        autofillCount: 0,
        topWebsites: {},
        passwordTypes: { random: 0, memorable: 0, pin: 0 },
        lastSevenDays: 0
      }

      const sevenDaysAgo = new Date()
      sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7)

      history.forEach(entry => {
        // Count actions
        if (entry.action === 'copy') stats.copyCount++
        if (entry.action === 'autofill') stats.autofillCount++

        // Count password types
        if (stats.passwordTypes[entry.passwordType] !== undefined) {
          stats.passwordTypes[entry.passwordType]++
        }

        // Count websites
        if (entry.domain) {
          stats.topWebsites[entry.domain] = (stats.topWebsites[entry.domain] || 0) + 1
        }

        // Count recent actions
        if (new Date(entry.timestamp) > sevenDaysAgo) {
          stats.lastSevenDays++
        }
      })

      return stats
    } catch (error) {
      console.error('Error getting password history stats:', error)
      return { total: 0, copyCount: 0, autofillCount: 0, topWebsites: {}, passwordTypes: { random: 0, memorable: 0, pin: 0 }, lastSevenDays: 0 }
    }
  }

  async getSavedCredentials(domain = '') {
    try {
      const normalizedDomain = normalizeDomain(domain)
      const credentials = await this.getSetting(STORAGE_KEYS.SAVED_CREDENTIALS)
      const allCredentials = Array.isArray(credentials) ? credentials : []
      const filteredCredentials = normalizedDomain
        ? allCredentials.filter(entry => entry.domain === normalizedDomain)
        : allCredentials

      return filteredCredentials.sort((a, b) => {
        const left = new Date(b.lastUsedAt || b.updatedAt || b.createdAt || 0).getTime()
        const right = new Date(a.lastUsedAt || a.updatedAt || a.createdAt || 0).getTime()
        return left - right
      })
    } catch (error) {
      console.error('Error getting saved credentials:', error)
      return []
    }
  }

  async saveCredential({ origin = '', domain = '', username = '', usernameEnc = null, passwordEnc = null, label = '' }) {
    try {
      const normalizedDomain = normalizeDomain(domain || origin)
      const normalizedOrigin = normalizeOrigin(origin)
      const trimmedUsername = String(username || '').trim()

      if (!normalizedDomain || !trimmedUsername || !usernameEnc || !passwordEnc) {
        return null
      }

      const currentCredentials = await this.getSavedCredentials()
      let existingCredential = null

      for (const entry of currentCredentials) {
        if (entry.domain !== normalizedDomain || !entry.usernameEnc) continue

        try {
          const savedUsername = await decryptText(entry.usernameEnc)
          if (savedUsername === trimmedUsername) {
            existingCredential = entry
            break
          }
        } catch (error) {
          // Ignore corrupt entries and continue matching others.
        }
      }

      const now = new Date().toISOString()
      const nextCredential = existingCredential
        ? {
            ...existingCredential,
            origin: normalizedOrigin || existingCredential.origin || '',
            usernamePreview: maskUsername(trimmedUsername),
            usernameEnc,
            passwordEnc,
            label: label || existingCredential.label || '',
            updatedAt: now
          }
        : {
            id: Date.now() + Math.random(),
            origin: normalizedOrigin,
            domain: normalizedDomain,
            usernamePreview: maskUsername(trimmedUsername),
            usernameEnc,
            passwordEnc,
            label,
            createdAt: now,
            updatedAt: now,
            lastUsedAt: null
          }

      const updatedCredentials = existingCredential
        ? currentCredentials.map(entry => (entry.id === existingCredential.id ? nextCredential : entry))
        : [nextCredential, ...currentCredentials]

      await this.setSetting(STORAGE_KEYS.SAVED_CREDENTIALS, updatedCredentials)
      return nextCredential
    } catch (error) {
      console.error('Error saving credential:', error)
      return null
    }
  }

  async removeSavedCredential(entryId) {
    try {
      const currentCredentials = await this.getSetting(STORAGE_KEYS.SAVED_CREDENTIALS)
      const updatedCredentials = (Array.isArray(currentCredentials) ? currentCredentials : []).filter(entry => entry.id !== entryId)
      await this.setSetting(STORAGE_KEYS.SAVED_CREDENTIALS, updatedCredentials)
    } catch (error) {
      console.error('Error removing saved credential:', error)
    }
  }

  async touchSavedCredentialUsage(entryId) {
    try {
      const currentCredentials = await this.getSetting(STORAGE_KEYS.SAVED_CREDENTIALS)
      const now = new Date().toISOString()
      const updatedCredentials = (Array.isArray(currentCredentials) ? currentCredentials : []).map(entry => (
        entry.id === entryId
          ? { ...entry, lastUsedAt: now, updatedAt: now }
          : entry
      ))
      await this.setSetting(STORAGE_KEYS.SAVED_CREDENTIALS, updatedCredentials)
    } catch (error) {
      console.error('Error updating saved credential usage:', error)
    }
  }

  async getNeverSaveDomains() {
    try {
      const domains = await this.getSetting(STORAGE_KEYS.CREDENTIAL_NEVER_SAVE_DOMAINS)
      return Array.isArray(domains) ? domains : []
    } catch (error) {
      console.error('Error getting never-save domains:', error)
      return []
    }
  }

  async isNeverSaveDomain(domain) {
    const normalizedDomain = normalizeDomain(domain)
    if (!normalizedDomain) return false

    const domains = await this.getNeverSaveDomains()
    return domains.includes(normalizedDomain)
  }

  async setNeverSaveDomain(domain, shouldNeverSave = true) {
    try {
      const normalizedDomain = normalizeDomain(domain)
      if (!normalizedDomain) return

      const currentDomains = await this.getNeverSaveDomains()
      const nextDomains = shouldNeverSave
        ? Array.from(new Set([...currentDomains, normalizedDomain]))
        : currentDomains.filter(entry => entry !== normalizedDomain)

      await this.setSetting(STORAGE_KEYS.CREDENTIAL_NEVER_SAVE_DOMAINS, nextDomains)
    } catch (error) {
      console.error('Error updating never-save domains:', error)
    }
  }
}

// Export singleton instance
const storageManager = new StorageManager()

export { storageManager, STORAGE_KEYS }
export default storageManager
