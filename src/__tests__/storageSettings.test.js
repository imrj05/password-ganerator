import { beforeEach, describe, expect, test, vi } from 'vitest'

const storageState = {}

const chromeMock = {
  storage: {
    local: {
      get: vi.fn(async (key) => {
        if (Array.isArray(key)) {
          return key.reduce((acc, item) => {
            acc[item] = storageState[item]
            return acc
          }, {})
        }
        return { [key]: storageState[key] }
      }),
      set: vi.fn(async (values) => {
        Object.assign(storageState, values)
      }),
      remove: vi.fn(async (key) => {
        delete storageState[key]
      }),
      clear: vi.fn(async () => {
        Object.keys(storageState).forEach(key => delete storageState[key])
      })
    },
    onChanged: {
      addListener: vi.fn()
    }
  }
}

function createLocalStorageMock() {
  const store = new Map()

  return {
    getItem: vi.fn(key => (store.has(key) ? store.get(key) : null)),
    setItem: vi.fn((key, value) => {
      store.set(key, String(value))
    }),
    removeItem: vi.fn(key => {
      store.delete(key)
    }),
    clear: vi.fn(() => {
      store.clear()
    })
  }
}

describe('storageUtils settings mirror', () => {
  beforeEach(() => {
    Object.keys(storageState).forEach(key => delete storageState[key])
    vi.resetModules()
    globalThis.chrome = chromeMock
    globalThis.localStorage = createLocalStorageMock()
  })

  test('removeSetting clears both chrome storage and the localStorage mirror', async () => {
    const { storageManager, STORAGE_KEYS } = await import('../storageUtils.js')

    await storageManager.setSetting(STORAGE_KEYS.LENGTH, 24)
    expect(localStorage.getItem(STORAGE_KEYS.LENGTH)).toBe('24')

    await storageManager.removeSetting(STORAGE_KEYS.LENGTH)

    expect(storageState.length).toBeUndefined()
    expect(localStorage.getItem(STORAGE_KEYS.LENGTH)).toBeNull()
  })

  test('clearAll clears chrome storage and every localStorage mirror', async () => {
    const { storageManager, STORAGE_KEYS } = await import('../storageUtils.js')

    await storageManager.setSetting(STORAGE_KEYS.LENGTH, 24)
    await storageManager.setSetting(STORAGE_KEYS.THEME, 'dark')

    await storageManager.clearAll()

    expect(Object.keys(storageState)).toHaveLength(0)
    expect(localStorage.getItem(STORAGE_KEYS.LENGTH)).toBeNull()
    expect(localStorage.getItem(STORAGE_KEYS.THEME)).toBeNull()
  })

  test('secrets are not mirrored and never read back from the mirror', async () => {
    const { storageManager, STORAGE_KEYS } = await import('../storageUtils.js')

    localStorage.setItem(STORAGE_KEYS.PASSWORD_HISTORY, JSON.stringify([{ id: 'stale' }]))

    await storageManager.setSetting(STORAGE_KEYS.PASSWORD_HISTORY, [{ id: 'fresh' }])

    expect(localStorage.getItem(STORAGE_KEYS.PASSWORD_HISTORY)).toBe(JSON.stringify([{ id: 'stale' }]))
    expect(storageState.passwordHistory).toEqual([{ id: 'fresh' }])
  })

  test('a secret with no chrome.storage value falls back to the default, not the mirror', async () => {
    const { storageManager, STORAGE_KEYS } = await import('../storageUtils.js')

    localStorage.setItem(STORAGE_KEYS.SAVED_CREDENTIALS, JSON.stringify([{ id: 'stale' }]))

    const credentials = await storageManager.getSetting(STORAGE_KEYS.SAVED_CREDENTIALS)

    expect(credentials).toEqual([])
  })

  test('removes a dismissed suggestion domain', async () => {
    const { storageManager } = await import('../storageUtils.js')

    await storageManager.setSetting('dismissedSuggestionDomains', ['example.com', 'bank.test'])
    await storageManager.removeDismissedSuggestionDomain('example.com')

    expect(await storageManager.getDismissedSuggestionDomains()).toEqual(['bank.test'])
  })
})
