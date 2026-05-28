import { beforeEach, describe, expect, test, vi } from 'vitest'

const storageState = {}

const chromeMock = {
  storage: {
    local: {
      get: vi.fn((key) => {
        let result = {}
        if (Array.isArray(key)) {
          result = key.reduce((acc, item) => {
            acc[item] = storageState[item]
            return acc
          }, {})
        } else if (typeof key === 'string') {
          result = { [key]: storageState[key] }
        }
        return Promise.resolve(result)
      }),
      set: vi.fn((values) => {
        Object.assign(storageState, values)
        return Promise.resolve()
      }),
      remove: vi.fn(async (key) => { delete storageState[key] }),
      clear: vi.fn(async () => {
        Object.keys(storageState).forEach(k => delete storageState[k])
      }),
    },
    onChanged: { addListener: vi.fn() },
  },
}

function createLocalStorageMock() {
  const store = new Map()
  return {
    getItem: vi.fn(key => (store.has(key) ? store.get(key) : null)),
    setItem: vi.fn((key, value) => { store.set(key, String(value)) }),
    removeItem: vi.fn(key => { store.delete(key) }),
    clear: vi.fn(() => { store.clear() }),
  }
}

describe('suggestionEnabled storage key', () => {
  beforeEach(() => {
    Object.keys(storageState).forEach(k => delete storageState[k])
    vi.resetModules()
    globalThis.chrome = chromeMock
    globalThis.localStorage = createLocalStorageMock()
  })

  test('SUGGESTION_ENABLED key exists in STORAGE_KEYS', async () => {
    const { STORAGE_KEYS } = await import('../storageUtils.js')
    expect(STORAGE_KEYS.SUGGESTION_ENABLED).toBe('suggestionEnabled')
  })

  test('default value for suggestionEnabled is true', async () => {
    const { storageManager, STORAGE_KEYS } = await import('../storageUtils.js')
    const val = await storageManager.getSetting(STORAGE_KEYS.SUGGESTION_ENABLED)
    expect(val).toBe(true)
  })

  test('setSetting persists suggestionEnabled and getSetting returns updated value', async () => {
    const { storageManager, STORAGE_KEYS } = await import('../storageUtils.js')
    await storageManager.setSetting(STORAGE_KEYS.SUGGESTION_ENABLED, false)
    const val = await storageManager.getSetting(STORAGE_KEYS.SUGGESTION_ENABLED)
    expect(val).toBe(false)
  })

  test('setting suggestionEnabled back to true is readable', async () => {
    const { storageManager, STORAGE_KEYS } = await import('../storageUtils.js')
    await storageManager.setSetting(STORAGE_KEYS.SUGGESTION_ENABLED, false)
    await storageManager.setSetting(STORAGE_KEYS.SUGGESTION_ENABLED, true)
    const val = await storageManager.getSetting(STORAGE_KEYS.SUGGESTION_ENABLED)
    expect(val).toBe(true)
  })
})
