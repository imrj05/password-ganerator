import { beforeEach, describe, expect, test, vi } from 'vitest'

const storageState = {}

const chromeMock = {
  storage: {
    local: {
      get: vi.fn((key, callback) => {
        let result = {}

        if (Array.isArray(key)) {
          result = key.reduce((acc, item) => {
            acc[item] = storageState[item]
            return acc
          }, {})
        } else if (typeof key === 'string') {
          result = { [key]: storageState[key] }
        }

        if (typeof callback === 'function') {
          callback(result)
          return undefined
        }

        return Promise.resolve(result)
      }),
      set: vi.fn((values, callback) => {
        Object.assign(storageState, values)
        if (typeof callback === 'function') {
          callback()
          return undefined
        }
        return Promise.resolve()
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

describe('storageUtils saved credentials', () => {
  beforeEach(async () => {
    Object.keys(storageState).forEach(key => delete storageState[key])
    vi.resetModules()
    globalThis.chrome = chromeMock
    globalThis.localStorage = createLocalStorageMock()
  })

  test('stores and filters saved credentials by domain', async () => {
    const cryptoModule = await import('../lib/crypto.js')
    const storageModule = await import('../storageUtils.js')
    const { storageManager } = storageModule

    const usernameEnc = await cryptoModule.encryptText('person@example.com')
    const passwordEnc = await cryptoModule.encryptText('Secret#12345')
    const otherUsernameEnc = await cryptoModule.encryptText('other@example.com')
    const otherPasswordEnc = await cryptoModule.encryptText('Other#12345')

    const firstSaved = await storageManager.saveCredential({
      origin: 'https://example.com/login',
      domain: 'example.com',
      username: 'person@example.com',
      usernameEnc,
      passwordEnc,
      label: 'Primary'
    })

    expect(firstSaved).toBeTruthy()

    const secondSaved = await storageManager.saveCredential({
      origin: 'https://example.org/login',
      domain: 'example.org',
      username: 'other@example.com',
      usernameEnc: otherUsernameEnc,
      passwordEnc: otherPasswordEnc,
      label: 'Other'
    })

    expect(secondSaved).toBeTruthy()

    const credentials = await storageManager.getSavedCredentials('example.com')

    expect(credentials).toHaveLength(1)
    expect(credentials[0].domain).toBe('example.com')
    expect(credentials[0].usernamePreview).toContain('pe')
  })

  test('tracks never-save domains', async () => {
    const storageModule = await import('../storageUtils.js')
    const { storageManager } = storageModule

    await storageManager.setNeverSaveDomain('https://example.com/login', true)
    expect(await storageManager.isNeverSaveDomain('example.com')).toBe(true)

    await storageManager.setNeverSaveDomain('example.com', false)
    expect(await storageManager.isNeverSaveDomain('example.com')).toBe(false)
  })
})
