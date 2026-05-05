import { beforeEach, describe, expect, test, vi } from 'vitest'

const chromeMock = {
  runtime: {
    onMessage: {
      addListener: vi.fn()
    }
  },
  storage: {
    local: {
      get: vi.fn(async () => ({})),
      set: vi.fn(async () => undefined)
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

function defineVisibleClientRects(input) {
  Object.defineProperty(input, 'getClientRects', {
    configurable: true,
    value: () => [{ width: 120, height: 40 }]
  })
}

describe('contentScript helpers', () => {
  beforeEach(async () => {
    vi.resetModules()
    document.body.innerHTML = ''
    globalThis.localStorage = createLocalStorageMock()
    globalThis.chrome = chromeMock
    await import('../../contentScript.js')
  })

  test('fills focused and empty same-form password fields', () => {
    document.body.innerHTML = `
      <form>
        <input id="new-password" type="password" />
        <input id="confirm-password" type="password" />
        <input id="current-password" type="password" value="existing-secret" />
      </form>
    `

    const primary = document.getElementById('new-password')
    const confirm = document.getElementById('confirm-password')
    const current = document.getElementById('current-password')

    defineVisibleClientRects(primary)
    defineVisibleClientRects(confirm)
    defineVisibleClientRects(current)

    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__
    const targets = api.getSameFormTargets(primary)

    expect(targets).toHaveLength(2)
    expect(targets).toContain(primary)
    expect(targets).toContain(confirm)

    const result = api.fillPasswordFields('Generated#Password123', primary)

    expect(result.success).toBe(true)
    expect(primary.value).toBe('Generated#Password123')
    expect(confirm.value).toBe('Generated#Password123')
    expect(current.value).toBe('existing-secret')
  })

  test('eligible suggestion fields must be password-like and empty', () => {
    document.body.innerHTML = `
      <input id="empty-password" type="password" />
      <input id="filled-password" type="password" value="already-here" />
      <input id="email" type="email" />
    `

    const emptyPassword = document.getElementById('empty-password')
    const filledPassword = document.getElementById('filled-password')
    const email = document.getElementById('email')

    defineVisibleClientRects(emptyPassword)
    defineVisibleClientRects(filledPassword)
    defineVisibleClientRects(email)

    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__

    expect(api.isEligibleSuggestionField(emptyPassword)).toBe(true)
    expect(api.isEligibleSuggestionField(filledPassword)).toBe(false)
    expect(api.isEligibleSuggestionField(email)).toBe(false)
  })

  test('picks the first eligible password field automatically', () => {
    document.body.innerHTML = `
      <input id="filled-password" type="password" value="already-here" />
      <input id="first-empty-password" type="password" />
      <input id="second-empty-password" type="password" />
    `

    const filledPassword = document.getElementById('filled-password')
    const firstEmptyPassword = document.getElementById('first-empty-password')
    const secondEmptyPassword = document.getElementById('second-empty-password')

    defineVisibleClientRects(filledPassword)
    defineVisibleClientRects(firstEmptyPassword)
    defineVisibleClientRects(secondEmptyPassword)

    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__
    const eligibleFields = api.getEligibleSuggestionFields()

    expect(eligibleFields).toHaveLength(2)
    expect(eligibleFields[0]).toBe(firstEmptyPassword)
    expect(api.getPreferredSuggestionField()).toBe(firstEmptyPassword)
  })

  test('extracts username and password from a submitted sign-in form', () => {
    document.body.innerHTML = `
      <form id="signin-form">
        <input id="username" type="email" autocomplete="username" value="person@example.com" />
        <input id="password" type="password" autocomplete="current-password" value="Secret#12345" />
      </form>
    `

    const form = document.getElementById('signin-form')
    const username = document.getElementById('username')
    const password = document.getElementById('password')

    defineVisibleClientRects(username)
    defineVisibleClientRects(password)

    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__
    const payload = api.getCredentialPayloadFromForm(form)

    expect(payload).toMatchObject({
      domain: 'localhost',
      username: 'person@example.com',
      password: 'Secret#12345',
      isSignup: false
    })
  })

  test('fills saved username and password into sign-in fields', () => {
    document.body.innerHTML = `
      <form>
        <input id="login-email" type="email" autocomplete="username" />
        <input id="login-password" type="password" autocomplete="current-password" />
      </form>
    `

    const usernameField = document.getElementById('login-email')
    const passwordField = document.getElementById('login-password')

    defineVisibleClientRects(usernameField)
    defineVisibleClientRects(passwordField)

    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__
    const result = api.fillSavedCredential({ username: 'person@example.com', password: 'Secret#12345' }, passwordField)

    expect(result.success).toBe(true)
    expect(usernameField.value).toBe('person@example.com')
    expect(passwordField.value).toBe('Secret#12345')
  })

  test('persists and restores pending save prompt across navigation state', async () => {
    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__

    await api.persistPendingSavePrompt({
      domain: 'example.com',
      origin: 'https://example.com/login',
      username: 'person@example.com',
      password: 'Secret#12345',
      isSignup: false,
      createdAt: new Date().toISOString()
    })

    document.body.innerHTML = '<main>dashboard</main>'
    const restored = await api.restorePendingSavePrompt()

    expect(restored).toMatchObject({
      domain: 'example.com',
      username: 'person@example.com'
    })

    const savedPrompt = await api.getStorageValue('pendingCredentialPrompt', null)
    expect(savedPrompt).not.toBeNull()
  })

  test('does not prompt when saved username and password are unchanged', async () => {
    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__
    const usernameEnc = await api.encryptText('person@example.com')
    const passwordEnc = await api.encryptText('Secret#12345')

    await api.saveCredentialPayload({
      domain: 'localhost',
      origin: 'http://localhost/login',
      username: 'person@example.com',
      password: 'Secret#12345',
      isSignup: false
    })

    const shouldPrompt = await api.shouldPromptForCredential({
      domain: 'localhost',
      origin: 'http://localhost/login',
      username: 'person@example.com',
      password: 'Secret#12345',
      isSignup: false,
      usernameEnc,
      passwordEnc
    })

    expect(shouldPrompt).toBe(false)
  })

  test('prompts when saved username exists but password changed', async () => {
    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__

    await api.saveCredentialPayload({
      domain: 'localhost',
      origin: 'http://localhost/login',
      username: 'person@example.com',
      password: 'OldSecret#12345',
      isSignup: false
    })

    const shouldPrompt = await api.shouldPromptForCredential({
      domain: 'localhost',
      origin: 'http://localhost/login',
      username: 'person@example.com',
      password: 'NewSecret#67890',
      isSignup: false
    })

    expect(shouldPrompt).toBe(true)
  })

  test('prompts when username is new for the same domain', async () => {
    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__

    await api.saveCredentialPayload({
      domain: 'localhost',
      origin: 'http://localhost/login',
      username: 'person@example.com',
      password: 'Secret#12345',
      isSignup: false
    })

    const shouldPrompt = await api.shouldPromptForCredential({
      domain: 'localhost',
      origin: 'http://localhost/login',
      username: 'other@example.com',
      password: 'Secret#12345',
      isSignup: false
    })

    expect(shouldPrompt).toBe(true)
  })
})
