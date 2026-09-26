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
    document.documentElement.querySelectorAll('[id^="securepass-"]').forEach(element => element.remove())
    globalThis.localStorage = createLocalStorageMock()
    globalThis.chrome = chromeMock
    chromeMock.runtime.onMessage.addListener.mockClear()
    chromeMock.storage.local.set.mockClear()
    chromeMock.storage.local.get.mockResolvedValue({})
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

  test('does not write password history for popup-triggered autofill', async () => {
    document.body.innerHTML = `
      <form>
        <input id="autofill-password" type="password" />
      </form>
    `
    defineVisibleClientRects(document.getElementById('autofill-password'))

    const listener = chromeMock.runtime.onMessage.addListener.mock.calls[0][0]
    const sendResponse = vi.fn()
    listener({ action: 'fillPassword', password: 'Generated#Password123' }, {}, sendResponse)

    await new Promise(resolve => setTimeout(resolve, 0))

    const historyWrites = chromeMock.storage.local.set.mock.calls.filter(
      ([payload]) => payload && Object.prototype.hasOwnProperty.call(payload, 'passwordHistory')
    )
    expect(historyWrites).toHaveLength(0)
    expect(sendResponse).toHaveBeenCalledWith(expect.objectContaining({ success: true }))
  })

  test('uses stored generator settings for in-page suggestions', async () => {
    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__
    const settings = {
      length: 16,
      includeUppercase: true,
      includeLowercase: true,
      includeNumbers: true,
      includeSymbols: true,
      symbolSet: 'basic',
      customSymbols: '',
      excludeAmbiguous: true,
    }
    chromeMock.storage.local.get.mockImplementation(async (key) => (
      typeof key === 'string' && key in settings ? { [key]: settings[key] } : {}
    ))

    const options = await api.getPasswordOptions()

    expect(options).toMatchObject({
      length: 16,
      includeSymbols: true,
      symbolSet: 'basic',
      excludeAmbiguous: true,
    })

    const password = api.generatePassword(options)
    expect(password).toHaveLength(16)
    expect(password).not.toMatch(/[il1Lo0O]/)
  })

  test('excludes ambiguous characters from generated passwords when requested', () => {
    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__

    const password = api.generatePassword({
      length: 32,
      includeUppercase: false,
      includeLowercase: false,
      includeNumbers: true,
      includeSymbols: false,
      excludeAmbiguous: true,
    })

    expect(password).toHaveLength(32)
    expect(password).toMatch(/^[2-9]+$/)
  })

  test('caches generator options until storage changes', async () => {
    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__
    let length = 16
    chromeMock.storage.local.get.mockImplementation(async (key) => (
      key === 'length' ? { length } : {}
    ))

    expect((await api.getPasswordOptions()).length).toBe(16)

    length = 24
    expect((await api.getPasswordOptions()).length).toBe(16)

    const onChanged = chromeMock.storage.onChanged.addListener.mock.calls.at(-1)[0]
    onChanged({ length: { newValue: 24 } }, 'local')

    expect((await api.getPasswordOptions()).length).toBe(24)
  })

  test('dismisses the suggestion bubble with Escape', async () => {
    document.body.innerHTML = `
      <form>
        <input id="suggest-password" type="password" />
      </form>
    `
    defineVisibleClientRects(document.getElementById('suggest-password'))

    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__
    await api.showSuggestionForFirstEligibleField()

    const root = document.getElementById('securepass-suggestion-root')
    expect(root.style.display).toBe('block')

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))

    expect(root.style.display).toBe('none')
  })

  test('describes generated password strength and length', () => {
    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__

    const weak = api.getPasswordStrengthInfo('abcd', { includeLowercase: true })
    expect(weak.tone).toBe('neutral')
    expect(weak.text).toContain('4 chars')

    const strong = api.getPasswordStrengthInfo('aB3!aB3!aB3!aB3!', {
      includeUppercase: true,
      includeLowercase: true,
      includeNumbers: true,
      includeSymbols: true,
      symbolSet: 'basic',
    })
    expect(strong.tone).toBe('strong')
    expect(strong.text).toContain('Strong')
  })

  test('offers an account picker for multiple saved logins', async () => {
    document.body.innerHTML = `
      <form>
        <input id="pick-password" type="password" />
      </form>
    `
    const field = document.getElementById('pick-password')
    defineVisibleClientRects(field)

    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__
    await api.showCredentialSuggestion(field, [
      { id: 1, domain: 'example.com', usernamePreview: 'first@example.com' },
      { id: 2, domain: 'example.com', usernamePreview: 'second@example.com' },
    ])

    const select = document.querySelector('#securepass-suggestion-root select')
    expect(select.style.display).toBe('block')
    expect(select.options).toHaveLength(2)

    select.value = '1'
    select.dispatchEvent(new Event('change', { bubbles: true }))

    const passwordText = Array.from(document.querySelectorAll('#securepass-suggestion-root div'))
      .find(element => element.style.fontFamily.includes('mono'))
    expect(passwordText.textContent).toBe('second@example.com')
  })

  test('hides the account picker when only one login is saved', async () => {
    document.body.innerHTML = `
      <form>
        <input id="single-password" type="password" />
      </form>
    `
    const field = document.getElementById('single-password')
    defineVisibleClientRects(field)

    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__
    await api.showCredentialSuggestion(field, [
      { id: 1, domain: 'example.com', usernamePreview: 'only@example.com' },
    ])

    const select = document.querySelector('#securepass-suggestion-root select')
    expect(select.style.display).toBe('none')
  })

  test('uses readable password colors in both themes', () => {
    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__

    expect(api.getPasswordCharColor('A', 0, 'light')).toBe('#111827')
    expect(api.getPasswordCharColor('a', 0, 'light')).toBe('#374151')
    expect(api.getPasswordCharColor('A', 0, 'dark')).toBe('#f4f4f5')
    expect(api.getPasswordCharColor('a', 0, 'dark')).toBe('#d4d4d8')
  })

  test('renders labeled action buttons and an svg trigger icon', async () => {
    document.body.innerHTML = `
      <form>
        <input id="label-password" type="password" />
      </form>
    `
    const field = document.getElementById('label-password')
    defineVisibleClientRects(field)

    const api = globalThis.__SECUREPASS_CONTENT_SCRIPT__
    await api.showSuggestionForFirstEligibleField()

    const buttonLabels = Array.from(document.querySelectorAll('#securepass-suggestion-root button'))
      .map(button => button.textContent)
    expect(buttonLabels).toContain('Fill')
    expect(buttonLabels).toContain('Copy')

    expect(document.querySelector('#securepass-trigger-root svg')).toBeTruthy()
    expect(document.querySelector('#securepass-trigger-root img')).toBeNull()
  })
})
