import { beforeEach, describe, expect, test, vi } from 'vitest'

function createChromeMock() {
  return {
    runtime: {
      onConnect: {
        addListener: vi.fn()
      }
    },
    storage: {
      local: {
        get: vi.fn(),
        set: vi.fn()
      }
    }
  }
}

describe('background clear-on-close', () => {
  let chromeMock

  beforeEach(async () => {
    vi.resetModules()
    chromeMock = createChromeMock()
    globalThis.chrome = chromeMock
    await import('../../background.js')
  })

  const connectPort = () => {
    const onConnect = chromeMock.runtime.onConnect.addListener.mock.calls.at(-1)[0]
    const port = { name: 'popup', onDisconnect: { addListener: vi.fn() } }
    onConnect(port)
    return port.onDisconnect.addListener.mock.calls[0][0]
  }

  test('clears history when the popup closes with the setting enabled', () => {
    const disconnect = connectPort()
    chromeMock.storage.local.get.mockImplementation((keys, callback) => callback({ historyClearOnClose: true }))

    disconnect()

    expect(chromeMock.storage.local.set).toHaveBeenCalledWith({ passwordHistory: [] })
  })

  test('keeps history when the setting is disabled', () => {
    const disconnect = connectPort()
    chromeMock.storage.local.get.mockImplementation((keys, callback) => callback({ historyClearOnClose: false }))

    disconnect()

    expect(chromeMock.storage.local.set).not.toHaveBeenCalled()
  })

  test('does not clear while another popup is still open', () => {
    const disconnectFirst = connectPort()
    const disconnectSecond = connectPort()
    chromeMock.storage.local.get.mockImplementation((keys, callback) => callback({ historyClearOnClose: true }))

    disconnectFirst()
    expect(chromeMock.storage.local.set).not.toHaveBeenCalled()

    disconnectSecond()
    expect(chromeMock.storage.local.set).toHaveBeenCalledWith({ passwordHistory: [] })
  })
})
