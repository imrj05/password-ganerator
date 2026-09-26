// MV3 service worker: clears password history when the popup closes while
// the "Clear History on Close" setting is enabled. The popup holds a port
// open for its lifetime, so a disconnect marks the popup as closed.

const HISTORY_KEY = 'passwordHistory'
const CLEAR_ON_CLOSE_KEY = 'historyClearOnClose'

let openPopupPorts = 0

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'popup') return

  openPopupPorts += 1

  port.onDisconnect.addListener(() => {
    openPopupPorts = Math.max(0, openPopupPorts - 1)
    if (openPopupPorts > 0) return

    chrome.storage.local.get([CLEAR_ON_CLOSE_KEY], (result) => {
      if (result?.[CLEAR_ON_CLOSE_KEY] !== true) return
      chrome.storage.local.set({ [HISTORY_KEY]: [] })
    })
  })
})
