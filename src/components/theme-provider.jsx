import React, { createContext, useContext, useEffect, useState } from 'react'

const ThemeProviderContext = createContext({ theme: 'system', setTheme: () => {} })

export function ThemeProvider({ children, defaultTheme = 'system', storageKey = 'vite-ui-theme' }) {
  const [theme, setThemeState] = useState(() => {
    try {
      return localStorage.getItem(storageKey) || defaultTheme
    } catch (e) {
      return defaultTheme
    }
  })

  useEffect(() => {
    const root = window.document.documentElement

    const applyTheme = () => {
      // keep both class and data-theme attribute in sync so CSS using either works
      root.classList.remove('light', 'dark')
      root.removeAttribute('data-theme')

      const resolved = theme === 'system'
        ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
        : theme

      root.classList.add(resolved)
      root.setAttribute('data-theme', resolved)
    }

    applyTheme()

    if (theme !== 'system') return undefined

    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const handleChange = () => applyTheme()
    media.addEventListener?.('change', handleChange)
    return () => media.removeEventListener?.('change', handleChange)
  }, [theme])

  const setTheme = (t) => {
    try {
      localStorage.setItem(storageKey, t)
    } catch (e) {
      // ignore
    }
    setThemeState(t)
  }

  return (
    <ThemeProviderContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeProviderContext.Provider>
  )
}

export const useTheme = () => {
  const context = useContext(ThemeProviderContext)
  if (!context) throw new Error('useTheme must be used within a ThemeProvider')
  return context
}

export default ThemeProvider
