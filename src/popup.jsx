import React from 'react'
import ReactDOM from 'react-dom/client'
import PopupApp from './PopupApp'
import { ThemeProvider } from './components/theme-provider'
import './styles/tailwind.css'
// Apply persisted theme early to reduce FOUC without inline scripts
try {
  const t = localStorage.getItem('vite-ui-theme')
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
  let mode = t || 'system'
  if (mode === 'system') mode = prefersDark ? 'dark' : 'light'
  const root = document.documentElement
  root.classList.remove('light','dark')
  root.removeAttribute('data-theme')
  root.classList.add(mode)
  root.setAttribute('data-theme', mode)
} catch(e) {}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ThemeProvider defaultTheme="system" storageKey="vite-ui-theme">
      <PopupApp />
    </ThemeProvider>
  </React.StrictMode>
)
