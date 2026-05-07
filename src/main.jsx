import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { ThemeProvider } from './components/theme-provider'
import './styles/tailwind.css'

try {
  const storedTheme = localStorage.getItem('vite-ui-theme')
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
  let mode = storedTheme || 'system'

  if (mode === 'system') mode = prefersDark ? 'dark' : 'light'

  const root = document.documentElement
  root.classList.remove('light', 'dark')
  root.removeAttribute('data-theme')
  root.classList.add(mode)
  root.setAttribute('data-theme', mode)
} catch (error) {}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ThemeProvider defaultTheme="system" storageKey="vite-ui-theme">
      <App />
    </ThemeProvider>
  </React.StrictMode>
)
