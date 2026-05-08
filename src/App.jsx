import React, { useEffect, useState } from 'react'
import {
  ClipboardCheck,
  DatabaseZap,
  Fingerprint,
  Github,
  KeyRound,
  LockKeyhole,
  Moon,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Sun,
  WandSparkles
} from 'lucide-react'
import appIcon from '../icons/icon128.png'

const product = {
  name: 'SecurePass Generator',
  description: 'Generate strong random passwords, memorable passphrases, and PINs locally with a privacy-first design.'
}

const featureGroups = [
  {
    icon: ShieldCheck,
    title: 'Cryptographic Generation',
    description: 'Creates passwords locally with the Web Crypto API and rejection sampling, avoiding weak randomness and modulo bias.'
  },
  {
    icon: WandSparkles,
    title: 'Multiple Password Modes',
    description: 'Supports random passwords, memorable passphrases, and numeric PINs for different sign-in and recovery scenarios.'
  },
  {
    icon: RefreshCw,
    title: 'Custom Controls',
    description: 'Tune length, numbers, capitalization, symbols, and curated or custom symbol sets before generating credentials.'
  },
  {
    icon: ClipboardCheck,
    title: 'Copy-Ready Output',
    description: 'Presents generated credentials clearly so users can copy and use them only when they choose.'
  },
  {
    icon: DatabaseZap,
    title: 'Local History Ready',
    description: 'Designed around local credential workflows, with room for encrypted history and clear-on-close controls.'
  },
  {
    icon: Fingerprint,
    title: 'Privacy-First Foundation',
    description: 'Keeps the product focused on local execution, browser security APIs, and minimal data handling.'
  }
]

const stats = [
  { value: '3', label: 'Generator modes' },
  { value: '4-50', label: 'Random password length' },
  { value: '4-12', label: 'PIN digits' }
]

const privacyPoints = [
  'No analytics, telemetry, or remote password processing',
  'Preferences stay on the local device',
  'Clipboard writes only happen after an explicit user action'
]

const legalDocuments = {
  privacy: {
    eyebrow: 'Privacy Policy',
    title: 'Privacy Policy',
    updated: 'Last updated: May 07, 2026',
    intro: 'SecurePass Generator is designed to generate credentials locally in your browser. This policy explains what information the website handles and how it is protected.',
    sections: [
      {
        title: 'Information We Handle',
        body: 'The website may store your preferences and password generation settings locally if those features are enabled. Generated passwords are not sent to us or any external server.'
      },
      {
        title: 'Local Storage And Encryption',
        body: 'Settings are intended to stay on your device. Any future history or saved credential features should be local-first and encrypted before being saved.'
      },
      {
        title: 'Network Activity',
        body: 'The website does not use analytics, telemetry, advertising trackers, or remote password processing. Password generation runs locally with browser cryptography APIs.'
      },
      {
        title: 'Clipboard And Autofill',
        body: 'Clipboard actions happen only after you explicitly use the related controls. The website does not need account passwords to leave your browser.'
      },
      {
        title: 'Your Control',
        body: 'You can clear locally stored website data from your browser at any time. If optional local history features are added, they should remain user-controlled.'
      },
      {
        title: 'Contact',
        body: 'For privacy questions or security reports, contact the project maintainer through the GitHub repository linked on this site.'
      }
    ]
  },
  terms: {
    eyebrow: 'Terms And Conditions',
    title: 'Terms and Conditions',
    updated: 'Last updated: May 07, 2026',
    intro: 'These terms describe the conditions for using SecurePass Generator. By using this website, you agree to use it responsibly and understand its limitations.',
    sections: [
      {
        title: 'Use Of The Website',
        body: 'SecurePass Generator is provided to help create strong credentials locally. You are responsible for deciding where and how to use generated passwords.'
      },
      {
        title: 'No Warranty',
        body: 'The website is provided as-is without warranties of any kind. We do not guarantee uninterrupted operation, compatibility with every browser, or complete protection from all security risks.'
      },
      {
        title: 'User Responsibility',
        body: 'You are responsible for keeping your device, browser profile, operating system, and online accounts secure. Strong passwords are only one part of account security.'
      },
      {
        title: 'Acceptable Use',
        body: 'Do not use the website for illegal activity, unauthorized access, credential theft, or any activity that violates another service provider’s terms.'
      },
      {
        title: 'Changes To These Terms',
        body: 'We may update these terms as the project changes. Continued use after updates means you accept the revised terms.'
      },
      {
        title: 'Contact',
        body: 'For questions about these terms, contact the project maintainer through the GitHub repository linked on this site.'
      }
    ]
  }
}

const LegalPage = ({ document }) => (
  <main className="min-h-screen bg-background text-foreground">
    <section className="mx-auto flex min-h-screen w-full max-w-4xl flex-col px-5 py-6 sm:px-8 lg:px-10">
      <header className="flex items-center justify-between gap-4 border-b border-border/80 pb-6">
        <a href="/" className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-sm border border-border/80 bg-card shadow-sm">
            <img src={appIcon} alt="SecurePass Generator" className="h-7 w-7 object-contain" />
          </div>
          <div>
            <p className="text-sm font-semibold tracking-tight">{product.name}</p>
            <p className="text-xs text-muted-foreground">Back to home</p>
          </div>
        </a>
      </header>

      <div className="flex-1 py-12">
        <div className="mb-10 max-w-3xl">
          <p className="text-xs font-semibold uppercase tracking-[0.22em] text-primary">{document.eyebrow}</p>
          <h1 className="mt-3 text-4xl font-semibold tracking-[-0.06em] sm:text-5xl">{document.title}</h1>
          <p className="mt-4 text-sm text-muted-foreground">{document.updated}</p>
          <p className="mt-6 text-base leading-7 text-muted-foreground sm:text-lg">{document.intro}</p>
        </div>

        <div className="space-y-4">
          {document.sections.map((section) => (
            <article key={section.title} className="rounded-sm border border-border/80 bg-card/80 p-5 shadow-sm">
              <h2 className="text-lg font-semibold tracking-[-0.03em]">{section.title}</h2>
              <p className="mt-3 text-sm leading-7 text-muted-foreground">{section.body}</p>
            </article>
          ))}
        </div>
      </div>

      <footer className="flex flex-col gap-3 border-t border-border/80 py-5 text-sm text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
        <span>{product.name}</span>
        <div className="flex gap-4">
          <a href="/privacy" className="text-foreground transition-colors hover:text-primary">Privacy Policy</a>
          <a href="/terms" className="text-foreground transition-colors hover:text-primary">Terms</a>
        </div>
      </footer>
    </section>
  </main>
)

const App = () => {
  const [isDarkMode, setIsDarkMode] = useState(false)
  const path = window.location.pathname
  const legalDocument = path === '/privacy' || path.endsWith('/privacy')
    ? legalDocuments.privacy
    : path === '/terms' || path.endsWith('/terms')
      ? legalDocuments.terms
      : null

  useEffect(() => {
    setIsDarkMode(document.documentElement.classList.contains('dark'))
  }, [])

  const toggleTheme = () => {
    const next = isDarkMode ? 'light' : 'dark'
    const root = document.documentElement

    root.classList.remove('light', 'dark')
    root.classList.add(next)
    root.setAttribute('data-theme', next)
    localStorage.setItem('vite-ui-theme', next)
    setIsDarkMode(next === 'dark')
  }

  if (legalDocument) {
    return <LegalPage document={legalDocument} />
  }

  return (
    <main className="min-h-screen bg-background text-foreground">
      <section className="mx-auto flex min-h-screen w-full max-w-6xl flex-col px-5 py-6 sm:px-8 lg:px-10">
        <header className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-sm border border-border/80 bg-card shadow-sm">
              <img src={appIcon} alt="SecurePass Generator" className="h-7 w-7 object-contain" />
            </div>
            <div>
              <p className="text-sm font-semibold tracking-tight">{product.name}</p>
              <p className="text-xs text-muted-foreground">Privacy-first password landing page</p>
            </div>
          </div>

          <button
            type="button"
            onClick={toggleTheme}
            className="inline-flex h-10 w-10 items-center justify-center rounded-sm border border-border/80 bg-card text-muted-foreground shadow-sm transition-colors hover:text-foreground"
            aria-label="Toggle theme"
          >
            {isDarkMode ? <Sun size={18} /> : <Moon size={18} />}
          </button>
        </header>

        <div className="grid flex-1 items-center gap-10 py-12 lg:grid-cols-[1.08fr_0.92fr] lg:py-16">
          <div className="space-y-8">
            <div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/10 px-3 py-1.5 text-xs font-medium text-primary">
              <LockKeyhole size={14} />
              Local-first password security
            </div>

            <div className="max-w-3xl space-y-5">
              <h1 className="text-4xl font-semibold tracking-[-0.06em] text-foreground sm:text-5xl lg:text-6xl">
                Generate, save, and autofill strong passwords without sending them anywhere.
              </h1>
              <p className="max-w-2xl text-base leading-7 text-muted-foreground sm:text-lg">
                SecurePass Generator is a privacy-first password tool concept for creating random passwords, memorable passphrases, and PINs with local-only security principles.
              </p>
            </div>

            <div className="grid gap-3 sm:grid-cols-3">
              {stats.map((item) => (
                <div key={item.label} className="rounded-sm border border-border/80 bg-card/80 p-4 shadow-sm">
                  <div className="font-mono text-2xl font-semibold tracking-[-0.05em] text-foreground">{item.value}</div>
                  <div className="mt-1 text-xs text-muted-foreground">{item.label}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-sm border border-border/80 bg-card p-4 shadow-xl shadow-black/5 dark:shadow-black/20">
            <div className="rounded-sm border border-border/80 bg-background/60 p-4">
              <div className="mb-5 flex items-center justify-between gap-3">
                <div>
                  <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-muted-foreground">Feature Overview</p>
                  <h2 className="mt-1 text-xl font-semibold tracking-[-0.04em]">Built for everyday credentials</h2>
                </div>
                <Sparkles className="text-primary" size={22} />
              </div>

              <div className="grid gap-3">
                {featureGroups.map(({ icon: Icon, title, description }) => (
                  <article key={title} className="group rounded-sm border border-border/70 bg-card/70 p-4 transition-colors hover:border-primary/35">
                    <div className="flex gap-3">
                      <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-sm bg-primary/10 text-primary">
                        <Icon size={18} />
                      </div>
                      <div>
                        <h3 className="text-sm font-semibold">{title}</h3>
                        <p className="mt-1 text-sm leading-6 text-muted-foreground">{description}</p>
                      </div>
                    </div>
                  </article>
                ))}
              </div>
            </div>
          </div>
        </div>

        <section className="grid gap-4 border-t border-border/80 py-6 md:grid-cols-[0.9fr_1.1fr] md:items-center">
          <div>
            <div className="flex items-center gap-2 text-sm font-semibold">
              <KeyRound size={17} className="text-primary" />
              Privacy And Security
            </div>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              The website is designed around local execution, explicit user actions, and minimal persisted data.
            </p>
          </div>

          <div className="grid gap-2 sm:grid-cols-3">
            {privacyPoints.map((point) => (
              <div key={point} className="rounded-sm border border-border/80 bg-card/70 p-3 text-sm leading-5 text-muted-foreground">
                {point}
              </div>
            ))}
          </div>
        </section>

        <footer className="flex flex-col gap-3 border-t border-border/80 py-5 text-sm text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
          <span>{product.description}</span>
          <div className="flex flex-wrap items-center gap-4">
            <a href="/privacy" className="text-foreground transition-colors hover:text-primary">Privacy Policy</a>
            <a href="/terms" className="text-foreground transition-colors hover:text-primary">Terms</a>
            <a
              href="https://github.com/work-rjkashyap/password-ganerator"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 text-foreground transition-colors hover:text-primary"
            >
              <Github size={16} />
              GitHub
            </a>
          </div>
        </footer>
      </section>
    </main>
  )
}

export default App
