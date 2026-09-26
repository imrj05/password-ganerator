import React, { useEffect, useMemo, useRef, useState } from 'react'
import { loadPasswordStrength } from '../lib/passwordStrength'
import SecurePasswordGenerator from '../securePasswordGenerator'

const fallbackGenerator = new SecurePasswordGenerator()

const GeneratedPasswordCard = ({ password, onCopy }) => {
  const [zxcvbnFn, setZxcvbnFn] = useState(null)
  const [estimateFailed, setEstimateFailed] = useState(false)
  const [copied, setCopied] = useState(false)
  const copyTimerRef = useRef(null)

  useEffect(() => () => {
    if (copyTimerRef.current) clearTimeout(copyTimerRef.current)
  }, [])

  const handleCopyClick = async () => {
    if (!password || !onCopy) return
    try {
      await Promise.resolve(onCopy())
      setCopied(true)
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current)
      copyTimerRef.current = setTimeout(() => setCopied(false), 1600)
    } catch (e) {
      // Copy errors are surfaced by the popup toast
    }
  }

  useEffect(() => {
    let mounted = true
    loadPasswordStrength()
      .then((fn) => {
        if (mounted) setZxcvbnFn(() => fn)
      })
      .catch(() => {
        if (mounted) setEstimateFailed(true)
      })
    return () => { mounted = false }
  }, [])

  const analysis = useMemo(() => {
    const val = password || ''
    if (!val) return { score: 0, label: 'Empty', crackTime: '', suggestions: [] }
    if (!zxcvbnFn) {
      if (!estimateFailed) return { score: 0, label: 'Estimating…', crackTime: '', suggestions: [] }
      // Fall back to the generator's own entropy estimate if zxcvbn cannot load
      const fallback = fallbackGenerator.assessPasswordStrength(val)
      return {
        score: Math.max(0, Math.min(4, fallback.score - 1)),
        label: fallback.label,
        crackTime: fallback.timeToCrack || '',
        suggestions: [],
      }
    }
    const r = zxcvbnFn(val)
    const score = r.score
    const label = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'][score] || 'Unknown'
    const crackTime = r.crackTimesDisplay?.offlineSlowHashing1e4PerSecond || ''
    const suggestions = r.feedback?.suggestions || []
    return { score, label, crackTime, suggestions }
  }, [password, zxcvbnFn, estimateFailed])

  const passwordSegments = useMemo(() => {
    if (!password) return []

    return Array.from(password).map((char, index) => {
      let className = 'text-foreground'

      if (/\d/.test(char)) {
        className = index % 2 === 0 ? 'text-sky-500' : 'text-cyan-400'
      } else if (/[^A-Za-z0-9]/.test(char)) {
        className = 'text-amber-500'
      } else if (/[A-Z]/.test(char)) {
        className = 'text-foreground'
      } else {
        className = 'text-slate-700 dark:text-slate-200'
      }

      return { char, className }
    })
  }, [password])

  return (
    <div className="p-0 shadow-none">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Generated password</div>
          <div className="mt-1 text-xs text-muted-foreground">
            {copied ? 'Copied to clipboard' : 'Click the password to copy'}
          </div>
        </div>
        <div className="rounded-sm border border-border/80 bg-background/35 px-2 py-1 text-[11px] font-medium text-muted-foreground">
          {password?.length || 0} chars
        </div>
      </div>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={handleCopyClick}
          disabled={!password}
          aria-label={copied ? 'Password copied' : 'Copy generated password'}
          className="min-h-14 w-full cursor-pointer rounded-sm border border-border/80 bg-background/25 px-3.5 py-3 text-left shadow-none transition-colors hover:border-primary/40 hover:bg-primary/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-default"
        >
          {password ? (
            <div className="break-all font-mono text-[1.55rem] font-medium leading-tight tracking-[-0.03em]">
              {passwordSegments.map(({ char, className }, index) => (
                <span key={`${char}-${index}`} className={className}>{char}</span>
              ))}
            </div>
          ) : (
            <div className="font-mono text-base text-muted-foreground">Your password will appear here...</div>
          )}
        </button>
      </div>
      <div className="mt-4 flex items-center justify-between gap-4 text-xs">
        <div className="flex flex-1 items-center gap-2">
          <div
            role="progressbar"
            aria-label="Password strength"
            aria-valuemin={0}
            aria-valuemax={4}
            aria-valuenow={analysis.score}
            aria-valuetext={analysis.label}
            className="h-1.5 w-full overflow-hidden rounded-full bg-muted/80"
          >
            <div
              className={`h-full rounded-full transition-all ${analysis.score <= 1 ? 'bg-rose-500' : analysis.score === 2 ? 'bg-amber-500' : analysis.score === 3 ? 'bg-primary/85' : 'bg-emerald-500'}`}
              style={{ width: `${(analysis.score / 4) * 100}%` }}
            />
          </div>
        </div>
        <div className="text-[11px] font-medium text-muted-foreground">{analysis.label}</div>
      </div>
      {analysis.score <= 2 && analysis.suggestions.length > 0 && (
        <div className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
          {analysis.suggestions.join(' ')}
        </div>
      )}
      {analysis.crackTime && (
        <div className="mt-2 text-[11px] text-muted-foreground">Offline crack time: {analysis.crackTime}</div>
      )}
    </div>
  )
}

export default GeneratedPasswordCard
