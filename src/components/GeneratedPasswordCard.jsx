import React, { useEffect, useMemo, useState } from 'react'
// Advanced estimator (install: npm i @zxcvbn-ts/core)
// Lazy-load zxcvbn to reduce initial bundle size


const GeneratedPasswordCard = ({ password }) => {
  const [zxcvbnFn, setZxcvbnFn] = useState(null)
  useEffect(() => {
    let mounted = true
    import('@zxcvbn-ts/core')
      .then((mod) => {
        if (mounted) setZxcvbnFn(() => mod.zxcvbn)
      })
      .catch(() => {})
    return () => { mounted = false }
  }, [])

  const analysis = useMemo(() => {
    const val = password || ''
    if (!val) return { score: 0, label: 'Empty', crackTime: '', suggestions: [] }
    if (!zxcvbnFn) return { score: 0, label: 'Estimating…', crackTime: '', suggestions: [] }
    const r = zxcvbnFn(val)
    const score = r.score
    const label = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'][score] || 'Unknown'
    const crackTime = r.crackTimesDisplay?.offlineSlowHashing1e4PerSecond || ''
    const suggestions = r.feedback?.suggestions || []
    return { score, label, crackTime, suggestions }
  }, [password, zxcvbnFn])

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
          <div className="mt-1 text-xs text-muted-foreground">Ready to copy or autofill</div>
        </div>
        <div className="rounded-sm border border-border/80 bg-background/35 px-2 py-1 text-[11px] font-medium text-muted-foreground">
          {password?.length || 0} chars
        </div>
      </div>
      <div className="flex items-center gap-2">
        <div className="min-h-14 w-full rounded-sm border border-border/80 bg-background/25 px-3.5 py-3 shadow-none">
          {password ? (
            <div className="break-all font-mono text-[1.55rem] font-medium leading-tight tracking-[-0.03em]">
              {passwordSegments.map(({ char, className }, index) => (
                <span key={`${char}-${index}`} className={className}>{char}</span>
              ))}
            </div>
          ) : (
            <div className="font-mono text-base text-muted-foreground">Your password will appear here...</div>
          )}
        </div>
      </div>
      <div className="mt-4 flex items-center justify-between gap-4 text-xs">
        <div className="flex flex-1 items-center gap-2">
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted/80">
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
