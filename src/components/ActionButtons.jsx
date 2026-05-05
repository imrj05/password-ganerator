import React, { useEffect, useRef, useState } from 'react'
import { Button } from './ui/button'
import { ClipboardCopy, CopyCheck, Send, BadgeCheck, RefreshCcw, Sparkles } from 'lucide-react'

const ActionButtons = ({ onCopy, onAutofill, onRefresh, disabled }) => {
  const [copyStatus, setCopyStatus] = useState('idle')
  const [autofillStatus, setAutofillStatus] = useState('idle')
  const [refreshStatus, setRefreshStatus] = useState('idle')
  const timersRef = useRef({ copy: null, autofill: null, refresh: null })

  const resetAfterDelay = (key, setter) => {
    if (timersRef.current[key]) clearTimeout(timersRef.current[key])
    timersRef.current[key] = setTimeout(() => {
      setter('idle')
      timersRef.current[key] = null
    }, 1000)
  }

  useEffect(() => () => {
    Object.values(timersRef.current).forEach(t => t && clearTimeout(t))
  }, [])

  const handleCopyClick = async () => {
    if (disabled) return
    try {
      await Promise.resolve(onCopy?.())
      setCopyStatus('success')
      resetAfterDelay('copy', setCopyStatus)
    } catch {
      setCopyStatus('idle')
    }
  }

  const handleAutofillClick = async () => {
    if (disabled) return
    try {
      await Promise.resolve(onAutofill?.())
      setAutofillStatus('success')
      resetAfterDelay('autofill', setAutofillStatus)
    } catch {
      setAutofillStatus('idle')
    }
  }

  const handleRefreshClick = async () => {
    try {
      await Promise.resolve(onRefresh?.())
      setRefreshStatus('success')
      resetAfterDelay('refresh', setRefreshStatus)
    } catch {
      setRefreshStatus('idle')
    }
  }

  return (
    <div className="space-y-2.5">
      <div className="grid grid-cols-2 gap-3">
        <Button
          variant="outline"
          onClick={handleRefreshClick}
          className="h-11 justify-center gap-2 border-border/80 bg-background/35 text-foreground"
        >
          {refreshStatus === 'success' ? <Sparkles size={18} /> : <RefreshCcw size={18} />}
          <span>{refreshStatus === 'success' ? 'Updated' : 'Refresh'}</span>
        </Button>

        <Button
          variant="outline"
          onClick={handleCopyClick}
          disabled={disabled}
          className="h-11 justify-center gap-2 border-border/80 bg-background/35 text-foreground"
        >
          {copyStatus === 'success' ? <CopyCheck size={18} /> : <ClipboardCopy size={18} />}
          <span>{copyStatus === 'success' ? 'Copied' : 'Copy'}</span>
        </Button>
      </div>

        <Button
          variant="secondary"
          onClick={handleAutofillClick}
          disabled={disabled}
          className="h-10 w-full justify-center gap-2 border border-border/80 bg-background/25 text-muted-foreground"
        >
        {autofillStatus === 'success' ? <BadgeCheck size={17} className="text-emerald-500" /> : <Send size={17} />}
        <span>{autofillStatus === 'success' ? 'Filled on page' : 'Autofill on current page'}</span>
      </Button>
    </div>
  )
}

export default ActionButtons
