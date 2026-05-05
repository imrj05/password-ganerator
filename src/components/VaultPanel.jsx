import React from 'react'
import { Button } from './ui/button'
import { Card } from './ui/card'
import { Badge } from './ui/badge'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip'
import { Copy, Eye, KeyRound, Trash2, UserRound, Send, ShieldCheck } from 'lucide-react'
import { decryptText } from '@/lib/crypto'
import { enrollPlatformCredential, isAuthWindowValid, verifyPlatformCredential } from '@/lib/webauthn'
import { toast } from 'sonner'

const VaultPanel = ({ credentialsEnabled, setCredentialsEnabled, credentialsData, onCopyField, onFillCredential, onRemoveCredential, formatTimestamp }) => {
  const [revealed, setRevealed] = React.useState({})
  const revealTimers = React.useRef({})

  const ensureVerified = async () => {
    try {
      if (isAuthWindowValid()) return true
      let ok = await verifyPlatformCredential()
      if (ok) return true
      await enrollPlatformCredential()
      ok = await verifyPlatformCredential()
      return ok
    } catch (error) {
      return false
    }
  }

  const maskCredential = (entryId) => {
    setRevealed(prev => {
      const next = { ...prev }
      delete next[entryId]
      return next
    })

    if (revealTimers.current[entryId]) {
      clearTimeout(revealTimers.current[entryId])
      delete revealTimers.current[entryId]
    }
  }

  const handleRevealPassword = async (entry) => {
    if (!entry?.passwordEnc) return

    const ok = await ensureVerified()
    if (!ok) {
      toast.error('Verification failed')
      return
    }

    try {
      const plaintext = await decryptText(entry.passwordEnc)
      setRevealed(prev => ({ ...prev, [entry.id]: plaintext }))
      if (revealTimers.current[entry.id]) {
        clearTimeout(revealTimers.current[entry.id])
      }
      revealTimers.current[entry.id] = setTimeout(() => maskCredential(entry.id), 30_000)
    } catch (error) {
      toast.error('Unable to reveal password')
    }
  }

  React.useEffect(() => () => {
    Object.values(revealTimers.current).forEach(timer => clearTimeout(timer))
    revealTimers.current = {}
  }, [])

  return (
    <TooltipProvider>
      <div className="space-y-3">
        <Card className="border border-white/10 bg-background/75 p-4">
          <div className="flex items-center justify-between gap-3">
          <div>
            <div className="text-sm font-semibold">Saved Logins</div>
            <div className="text-xs text-muted-foreground">Store encrypted usernames and passwords for sign-in autofill.</div>
          </div>
          <button
            type="button"
            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors ${credentialsEnabled ? 'border-emerald-500/20 bg-emerald-500/12 text-emerald-700 dark:text-emerald-300' : 'border-border/60 bg-muted/70 text-muted-foreground'}`}
            onClick={() => setCredentialsEnabled(!credentialsEnabled)}
          >
            <ShieldCheck size={14} />
            {credentialsEnabled ? 'Enabled' : 'Disabled'}
          </button>
          </div>
        </Card>

        {credentialsData.length === 0 ? (
          <Card className="border border-dashed border-border/70 bg-background/55 p-5 text-center shadow-none">
            <div className="flex flex-col items-center gap-2 text-muted-foreground">
              <KeyRound size={26} />
              <div className="text-sm">No saved logins yet</div>
              <div className="text-xs">When you submit a sign-in or sign-up form, the extension can offer to save it.</div>
            </div>
          </Card>
        ) : (
          credentialsData.map(entry => (
            <Card key={entry.id} className="border border-white/10 bg-background/60 p-3.5 shadow-none transition-colors hover:bg-background/72">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge variant="default">{entry.domain}</Badge>
                    {entry.label ? <Badge variant="outline">{entry.label}</Badge> : null}
                  </div>
                  <div className="mt-2 flex items-center gap-2 text-sm text-foreground truncate">
                    <UserRound size={14} className="text-muted-foreground" />
                    <span className="truncate">{entry.usernamePreview || 'Unknown account'}</span>
                  </div>
                  <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
                    <span>Updated {formatTimestamp(entry.updatedAt)}</span>
                    {entry.lastUsedAt ? <span>• Used {formatTimestamp(entry.lastUsedAt)}</span> : null}
                  </div>
                </div>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="ghost" size="icon" onClick={() => onRemoveCredential(entry.id)} aria-label="Delete saved login">
                      <Trash2 size={14} />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Delete saved login</TooltipContent>
                </Tooltip>
              </div>

              <div className="rounded-sm border border-border/60 bg-background/65 px-3 py-2.5 text-sm font-mono truncate">
                {revealed[entry.id] || '••••••••••••'}
              </div>

              <div className="flex items-center justify-end gap-2">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="secondary" size="icon" onClick={() => handleRevealPassword(entry)} aria-label="Reveal password">
                      <Eye size={14} />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Reveal password</TooltipContent>
                </Tooltip>

                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="secondary" size="icon" onClick={() => onCopyField(entry, 'username')} aria-label="Copy username">
                      <UserRound size={14} />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Copy username</TooltipContent>
                </Tooltip>

                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="secondary" size="icon" onClick={() => onCopyField(entry, 'password')} aria-label="Copy password">
                      <Copy size={14} />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Copy password</TooltipContent>
                </Tooltip>

                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="default" size="icon" onClick={() => onFillCredential(entry)} aria-label="Fill login on page">
                      <Send size={14} />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Fill on current page</TooltipContent>
                </Tooltip>
              </div>
            </Card>
          ))
        )}
      </div>
    </TooltipProvider>
  )
}

export default VaultPanel
