import React from 'react'
import { Button } from './ui/button'
import { Card } from './ui/card'
import { Badge } from './ui/badge'
import { Input } from './ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip'
import { Copy, Eye, KeyRound, Trash2, UserRound, Send, Pencil, Check, X } from 'lucide-react'
import { filterVaultCredentials, sortVaultCredentials } from '../vaultFilters'
import { getCredentialAgeStatus } from '../credentialAge'
import { decryptText } from '@/lib/crypto'
import { enrollPlatformCredential, isAuthWindowValid, verifyPlatformCredential } from '@/lib/webauthn'
import { toast } from 'sonner'

const VaultPanel = ({ credentialsData, onCopyField, onFillCredential, onRemoveCredential, onUpdateCredentialLabel, formatTimestamp }) => {
  const [revealed, setRevealed] = React.useState({})
  const [searchQuery, setSearchQuery] = React.useState('')
  const [sortBy, setSortBy] = React.useState('updated')
  const [editingLabelId, setEditingLabelId] = React.useState(null)
  const [labelDraft, setLabelDraft] = React.useState('')
  const revealTimers = React.useRef({})
  const filteredCredentials = React.useMemo(() => (
    sortVaultCredentials(filterVaultCredentials(credentialsData, searchQuery), sortBy)
  ), [credentialsData, searchQuery, sortBy])

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

  const startEditingLabel = (entry) => {
    setEditingLabelId(entry.id)
    setLabelDraft(entry.label || '')
  }

  const cancelEditingLabel = () => {
    setEditingLabelId(null)
    setLabelDraft('')
  }

  const saveEditingLabel = async (entryId) => {
    await onUpdateCredentialLabel(entryId, labelDraft)
    cancelEditingLabel()
  }

  const getAgeBadgeClassName = (status) => {
    if (status === 'rotate') return 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300'
    if (status === 'review') return 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300'
    if (status === 'fresh') return 'border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
    return 'border-border/70 bg-background/40 text-muted-foreground'
  }

  return (
    <TooltipProvider>
      <div className="space-y-3">
        <Card className="border border-white/10 bg-background/75 p-4">
          <div>
            <div className="text-sm font-semibold">Saved Logins</div>
            <div className="text-xs text-muted-foreground">Store encrypted usernames and passwords for sign-in autofill.</div>
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
          <>
            <Card className="border border-white/10 bg-background/60 p-3 shadow-none">
              <div className="space-y-2">
                <Input
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  placeholder="Search domain, account, or label"
                  aria-label="Search saved logins"
                />
                <Select value={sortBy} onValueChange={setSortBy}>
                  <SelectTrigger className="h-9 text-xs" aria-label="Sort saved logins">
                    <SelectValue placeholder="Sort saved logins" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="updated">Recently updated</SelectItem>
                    <SelectItem value="used">Recently used</SelectItem>
                    <SelectItem value="oldest">Oldest updated</SelectItem>
                    <SelectItem value="domain">Domain</SelectItem>
                    <SelectItem value="label">Label</SelectItem>
                  </SelectContent>
                </Select>
                <div className="text-[11px] text-muted-foreground">
                  Showing {filteredCredentials.length} of {credentialsData.length} saved logins
                </div>
              </div>
            </Card>

            {filteredCredentials.length === 0 ? (
              <Card className="border border-dashed border-border/70 bg-background/55 p-5 text-center shadow-none">
                <div className="flex flex-col items-center gap-2 text-muted-foreground">
                  <KeyRound size={26} />
                  <div className="text-sm">No matching saved logins</div>
                  <div className="text-xs">Try a different domain, account, or label</div>
                </div>
              </Card>
            ) : filteredCredentials.map(entry => {
              const ageStatus = getCredentialAgeStatus(entry)

              return (
            <Card key={entry.id} className="border border-white/10 bg-background/60 p-3.5 shadow-none transition-colors hover:bg-background/72">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge variant="default">{entry.domain}</Badge>
                    {entry.label ? <Badge variant="outline">{entry.label}</Badge> : null}
                    <span
                      className={`rounded-sm border px-2 py-0.5 text-[10px] font-medium ${getAgeBadgeClassName(ageStatus.status)}`}
                      title={ageStatus.description}
                    >
                      {ageStatus.label}
                    </span>
                  </div>
                  <div className="mt-2 flex items-center gap-2 text-sm text-foreground truncate">
                    <UserRound size={14} className="text-muted-foreground" />
                    <span className="truncate">{entry.usernamePreview || 'Unknown account'}</span>
                  </div>
                  <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
                    <span>Updated {formatTimestamp(entry.updatedAt)}</span>
                    {ageStatus.daysOld !== null ? <span>• {ageStatus.daysOld}d old</span> : null}
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

              {editingLabelId === entry.id ? (
                <div className="mt-3 flex items-center gap-2">
                  <Input
                    value={labelDraft}
                    onChange={(event) => setLabelDraft(event.target.value)}
                    maxLength={40}
                    placeholder="Label, e.g. Work or Personal"
                    aria-label="Saved login label"
                  />
                  <Button variant="secondary" size="icon" onClick={() => saveEditingLabel(entry.id)} aria-label="Save label">
                    <Check size={14} />
                  </Button>
                  <Button variant="ghost" size="icon" onClick={cancelEditingLabel} aria-label="Cancel label edit">
                    <X size={14} />
                  </Button>
                </div>
              ) : (
                <div className="mt-3 flex items-center justify-between gap-2 rounded-sm border border-border/60 bg-background/35 px-3 py-2 text-xs text-muted-foreground">
                  <span className="truncate">Label: {entry.label || 'None'}</span>
                  <Button variant="ghost" size="icon" onClick={() => startEditingLabel(entry)} aria-label="Edit label">
                    <Pencil size={13} />
                  </Button>
                </div>
              )}

              <div className="mt-3 rounded-sm border border-border/60 bg-background/65 px-3 py-2.5 text-sm font-mono truncate">
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
              )
            })}
          </>
        )}
      </div>
    </TooltipProvider>
  )
}

export default VaultPanel
