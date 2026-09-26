import React from 'react'
import { Button } from './ui/button'
import { Card } from './ui/card'
import { Badge } from './ui/badge'
import { Input } from './ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip'
import { Copy, Eye, EyeOff, KeyRound, Trash2, UserRound, Send, Pencil, Check, Plus, Wand2 } from 'lucide-react'
import { filterVaultCredentials, sortVaultCredentials } from '../vaultFilters'
import { getCredentialAgeStatus } from '../credentialAge'
import { decryptText } from '@/lib/crypto'
import { enrollPlatformCredential, isAuthWindowValid, verifyPlatformCredential } from '@/lib/webauthn'

const CredentialForm = ({
  title,
  submitLabel,
  initialValues = {},
  passwordRequired = true,
  onCancel,
  onSubmit,
  onGeneratePassword,
}) => {
  const formId = React.useId()
  const [values, setValues] = React.useState({
    label: initialValues.label || '',
    domain: initialValues.domain || '',
    username: initialValues.username || '',
    password: '',
  })
  const [showPassword, setShowPassword] = React.useState(false)
  const [error, setError] = React.useState('')
  const [saving, setSaving] = React.useState(false)

  const updateField = (key) => (event) => setValues(prev => ({ ...prev, [key]: event.target.value }))

  const handleGenerate = () => {
    if (!onGeneratePassword) return
    const generated = onGeneratePassword()
    if (!generated) return
    setValues(prev => ({ ...prev, password: generated }))
    setShowPassword(true)
  }

  const handleSubmit = async (event) => {
    event.preventDefault()

    if (!values.domain.trim() || !values.username.trim()) {
      setError('Website and username are required')
      return
    }
    if (passwordRequired && !values.password) {
      setError('Password is required')
      return
    }

    setSaving(true)
    const ok = await onSubmit(values)
    setSaving(false)
    if (!ok) setError('Could not save login')
  }

  return (
    <form onSubmit={handleSubmit} className="mt-3 space-y-2.5 rounded-sm border border-primary/30 bg-background/45 p-3">
      <div className="text-xs font-semibold text-foreground">{title}</div>

      <div className="space-y-1">
        <label htmlFor={`${formId}-domain`} className="text-[11px] font-medium text-muted-foreground">Website</label>
        <Input
          id={`${formId}-domain`}
          value={values.domain}
          onChange={updateField('domain')}
          placeholder="example.com or https://example.com/login"
          autoFocus={passwordRequired}
        />
      </div>

      <div className="space-y-1">
        <label htmlFor={`${formId}-username`} className="text-[11px] font-medium text-muted-foreground">Username</label>
        <Input
          id={`${formId}-username`}
          value={values.username}
          onChange={updateField('username')}
          placeholder="you@example.com"
        />
      </div>

      <div className="space-y-1">
        <label htmlFor={`${formId}-password`} className="text-[11px] font-medium text-muted-foreground">
          {passwordRequired ? 'Password' : 'New password (leave blank to keep current)'}
        </label>
        <div className="relative">
          <Input
            id={`${formId}-password`}
            type={showPassword ? 'text' : 'password'}
            value={values.password}
            onChange={updateField('password')}
            placeholder={passwordRequired ? 'Password' : '••••••••'}
            className="pr-16"
          />
          <div className="absolute inset-y-0 right-1.5 flex items-center gap-0.5">
            {onGeneratePassword && (
              <Button type="button" variant="ghost" size="icon" className="h-8 w-8" onClick={handleGenerate} aria-label="Generate password">
                <Wand2 size={13} />
              </Button>
            )}
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => setShowPassword(value => !value)}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
            >
              {showPassword ? <EyeOff size={13} /> : <Eye size={13} />}
            </Button>
          </div>
        </div>
      </div>

      <div className="space-y-1">
        <label htmlFor={`${formId}-label`} className="text-[11px] font-medium text-muted-foreground">Label (optional)</label>
        <Input
          id={`${formId}-label`}
          value={values.label}
          onChange={updateField('label')}
          maxLength={40}
          placeholder="Work, Personal…"
        />
      </div>

      {error && <div className="text-[11px] text-rose-500">{error}</div>}

      <div className="flex justify-end gap-2">
        <Button type="button" variant="ghost" size="sm" onClick={onCancel}>Cancel</Button>
        <Button type="submit" size="sm" disabled={saving}>{saving ? 'Saving…' : submitLabel}</Button>
      </div>
    </form>
  )
}

const VaultPanel = ({
  credentialsData,
  onCopyField,
  onFillCredential,
  onRemoveCredential,
  onSaveCredential,
  onUpdateCredential,
  onGeneratePassword,
  formatTimestamp,
  onToast,
}) => {
  const [revealed, setRevealed] = React.useState({})
  const [searchQuery, setSearchQuery] = React.useState('')
  const [sortBy, setSortBy] = React.useState('updated')
  const [confirmingDeleteId, setConfirmingDeleteId] = React.useState(null)
  const [formMode, setFormMode] = React.useState(null)
  const [editingEntryId, setEditingEntryId] = React.useState(null)
  const [editValues, setEditValues] = React.useState({})
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
      onToast('Verification failed', 'error')
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
      onToast('Unable to reveal password', 'error')
    }
  }

  React.useEffect(() => () => {
    Object.values(revealTimers.current).forEach(timer => clearTimeout(timer))
    revealTimers.current = {}
  }, [])

  const startAdd = () => {
    setEditingEntryId(null)
    setFormMode('add')
  }

  const startEdit = async (entry) => {
    const ok = await ensureVerified()
    if (!ok) {
      onToast('Verification failed', 'error')
      return
    }

    try {
      const username = entry.usernameEnc ? await decryptText(entry.usernameEnc) : ''
      setFormMode(null)
      setEditValues({ username, domain: entry.domain || '', label: entry.label || '' })
      setEditingEntryId(entry.id)
    } catch (error) {
      onToast('Unable to edit login', 'error')
    }
  }

  const saveNew = async (values) => {
    const ok = await onSaveCredential(values)
    if (ok) setFormMode(null)
    return ok
  }

  const saveEdit = async (values) => {
    const ok = await onUpdateCredential(editingEntryId, values)
    if (ok) setEditingEntryId(null)
    return ok
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
        <Card className="border border-border/80 bg-card/80 p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-sm font-semibold">Saved Logins</div>
              <div className="text-xs text-muted-foreground">Store encrypted usernames and passwords for sign-in autofill.</div>
            </div>
            <Button size="sm" onClick={startAdd}>
              <Plus size={14} />
              New login
            </Button>
          </div>
        </Card>

        {formMode === 'add' && (
          <CredentialForm
            title="New login"
            submitLabel="Save login"
            onCancel={() => setFormMode(null)}
            onSubmit={saveNew}
            onGeneratePassword={onGeneratePassword}
          />
        )}

        {credentialsData.length === 0 ? (
          <Card className="border border-dashed border-border/70 bg-card/80 p-5 text-center shadow-none">
            <div className="flex flex-col items-center gap-2 text-muted-foreground">
              <KeyRound size={26} />
              <div className="text-sm">No saved logins yet</div>
              <div className="text-xs">Save a login manually, or submit a sign-in form and let the extension offer to save it.</div>
              <Button variant="outline" size="sm" className="mt-1" onClick={startAdd}>
                <Plus size={14} />
                Add your first login
              </Button>
            </div>
          </Card>
        ) : (
          <>
            <Card className="border border-border/80 bg-card/80 p-3 shadow-none">
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
              <Card className="border border-dashed border-border/70 bg-card/80 p-5 text-center shadow-none">
                <div className="flex flex-col items-center gap-2 text-muted-foreground">
                  <KeyRound size={26} />
                  <div className="text-sm">No matching saved logins</div>
                  <div className="text-xs">Try a different domain, account, or label</div>
                </div>
              </Card>
            ) : filteredCredentials.map((entry, index) => {
              const ageStatus = getCredentialAgeStatus(entry)
              const previousEntry = filteredCredentials[index - 1]
              const showDomainHeader = sortBy === 'domain' && (!previousEntry || previousEntry.domain !== entry.domain)

              return (
            <React.Fragment key={entry.id}>
              {showDomainHeader && (
                <div className="pt-1 text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                  {entry.domain}
                </div>
              )}
            <Card className="border border-border/80 bg-card/80 p-3.5 shadow-none transition-colors hover:bg-card/90">
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
                <div className="flex items-center gap-1">
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button variant="ghost" size="icon" onClick={() => startEdit(entry)} aria-label="Edit saved login">
                        <Pencil size={14} />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>Edit login</TooltipContent>
                  </Tooltip>
                  {confirmingDeleteId === entry.id ? (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-rose-500 hover:text-rose-500"
                          onClick={() => {
                            onRemoveCredential(entry.id)
                            setConfirmingDeleteId(null)
                          }}
                          aria-label="Confirm delete saved login"
                        >
                          <Check size={14} />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>Confirm delete</TooltipContent>
                    </Tooltip>
                  ) : (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => {
                            setConfirmingDeleteId(entry.id)
                            onToast('Click the check to delete')
                          }}
                          aria-label="Delete saved login"
                        >
                          <Trash2 size={14} />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>Delete saved login</TooltipContent>
                    </Tooltip>
                  )}
                </div>
              </div>

              {editingEntryId === entry.id ? (
                <CredentialForm
                  title="Edit login"
                  submitLabel="Save changes"
                  passwordRequired={false}
                  initialValues={editValues}
                  onCancel={() => setEditingEntryId(null)}
                  onSubmit={saveEdit}
                  onGeneratePassword={onGeneratePassword}
                />
              ) : (
                <>
                  <div className="mt-3 rounded-sm border border-border/60 bg-background/35 px-3 py-2 text-xs text-muted-foreground">
                    <span className="truncate">Label: {entry.label || 'None'}</span>
                  </div>

                  <div className="mt-3 rounded-sm border border-border/60 bg-background/65 px-3 py-2.5 text-sm font-mono truncate">
                    {revealed[entry.id] || '••••••••••••'}
                  </div>

                  <div className="flex items-center justify-end gap-2">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button variant="secondary" size="icon" onClick={() => handleRevealPassword(entry)} aria-label="Reveal password" aria-pressed={Boolean(revealed[entry.id])}>
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
                        <Button variant="default" className="h-10 gap-1.5 px-3" onClick={() => onFillCredential(entry)} aria-label="Fill login on page">
                          <Send size={14} />
                          <span className="text-xs font-medium">Fill</span>
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>Fill on current page</TooltipContent>
                    </Tooltip>
                  </div>
                </>
              )}
            </Card>
            </React.Fragment>
              )
            })}
          </>
        )}
      </div>
    </TooltipProvider>
  )
}

export default VaultPanel
