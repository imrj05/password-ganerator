import React from 'react'
import { Button } from './ui/button'
import { Card } from './ui/card'
import { Badge } from './ui/badge'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from './ui/dialog'
import { History, Download, Trash2, X, Copy, Send, Clock, Globe, Lock, Eye } from 'lucide-react'
import { decryptFromHistory } from '@/lib/crypto'
import { enrollPlatformCredential, verifyPlatformCredential, isAuthWindowValid } from '@/lib/webauthn'
import { toast } from 'sonner'
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from './ui/tooltip'
import { Switch } from './ui/switch'
import { clearAuthWindow } from '@/lib/webauthn'

const HistoryPanel = ({
  showHistory,
  setShowHistory,
  onBack,
  historyData,
  historyStats,
  historyEnabled,
  setHistoryEnabled,
  historyClearOnClose,
  setConfirmModalMode,
  setShowConfirmModal,
  exportHistory,
  clearHistory,
  removeHistoryEntry,
  formatTimestamp,
  getPasswordTypeIcon,
  showConfirmModal,
  setShowConfirmModalLocal,
  confirmModalMode,
  onConfirmClearOnClose
}) => {
  const [revealed, setRevealed] = React.useState({}) // id -> plaintext
  const revealTimers = React.useRef({})

  const maskEntry = (id) => {
    setRevealed((prev) => {
      const next = { ...prev }
      delete next[id]
      return next
    })
    if (revealTimers.current[id]) {
      clearTimeout(revealTimers.current[id])
      delete revealTimers.current[id]
    }
  }

  const ensureVerified = async () => {
    try {
      if (isAuthWindowValid()) return true
      let ok = await verifyPlatformCredential()
      if (ok) return true
      // try enroll once then verify again
      await enrollPlatformCredential()
      ok = await verifyPlatformCredential()
      return ok
    } catch (e) {
      return false
    }
  }

  const handleReveal = async (entry) => {
    try {
      if (!entry?.passwordEnc) return
      const ok = await ensureVerified()
      if (!ok) { toast.error('Verification failed'); return }
      const plain = await decryptFromHistory(entry.passwordEnc)
      setRevealed((prev) => ({ ...prev, [entry.id]: plain }))
      if (revealTimers.current[entry.id]) clearTimeout(revealTimers.current[entry.id])
      revealTimers.current[entry.id] = setTimeout(() => maskEntry(entry.id), 30_000)
    } catch (e) {
      toast.error('Unable to reveal password')
    }
  }

  const handleCopy = async (entry) => {
    try {
      if (!entry?.passwordEnc) return
      const ok = await ensureVerified()
      if (!ok) { toast.error('Verification failed'); return }
      const plain = await decryptFromHistory(entry.passwordEnc)
      await navigator.clipboard.writeText(plain)
      toast.success('Password copied', { duration: 1800 })
    } catch (e) {
      toast.error('Unable to copy password')
    }
  }

  React.useEffect(() => () => {
    // cleanup timers on unmount
    Object.values(revealTimers.current).forEach((t) => clearTimeout(t))
    revealTimers.current = {}
  }, [])

  if (!showHistory) return null

  return (
    <TooltipProvider>
      <>
        <div className="w-full space-y-3">
        <Card className="sticky top-0 z-10 border border-white/10 bg-background/75 px-4 py-3 shadow-md backdrop-blur-xl supports-[backdrop-filter]:bg-background/65">
          <div className="flex items-center gap-2">
            <div className="rounded-sm bg-primary/12 p-2 text-primary"><History size={15} /></div>
            <div>
              <div className="text-sm font-semibold">Password History</div>
              <div className="text-xs text-muted-foreground">Encrypted activity snapshots for copy and autofill.</div>
            </div>
          </div>
          <TooltipProvider>
            <div className="flex flex-wrap items-center gap-2 justify-between md:justify-end">

              <div className="flex items-center gap-2 rounded-full border border-border/60 bg-background/60 px-3 py-1.5">
                <span className="text-xs text-muted-foreground">History</span>
                <Switch
                  id="history-enabled"
                  checked={!!historyEnabled}
                  onCheckedChange={(checked) => {
                    setHistoryEnabled(checked)
                    try {
                      toast.success(checked ? 'History enabled' : 'History disabled', { duration: 1800 })
                    } catch (e) {}
                  }}
                />
              </div>

              <div className="flex items-center gap-2 rounded-full border border-border/60 bg-background/60 px-3 py-1.5">
                <span className="text-xs text-muted-foreground">Clear on close</span>
                <Switch
                  id="history-clear-on-close"
                  checked={!!historyClearOnClose}
                  onCheckedChange={() => {
                    setConfirmModalMode(historyClearOnClose ? 'disable' : 'enable')
                    setShowConfirmModal(true)
                  }}
                />
              </div>

              {historyData.length > 0 && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="ghost" size="icon" onClick={exportHistory} aria-label="Export">
                      <Download size={14} />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Export</TooltipContent>
                </Tooltip>
              )}
            </div>
          </TooltipProvider>
        </Card>

        {historyStats && (
          <Card className="border border-white/10 bg-background/60 p-3 shadow-none">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <div className="flex items-center gap-2">
                <span>Total</span>
                <Badge variant="secondary">{historyStats.total}</Badge>
              </div>
              <div className="flex items-center gap-2">
                <span>7 days</span>
                <Badge variant="secondary">{historyStats.lastSevenDays}</Badge>
              </div>
              <div className="flex items-center gap-2">
                <Copy size={12} />
                <span>{historyStats.copyCount}</span>
              </div>
              <div className="flex items-center gap-2">
                <Send size={12} />
                <span>{historyStats.autofillCount}</span>
              </div>
            </div>
          </Card>
        )}

        <div className="space-y-2">
          {historyData.length === 0 ? (
            <Card className="border border-dashed border-border/70 bg-background/55 p-6 text-center shadow-none">
              <div className="flex flex-col items-center gap-2 text-muted-foreground">
                <History size={28} />
                <div className="text-sm">No password history yet</div>
                <div className="text-xs">Your copy and autofill actions will appear here</div>
              </div>
            </Card>
          ) : (
            historyData.map((entry) => (
              <Card key={entry.id} className="border border-white/10 bg-background/60 p-3.5 shadow-none transition-colors hover:bg-background/72">
                <div className="flex items-start gap-3">
                <div className="mt-0.5 rounded-sm bg-muted/70 p-2 text-muted-foreground">
                  {getPasswordTypeIcon(entry.passwordType)}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge variant={entry.action === 'copy' ? 'secondary' : 'default'} className="gap-1">
                      {entry.action === 'copy' ? <Copy size={12} /> : <Send size={12} />}
                      {entry.action === 'copy' ? 'Copied' : 'Auto-filled'}
                    </Badge>
                    <Badge variant="outline">{entry.passwordType}</Badge>
                    <span className="text-xs text-muted-foreground">({entry.passwordLength} chars)</span>
                  </div>
                  <div className="mt-1 text-sm text-foreground truncate flex items-center gap-2">
                    {entry.domain ? (
                      <>
                        <Globe size={12} className="text-muted-foreground" />
                        <span className="truncate">{entry.domain}</span>
                      </>
                    ) : (
                      <span className="text-muted-foreground">Extension popup</span>
                    )}
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
                    <Clock size={12} />
                    <span>{formatTimestamp(entry.timestamp)}</span>
                  </div>
                  {entry.passwordEnc ? (
                    <div className="mt-2 flex items-center justify-between gap-2">
                      <div className="rounded-sm border border-border/60 bg-background/65 px-3 py-2 text-sm font-mono truncate">
                        {revealed[entry.id] ? revealed[entry.id] : '••••••••••••'}
                      </div>
                      <div className="flex items-center gap-1.5">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button variant="ghost" size="icon" onClick={() => handleReveal(entry)} aria-label="Reveal">
                              <Eye size={14} />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Reveal</TooltipContent>
                        </Tooltip>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button variant="ghost" size="icon" onClick={() => handleCopy(entry)} aria-label="Copy">
                              <Copy size={14} />
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>Copy</TooltipContent>
                        </Tooltip>
                      </div>
                    </div>
                  ) : null}
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="ghost" size="icon" onClick={() => removeHistoryEntry(entry.id)} title="Remove this entry">
                    <X size={14} />
                  </Button>
                </div>
                </div>
              </Card>
            ))
          )}
        </div>
      </div>

      {/* Optional confirmation modal wiring (uses shadcn dialog) */}
      {typeof showConfirmModal !== 'undefined' && (
        <Dialog open={showConfirmModal} onOpenChange={setShowConfirmModalLocal}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>
                {confirmModalMode === 'enable' ? 'Enable clear on close?' : confirmModalMode === 'disable' ? 'Disable clear on close?' : 'Confirm'}
              </DialogTitle>
            </DialogHeader>
            <div className="text-sm text-muted-foreground">
              {confirmModalMode === 'enable'
                ? 'Passwords will be cleared from history each time the popup closes.'
                : 'Passwords will persist in history until manually cleared.'}
            </div>
            <DialogFooter>
              <Button variant="ghost" onClick={() => setShowConfirmModalLocal(false)}>Cancel</Button>
              <Button onClick={() => {
                const enable = confirmModalMode === 'enable'
                onConfirmClearOnClose?.(enable)
                setShowConfirmModalLocal(false)
              }}>Confirm</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
      </>
    </TooltipProvider>
  )
}

export default HistoryPanel
