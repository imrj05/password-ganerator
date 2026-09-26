import React from 'react'
import { Button } from './ui/button'
import { Card } from './ui/card'
import { Badge } from './ui/badge'
import { Input } from './ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select'
import { History, Download, X, Copy, Send, Clock, Globe, Eye, Check, Trash2 } from 'lucide-react'
import { filterHistoryEntries, getHistoryDayLabel, getHistoryPasswordTypes, getPasswordTypeLabel, sortHistoryEntries } from '../historyFilters'
import { decryptFromHistory } from '@/lib/crypto'
import { enrollPlatformCredential, verifyPlatformCredential, isAuthWindowValid } from '@/lib/webauthn'
import { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider } from './ui/tooltip'

const HistoryPanel = ({
  showHistory,
  setShowHistory,
  onBack,
  historyData,
  historyStats,
  exportHistory,
  clearHistory,
  removeHistoryEntry,
  formatTimestamp,
  getPasswordTypeIcon,
  onToast
}) => {
  const [revealed, setRevealed] = React.useState({}) // id -> plaintext
  const [searchQuery, setSearchQuery] = React.useState('')
  const [actionFilter, setActionFilter] = React.useState('all')
  const [typeFilter, setTypeFilter] = React.useState('all')
  const [sortBy, setSortBy] = React.useState('newest')
  const [confirmingClear, setConfirmingClear] = React.useState(false)
  const [confirmingDeleteId, setConfirmingDeleteId] = React.useState(null)
  const revealTimers = React.useRef({})
  const passwordTypes = React.useMemo(() => getHistoryPasswordTypes(historyData), [historyData])
  const filteredHistory = React.useMemo(() => {
    const filtered = filterHistoryEntries(historyData, {
      query: searchQuery,
      action: actionFilter,
      passwordType: typeFilter,
    })

    return sortHistoryEntries(filtered, sortBy)
  }, [historyData, searchQuery, actionFilter, typeFilter, sortBy])

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
      if (!ok) { onToast('Verification failed', 'error'); return }
      const plain = await decryptFromHistory(entry.passwordEnc)
      setRevealed((prev) => ({ ...prev, [entry.id]: plain }))
      if (revealTimers.current[entry.id]) clearTimeout(revealTimers.current[entry.id])
      revealTimers.current[entry.id] = setTimeout(() => maskEntry(entry.id), 30_000)
    } catch (e) {
      onToast('Unable to reveal password', 'error')
    }
  }

  const handleCopy = async (entry) => {
    try {
      if (!entry?.passwordEnc) return
      const ok = await ensureVerified()
      if (!ok) { onToast('Verification failed', 'error'); return }
      const plain = await decryptFromHistory(entry.passwordEnc)
      await navigator.clipboard.writeText(plain)
      onToast('Password copied')
    } catch (e) {
      onToast('Unable to copy password', 'error')
    }
  }

  const handleClearHistory = async () => {
    await clearHistory()
    setConfirmingClear(false)
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
        <Card className="sticky top-0 z-10 border border-border/80 bg-card/80 px-4 py-3 shadow-md backdrop-blur-xl supports-[backdrop-filter]:bg-card/65">
          <div className="flex items-center gap-2">
            <div className="rounded-sm bg-primary/12 p-2 text-primary"><History size={15} /></div>
            <div>
              <div className="text-sm font-semibold">Password History</div>
              <div className="text-xs text-muted-foreground">Encrypted activity snapshots for copy and autofill.</div>
            </div>
          </div>
          <TooltipProvider>
            <div className="flex flex-wrap items-center gap-2 justify-between md:justify-end">
              {historyData.length > 0 && (
                <>
                  <Button variant="ghost" size="sm" onClick={exportHistory}>
                    <Download size={14} />
                    Export
                  </Button>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => setConfirmingClear(true)} aria-label="Clear history">
                        <Trash2 size={14} />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>Clear history</TooltipContent>
                  </Tooltip>
                </>
              )}
            </div>
          </TooltipProvider>
        </Card>

        {confirmingClear && (
          <Card className="border border-destructive/40 bg-destructive/5 p-3.5 shadow-none">
            <div className="text-sm font-medium text-foreground">Clear all history?</div>
            <div className="mt-1 text-xs text-muted-foreground">This removes every saved history entry and cannot be undone.</div>
            <div className="mt-3 flex justify-end gap-2">
              <Button variant="ghost" size="sm" onClick={() => setConfirmingClear(false)}>Cancel</Button>
              <Button variant="destructive" size="sm" onClick={handleClearHistory}>Clear history</Button>
            </div>
          </Card>
        )}

        {historyStats && (
          <Card className="border border-border/80 bg-card/80 p-3 shadow-none">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <div className="flex items-center gap-2">
                <span>Total</span>
                <Badge variant="secondary">{historyStats.total}</Badge>
              </div>
              <div className="flex items-center gap-2">
                <span>Last 7 days</span>
                <Badge variant="secondary">{historyStats.lastSevenDays}</Badge>
              </div>
            </div>
            <div className="mt-2 flex items-center gap-4 text-xs text-muted-foreground">
              <div className="flex items-center gap-1.5">
                <Copy size={12} aria-hidden="true" />
                <span>Copied</span>
                <Badge variant="secondary">{historyStats.copyCount}</Badge>
              </div>
              <div className="flex items-center gap-1.5">
                <Send size={12} aria-hidden="true" />
                <span>Auto-filled</span>
                <Badge variant="secondary">{historyStats.autofillCount}</Badge>
              </div>
            </div>
          </Card>
        )}

        {historyData.length > 0 && (
          <Card className="border border-border/80 bg-card/80 p-3 shadow-none">
            <div className="space-y-2">
              <Input
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.target.value)}
                placeholder="Search domain, URL, type, or action"
                aria-label="Search history"
              />
              <div className="grid grid-cols-3 gap-2">
                <Select
                  value={actionFilter}
                  onValueChange={setActionFilter}
                >
                  <SelectTrigger className="h-9 text-xs" aria-label="Filter by action">
                    <SelectValue placeholder="All actions" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All actions</SelectItem>
                    <SelectItem value="copy">Copied</SelectItem>
                    <SelectItem value="autofill">Auto-filled</SelectItem>
                  </SelectContent>
                </Select>
                <Select
                  value={typeFilter}
                  onValueChange={setTypeFilter}
                >
                  <SelectTrigger className="h-9 text-xs" aria-label="Filter by password type">
                    <SelectValue placeholder="All types" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All types</SelectItem>
                  {passwordTypes.map(type => (
                    <SelectItem key={type} value={type}>{getPasswordTypeLabel(type)}</SelectItem>
                  ))}
                  </SelectContent>
                </Select>
                <Select
                  value={sortBy}
                  onValueChange={setSortBy}
                >
                  <SelectTrigger className="h-9 text-xs" aria-label="Sort history">
                    <SelectValue placeholder="Sort" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="newest">Newest</SelectItem>
                    <SelectItem value="oldest">Oldest</SelectItem>
                    <SelectItem value="domain">Domain</SelectItem>
                    <SelectItem value="type">Type</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="text-[11px] text-muted-foreground">
                Showing {filteredHistory.length} of {historyData.length} entries
              </div>
            </div>
          </Card>
        )}

        <div className="space-y-2">
          {historyData.length === 0 ? (
            <Card className="border border-dashed border-border/70 bg-card/80 p-6 text-center shadow-none">
              <div className="flex flex-col items-center gap-2 text-muted-foreground">
                <History size={28} />
                <div className="text-sm">No password history yet</div>
                <div className="text-xs">Your copy and autofill actions will appear here</div>
              </div>
            </Card>
          ) : filteredHistory.length === 0 ? (
            <Card className="border border-dashed border-border/70 bg-card/80 p-6 text-center shadow-none">
              <div className="flex flex-col items-center gap-2 text-muted-foreground">
                <History size={28} />
                <div className="text-sm">No matching history entries</div>
                <div className="text-xs">Try changing the search text or filters</div>
              </div>
            </Card>
          ) : (
            filteredHistory.map((entry, index) => {
              const previousEntry = filteredHistory[index - 1]
              const showDayHeader = sortBy !== 'domain' && sortBy !== 'type' && (!previousEntry || getHistoryDayLabel(previousEntry.timestamp) !== getHistoryDayLabel(entry.timestamp))

              return (
              <React.Fragment key={entry.id}>
                {showDayHeader && (
                  <div className="pt-1 text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
                    {getHistoryDayLabel(entry.timestamp)}
                  </div>
                )}
              <Card className="border border-border/80 bg-card/80 p-3.5 shadow-none transition-colors hover:bg-card/90">
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
                    <Badge variant="outline">{getPasswordTypeLabel(entry.passwordType)}</Badge>
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
                            <Button variant="ghost" size="icon" onClick={() => handleReveal(entry)} aria-label="Reveal" aria-pressed={Boolean(revealed[entry.id])}>
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
                  {confirmingDeleteId === entry.id ? (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="text-rose-500 hover:text-rose-500"
                          onClick={async () => {
                            await removeHistoryEntry(entry.id)
                            setConfirmingDeleteId(null)
                            onToast('Entry removed')
                          }}
                          aria-label="Confirm remove entry"
                        >
                          <Check size={14} />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>Confirm remove</TooltipContent>
                    </Tooltip>
                  ) : (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => {
                            setConfirmingDeleteId(entry.id)
                            onToast('Click the check to remove')
                          }}
                          aria-label="Remove entry"
                        >
                          <X size={14} />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>Remove entry</TooltipContent>
                    </Tooltip>
                  )}
                </div>
                </div>
              </Card>
              </React.Fragment>
              )
            })
          )}
        </div>
      </div>

      </>
    </TooltipProvider>
  )
}

export default HistoryPanel
