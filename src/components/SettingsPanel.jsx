import React from 'react'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Switch } from './ui/switch'
import { Button } from './ui/button'
import { SlidersHorizontal, Lightbulb, KeyRound, History, Timer, Trash2, Sun, Globe, X } from 'lucide-react'

const SettingRow = ({ id, icon: Icon, label, description, checked, onCheckedChange }) => (
  <div className="flex items-center gap-4 rounded-sm border border-border/80 bg-background/25 px-4 py-3.5 transition-colors hover:bg-background/40">
    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-sm bg-primary/10 text-primary">
      <Icon size={17} />
    </div>
    <div className="min-w-0 flex-1">
      <label htmlFor={id} className="cursor-pointer text-sm font-medium text-foreground">
        {label}
      </label>
      <p className="mt-0.5 text-[11px] leading-4 text-muted-foreground">{description}</p>
    </div>
    <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} />
  </div>
)

const ThemeRow = ({ theme, onChange }) => (
  <div className="rounded-sm border border-border/80 bg-background/25 px-4 py-3.5">
    <div className="flex items-center gap-4">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-sm bg-primary/10 text-primary">
        <Sun size={17} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-foreground">Theme</div>
        <p className="mt-0.5 text-[11px] leading-4 text-muted-foreground">Choose light, dark, or follow your system setting.</p>
      </div>
    </div>
    <div className="mt-3 grid grid-cols-3 gap-1.5">
      {['system', 'light', 'dark'].map(mode => (
        <Button
          key={mode}
          variant={theme === mode ? 'default' : 'outline'}
          size="sm"
          className="capitalize"
          aria-pressed={theme === mode}
          onClick={() => onChange(mode)}
        >
          {mode}
        </Button>
      ))}
    </div>
  </div>
)

const DangerAction = ({ label, description, buttonLabel, disabled, onConfirm }) => {
  const [confirming, setConfirming] = React.useState(false)
  const [busy, setBusy] = React.useState(false)

  const handleConfirm = async () => {
    setBusy(true)
    await onConfirm()
    setBusy(false)
    setConfirming(false)
  }

  return (
    <div className="rounded-sm border border-border/80 bg-background/25 px-4 py-3.5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm font-medium text-foreground">{label}</div>
          <p className="mt-0.5 text-[11px] leading-4 text-muted-foreground">{description}</p>
        </div>
        {!confirming && (
          <Button variant="outline" size="sm" disabled={disabled} onClick={() => setConfirming(true)}>
            {buttonLabel}
          </Button>
        )}
      </div>

      {confirming && (
        <div className="mt-3 flex items-center justify-end gap-2">
          <Button variant="ghost" size="sm" disabled={busy} onClick={() => setConfirming(false)}>Cancel</Button>
          <Button variant="destructive" size="sm" disabled={busy} onClick={handleConfirm}>
            {busy ? 'Clearing…' : 'Confirm'}
          </Button>
        </div>
      )}
    </div>
  )
}

const SettingsPanel = ({
  suggestionEnabled,
  setSuggestionEnabled,
  credentialsEnabled,
  setCredentialsEnabled,
  historyEnabled,
  setHistoryEnabled,
  historyClearOnClose,
  setHistoryClearOnClose,
  onClearHistory,
  onClearVault,
  onClearAllData,
  hasHistory,
  hasCredentials,
  theme,
  setTheme,
  dismissedDomains,
  onRemoveDismissedDomain,
}) => (
  <div className="space-y-3">
    <Card className="border border-border/80 bg-card/80 px-0 py-0 shadow-none">
      <CardHeader className="px-5 pb-3 pt-5">
        <CardTitle className="flex items-center gap-2 text-base font-medium">
          <SlidersHorizontal size={16} className="text-primary" />
          Feature Settings
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2.5 px-5 pb-5 pt-0">
        <ThemeRow theme={theme} onChange={setTheme} />

        <SettingRow
          id="setting-suggestion"
          icon={Lightbulb}
          label="Password Suggestion"
          description="Show an in-page suggestion popup when you focus a password field on any website."
          checked={!!suggestionEnabled}
          onCheckedChange={setSuggestionEnabled}
        />

        <SettingRow
          id="setting-credentials"
          icon={KeyRound}
          label="Saved Logins"
          description="Offer to save and autofill usernames and passwords when you sign in or sign up."
          checked={!!credentialsEnabled}
          onCheckedChange={setCredentialsEnabled}
        />

        <SettingRow
          id="setting-history"
          icon={History}
          label="Password History"
          description="Keep an encrypted record of passwords you copy or autofill from the extension."
          checked={!!historyEnabled}
          onCheckedChange={setHistoryEnabled}
        />

        <SettingRow
          id="setting-clear-on-close"
          icon={Timer}
          label="Clear History on Close"
          description="Automatically wipe all password history each time the extension popup closes."
          checked={!!historyClearOnClose}
          onCheckedChange={setHistoryClearOnClose}
        />
      </CardContent>
    </Card>

    {dismissedDomains?.length > 0 && (
      <Card className="border border-border/80 bg-card/80 px-0 py-0 shadow-none">
        <CardHeader className="px-5 pb-3 pt-5">
          <CardTitle className="flex items-center gap-2 text-base font-medium">
            <Globe size={16} className="text-primary" />
            Dismissed Sites
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 px-5 pb-5 pt-0">
          <p className="text-[11px] leading-4 text-muted-foreground">
            In-page suggestions are hidden on these sites. Remove one to show suggestions again.
          </p>
          {dismissedDomains.map(domain => (
            <div key={domain} className="flex items-center justify-between gap-2 rounded-sm border border-border/80 bg-background/25 px-3 py-2 text-xs">
              <span className="truncate text-foreground">{domain}</span>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={() => onRemoveDismissedDomain(domain)}
                aria-label={`Re-enable suggestions on ${domain}`}
              >
                <X size={13} />
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>
    )}

    <Card className="border border-border/80 bg-card/80 px-0 py-0 shadow-none">
      <CardHeader className="px-5 pb-3 pt-5">
        <CardTitle className="flex items-center gap-2 text-base font-medium">
          <Trash2 size={16} className="text-primary" />
          Data & Privacy
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2.5 px-5 pb-5 pt-0">
        <DangerAction
          label="Password history"
          description="Remove every saved history entry. Saved logins are not affected."
          buttonLabel="Clear"
          disabled={!hasHistory}
          onConfirm={onClearHistory}
        />
        <DangerAction
          label="Saved logins"
          description="Remove all stored usernames and passwords. History is not affected."
          buttonLabel="Clear"
          disabled={!hasCredentials}
          onConfirm={onClearVault}
        />
        <DangerAction
          label="All extension data"
          description="Reset settings and remove all history and saved logins."
          buttonLabel="Delete"
          onConfirm={onClearAllData}
        />
      </CardContent>
    </Card>

    <div className="rounded-sm border border-border/60 bg-card/50 px-4 py-3 text-[11px] leading-5 text-muted-foreground">
      All settings are stored locally on your device. No data is sent to any server.
    </div>
  </div>
)

export default SettingsPanel
