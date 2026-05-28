import React from 'react'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Switch } from './ui/switch'
import { SlidersHorizontal, Lightbulb, KeyRound, History, Timer } from 'lucide-react'

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

const SettingsPanel = ({
  suggestionEnabled,
  setSuggestionEnabled,
  credentialsEnabled,
  setCredentialsEnabled,
  historyEnabled,
  setHistoryEnabled,
  historyClearOnClose,
  setHistoryClearOnClose,
}) => (
  <div className="space-y-3">
    <Card className="border border-white/10 bg-background/75 px-0 py-0 shadow-none">
      <CardHeader className="px-5 pb-3 pt-5">
        <CardTitle className="flex items-center gap-2 text-base font-medium">
          <SlidersHorizontal size={16} className="text-primary" />
          Feature Settings
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2.5 px-5 pb-5 pt-0">
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

    <div className="rounded-sm border border-border/60 bg-card/50 px-4 py-3 text-[11px] leading-5 text-muted-foreground">
      All settings are stored locally on your device. No data is sent to any server.
    </div>
  </div>
)

export default SettingsPanel
