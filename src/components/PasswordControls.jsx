import React from 'react'
import { Combobox } from './ui/Combobox'
import { Switch } from './ui/switch'
import { Input } from './ui/input'
import { Card, CardHeader, CardTitle, CardContent } from './ui/card'

const ToggleField = ({ id, label, checked, onCheckedChange }) => (
  <div className="rounded-sm border border-border/80 bg-background/25 px-3 py-2.5">
    <div className="flex items-center justify-between gap-2">
      <label htmlFor={id} className="text-sm font-medium text-foreground">{label}</label>
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} />
    </div>
  </div>
)

const OptionsShell = ({ title, children }) => (
  <Card className="border border-border/80 bg-card/80 px-0 py-0 shadow-none">
    <CardHeader className="px-5 pb-3 pt-5">
      <CardTitle className="text-base font-medium">{title}</CardTitle>
    </CardHeader>
    <CardContent className="space-y-5 px-5 pb-5 pt-0">
      {children}
    </CardContent>
  </Card>
)

const PasswordControls = ({
  activeTab,
  includeLowercase, setIncludeLowercase,
  includeUppercase, setIncludeUppercase,
  includeNumbers, setIncludeNumbers,
  includeSymbols, setIncludeSymbols,
  excludeAmbiguous, setExcludeAmbiguous,
  symbolSet, setSymbolSet,
  customSymbols, setCustomSymbols,
  symbolSets,
  includeCapitalization, setIncludeCapitalization,
}) => {
  if (activeTab === 'random') {
    return (
      <OptionsShell title="Password options">
        <div className="space-y-3">
          <ToggleField id="includeLowercase" label="Lowercase letters (a-z)" checked={includeLowercase} onCheckedChange={setIncludeLowercase} />
          <ToggleField id="includeUppercase" label="Uppercase letters (A-Z)" checked={includeUppercase} onCheckedChange={setIncludeUppercase} />
          <ToggleField id="includeNumbers" label="Numbers (0-9)" checked={includeNumbers} onCheckedChange={setIncludeNumbers} />
          <ToggleField id="includeSymbols" label="Symbols" checked={includeSymbols} onCheckedChange={setIncludeSymbols} />
          <ToggleField id="excludeAmbiguous" label="Exclude Ambiguous (e.g. o, 0, l, 1)" checked={excludeAmbiguous} onCheckedChange={setExcludeAmbiguous} />
        </div>

        {includeSymbols && (
          <Card className="border border-border/80 bg-background/20 shadow-none">
            <CardContent className="space-y-3 px-4 pb-4 pt-4">
              <div className="space-y-1.5">
                <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Symbol Set</div>
                <Combobox
                  value={symbolSet}
                  onChange={(v) => setSymbolSet(v)}
                  placeholder="Select symbol set"
                  options={Object.entries(symbolSets).map(([key, set]) => ({
                    value: key,
                    label: set.name,
                    preview: set.symbols,
                    description: set.description
                  }))}
                  className="w-full"
                />
              </div>

              {symbolSet === 'custom' && (
                <div className="space-y-1.5">
                  <label className="text-sm font-medium text-foreground">Custom Symbols</label>
                  <Input
                    placeholder="Enter custom symbols"
                    value={customSymbols}
                    onChange={(event) => setCustomSymbols(event.target.value)}
                  />
                </div>
              )}

              <div className="rounded-sm border border-border/80 bg-background/20 px-3 py-2 text-xs text-muted-foreground">
                <span className="mr-1 font-medium text-foreground">Using:</span>
                <span>{symbolSet === 'custom' ? customSymbols || 'No custom symbols' : symbolSets[symbolSet]?.symbols}</span>
              </div>
            </CardContent>
          </Card>
        )}
      </OptionsShell>
    )
  }

  if (activeTab === 'memorable') {
    return (
      <OptionsShell title="Passphrase options">
        <ToggleField
          id="includeCapitalization"
          label="Capitalization"
          checked={includeCapitalization}
          onCheckedChange={setIncludeCapitalization}
        />
      </OptionsShell>
    )
  }

  // PIN and Hexadecimal lengths are controlled by the slider above
  return null
}

export default PasswordControls
