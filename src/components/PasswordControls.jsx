import React, { useState } from 'react'
import { Combobox } from './ui/Combobox'
import { Switch } from './ui/switch'
import { Input } from './ui/input'
import { Card, CardHeader, CardTitle, CardContent } from './ui/card'
import { Slider } from './ui/slider'
import PasswordTypeTabs from './PasswordTypeTabs'

const SliderField = ({
  label,
  min,
  max,
  value,
  onChange,
  dragging,
  setDragging,
  ariaLabel
}) => (
  <div className="space-y-4">
    <div className="flex items-baseline justify-between gap-3">
      <label className="text-sm font-medium text-foreground">{label} <span className="text-muted-foreground">({min}-{max})</span></label>
      <span className="text-sm text-foreground">{value}</span>
    </div>
    <div
      className="relative"
      onMouseDown={() => setDragging(true)}
      onMouseUp={() => setDragging(false)}
      onMouseLeave={() => setDragging(false)}
      onTouchStart={() => setDragging(true)}
      onTouchEnd={() => setDragging(false)}
    >
      <Slider
        value={[value]}
        min={min}
        max={max}
        onValueChange={(val) => onChange(val[0])}
        aria-label={ariaLabel}
      />
      <div
        className="absolute -top-8 translate-x-[-50%] rounded-sm border border-border/60 bg-popover px-2 py-0.5 text-[10px] text-popover-foreground shadow-sm transition-all duration-150 ease-out"
        style={{ left: `${Math.min(100, Math.max(0, ((value - min) / (max - min)) * 100))}%` }}
        data-active={dragging ? 'true' : 'false'}
      >
        {value}
      </div>
    </div>
  </div>
)

const ToggleField = ({ id, label, checked, onCheckedChange }) => (
  <div className="rounded-sm border border-border/80 bg-background/25 px-3 py-2.5">
    <div className="flex items-center justify-between gap-2">
      <label htmlFor={id} className="text-sm font-medium text-foreground">{label}</label>
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} />
    </div>
  </div>
)

const ControlsShell = ({ activeTab, setActiveTab, children }) => (
  <Card className="border border-border/80 bg-card/80 px-0 py-0 shadow-none">
    <CardHeader className="px-5 pb-3 pt-5">
      <CardTitle className="text-base font-medium">Type</CardTitle>
    </CardHeader>
    <CardContent className="space-y-5 px-5 pb-5 pt-0">
      <PasswordTypeTabs activeTab={activeTab} setActiveTab={setActiveTab} />
      {children}
    </CardContent>
  </Card>
)

const PasswordControls = ({
  activeTab,
  setActiveTab,
  length, setLength,
  includeNumbers, setIncludeNumbers,
  includeSymbols, setIncludeSymbols,
  symbolSet, setSymbolSet,
  customSymbols, setCustomSymbols,
  symbolSets,
  wordCount, setWordCount,
  includeCapitalization, setIncludeCapitalization,
  pinLength, setPinLength
}) => {
  const [draggingLen, setDraggingLen] = useState(false)
  const [draggingWords, setDraggingWords] = useState(false)
  const [draggingPin, setDraggingPin] = useState(false)

  if (activeTab === 'random') {
    return (
      <ControlsShell activeTab={activeTab} setActiveTab={setActiveTab}>
        <div className="border-t border-border/80 pt-5">
          <SliderField
            label="Length"
            min={4}
            max={50}
            value={length}
            onChange={setLength}
            dragging={draggingLen}
            setDragging={setDraggingLen}
            ariaLabel="Characters"
          />
        </div>

        <div className="space-y-3 border-t border-border/80 pt-5">
          <ToggleField id="includeNumbers" label="Numbers" checked={includeNumbers} onCheckedChange={setIncludeNumbers} />
          <ToggleField id="includeSymbols" label="Symbols" checked={includeSymbols} onCheckedChange={setIncludeSymbols} />
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
      </ControlsShell>
    )
  }

  if (activeTab === 'memorable') {
    return (
      <ControlsShell activeTab={activeTab} setActiveTab={setActiveTab}>
        <div className="border-t border-border/80 pt-5">
          <SliderField
            label="Length"
            min={2}
            max={6}
            value={wordCount}
            onChange={setWordCount}
            dragging={draggingWords}
            setDragging={setDraggingWords}
            ariaLabel="Words"
          />
        </div>

        <div className="border-t border-border/80 pt-5">
          <ToggleField
            id="includeCapitalization"
            label="Capitalization"
            checked={includeCapitalization}
            onCheckedChange={setIncludeCapitalization}
          />
        </div>
      </ControlsShell>
    )
  }

  if (activeTab === 'pin') {
    return (
      <ControlsShell activeTab={activeTab} setActiveTab={setActiveTab}>
        <div className="border-t border-border/80 pt-5">
          <SliderField
            label="Length"
            min={4}
            max={12}
            value={pinLength}
            onChange={setPinLength}
            dragging={draggingPin}
            setDragging={setDraggingPin}
            ariaLabel="Digits"
          />
        </div>
      </ControlsShell>
    )
  }

  return null
}

export default PasswordControls
