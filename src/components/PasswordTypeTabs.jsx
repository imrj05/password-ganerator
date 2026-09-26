import React from 'react'
import { Shuffle, Lightbulb, Hash, Hexagon } from 'lucide-react'

const tabs = [
  { id: 'random', label: 'Password', icon: Shuffle },
  { id: 'memorable', label: 'Passphrase', icon: Lightbulb },
  { id: 'pin', label: 'PIN', icon: Hash },
  { id: 'hex', label: 'Hexadecimal', icon: Hexagon }
]

const PasswordTypeTabs = ({ activeTab, setActiveTab }) => (
  <div
    role="tablist"
    aria-label="Password type"
    className="grid grid-cols-4 gap-1 rounded-sm border border-border/80 bg-card/60 p-1"
  >
    {tabs.map(({ id, label, icon: Icon }) => {
      const isActive = activeTab === id

      return (
        <button
          key={id}
          type="button"
          role="tab"
          aria-selected={isActive}
          onClick={() => setActiveTab(id)}
          className={`flex flex-col items-center gap-1 rounded-sm px-1 py-2 text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
            isActive
              ? 'bg-primary/12 text-primary'
              : 'text-muted-foreground hover:bg-background/60 hover:text-foreground'
          }`}
        >
          <Icon size={15} />
          <span>{label}</span>
        </button>
      )
    })}
  </div>
)

export default PasswordTypeTabs
