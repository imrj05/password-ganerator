import React from 'react'
import { Shuffle, Lightbulb, Hash } from 'lucide-react'
import { Button } from './ui/button'

const tabs = [
  { id: 'random', label: 'Password', icon: Shuffle },
  { id: 'memorable', label: 'Passphrase', icon: Lightbulb },
  { id: 'pin', label: 'PIN', icon: Hash }
]

const PasswordTypeTabs = ({ activeTab, setActiveTab }) => {
  return (
    <div className="space-y-2">
      {tabs.map(({ id, label, icon: Icon }) => {
        const isActive = activeTab === id

        return (
          <Button
            key={id}
            variant="ghost"
            onClick={() => setActiveTab(id)}
            className={`h-auto w-full justify-start gap-3 border border-transparent px-0 py-0 text-left ${isActive ? 'bg-transparent hover:bg-transparent' : 'bg-transparent text-muted-foreground hover:bg-transparent hover:text-foreground'}`}
          >
            <span className={`flex h-5 w-5 items-center justify-center rounded-full border ${isActive ? 'border-primary/80 bg-primary/10 text-primary' : 'border-border bg-transparent text-transparent'}`}>
              <span className={`h-2 w-2 rounded-full ${isActive ? 'bg-primary' : 'bg-transparent'}`} />
            </span>
            <Icon size={16} className={isActive ? 'text-primary' : 'text-muted-foreground'} />
            <span className={`text-[15px] ${isActive ? 'font-medium text-foreground' : 'font-normal text-muted-foreground'}`}>{label}</span>
          </Button>
        )
      })}
    </div>
  )
}

export default PasswordTypeTabs
