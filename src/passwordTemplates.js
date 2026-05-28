export const PASSWORD_TEMPLATES = [
  {
    id: 'banking',
    name: 'Banking',
    description: 'Long random password with safer symbols.',
    settings: {
      activeTab: 'random',
      length: 24,
      includeLowercase: true,
      includeUppercase: true,
      includeNumbers: true,
      includeSymbols: true,
      symbolSet: 'safe',
      customSymbols: '',
      excludeAmbiguous: true,
    },
  },
  {
    id: 'social',
    name: 'Social',
    description: 'Balanced password for everyday accounts.',
    settings: {
      activeTab: 'random',
      length: 18,
      includeLowercase: true,
      includeUppercase: true,
      includeNumbers: true,
      includeSymbols: true,
      symbolSet: 'basic',
      customSymbols: '',
      excludeAmbiguous: false,
    },
  },
  {
    id: 'email',
    name: 'Email',
    description: 'Memorable passphrase for primary logins.',
    settings: {
      activeTab: 'memorable',
      wordCount: 4,
      includeCapitalization: true,
    },
  },
  {
    id: 'database',
    name: 'DB / Env',
    description: 'Shell and environment variable friendly.',
    settings: {
      activeTab: 'random',
      length: 32,
      includeLowercase: true,
      includeUppercase: true,
      includeNumbers: true,
      includeSymbols: true,
      symbolSet: 'dbsafe',
      customSymbols: '',
      excludeAmbiguous: true,
    },
  },
  {
    id: 'api',
    name: 'API Key',
    description: 'Hexadecimal secret for tokens and keys.',
    settings: {
      activeTab: 'hex',
      hexLength: 64,
    },
  },
  {
    id: 'pin',
    name: 'PIN',
    description: 'Six-digit numeric code.',
    settings: {
      activeTab: 'pin',
      pinLength: 6,
    },
  },
]

export function getPasswordTemplate(templateId) {
  return PASSWORD_TEMPLATES.find(template => template.id === templateId) || null
}
