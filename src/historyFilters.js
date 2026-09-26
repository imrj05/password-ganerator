const PASSWORD_TYPE_LABELS = {
  random: 'Password',
  memorable: 'Passphrase',
  pin: 'PIN',
  hex: 'Hexadecimal',
}

export function getPasswordTypeLabel(type) {
  return PASSWORD_TYPE_LABELS[type] || type || 'Password'
}

export function filterHistoryEntries(entries = [], filters = {}) {
  const query = String(filters.query || '').trim().toLowerCase()
  const action = filters.action || 'all'
  const passwordType = filters.passwordType || 'all'

  return entries.filter(entry => {
    if (action !== 'all' && entry.action !== action) return false
    if (passwordType !== 'all' && entry.passwordType !== passwordType) return false

    if (!query) return true

    const searchable = [
      entry.domain,
      entry.website,
      entry.passwordType,
      getPasswordTypeLabel(entry.passwordType),
      entry.action,
      entry.timestamp,
    ].filter(Boolean).join(' ').toLowerCase()

    return searchable.includes(query)
  })
}

export function sortHistoryEntries(entries = [], sortBy = 'newest') {
  const sorted = [...entries]

  return sorted.sort((a, b) => {
    if (sortBy === 'oldest') {
      return new Date(a.timestamp || 0).getTime() - new Date(b.timestamp || 0).getTime()
    }

    if (sortBy === 'domain') {
      return String(a.domain || '').localeCompare(String(b.domain || ''))
    }

    if (sortBy === 'type') {
      return String(a.passwordType || '').localeCompare(String(b.passwordType || ''))
    }

    return new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime()
  })
}

export function getHistoryPasswordTypes(entries = []) {
  return [...new Set(entries.map(entry => entry.passwordType).filter(Boolean))].sort()
}

export function getHistoryDayLabel(timestamp, reference = new Date()) {
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) return 'Unknown date'

  const startOfReferenceDay = new Date(reference.getFullYear(), reference.getMonth(), reference.getDate())
  const startOfDate = new Date(date.getFullYear(), date.getMonth(), date.getDate())
  const diffDays = Math.round((startOfReferenceDay - startOfDate) / 86400000)

  if (diffDays === 0) return 'Today'
  if (diffDays === 1) return 'Yesterday'
  if (diffDays > 1 && diffDays < 7) return date.toLocaleDateString(undefined, { weekday: 'long' })
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}
