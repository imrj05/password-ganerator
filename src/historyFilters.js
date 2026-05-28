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
