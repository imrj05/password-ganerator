export function filterVaultCredentials(credentials = [], query = '') {
  const normalizedQuery = String(query || '').trim().toLowerCase()

  if (!normalizedQuery) return credentials

  return credentials.filter(entry => {
    const searchable = [
      entry.domain,
      entry.origin,
      entry.usernamePreview,
      entry.label,
      entry.updatedAt,
      entry.lastUsedAt,
    ].filter(Boolean).join(' ').toLowerCase()

    return searchable.includes(normalizedQuery)
  })
}

function timeValue(value) {
  const time = new Date(value || 0).getTime()
  return Number.isFinite(time) ? time : 0
}

export function sortVaultCredentials(credentials = [], sortBy = 'updated') {
  const sorted = [...credentials]

  return sorted.sort((a, b) => {
    if (sortBy === 'used') {
      return timeValue(b.lastUsedAt || b.updatedAt || b.createdAt) - timeValue(a.lastUsedAt || a.updatedAt || a.createdAt)
    }

    if (sortBy === 'domain') {
      return String(a.domain || '').localeCompare(String(b.domain || ''))
    }

    if (sortBy === 'label') {
      return String(a.label || '').localeCompare(String(b.label || ''))
    }

    if (sortBy === 'oldest') {
      return timeValue(a.updatedAt || a.createdAt) - timeValue(b.updatedAt || b.createdAt)
    }

    return timeValue(b.updatedAt || b.createdAt) - timeValue(a.updatedAt || a.createdAt)
  })
}
