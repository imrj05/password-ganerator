const CSV_HEADERS = ['timestamp', 'action', 'passwordType', 'domain', 'website', 'passwordLength', 'password']

export function escapeCsvValue(value) {
  const text = String(value ?? '')
  if (/[",\r\n]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`
  }
  return text
}

export function buildHistoryCsv(entries = [], passwordForEntry = () => '') {
  const rows = entries.map(entry => [
    entry.timestamp || '',
    entry.action || '',
    entry.passwordType || '',
    entry.domain || '',
    entry.website || '',
    entry.passwordLength ?? '',
    passwordForEntry(entry) || '',
  ])

  return [CSV_HEADERS, ...rows]
    .map(row => row.map(escapeCsvValue).join(','))
    .join('\r\n')
}
