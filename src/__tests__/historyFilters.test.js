import { filterHistoryEntries, getHistoryDayLabel, getHistoryPasswordTypes, getPasswordTypeLabel, sortHistoryEntries } from '../historyFilters'

const entries = [
  {
    action: 'copy',
    passwordType: 'random',
    domain: 'example.com',
    website: 'https://example.com/login',
    timestamp: '2026-05-28T10:00:00.000Z',
  },
  {
    action: 'autofill',
    passwordType: 'memorable',
    domain: 'bank.test',
    website: 'https://bank.test/sign-in',
    timestamp: '2026-05-27T10:00:00.000Z',
  },
]

describe('historyFilters', () => {
  test('filters by domain query', () => {
    const result = filterHistoryEntries(entries, { query: 'bank' })

    expect(result).toHaveLength(1)
    expect(result[0].domain).toBe('bank.test')
  })

  test('filters by action and password type', () => {
    const result = filterHistoryEntries(entries, {
      action: 'autofill',
      passwordType: 'memorable',
    })

    expect(result).toHaveLength(1)
    expect(result[0].action).toBe('autofill')
  })

  test('returns sorted password types', () => {
    expect(getHistoryPasswordTypes(entries)).toEqual(['memorable', 'random'])
  })

  test('maps password types to friendly labels', () => {
    expect(getPasswordTypeLabel('random')).toBe('Password')
    expect(getPasswordTypeLabel('memorable')).toBe('Passphrase')
    expect(getPasswordTypeLabel('pin')).toBe('PIN')
    expect(getPasswordTypeLabel('hex')).toBe('Hexadecimal')
  })

  test('matches friendly labels in search', () => {
    const result = filterHistoryEntries(entries, { query: 'passphrase' })

    expect(result).toHaveLength(1)
    expect(result[0].passwordType).toBe('memorable')
  })

  test('labels history days relative to today', () => {
    const reference = new Date(2026, 4, 30, 12)

    expect(getHistoryDayLabel(new Date(2026, 4, 30, 9), reference)).toBe('Today')
    expect(getHistoryDayLabel(new Date(2026, 4, 29, 9), reference)).toBe('Yesterday')
    expect(getHistoryDayLabel('not-a-date', reference)).toBe('Unknown date')

    const older = getHistoryDayLabel(new Date(2026, 4, 27, 9), reference)
    expect(older).not.toBe('Today')
    expect(older).not.toBe('Yesterday')
    expect(older.length).toBeGreaterThan(0)
  })

  test('sorts history entries by newest and oldest timestamps', () => {
    expect(sortHistoryEntries(entries, 'newest')[0].domain).toBe('example.com')
    expect(sortHistoryEntries(entries, 'oldest')[0].domain).toBe('bank.test')
  })

  test('sorts history entries by domain and type', () => {
    expect(sortHistoryEntries(entries, 'domain')[0].domain).toBe('bank.test')
    expect(sortHistoryEntries(entries, 'type')[0].passwordType).toBe('memorable')
  })
})
