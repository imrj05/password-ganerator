import { filterHistoryEntries, getHistoryPasswordTypes, sortHistoryEntries } from '../historyFilters'

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

  test('sorts history entries by newest and oldest timestamps', () => {
    expect(sortHistoryEntries(entries, 'newest')[0].domain).toBe('example.com')
    expect(sortHistoryEntries(entries, 'oldest')[0].domain).toBe('bank.test')
  })

  test('sorts history entries by domain and type', () => {
    expect(sortHistoryEntries(entries, 'domain')[0].domain).toBe('bank.test')
    expect(sortHistoryEntries(entries, 'type')[0].passwordType).toBe('memorable')
  })
})
