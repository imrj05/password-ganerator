import { filterVaultCredentials, sortVaultCredentials } from '../vaultFilters'

const credentials = [
  {
    domain: 'example.com',
    origin: 'https://example.com',
    usernamePreview: 'pe***@example.com',
    label: 'Personal',
    updatedAt: '2026-05-28T10:00:00.000Z',
    lastUsedAt: null,
  },
  {
    domain: 'work.test',
    origin: 'https://work.test',
    usernamePreview: 'wo***@company.test',
    label: 'Work',
    updatedAt: '2026-05-27T10:00:00.000Z',
    lastUsedAt: '2026-05-29T10:00:00.000Z',
  },
]

describe('filterVaultCredentials', () => {
  test('returns all credentials for an empty query', () => {
    expect(filterVaultCredentials(credentials, '')).toHaveLength(2)
  })

  test('filters by label', () => {
    const result = filterVaultCredentials(credentials, 'work')

    expect(result).toHaveLength(1)
    expect(result[0].domain).toBe('work.test')
  })

  test('filters by username preview', () => {
    const result = filterVaultCredentials(credentials, 'example')

    expect(result).toHaveLength(1)
    expect(result[0].label).toBe('Personal')
  })

  test('sorts credentials by updated and used timestamps', () => {
    expect(sortVaultCredentials(credentials, 'updated')[0].domain).toBe('example.com')
    expect(sortVaultCredentials(credentials, 'used')[0].domain).toBe('work.test')
  })

  test('sorts credentials by domain, label, and oldest update', () => {
    expect(sortVaultCredentials(credentials, 'domain')[0].domain).toBe('example.com')
    expect(sortVaultCredentials(credentials, 'label')[0].label).toBe('Personal')
    expect(sortVaultCredentials(credentials, 'oldest')[0].domain).toBe('work.test')
  })
})
