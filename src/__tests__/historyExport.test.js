import { describe, expect, test } from 'vitest'
import { buildHistoryCsv, escapeCsvValue } from '../historyExport'

describe('history export', () => {
  test('escapes commas, quotes, and newlines', () => {
    expect(escapeCsvValue('a,b')).toBe('"a,b"')
    expect(escapeCsvValue('say "hi"')).toBe('"say ""hi"""')
    expect(escapeCsvValue('line\nbreak')).toBe('"line\nbreak"')
    expect(escapeCsvValue('plain')).toBe('plain')
  })

  test('builds one CSV row per entry with decrypted passwords', () => {
    const entries = [
      {
        id: 1,
        timestamp: '2026-01-01T00:00:00.000Z',
        action: 'copy',
        passwordType: 'random',
        domain: 'example.com',
        website: 'https://example.com/login',
        passwordLength: 20,
      },
      {
        id: 2,
        timestamp: '2026-01-02T00:00:00.000Z',
        action: 'autofill',
        passwordType: 'pin',
        domain: 'bank.test',
        website: '',
        passwordLength: 6,
      },
    ]

    const csv = buildHistoryCsv(entries, entry => (entry.id === 1 ? 'p@ss,word' : '123456'))
    const lines = csv.split('\r\n')

    expect(lines[0]).toBe('timestamp,action,passwordType,domain,website,passwordLength,password')
    expect(lines[1]).toContain('"p@ss,word"')
    expect(lines[2]).toContain('123456')
    expect(lines).toHaveLength(3)
  })

  test('leaves the password column empty when none is available', () => {
    const csv = buildHistoryCsv([{ id: 3, action: 'copy', passwordLength: 8 }])

    expect(csv.split('\r\n')[1].endsWith(',8,')).toBe(true)
  })
})
