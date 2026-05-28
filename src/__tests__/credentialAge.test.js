import { getCredentialAgeStatus } from '../credentialAge'

const now = new Date('2026-05-29T00:00:00.000Z')

describe('getCredentialAgeStatus', () => {
  test('marks recent credentials as fresh', () => {
    const result = getCredentialAgeStatus({ updatedAt: '2026-05-01T00:00:00.000Z' }, now)

    expect(result.status).toBe('fresh')
    expect(result.daysOld).toBe(28)
  })

  test('marks six month old credentials for review', () => {
    const result = getCredentialAgeStatus({ updatedAt: '2025-11-01T00:00:00.000Z' }, now)

    expect(result.status).toBe('review')
  })

  test('marks year old credentials for rotation', () => {
    const result = getCredentialAgeStatus({ updatedAt: '2025-05-01T00:00:00.000Z' }, now)

    expect(result.status).toBe('rotate')
  })

  test('handles missing dates', () => {
    const result = getCredentialAgeStatus({}, now)

    expect(result.status).toBe('unknown')
    expect(result.daysOld).toBeNull()
  })
})
