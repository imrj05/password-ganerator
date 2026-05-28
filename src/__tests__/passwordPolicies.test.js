import { getPasswordPolicy, validatePasswordPolicy } from '../passwordPolicies'

describe('passwordPolicies', () => {
  test('returns standard policy as fallback', () => {
    expect(getPasswordPolicy('missing').id).toBe('standard')
  })

  test('validates standard policy requirements', () => {
    const result = validatePasswordPolicy('StrongPassword123', 'standard')

    expect(result.passed).toBe(true)
    expect(result.passedCount).toBe(result.totalCount)
  })

  test('flags missing strict symbol requirement', () => {
    const result = validatePasswordPolicy('StrongPassword123456', 'strict')

    expect(result.passed).toBe(false)
    expect(result.checks.find(check => check.id === 'symbol').passed).toBe(false)
  })

  test('flags ambiguous characters for strict policy', () => {
    const result = validatePasswordPolicy('Str0ngPassword123!', 'strict')

    expect(result.checks.find(check => check.id === 'ambiguous').passed).toBe(false)
  })
})
