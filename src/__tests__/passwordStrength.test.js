import { describe, expect, test } from 'vitest'
import { loadPasswordStrength } from '../lib/passwordStrength'

describe('password strength estimator', () => {
  test('scores common passwords as weak', async () => {
    const zxcvbn = await loadPasswordStrength()

    expect(zxcvbn('password123').score).toBeLessThanOrEqual(1)
    expect(zxcvbn('qwerty').score).toBeLessThanOrEqual(1)
    expect(zxcvbn('1234').score).toBeLessThanOrEqual(1)
  }, 20000)

  test('scores random passwords as strong', async () => {
    const zxcvbn = await loadPasswordStrength()

    expect(zxcvbn('4f8Kq2mN9xLp7Rt3').score).toBeGreaterThanOrEqual(3)
  }, 20000)
})
