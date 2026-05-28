import { generatePasswordBatch } from '../batchPasswordGenerator'

describe('generatePasswordBatch', () => {
  test('generates the requested number of unique passwords', () => {
    let index = 0
    const batch = generatePasswordBatch(() => `password-${index += 1}`, 5)

    expect(batch).toHaveLength(5)
    expect(new Set(batch).size).toBe(5)
  })

  test('clamps batch size between 1 and 10', () => {
    let index = 0
    const batch = generatePasswordBatch(() => `item-${index += 1}`, 25)

    expect(batch).toHaveLength(10)
  })

  test('requires a generator function', () => {
    expect(() => generatePasswordBatch(null)).toThrow('A password generator function is required')
  })
})
