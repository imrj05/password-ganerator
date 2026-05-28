import MemorablePasswordGenerator from '../memorablePasswordGenerator'

describe('MemorablePasswordGenerator', () => {
  const gen = new MemorablePasswordGenerator()

  test('generates passphrase within length bounds', () => {
    const p = gen.generateMemorablePassword({ wordCount: 3, minLength: 8, maxLength: 50 })
    expect(p.length).toBeGreaterThanOrEqual(8)
    expect(p.length).toBeLessThanOrEqual(50)
  })

  test('assessMemorableStrength returns object with entropy', () => {
    const p = 'Bright-Apple-123'
    const s = gen.assessMemorableStrength(p)
    expect(s).toHaveProperty('entropy')
    expect(typeof s.entropy).toBe('number')
  })

  test('exposes an expanded unique vocabulary', () => {
    const stats = gen.getVocabularyStats()

    expect(stats.words).toBeGreaterThan(250)
    expect(stats.adjectives).toBeGreaterThan(150)
    expect(stats.total).toBe(gen.words.length + gen.adjectives.length)
    expect(new Set(gen.words).size).toBe(gen.words.length)
    expect(new Set(gen.adjectives).size).toBe(gen.adjectives.length)
  })

  test('uses crypto-backed random integers within bounds', () => {
    for (let i = 0; i < 20; i += 1) {
      const value = gen.getRandomInt(7)

      expect(value).toBeGreaterThanOrEqual(0)
      expect(value).toBeLessThan(7)
    }
  })
})
