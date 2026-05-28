import SecurePasswordGenerator from '../securePasswordGenerator'
import { PASSWORD_TEMPLATES, getPasswordTemplate } from '../passwordTemplates'

describe('password templates', () => {
  test('exposes unique template ids', () => {
    const ids = PASSWORD_TEMPLATES.map(template => template.id)

    expect(new Set(ids).size).toBe(ids.length)
  })

  test('finds templates by id', () => {
    expect(getPasswordTemplate('banking')?.name).toBe('Banking')
    expect(getPasswordTemplate('missing')).toBeNull()
  })

  test('random templates generate valid passwords', () => {
    const gen = new SecurePasswordGenerator()
    const randomTemplates = PASSWORD_TEMPLATES.filter(template => template.settings.activeTab === 'random')

    randomTemplates.forEach(template => {
      const password = gen.generateSecurePassword(template.settings)

      expect(password).toHaveLength(template.settings.length)
    })
  })
})
