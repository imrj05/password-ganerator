const AMBIGUOUS_CHARS = 'il1Lo0O'

export const PASSWORD_POLICIES = [
  {
    id: 'standard',
    name: 'Standard',
    description: 'Good default for most accounts.',
    rules: {
      minLength: 12,
      requireLowercase: true,
      requireUppercase: true,
      requireNumber: true,
      noWhitespace: true,
    },
  },
  {
    id: 'strict',
    name: 'Strict',
    description: 'Longer password with symbols and no ambiguous characters.',
    rules: {
      minLength: 16,
      requireLowercase: true,
      requireUppercase: true,
      requireNumber: true,
      requireSymbol: true,
      noAmbiguous: true,
      noWhitespace: true,
    },
  },
  {
    id: 'developer',
    name: 'Developer',
    description: 'Long secret suitable for tokens, keys, and service accounts.',
    rules: {
      minLength: 32,
      requireLowercase: true,
      requireNumber: true,
      noWhitespace: true,
    },
  },
]

export function getPasswordPolicy(policyId) {
  return PASSWORD_POLICIES.find(policy => policy.id === policyId) || PASSWORD_POLICIES[0]
}

export function validatePasswordPolicy(password = '', policyId = 'standard') {
  const policy = getPasswordPolicy(policyId)
  const value = String(password || '')
  const rules = policy.rules
  const checks = [
    {
      id: 'minLength',
      label: `At least ${rules.minLength} characters`,
      passed: value.length >= rules.minLength,
    },
  ]

  if (rules.requireLowercase) {
    checks.push({ id: 'lowercase', label: 'Contains lowercase letter', passed: /[a-z]/.test(value) })
  }

  if (rules.requireUppercase) {
    checks.push({ id: 'uppercase', label: 'Contains uppercase letter', passed: /[A-Z]/.test(value) })
  }

  if (rules.requireNumber) {
    checks.push({ id: 'number', label: 'Contains number', passed: /\d/.test(value) })
  }

  if (rules.requireSymbol) {
    checks.push({ id: 'symbol', label: 'Contains symbol', passed: /[^A-Za-z0-9\s]/.test(value) })
  }

  if (rules.noAmbiguous) {
    checks.push({
      id: 'ambiguous',
      label: 'Avoids ambiguous characters',
      passed: !Array.from(value).some(char => AMBIGUOUS_CHARS.includes(char)),
    })
  }

  if (rules.noWhitespace) {
    checks.push({ id: 'whitespace', label: 'No spaces or whitespace', passed: !/\s/.test(value) })
  }

  const passedCount = checks.filter(check => check.passed).length

  return {
    policy,
    checks,
    passed: passedCount === checks.length,
    passedCount,
    totalCount: checks.length,
  }
}
