class SecurePasswordGenerator {
  constructor() {
    this.charSets = {
      uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      lowercase: 'abcdefghijklmnopqrstuvwxyz',
      numbers: '0123456789',
      // Organized symbol sets
      symbolSets: {
        basic: '!@#$%&*+-=?',
        extended: '!@#$%^&*()_+-=[]{}|;:,.<>?',
        safe: '!@#$%&*+-=?.',
        brackets: '()[]{}',
        punctuation: '!@#$%&*+-=?:;,.',
        math: '+-=*%^',
        dbsafe: '_.-~*+',
        custom: ''
      },
      ambiguous: 'il1Lo0O', // Characters that can be confused
    }
  }

  /**
   * Generate a cryptographically secure password using Web Crypto API
   * @param {Object} options - Password generation options
   * @returns {string} - Generated password
   */
  generateSecurePassword(options = {}) {
    const {
      length = 16,
      includeUppercase = true,
      includeLowercase = true,
      includeNumbers = true,
      includeSymbols = true,
      symbolSet = 'basic',
      customSymbols = '',
      excludeAmbiguous = false,
      ensureComplexity = true,
    } = options

    // Build character set
    let charset = this.buildCharset({
      includeUppercase,
      includeLowercase,
      includeNumbers,
      includeSymbols,
      symbolSet,
      customSymbols,
      excludeAmbiguous,
    })

    if (charset.length === 0) {
      throw new Error('At least one character type must be selected')
    }

    // Generate password with cryptographically secure randomness
    let password = this.generateRandomPassword(length, charset)

    // Ensure password meets complexity requirements
    if (ensureComplexity) {
      password = this.ensureComplexity(password, options)
    }

    return password
  }

  /**
   * Build character set based on options
   * @param {Object} options - Character set options
   * @returns {string} - Combined character set
   */
  buildCharset(options) {
    let charset = ''

    if (options.includeUppercase) charset += this.charSets.uppercase
    if (options.includeLowercase) charset += this.charSets.lowercase
    if (options.includeNumbers) charset += this.charSets.numbers

    if (options.includeSymbols) {
      if (options.symbolSet === 'custom' && options.customSymbols) {
        charset += options.customSymbols
      } else {
        charset += this.charSets.symbolSets[options.symbolSet] || this.charSets.symbolSets.basic
      }
    }

    // Remove ambiguous characters if requested
    if (options.excludeAmbiguous) {
      charset = this.removeAmbiguousChars(charset)
    }

    return charset
  }

  /**
   * Get available symbol sets
   * @returns {Object} - Available symbol sets with descriptions
   */
  getSymbolSets() {
    return {
      basic: {
        symbols: this.charSets.symbolSets.basic,
        name: 'Basic',
        description: 'Common safe symbols'
      },
      safe: {
        symbols: this.charSets.symbolSets.safe,
        name: 'Safe',
        description: 'Very safe symbols'
      },
      extended: {
        symbols: this.charSets.symbolSets.extended,
        name: 'Extended',
        description: 'All common symbols'
      },
      brackets: {
        symbols: this.charSets.symbolSets.brackets,
        name: 'Brackets',
        description: 'Bracket symbols only'
      },
      punctuation: {
        symbols: this.charSets.symbolSets.punctuation,
        name: 'Punctuation',
        description: 'Punctuation symbols'
      },
      math: {
        symbols: this.charSets.symbolSets.math,
        name: 'Math',
        description: 'Mathematical symbols'
      },
      dbsafe: {
        symbols: this.charSets.symbolSets.dbsafe,
        name: 'DB & Env Safe',
        description: 'Safe for DB URLs, .env files, & shell cmd'
      },
      custom: {
        symbols: '',
        name: 'Custom',
        description: 'Your own symbols'
      }
    }
  }

  /**
   * Remove ambiguous characters from charset
   * @param {string} charset - Original character set
   * @returns {string} - Filtered character set
   */
  removeAmbiguousChars(charset) {
    return charset.split('').filter(char =>
      !this.charSets.ambiguous.includes(char)
    ).join('')
  }

  /**
   * Generate password using cryptographically secure randomness
   * @param {number} length - Password length
   * @param {string} charset - Character set to use
   * @returns {string} - Generated password
   */
  generateRandomPassword(length, charset) {
    const array = new Uint32Array(length)

    // Use Web Crypto API for cryptographically secure random values
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(array)
    } else {
      // Fallback for environments without crypto API
      throw new Error('Secure random number generation not available')
    }

    let password = ''
    for (let i = 0; i < length; i++) {
      // Use rejection sampling to avoid modulo bias
      const randomValue = this.getUnbiasedRandom(array[i], charset.length)
      password += charset[randomValue]
    }

    return password
  }

  /**
   * Get unbiased random number using rejection sampling
   * @param {number} randomValue - Raw random value
   * @param {number} max - Maximum value (exclusive)
   * @returns {number} - Unbiased random number
   */
  getUnbiasedRandom(randomValue, max) {
    const maxUint32 = 0x100000000
    const range = Math.floor(maxUint32 / max) * max
    let value = randomValue
    // Iteratively reject biased values to avoid recursion
    while (value >= range) {
      const newArray = new Uint32Array(1)
      crypto.getRandomValues(newArray)
      value = newArray[0]
    }
    return value % max
  }

  /**
   * Ensure password meets complexity requirements
   * @param {string} password - Generated password
   * @param {Object} options - Generation options
   * @returns {string} - Password meeting complexity requirements
   */
  ensureComplexity(password, options) {
    const {
      includeUppercase,
      includeLowercase,
      includeNumbers,
      includeSymbols,
      length
    } = options

    let attempts = 0
    const maxAttempts = 100 // Prevent infinite loops

    while (attempts < maxAttempts) {
      let needsChange = false

      // Check if password meets all required character types
      if (includeUppercase && !/[A-Z]/.test(password)) needsChange = true
      if (includeLowercase && !/[a-z]/.test(password)) needsChange = true
      if (includeNumbers && !/[0-9]/.test(password)) needsChange = true
      if (includeSymbols && !/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?~`]/.test(password)) needsChange = true

      if (!needsChange) break

      // Regenerate password if it doesn't meet requirements
      const charset = this.buildCharset(options)
      password = this.generateRandomPassword(length, charset)
      attempts++
    }

    return password
  }

  /**
   * Calculate password entropy
   * @param {string} password - Password to analyze
   * @param {Object} options - Generation options
   * @returns {number} - Entropy in bits
   */
  calculateEntropy(password, options = {}) {
    // Dedupe charset to avoid inflated sizes and guard against zero
    const charset = Array.from(new Set(this.buildCharset(options).split(''))).join('')
    const charsetSize = Math.max(1, charset.length)
    return password.length * Math.log2(charsetSize)
  }

  /**
   * Assess password strength
   * @param {string} password - Password to analyze
   * @returns {Object} - Strength assessment
   */
  // Accept options so callers can pass the generation options used
  assessPasswordStrength(password, options = {}) {
    if (!password) return { score: 0, label: 'None', entropy: 0 }

    let charsetSize = 0
    // If options provided, derive charset from them for accurate entropy
    if (options && Object.keys(options).length > 0) {
      const charset = Array.from(new Set(this.buildCharset(options).split(''))).join('')
      charsetSize = Math.max(1, charset.length)
    } else {
      // Fallback: infer from password characters
      if (/[a-z]/.test(password)) charsetSize += 26
      if (/[A-Z]/.test(password)) charsetSize += 26
      if (/[0-9]/.test(password)) charsetSize += 10
      if (/[!@#$%^&*()_+\-=[\]{}|;:,.<>?~`]/.test(password)) charsetSize += 32
      charsetSize = Math.max(1, charsetSize)
    }

    const entropy = password.length * Math.log2(charsetSize || 1)

    // Score based on entropy and length
    let score = 0
    if (entropy < 25) score = 1
    else if (entropy < 50) score = 2
    else if (entropy < 75) score = 3
    else if (entropy < 100) score = 4
    else score = 5

    if (password.length < 8) score = Math.min(score, 2)
    else if (password.length >= 16) score = Math.min(score + 1, 5)

    const charTypes = [
      /[a-z]/.test(password),
      /[A-Z]/.test(password),
      /[0-9]/.test(password),
      /[!@#$%^&*()_+\-=[\]{}|;:,.<>?~`]/.test(password)
    ].filter(Boolean).length

    if (charTypes < 2) score = Math.min(score, 2)
    else if (charTypes >= 4) score = Math.min(score + 1, 5)

    const labels = ['None', 'Very Weak', 'Weak', 'Fair', 'Good', 'Strong']

    return {
      score,
      label: labels[score],
      entropy: Math.round(entropy),
      charsetSize,
      charTypes,
      timeToCrack: this.estimateTimeToCrack(entropy)
    }
  }

  /**
   * Estimate time to crack password
   * @param {number} entropy - Password entropy in bits
   * @returns {string} - Human-readable time estimate
   */
  estimateTimeToCrack(entropy) {
    // Assume 1 billion guesses per second (modern hardware)
    const guessesPerSecond = 1e9
    const totalCombinations = Math.pow(2, entropy)
    const secondsToCrack = totalCombinations / (2 * guessesPerSecond) // Average case

    if (secondsToCrack < 60) return 'Instantly'
    if (secondsToCrack < 3600) return `${Math.round(secondsToCrack / 60)} minutes`
    if (secondsToCrack < 86400) return `${Math.round(secondsToCrack / 3600)} hours`
    if (secondsToCrack < 31536000) return `${Math.round(secondsToCrack / 86400)} days`
    if (secondsToCrack < 31536000000) return `${Math.round(secondsToCrack / 31536000)} years`
    return 'Centuries'
  }

  /**
   * Generate multiple password options
   * @param {Object} options - Generation options
   * @param {number} count - Number of passwords to generate
   * @returns {Array} - Array of generated passwords
   */
  generatePasswordOptions(options, count = 5) {
    const passwords = []
    for (let i = 0; i < count; i++) {
      passwords.push(this.generateSecurePassword(options))
    }
    return passwords
  }

  /**
   * Validate password generation options
   * @param {Object} options - Options to validate
   * @returns {Object} - Validation result
   */
  validateOptions(options) {
    const errors = []

    if (options.length < 4) errors.push('Password length must be at least 4')
    if (options.length > 256) errors.push('Password length cannot exceed 256')

    const hasAnyCharType = options.includeUppercase ||
                          options.includeLowercase ||
                          options.includeNumbers ||
                          options.includeSymbols

    if (!hasAnyCharType) errors.push('At least one character type must be selected')

    return {
      isValid: errors.length === 0,
      errors
    }
  }
}

export default SecurePasswordGenerator
