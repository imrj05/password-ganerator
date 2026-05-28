class MemorablePasswordGenerator {
  constructor() {
    this.words = [
      'apple', 'banana', 'cherry', 'dragon', 'elephant', 'falcon', 'guitar', 'horizon',
      'island', 'jungle', 'knight', 'lemon', 'mountain', 'ocean', 'planet', 'queen',
      'rainbow', 'sunset', 'thunder', 'universe', 'victory', 'wizard', 'xenon', 'yellow',
      'zebra', 'anchor', 'bridge', 'castle', 'diamond', 'eagle', 'forest', 'galaxy',
      'hammer', 'iceberg', 'journey', 'kingdom', 'lighthouse', 'magnet', 'ninja', 'orbit',
      'phoenix', 'quartz', 'rocket', 'silver', 'tiger', 'umbrella', 'volcano', 'warrior',
      'crystal', 'breeze', 'storm', 'flower', 'river', 'star', 'moon', 'fire', 'water',
      'earth', 'wind', 'light', 'shadow', 'dream', 'spirit', 'power', 'magic', 'truth',
      'peace', 'love', 'hope', 'joy', 'freedom', 'wisdom', 'courage', 'strength', 'honor',
        'trust', 'friendship', 'adventure', 'journey', 'exploration', 'discovery', 'imagination',
        'creativity', 'innovation', 'passion', 'inspiration', 'dedication', 'perseverance', 'resilience', 'gratitude',
        'kindness', 'compassion', 'empathy', 'unity', 'diversity', 'harmony', 'balance', 'serenity',
        'tranquility', 'joyful', 'playful', 'thoughtful', 'mindful', 'graceful', 'fearless', 'hopeful', 'radiant',
        'vibrant', 'dynamic', 'energetic', 'enthusiastic', 'optimistic', 'confident', 'determined', 'ambitious', 'resourceful',
        'adaptable', 'flexible', 'open-minded', 'curious', 'explorative', 'inventive', 'original', 'unique', 'authentic', 'genuine',
        'sincere', 'honest', 'transparent', 'respectful', 'supportive', 'encouraging', 'uplifting', 'motivating', 'empowering', 'influential',
        'charismatic', 'charming', 'captivating', 'engaging', 'entertaining', 'enlightening', 'educational', 'informative', 'insightful', 'thought-provoking', 'stimulating', 'challenging', 'rewarding', 'fulfilling', 'satisfying', 'enriching', 'transformative',
        'life-changing', 'mind-expanding', 'perspective-shifting', 'worldview-altering', 'paradigm-shifting', 'revolutionary', 'groundbreaking', 'pioneering', 'trailblazing', 'path-breaking', 'innovative', 'cutting-edge', 'state-of-the-art', 'advanced', 'progressive', 'forward-thinking'
    ]

    this.words = this.uniqueWords(this.words.concat([
      'acorn', 'artist', 'atlas', 'aurora', 'avenue', 'beacon', 'beaver', 'bison',
      'brook', 'canyon', 'cedar', 'cipher', 'clover', 'comet', 'copper', 'cosmos',
      'delta', 'ember', 'falconer', 'fern', 'fjord', 'glacier', 'harbor', 'hazel',
      'heron', 'ivory', 'jade', 'jasper', 'keeper', 'lagoon', 'lantern', 'lotus',
      'maple', 'meadow', 'meteor', 'mirror', 'nebula', 'nova', 'otter', 'pebble',
      'prairie', 'raven', 'reef', 'saffron', 'sailor', 'signal', 'summit', 'temple',
      'timber', 'valley', 'velvet', 'voyage', 'willow', 'zephyr', 'apricot', 'badger',
      'bamboo', 'basil', 'basket', 'beetle', 'birch', 'blossom', 'butter', 'canvas',
      'caravan', 'cobalt', 'coral', 'dawn', 'desert', 'dolphin', 'echo', 'elm',
      'engine', 'feather', 'flame', 'garden', 'geyser', 'granite', 'grove', 'honey',
      'indigo', 'jasmine', 'kernel', 'ladder', 'marble', 'mosaic', 'nectar', 'onyx',
      'orchid', 'panda', 'pepper', 'plume', 'ripple', 'sable', 'scarlet', 'sparrow',
      'spruce', 'starlight', 'tulip', 'tundra', 'violet', 'walnut', 'whisper', 'winter',
      'amber', 'arrow', 'ash', 'badge', 'bay', 'blizzard', 'boulder', 'branch',
      'bronze', 'cactus', 'canopy', 'carbon', 'carrot', 'citadel', 'cloud', 'compass',
      'cricket', 'daisy', 'dune', 'engineer', 'finch', 'frost', 'harvest', 'helmet',
      'iris', 'juniper', 'kettle', 'labyrinth', 'lion', 'mango', 'mist', 'monarch',
      'olive', 'opal', 'pioneer', 'radar', 'sapphire', 'satellite', 'sequoia', 'sonnet',
      'spark', 'torch', 'turtle', 'wanderer', 'wave', 'wildflower', 'yonder'
    ]))

    this.adjectives = [
      'bright', 'swift', 'strong', 'gentle', 'brave', 'wise', 'cool', 'warm', 'dark',
      'light', 'fast', 'slow', 'big', 'small', 'loud', 'quiet', 'smooth', 'rough',
      'sharp', 'soft', 'hard', 'easy', 'tough', 'sweet', 'sour', 'hot', 'cold',
      'fresh', 'old', 'new', 'clean', 'dirty', 'rich', 'poor', 'happy', 'sad',
      'angry', 'calm', 'wild', 'tame', 'free', 'bound', 'open', 'closed', 'clear',
      'cloudy', 'sunny', 'rainy', 'snowy', 'windy', 'still', 'moving', 'stable',
        'shaky', 'solid', 'liquid', 'gaseous', 'frozen', 'melting', 'burning', 'cooling',
        'shining', 'glowing', 'flickering', 'blinking', 'radiant', 'dull', 'vivid', 'faded',
        'colorful', 'monochrome', 'vibrant', 'muted', 'bold', 'subtle', 'elegant', 'simple',
        'complex', 'intricate', 'plain', 'ornate', 'modern', 'classic', 'timeless', 'trendy',
        'futuristic', 'retro', 'vintage', 'rustic', 'urban', 'rural', 'cosmopolitan', 'provincial',
        'metropolitan', 'suburban', 'industrial', 'commercial', 'residential', 'institutional', 'educational', 'cultural', 'recreational', 'natural', 'artificial', 'organic', 'synthetic',
        'biological', 'technological', 'digital', 'analog', 'virtual', 'augmented', 'immersive', 'interactive', 'static', 'dynamic',
        'responsive', 'adaptive', 'intuitive', 'user-friendly', 'accessible', 'inclusive', 'diverse', 'multicultural', 'global', 'local', 'regional', 'national', 'international', 'transnational', 'cross-cultural', 'intercultural', 'multilingual', 'bilingual', 'monolingual', 'polyglot', 'linguistic', 'cognitive', 'psychological', 'emotional', 'social', 'cultural',
      'spiritual', 'philosophical', 'ethical', 'moral', 'aesthetic', 'artistic', 'creative', 'imaginative', 'innovative', 'inventive', 'original', 'unique', 'authentic', 'genuine', 'sincere', 'honest', 'transparent', 'respectful', 'supportive', 'encouraging', 'uplifting', 'motivating', 'inspiring', 'empowering', 'influential', 'charismatic', 'charming', 'captivating', 'engaging',
      'entertaining', 'enlightening', 'educational', 'informative', 'insightful', 'thought-provoking', 'stimulating', 'challenging', 'rewarding', 'fulfilling', 'satisfying', 'enriching', 'transformative',
      'life-changing'
    ]

    this.adjectives = this.uniqueWords(this.adjectives.concat([
      'agile', 'ancient', 'brisk', 'bronze', 'clever', 'cosmic', 'crisp', 'curious',
      'daring', 'deep', 'eager', 'earthy', 'electric', 'fabled', 'fierce', 'fluent',
      'frosty', 'golden', 'hidden', 'humble', 'jade', 'jolly', 'keen', 'lively',
      'lucid', 'lunar', 'mellow', 'mighty', 'nimble', 'noble', 'polished', 'proud',
      'rapid', 'rare', 'restful', 'robust', 'silent', 'solar', 'steady', 'stellar',
      'tidy', 'vivid', 'woven', 'zesty', 'amber', 'brilliant', 'candid', 'cerulean',
      'cheerful', 'coastal', 'compact', 'dapper', 'durable', 'earnest', 'emerald', 'even',
      'fearless', 'fertile', 'friendly', 'glossy', 'granite', 'harmonic', 'honorable', 'icy',
      'loyal', 'marble', 'neat', 'patient', 'quiet', 'sandy', 'scarlet', 'silver',
      'skillful', 'spry', 'sunlit', 'verdant', 'wild', 'witty'
    ]))

    this.separators = ['-', '_', '.', '!', '@', '#', '$', '%', '^', '&', '*']
  }

  uniqueWords(words) {
    return [...new Set(words.map(word => String(word).trim()).filter(Boolean))]
  }

  getRandomInt(max) {
    if (!Number.isInteger(max) || max <= 0) {
      throw new Error('Maximum random value must be a positive integer')
    }

    const maxUint32 = 0x100000000
    const range = Math.floor(maxUint32 / max) * max
    const array = new Uint32Array(1)
    let value

    do {
      crypto.getRandomValues(array)
      value = array[0]
    } while (value >= range)

    return value % max
  }

  getVocabularyStats() {
    return {
      words: this.words.length,
      adjectives: this.adjectives.length,
      total: this.words.length + this.adjectives.length,
    }
  }

  /**
   * Generate a memorable password using words
   * @param {Object} options - Generation options
   * @returns {string} - Generated memorable password
   */
  generateMemorablePassword(options = {}) {
    const {
      wordCount = 3,
      includeNumbers = true,
      includeCapitalization = true,
      separatorType = 'random', // 'random', 'dash', 'underscore', 'none'
      minLength = 8,
      maxLength = 50
    } = options

    let password = ''
    let attempts = 0
    const maxAttempts = 50

    while (attempts < maxAttempts) {
      const words = this.selectWords(wordCount, includeCapitalization)
      const separator = this.getSeparator(separatorType)
      const numbers = includeNumbers ? this.getRandomNumbers() : ''

      password = words.join(separator) + numbers

      if (password.length >= minLength && password.length <= maxLength) {
        break
      }

      attempts++
    }

    return password
  }

  /**
   * Select random words for the password
   * @param {number} count - Number of words to select
   * @param {boolean} includeCapitalization - Whether to capitalize words
   * @returns {Array} - Array of selected words
   */
  selectWords(count, includeCapitalization) {
    const selectedWords = []

    for (let i = 0; i < count; i++) {
      let word

      if (i === 0 && this.getRandomInt(2) === 0) {
        // Sometimes start with an adjective
        word = this.getRandomWord(this.adjectives)
      } else {
        word = this.getRandomWord(this.words)
      }

      if (includeCapitalization) {
        word = this.capitalizeWord(word)
      }

      selectedWords.push(word)
    }

    return selectedWords
  }

  /**
   * Get a random word from an array
   * @param {Array} wordArray - Array of words to choose from
   * @returns {string} - Random word
   */
  getRandomWord(wordArray) {
    return wordArray[this.getRandomInt(wordArray.length)]
  }

  /**
   * Capitalize a word randomly
   * @param {string} word - Word to capitalize
   * @returns {string} - Capitalized word
   */
  capitalizeWord(word) {
    const random = this.getRandomInt(3)

    if (random === 0) {
      return word.charAt(0).toUpperCase() + word.slice(1)
    } else if (random === 1) {
      return word.toUpperCase()
    } else {
      return word
    }
  }

  /**
   * Get separator based on type
   * @param {string} separatorType - Type of separator
   * @returns {string} - Separator character
   */
  getSeparator(separatorType) {
    if (separatorType === 'none') return ''
    if (separatorType === 'dash') return '-'
    if (separatorType === 'underscore') return '_'

    // Random separator
    return this.separators[this.getRandomInt(this.separators.length)]
  }

  /**
   * Generate random numbers to append
   * @returns {string} - Random numbers
   */
  getRandomNumbers() {
    const numberCount = this.getRandomInt(3) + 1 // 1-3 numbers

    let numbers = ''
    for (let i = 0; i < numberCount; i++) {
      numbers += this.getRandomInt(10).toString()
    }

    return numbers
  }

  /**
   * Generate passphrase with specific pattern
   * @param {Object} options - Generation options
   * @returns {string} - Generated passphrase
   */
  generatePassphrase(options = {}) {
    const {
      pattern = 'Adjective-Noun-Number',
      length = 4
    } = options

    const patterns = {
      'Adjective-Noun-Number': () => {
        const adjective = this.capitalizeWord(this.getRandomWord(this.adjectives))
        const noun = this.capitalizeWord(this.getRandomWord(this.words))
        const number = this.getRandomNumbers()
        return `${adjective}-${noun}-${number}`
      },
      'Word-Word-Word': () => {
        const words = this.selectWords(3, true)
        return words.join('-')
      },
      'Mixed': () => {
        const wordCount = this.getRandomInt(3) + 2 // 2-4 words
        return this.generateMemorablePassword({ wordCount })
      }
    }

    return patterns[pattern] ? patterns[pattern]() : this.generateMemorablePassword({ wordCount: length })
  }

  /**
   * Assess memorable password strength
   * @param {string} password - Password to assess
   * @returns {Object} - Strength assessment
   */
  assessMemorableStrength(password) {
    if (!password) return { score: 0, label: 'None', entropy: 0 }

    let entropy = 0
    let score = 0

    // Estimate entropy based on word count and complexity
    const wordCount = password.split(/[-_.\s]/).length
    const hasNumbers = /\d/.test(password)
    const hasCapitals = /[A-Z]/.test(password)
    const hasSymbols = /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)

    // Base entropy from word selection (assuming 1000 word vocabulary)
    entropy += wordCount * Math.log2(1000)

    // Additional entropy from numbers
    if (hasNumbers) entropy += 10 // ~3 digits from 10^3 possibilities

    // Additional entropy from capitalization patterns
    if (hasCapitals) entropy += wordCount * Math.log2(3) // 3 capitalization options per word

    // Additional entropy from separators
    if (hasSymbols) entropy += Math.log2(10) // ~10 separator options

    // Score based on entropy
    if (entropy < 30) score = 1
    else if (entropy < 50) score = 2
    else if (entropy < 70) score = 3
    else if (entropy < 90) score = 4
    else score = 5

    const labels = ['None', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong']

    return {
      score,
      label: labels[score],
      entropy: Math.round(entropy),
      wordCount,
      hasNumbers,
      hasCapitals,
      hasSymbols
    }
  }
}

export default MemorablePasswordGenerator
