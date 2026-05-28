export function generatePasswordBatch(generatePassword, count = 5) {
  if (typeof generatePassword !== 'function') {
    throw new Error('A password generator function is required')
  }

  const safeCount = Math.min(10, Math.max(1, Number(count) || 5))
  const seen = new Set()
  const passwords = []
  let attempts = 0

  while (passwords.length < safeCount && attempts < safeCount * 4) {
    attempts += 1
    const password = generatePassword()
    if (!password || seen.has(password)) continue

    seen.add(password)
    passwords.push(password)
  }

  return passwords
}
