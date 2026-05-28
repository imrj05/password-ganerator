export function getCredentialAgeStatus(credential = {}, now = new Date()) {
  const updatedAt = credential.updatedAt || credential.createdAt
  if (!updatedAt) {
    return {
      status: 'unknown',
      label: 'Age unknown',
      description: 'No update date is available for this login.',
      daysOld: null,
    }
  }

  const updatedTime = new Date(updatedAt).getTime()
  const nowTime = now instanceof Date ? now.getTime() : new Date(now).getTime()

  if (!Number.isFinite(updatedTime) || !Number.isFinite(nowTime)) {
    return {
      status: 'unknown',
      label: 'Age unknown',
      description: 'No valid update date is available for this login.',
      daysOld: null,
    }
  }

  const daysOld = Math.max(0, Math.floor((nowTime - updatedTime) / 86_400_000))

  if (daysOld >= 365) {
    return {
      status: 'rotate',
      label: 'Rotate soon',
      description: 'This login has not been updated in over a year.',
      daysOld,
    }
  }

  if (daysOld >= 180) {
    return {
      status: 'review',
      label: 'Review',
      description: 'This login is older than six months.',
      daysOld,
    }
  }

  return {
    status: 'fresh',
    label: 'Fresh',
    description: 'This login was updated recently.',
    daysOld,
  }
}
