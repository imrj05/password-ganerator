export const GENERATOR_SHORTCUTS = [
  { key: 'r', action: 'refresh', label: 'R', description: 'Regenerate password' },
  { key: 'c', action: 'copy', label: 'C', description: 'Copy current password' },
  { key: 'b', action: 'batch', label: 'B', description: 'Generate batch' },
]

export function isEditableShortcutTarget(target) {
  if (!target) return false

  const tagName = String(target.tagName || '').toLowerCase()
  return target.isContentEditable || ['input', 'textarea', 'select'].includes(tagName)
}

export function getGeneratorShortcutAction(event) {
  if (!event || event.altKey || event.ctrlKey || event.metaKey) return null
  if (isEditableShortcutTarget(event.target)) return null

  const key = String(event.key || '').toLowerCase()
  return GENERATOR_SHORTCUTS.find(shortcut => shortcut.key === key)?.action || null
}
