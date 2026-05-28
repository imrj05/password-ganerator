import { getGeneratorShortcutAction, isEditableShortcutTarget } from '../keyboardShortcuts'

describe('keyboardShortcuts', () => {
  test('maps generator shortcut keys to actions', () => {
    expect(getGeneratorShortcutAction({ key: 'r', target: {} })).toBe('refresh')
    expect(getGeneratorShortcutAction({ key: 'C', target: {} })).toBe('copy')
    expect(getGeneratorShortcutAction({ key: 'b', target: {} })).toBe('batch')
  })

  test('ignores modified shortcut events', () => {
    expect(getGeneratorShortcutAction({ key: 'r', ctrlKey: true, target: {} })).toBeNull()
    expect(getGeneratorShortcutAction({ key: 'r', metaKey: true, target: {} })).toBeNull()
    expect(getGeneratorShortcutAction({ key: 'r', altKey: true, target: {} })).toBeNull()
  })

  test('detects editable shortcut targets', () => {
    expect(isEditableShortcutTarget({ tagName: 'INPUT' })).toBe(true)
    expect(isEditableShortcutTarget({ tagName: 'textarea' })).toBe(true)
    expect(isEditableShortcutTarget({ isContentEditable: true })).toBe(true)
    expect(isEditableShortcutTarget({ tagName: 'button' })).toBe(false)
  })

  test('ignores shortcuts while typing in editable fields', () => {
    expect(getGeneratorShortcutAction({ key: 'c', target: { tagName: 'INPUT' } })).toBeNull()
  })
})
