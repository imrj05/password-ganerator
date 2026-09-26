// Lazily loads and configures the zxcvbn estimator with its required
// language data. Without setOptions, zxcvbn scores common passwords like
// "password123" as strong.
let estimatorPromise = null

export function loadPasswordStrength() {
  if (!estimatorPromise) {
    estimatorPromise = Promise.all([
      import('@zxcvbn-ts/core'),
      import('@zxcvbn-ts/language-common'),
    ]).then(([core, common]) => {
      core.zxcvbnOptions.setOptions({
        dictionary: common.dictionary,
        graphs: common.adjacencyGraphs,
      })
      return core.zxcvbn
    }).catch((error) => {
      estimatorPromise = null
      throw error
    })
  }

  return estimatorPromise
}
