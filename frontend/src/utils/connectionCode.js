// One-paste connection code for the EagleEye agent: the API URL, agent ID and API key
// in a single string, so a user pastes one value into the agent's Settings instead of
// three. Format: "EE1." + base64url(JSON {u, i, k}). The agent parses it in
// eagleeye/enrol.py; keep both sides in step when the format changes (new prefix).
export const CONNECTION_CODE_PREFIX = 'EE1.'

function base64url(text) {
  const bytes = new TextEncoder().encode(text)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** The absolute API URL agents connect to (VITE_API_URL may be a relative path in dev). */
export function agentApiUrl(baseURL) {
  try {
    return new URL(baseURL || '/api/v1', window.location.origin).href.replace(/\/+$/, '')
  } catch {
    return baseURL
  }
}

export function makeConnectionCode({ apiUrl, agentId, apiKey }) {
  return CONNECTION_CODE_PREFIX + base64url(JSON.stringify({ u: apiUrl, i: agentId, k: apiKey }))
}
