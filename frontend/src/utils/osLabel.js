// The security baseline's systems (workers/src/lib/baseline.ts BaselineOs) and the agents' platform names.
const NAMES = { windows: 'Windows', linux: 'Linux', macos: 'macOS', darwin: 'macOS' }

export const osLabel = (os) => NAMES[os] ?? os ?? '—'

/** Agent platforms that have a security baseline (an inventory's `platform`). */
export const BASELINE_PLATFORMS = ['windows', 'linux', 'darwin']
