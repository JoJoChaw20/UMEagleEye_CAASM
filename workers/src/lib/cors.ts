/**
 * cors.ts - who may call the API from a browser, and with which methods.
 *
 * The dashboard is on another origin than the API, so a browser only sends a request whose method
 * CORS allows. Every method a route uses must be listed (cors.test.ts checks the route files):
 * PUT was once missing, and Edit access and Save recovery plan failed in the browser only.
 */
export const CORS_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as const

export const CORS_HEADERS = ['Content-Type', 'Authorization', 'Mcp-Session-Id', 'MCP-Protocol-Version', 'Last-Event-ID']

/** PURE. The dashboards allowed to call the API; a local dev server only outside production. */
export function corsOrigins(env: { APP_ENV?: string; FRONTEND_URL?: string }): string[] {
  return [
    'https://umeagleeye.csnet.my',
    'https://umeagleeye.pages.dev',
    env.FRONTEND_URL ?? '',
    // A local dev server only outside production (a page on localhost could be anything)
    ...(env.APP_ENV === 'production' ? [] : ['http://localhost:5173', 'http://localhost:3000']),
  ].filter(Boolean)
}
