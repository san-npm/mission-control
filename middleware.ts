import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

/** Edge-compatible constant-time string comparison. Pads to equal length to avoid timing leak. */
function safeCompare(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false
  const encoder = new TextEncoder()
  const bufA = encoder.encode(a)
  const bufB = encoder.encode(b)
  const maxLen = Math.max(bufA.length, bufB.length)
  if (maxLen === 0) return false
  // Pad both to equal length to prevent length-based timing leaks
  const padA = new Uint8Array(maxLen)
  const padB = new Uint8Array(maxLen)
  padA.set(bufA)
  padB.set(bufB)
  let result = bufA.length ^ bufB.length
  for (let i = 0; i < maxLen; i++) {
    result |= padA[i] ^ padB[i]
  }
  return result === 0
}

function envFlag(name: string): boolean {
  const raw = process.env[name]
  if (raw === undefined) return false
  const v = String(raw).trim().toLowerCase()
  return v === '1' || v === 'true' || v === 'yes' || v === 'on'
}

function getRequestHostname(request: NextRequest): string {
  const raw = request.headers.get('x-forwarded-host') || request.headers.get('host') || ''
  // If multiple hosts are present, take the first (proxy chain).
  const first = raw.split(',')[0] || ''
  return first.trim().split(':')[0] || ''
}

function hostMatches(pattern: string, hostname: string): boolean {
  const p = pattern.trim().toLowerCase()
  const h = hostname.trim().toLowerCase()
  if (!p || !h) return false

  // "*.example.com" matches "a.example.com" (but not bare "example.com")
  if (p.startsWith('*.')) {
    const suffix = p.slice(2)
    return h.endsWith(`.${suffix}`)
  }

  // "100.*" matches "100.64.0.1"
  if (p.endsWith('.*')) {
    const prefix = p.slice(0, -1)
    return h.startsWith(prefix)
  }

  return h === p
}

function generateNonce(): string {
  const array = new Uint8Array(16)
  crypto.getRandomValues(array)
  // Base64 encode
  let binary = ''
  for (const byte of array) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function buildCspHeader(nonce: string): string {
  const googleEnabled = !!(process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID || process.env.GOOGLE_CLIENT_ID)
  const isDev = process.env.NODE_ENV !== 'production'
  return [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${googleEnabled ? ' https://accounts.google.com' : ''}`,
    `style-src 'self' 'unsafe-inline'`,
    `connect-src 'self' wss:${isDev ? ' ws: http://127.0.0.1:* http://localhost:*' : ''}`,
    `img-src 'self' data: blob:${googleEnabled ? ' https://*.googleusercontent.com https://lh3.googleusercontent.com' : ''}`,
    `font-src 'self' data:`,
    `frame-src 'self'${googleEnabled ? ' https://accounts.google.com' : ''}`,
  ].join('; ')
}

export function middleware(request: NextRequest) {
  // Network access control.
  // In production: default-deny unless explicitly allowed.
  // In dev/test: allow all hosts unless overridden.
  const hostName = getRequestHostname(request)
  const allowAnyHost = envFlag('MC_ALLOW_ANY_HOST') || process.env.NODE_ENV !== 'production'
  const allowedPatterns = String(process.env.MC_ALLOWED_HOSTS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

  const isAllowedHost = allowAnyHost || allowedPatterns.some((p) => hostMatches(p, hostName))

  if (!isAllowedHost) {
    return new NextResponse('Forbidden', { status: 403 })
  }

  const { pathname } = request.nextUrl

  // CSRF Origin validation for mutating requests
  const method = request.method.toUpperCase()
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    const origin = request.headers.get('origin')
    if (origin) {
      let originHost: string
      try { originHost = new URL(origin).host } catch { originHost = '' }
      const requestHost = request.headers.get('host') || ''
      if (originHost && requestHost && originHost !== requestHost.split(',')[0].trim()) {
        return NextResponse.json({ error: 'CSRF origin mismatch' }, { status: 403 })
      }
    }
  }

  // Generate a CSP nonce for page responses
  const nonce = generateNonce()
  const cspHeader = buildCspHeader(nonce)

  // Helper to attach CSP + nonce headers to a response
  function withCsp(response: NextResponse): NextResponse {
    response.headers.set('Content-Security-Policy', cspHeader)
    response.headers.set('x-nonce', nonce)
    return response
  }

  // Allow login page and auth API without session
  if (pathname === '/login' || pathname.startsWith('/api/auth/')) {
    const requestHeaders = new Headers(request.headers)
    requestHeaders.set('x-nonce', nonce)
    const response = NextResponse.next({ request: { headers: requestHeaders } })
    return withCsp(response)
  }

  // Check for session cookie
  const sessionToken = request.cookies.get('mc-session')?.value

  // API routes: accept session cookie OR API key
  if (pathname.startsWith('/api/')) {
    const apiKey = request.headers.get('x-api-key')
    const configuredKey = process.env.API_KEY || ''
    if (sessionToken || (apiKey && configuredKey.length >= 16 && safeCompare(apiKey, configuredKey))) {
      return NextResponse.next()
    }

    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  // Page routes: redirect to login if no session
  if (sessionToken) {
    const requestHeaders = new Headers(request.headers)
    requestHeaders.set('x-nonce', nonce)
    const response = NextResponse.next({ request: { headers: requestHeaders } })
    return withCsp(response)
  }

  // Redirect to login
  const loginUrl = request.nextUrl.clone()
  loginUrl.pathname = '/login'
  return NextResponse.redirect(loginUrl)
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']
}
