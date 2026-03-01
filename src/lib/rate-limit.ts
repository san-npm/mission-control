import { NextResponse } from 'next/server'

interface RateLimitEntry {
  count: number
  resetAt: number
}

interface RateLimiterOptions {
  windowMs: number
  maxRequests: number
  message?: string
}

// Track intervals for cleanup during HMR to prevent leaks in development
const _hmrIntervals: NodeJS.Timeout[] = (globalThis as any).__rateLimitIntervals ??= []

export function createRateLimiter(options: RateLimiterOptions) {
  const store = new Map<string, RateLimitEntry>()

  // Periodic cleanup every 60s
  const cleanupInterval = setInterval(() => {
    const now = Date.now()
    for (const [key, entry] of store) {
      if (now > entry.resetAt) store.delete(key)
    }
  }, 60_000)
  // Don't prevent process exit
  if (cleanupInterval.unref) cleanupInterval.unref()
  // Track for HMR cleanup
  _hmrIntervals.push(cleanupInterval)

  return function checkRateLimit(request: Request): NextResponse | null {
    // Use the last (rightmost) IP from x-forwarded-for, which is the one added by our trusted proxy.
    // The leftmost IP can be spoofed by the client.
    const forwardedFor = request.headers.get('x-forwarded-for')
    const ip = forwardedFor
      ? forwardedFor.split(',').map(s => s.trim()).filter(Boolean).pop() || 'unknown'
      : 'unknown'
    const now = Date.now()
    const entry = store.get(ip)

    if (!entry || now > entry.resetAt) {
      store.set(ip, { count: 1, resetAt: now + options.windowMs })
      return null
    }

    entry.count++
    if (entry.count > options.maxRequests) {
      return NextResponse.json(
        { error: options.message || 'Too many requests. Please try again later.' },
        { status: 429 }
      )
    }

    return null
  }
}

export const loginLimiter = createRateLimiter({
  windowMs: 60_000,
  maxRequests: 5,
  message: 'Too many login attempts. Try again in a minute.',
})

export const mutationLimiter = createRateLimiter({
  windowMs: 60_000,
  maxRequests: 60,
})

export const heavyLimiter = createRateLimiter({
  windowMs: 60_000,
  maxRequests: 10,
  message: 'Too many requests for this resource. Please try again later.',
})

// Clean up stale intervals on HMR module reload (dev only)
if ((module as any).hot) {
  (module as any).hot.dispose(() => {
    for (const interval of _hmrIntervals) clearInterval(interval)
    _hmrIntervals.length = 0
  })
}
