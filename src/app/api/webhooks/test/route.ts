import { NextRequest, NextResponse } from 'next/server'
import { getDatabase } from '@/lib/db'
import { requireRole } from '@/lib/auth'
import { createHmac } from 'crypto'
import { lookup } from 'dns/promises'

/**
 * POST /api/webhooks/test - Send a test event to a webhook
 */
export async function POST(request: NextRequest) {
  const auth = requireRole(request, 'admin')
  if ('error' in auth) return NextResponse.json({ error: auth.error }, { status: auth.status })

  try {
    const db = getDatabase()
    const { id } = await request.json()

    if (!id) {
      return NextResponse.json({ error: 'Webhook ID is required' }, { status: 400 })
    }

    const webhook = db.prepare('SELECT * FROM webhooks WHERE id = ?').get(id) as any
    if (!webhook) {
      return NextResponse.json({ error: 'Webhook not found' }, { status: 404 })
    }

    // SSRF check: validate webhook URL doesn't point to internal networks
    try {
      const parsed = new URL(webhook.url)
      if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
        return NextResponse.json({ error: 'Webhook URL must use http or https' }, { status: 400 })
      }
      const { address } = await lookup(parsed.hostname)
      if (/^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.0\.0\.0)/.test(address) || address === '::1') {
        return NextResponse.json({ error: 'Webhook URL resolves to a private IP address' }, { status: 400 })
      }
    } catch (dnsErr: any) {
      if (dnsErr.message?.includes('private IP')) {
        return NextResponse.json({ error: dnsErr.message }, { status: 400 })
      }
      return NextResponse.json({ error: `Cannot resolve webhook hostname` }, { status: 400 })
    }

    const body = JSON.stringify({
      event: 'test.ping',
      timestamp: Math.floor(Date.now() / 1000),
      data: {
        message: 'This is a test webhook from Mission Control',
        webhook_id: webhook.id,
        webhook_name: webhook.name,
        triggered_by: auth.user.username,
      },
    })

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'MissionControl-Webhook/1.0',
      'X-MC-Event': 'test.ping',
    }

    if (webhook.secret) {
      const sig = createHmac('sha256', webhook.secret).update(body).digest('hex')
      headers['X-MC-Signature'] = `sha256=${sig}`
    }

    const start = Date.now()
    let statusCode: number | null = null
    let responseBody: string | null = null
    let error: string | null = null

    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 10000)

      const res = await fetch(webhook.url, {
        method: 'POST',
        headers,
        body,
        signal: controller.signal,
      })

      clearTimeout(timeout)
      statusCode = res.status
      responseBody = await res.text().catch(() => null)
      if (responseBody && responseBody.length > 1000) {
        responseBody = responseBody.slice(0, 1000) + '...'
      }
    } catch (err: any) {
      error = err.name === 'AbortError' ? 'Timeout (10s)' : err.message
    }

    const durationMs = Date.now() - start

    // Log the test delivery
    db.prepare(`
      INSERT INTO webhook_deliveries (webhook_id, event_type, payload, status_code, response_body, error, duration_ms)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(webhook.id, 'test.ping', body, statusCode, responseBody, error, durationMs)

    db.prepare(`
      UPDATE webhooks SET last_fired_at = unixepoch(), last_status = ?, updated_at = unixepoch()
      WHERE id = ?
    `).run(statusCode ?? -1, webhook.id)

    const success = statusCode !== null && statusCode >= 200 && statusCode < 300

    return NextResponse.json({
      success,
      status_code: statusCode,
      response_body: responseBody,
      error,
      duration_ms: durationMs,
    })
  } catch (error) {
    console.error('POST /api/webhooks/test error:', error)
    return NextResponse.json({ error: 'Failed to test webhook' }, { status: 500 })
  }
}
