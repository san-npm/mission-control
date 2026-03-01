import { createHmac } from 'crypto'
import { lookup } from 'dns/promises'
import { eventBus, type ServerEvent } from './event-bus'
import { logger } from './logger'

/** Block webhooks to private/internal IP ranges to prevent SSRF */
function isPrivateIP(ip: string): boolean {
  // IPv4 private ranges
  if (/^127\./.test(ip)) return true
  if (/^10\./.test(ip)) return true
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true
  if (/^192\.168\./.test(ip)) return true
  if (/^169\.254\./.test(ip)) return true
  if (ip === '0.0.0.0') return true
  // IPv6 loopback / link-local
  if (ip === '::1' || ip === '::' || ip.startsWith('fe80:') || ip.startsWith('fc00:') || ip.startsWith('fd')) return true
  return false
}

async function validateWebhookUrl(url: string): Promise<void> {
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    throw new Error('Invalid webhook URL')
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('Webhook URL must use http or https')
  }
  // Resolve hostname and check for private IPs
  try {
    const { address } = await lookup(parsed.hostname)
    if (isPrivateIP(address)) {
      throw new Error('Webhook URL resolves to a private IP address')
    }
  } catch (err: any) {
    if (err.message.includes('private IP')) throw err
    throw new Error(`Cannot resolve webhook hostname: ${parsed.hostname}`)
  }
}

interface Webhook {
  id: number
  name: string
  url: string
  secret: string | null
  events: string // JSON array
  enabled: number
}

// Map event bus events to webhook event types
const EVENT_MAP: Record<string, string> = {
  'activity.created': 'activity',         // Dynamically becomes activity.<type>
  'notification.created': 'notification',  // Dynamically becomes notification.<type>
  'agent.status_changed': 'agent.status_change',
  'audit.security': 'security',           // Dynamically becomes security.<action>
  'task.created': 'activity.task_created',
  'task.updated': 'activity.task_updated',
  'task.deleted': 'activity.task_deleted',
}

/**
 * Subscribe to the event bus and fire webhooks for matching events.
 * Called once during server initialization.
 */
export function initWebhookListener() {
  eventBus.on('server-event', (event: ServerEvent) => {
    const mapping = EVENT_MAP[event.type]
    if (!mapping) return

    // Build the specific webhook event type
    let webhookEventType: string
    if (mapping === 'activity' && event.data?.type) {
      webhookEventType = `activity.${event.data.type}`
    } else if (mapping === 'notification' && event.data?.type) {
      webhookEventType = `notification.${event.data.type}`
    } else if (mapping === 'security' && event.data?.action) {
      webhookEventType = `security.${event.data.action}`
    } else {
      webhookEventType = mapping
    }

    // Also fire agent.error for error status specifically
    const isAgentError = event.type === 'agent.status_changed' && event.data?.status === 'error'

    fireWebhooksAsync(webhookEventType, event.data).catch((err) => {
      logger.error({ err }, 'Webhook dispatch error')
    })

    if (isAgentError) {
      fireWebhooksAsync('agent.error', event.data).catch((err) => {
        logger.error({ err }, 'Webhook dispatch error')
      })
    }
  })
}

/**
 * Fire all matching webhooks for an event type (public for test endpoint).
 */
export function fireWebhooks(eventType: string, payload: Record<string, any>) {
  fireWebhooksAsync(eventType, payload).catch((err) => {
    logger.error({ err }, 'Webhook dispatch error')
  })
}

async function fireWebhooksAsync(eventType: string, payload: Record<string, any>) {
  let webhooks: Webhook[]
  try {
    // Lazy import to avoid circular dependency
    const { getDatabase } = await import('./db')
    const db = getDatabase()
    webhooks = db.prepare(
      'SELECT * FROM webhooks WHERE enabled = 1'
    ).all() as Webhook[]
  } catch {
    return // DB not ready or table doesn't exist yet
  }

  if (webhooks.length === 0) return

  const matchingWebhooks = webhooks.filter((wh) => {
    try {
      const events: string[] = JSON.parse(wh.events)
      return events.includes('*') || events.includes(eventType)
    } catch {
      return false
    }
  })

  await Promise.allSettled(
    matchingWebhooks.map((wh) => deliverWebhook(wh, eventType, payload))
  )
}

async function deliverWebhook(
  webhook: Webhook,
  eventType: string,
  payload: Record<string, any>
) {
  // Validate URL to prevent SSRF to internal networks
  try {
    await validateWebhookUrl(webhook.url)
  } catch (err: any) {
    logger.warn({ webhookId: webhook.id, url: webhook.url, err: err.message }, 'Webhook URL blocked by SSRF check')
    return
  }

  const body = JSON.stringify({
    event: eventType,
    timestamp: Math.floor(Date.now() / 1000),
    data: payload,
  })

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': 'MissionControl-Webhook/1.0',
    'X-MC-Event': eventType,
  }

  // HMAC signature if secret is configured
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

  // Log delivery attempt
  try {
    const { getDatabase } = await import('./db')
    const db = getDatabase()
    db.prepare(`
      INSERT INTO webhook_deliveries (webhook_id, event_type, payload, status_code, response_body, error, duration_ms)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      webhook.id,
      eventType,
      body,
      statusCode,
      responseBody,
      error,
      durationMs
    )

    // Update webhook last_fired
    db.prepare(`
      UPDATE webhooks SET last_fired_at = unixepoch(), last_status = ?, updated_at = unixepoch()
      WHERE id = ?
    `).run(statusCode ?? -1, webhook.id)

    // Prune old deliveries (keep last 200 per webhook)
    db.prepare(`
      DELETE FROM webhook_deliveries
      WHERE webhook_id = ? AND id NOT IN (
        SELECT id FROM webhook_deliveries WHERE webhook_id = ? ORDER BY created_at DESC LIMIT 200
      )
    `).run(webhook.id, webhook.id)
  } catch {
    // Silent - delivery logging is best-effort
  }
}
