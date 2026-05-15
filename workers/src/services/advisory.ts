import type { DB } from '../db/client'
import { advisories, events, assets } from '../db/schema'
import { eq } from 'drizzle-orm'

interface OpenRouterMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
}

async function callOpenRouter(
  messages: OpenRouterMessage[],
  apiKey: string,
  model: string
): Promise<string> {
  const res = await fetch('https://openrouter.ai/api/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'HTTP-Referer': 'https://umeagleeye.pages.dev',
      'X-Title': 'UMEagleEye CAASM',
    },
    body: JSON.stringify({ model, messages, max_tokens: 1024, temperature: 0.3 }),
  })
  if (!res.ok) throw new Error(`OpenRouter error: ${res.status}`)
  const data = await res.json() as { choices: Array<{ message: { content: string } }> }
  return data.choices[0]?.message.content ?? ''
}

export async function generateAdvisory(
  db: DB,
  eventId: string,
  apiKey: string,
  model: string
): Promise<void> {
  // Load event + asset context
  const eventRows = await db
    .select()
    .from(events)
    .where(eq(events.eventId, eventId))
    .limit(1)

  const event = eventRows[0]
  if (!event) throw new Error(`Event ${eventId} not found`)

  const assetRows = await db
    .select()
    .from(assets)
    .where(eq(assets.assetId, event.assetId))
    .limit(1)

  const asset = assetRows[0]

  const context = [
    `Event Type: ${event.eventType}`,
    `Severity: ${event.severity}`,
    `Details: ${JSON.stringify(event.details)}`,
    asset ? `Asset: ${asset.hostname ?? asset.ipAddress} (${asset.deviceType}, criticality: ${asset.criticalityScore}/10)` : '',
    asset?.osInfo ? `OS/Ports: ${JSON.stringify(asset.osInfo)}` : '',
  ].filter(Boolean).join('\n')

  const messages: OpenRouterMessage[] = [
    {
      role: 'system',
      content: `You are a senior cybersecurity analyst for UMEagleEye CAASM.
Given a security event, provide a concise advisory with:
1. A 2-3 sentence SUMMARY explaining the risk
2. Specific RECOMMENDED_ACTION steps (numbered list, max 5 steps)
Keep language technical but actionable. Format response as JSON: {"summary": "...", "recommended_action": "..."}`,
    },
    {
      role: 'user',
      content: `Security event requires advisory:\n\n${context}`,
    },
  ]

  let summary = `Security event of type ${event.eventType} detected with ${event.severity} severity.`
  let recommendedAction = 'Investigate the affected asset and review security controls.'

  try {
    const raw = await callOpenRouter(messages, apiKey, model)
    const parsed = JSON.parse(raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim()) as {
      summary?: string
      recommended_action?: string
    }
    if (parsed.summary) summary = parsed.summary
    if (parsed.recommended_action) recommendedAction = parsed.recommended_action
  } catch {
    // Use fallback text if AI fails
  }

  await db.insert(advisories).values({
    eventId,
    summary,
    recommendedAction,
    status: 'open',
  })
}
