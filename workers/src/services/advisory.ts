import type { DB } from '../db/client'
import { advisories, events, assets } from '../db/schema'
import { eq } from 'drizzle-orm'

interface AIMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
}

interface GeneratedAdvisory {
  advisoryId: string
  summary: string
  recommendedAction: string
  eventType: string
  severity: string
  assetLabel: string
}

async function callAI(
  messages: AIMessage[],
  deepseekKey: string | undefined,
  openrouterKey: string,
  model: string | undefined,
): Promise<string> {
  const useDeepSeek = !!deepseekKey
  const apiKey  = useDeepSeek ? deepseekKey! : openrouterKey
  const baseUrl = useDeepSeek
    ? 'https://api.deepseek.com/chat/completions'
    : 'https://openrouter.ai/api/v1/chat/completions'
  const resolvedModel = useDeepSeek ? 'deepseek-chat' : (model ?? 'deepseek/deepseek-chat')

  const headers: Record<string, string> = {
    'Authorization': `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
  }
  if (!useDeepSeek) {
    headers['HTTP-Referer'] = 'https://umeagleeye.pages.dev'
    headers['X-Title'] = 'UMEagleEye CAASM'
  }

  const res = await fetch(baseUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({ model: resolvedModel, messages, max_tokens: 1024, temperature: 0.3 }),
  })
  if (!res.ok) throw new Error(`AI API error: ${res.status}`)
  const data = await res.json() as { choices: Array<{ message: { content: string } }> }
  return data.choices[0]?.message.content ?? ''
}

export async function generateAdvisory(
  db: DB,
  eventId: string,
  openrouterKey: string,
  model: string | undefined,
  deepseekKey?: string,
): Promise<GeneratedAdvisory | null> {
  // Load event + asset context
  const eventRows = await db
    .select()
    .from(events)
    .where(eq(events.eventId, eventId))
    .limit(1)

  const event = eventRows[0]
  if (!event) return null

  const assetRows = await db
    .select()
    .from(assets)
    .where(eq(assets.assetId, event.assetId))
    .limit(1)

  const asset = assetRows[0]
  const assetLabel = asset ? (asset.hostname ?? asset.ipAddress ?? 'Unknown') : 'Unknown'

  const context = [
    `Event Type: ${event.eventType}`,
    `Severity: ${event.severity}`,
    `Details: ${JSON.stringify(event.details)}`,
    asset ? `Asset: ${assetLabel} (${asset.deviceType}, criticality: ${asset.criticalityScore}/10)` : '',
    asset?.osInfo ? `OS/Ports: ${JSON.stringify(asset.osInfo)}` : '',
  ].filter(Boolean).join('\n')

  const messages: AIMessage[] = [
    {
      role: 'system',
      content: `You are a senior cybersecurity analyst for UMEagleEye CAASM.
Given a security event, provide a concise advisory with:
1. A 2-3 sentence SUMMARY explaining the risk
2. Specific RECOMMENDED_ACTION steps (numbered list, max 5 steps)
Keep language technical but actionable.
Format response as JSON where recommended_action is a plain string with steps separated by newlines:
{"summary": "...", "recommended_action": "1. First step\n2. Second step\n3. Third step"}`,
    },
    {
      role: 'user',
      content: `Security event requires advisory:\n\n${context}`,
    },
  ]

  let summary = `Security event of type ${event.eventType} detected with ${event.severity} severity.`
  let recommendedAction = 'Investigate the affected asset and review security controls.'

  try {
    const raw = await callAI(messages, deepseekKey, openrouterKey, model)
    const parsed = JSON.parse(raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim()) as {
      summary?: string
      recommended_action?: string
    }
    if (parsed.summary) summary = parsed.summary
    if (parsed.recommended_action) recommendedAction = parsed.recommended_action
  } catch {
    // Use fallback text if AI fails
  }

  const [inserted] = await db.insert(advisories).values({
    eventId,
    summary,
    recommendedAction,
    status: 'open',
  }).returning()

  return {
    advisoryId:        inserted.advisoryId,
    summary,
    recommendedAction,
    eventType:         event.eventType,
    severity:          event.severity,
    assetLabel,
  }
}
