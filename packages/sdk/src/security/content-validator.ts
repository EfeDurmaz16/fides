/**
 * Content validation for AI agent communications
 * Detects common prompt injection patterns in request payloads
 */

export interface ContentValidationResult {
  safe: boolean
  threats: ContentThreat[]
}

export interface ContentThreat {
  type: 'prompt_injection' | 'instruction_override' | 'data_exfiltration' | 'privilege_escalation'
  pattern: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  description: string
}

// Patterns that indicate prompt injection attempts
const INJECTION_PATTERNS: Array<{
  regex: RegExp
  type: ContentThreat['type']
  severity: ContentThreat['severity']
  description: string
}> = [
  {
    regex: /ignore\s+(all\s+)?previous\s+(instructions?|prompts?|rules?)/i,
    type: 'prompt_injection',
    severity: 'critical',
    description: 'Attempt to override previous instructions',
  },
  {
    regex: /you\s+are\s+now\s+/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Attempt to redefine agent identity',
  },
  {
    regex: /system\s*:?\s*prompt/i,
    type: 'prompt_injection',
    severity: 'high',
    description: 'Attempt to inject system prompt',
  },
  {
    regex: /disregard\s+(all\s+)?(previous|prior|above)/i,
    type: 'prompt_injection',
    severity: 'critical',
    description: 'Attempt to disregard prior context',
  },
  {
    regex: /\bdo\s+not\s+follow\b.*\b(rules?|instructions?|guidelines?)\b/i,
    type: 'instruction_override',
    severity: 'high',
    description: 'Attempt to bypass rules',
  },
  {
    regex: /transfer\s+(all\s+)?(data|files?|credentials?|keys?|tokens?)\s+to/i,
    type: 'data_exfiltration',
    severity: 'critical',
    description: 'Potential data exfiltration attempt',
  },
  {
    regex: /\bsudo\b|\broot\b|\badmin\s+mode\b|\bgod\s+mode\b/i,
    type: 'privilege_escalation',
    severity: 'high',
    description: 'Privilege escalation attempt',
  },
  {
    regex: /forget\s+(everything|all|what)\s+(you|i)\s+(told|said|know)/i,
    type: 'prompt_injection',
    severity: 'high',
    description: 'Attempt to clear agent memory/context',
  },
  {
    regex: /act\s+as\s+(if\s+)?(you\s+are|a)\s+/i,
    type: 'instruction_override',
    severity: 'medium',
    description: 'Attempt to change agent behavior',
  },
  {
    regex: /\bexec\s*\(|\beval\s*\(|\bFunction\s*\(/i,
    type: 'privilege_escalation',
    severity: 'critical',
    description: 'Code execution attempt',
  },
]

/**
 * Validate content for potential security threats
 */
export function validateContent(content: string): ContentValidationResult {
  const threats: ContentThreat[] = []

  for (const pattern of INJECTION_PATTERNS) {
    const match = content.match(pattern.regex)
    if (match) {
      threats.push({
        type: pattern.type,
        pattern: match[0],
        severity: pattern.severity,
        description: pattern.description,
      })
    }
  }

  return {
    safe: threats.length === 0,
    threats,
  }
}

/**
 * Validate a request body for content threats
 */
export function validateRequestContent(body: string | undefined): ContentValidationResult {
  if (!body) {
    return { safe: true, threats: [] }
  }

  // Check the raw body
  const rawResult = validateContent(body)

  // Also try to parse as JSON and check string values recursively
  try {
    const parsed = JSON.parse(body)
    const jsonThreats = scanObject(parsed)
    return {
      safe: rawResult.safe && jsonThreats.length === 0,
      threats: [...rawResult.threats, ...jsonThreats],
    }
  } catch {
    return rawResult
  }
}

function scanObject(obj: unknown, depth = 0): ContentThreat[] {
  if (depth > 10) return [] // prevent infinite recursion

  const threats: ContentThreat[] = []

  if (typeof obj === 'string') {
    const result = validateContent(obj)
    threats.push(...result.threats)
  } else if (Array.isArray(obj)) {
    for (const item of obj) {
      threats.push(...scanObject(item, depth + 1))
    }
  } else if (obj && typeof obj === 'object') {
    for (const value of Object.values(obj)) {
      threats.push(...scanObject(value, depth + 1))
    }
  }

  return threats
}
