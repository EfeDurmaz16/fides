/**
 * RFC 9421 HTTP Message Signatures - Canonicalization
 */

export interface RequestLike {
  method: string
  url: string
  headers: Record<string, string>
  body?: string | Uint8Array
}

export interface SignatureComponent {
  name: string
  value: string
}

export interface SignatureParams {
  components: string[]
  created: number
  expires: number
  keyid: string
  alg: string
}

/**
 * Extract component value from a request
 */
function extractComponent(
  request: RequestLike,
  componentName: string
): string {
  // Derived components start with @
  if (componentName.startsWith('@')) {
    const url = new URL(request.url)

    switch (componentName) {
      case '@method':
        return request.method.toUpperCase()

      case '@target-uri':
        return request.url

      case '@authority':
        return url.host

      case '@path':
        return url.pathname + url.search

      default:
        throw new Error(`Unknown derived component: ${componentName}`)
    }
  }

  // Regular header field - case insensitive lookup
  const normalizedName = componentName.toLowerCase()
  const headerValue = Object.entries(request.headers).find(
    ([key]) => key.toLowerCase() === normalizedName
  )?.[1]

  if (headerValue === undefined) {
    throw new Error(`Header not found: ${componentName}`)
  }

  return headerValue
}

/**
 * Create the signature base string per RFC 9421
 *
 * Format:
 * "component-name": value
 * ...
 * "@signature-params": (component-list);created=UNIX;expires=UNIX;keyid="DID";alg="ed25519"
 */
export function createSignatureBase(
  request: RequestLike,
  params: SignatureParams
): string {
  const lines: string[] = []

  // Add each component
  for (const componentName of params.components) {
    const value = extractComponent(request, componentName)
    // RFC 9421 format: "component-name": value
    lines.push(`"${componentName}": ${value}`)
  }

  // Build signature params line
  const componentList = params.components.map(c => `"${c}"`).join(' ')
  const paramsLine = `"@signature-params": (${componentList});created=${params.created};expires=${params.expires};keyid="${params.keyid}";alg="${params.alg}"`
  lines.push(paramsLine)

  return lines.join('\n')
}

/**
 * Parse Signature-Input header to extract parameters
 * Format: sig1=("@method" "@target-uri");created=123;expires=456;keyid="did:fides:...";alg="ed25519"
 */
export function parseSignatureInput(signatureInput: string): {
  label: string
  params: SignatureParams
} {
  // Extract label and rest
  const eqIndex = signatureInput.indexOf('=')
  if (eqIndex === -1) {
    throw new Error('Invalid Signature-Input format: missing =')
  }

  const label = signatureInput.substring(0, eqIndex)
  const rest = signatureInput.substring(eqIndex + 1)

  // Extract component list from parentheses
  const componentsMatch = rest.match(/\(([^)]+)\)/)
  if (!componentsMatch) {
    throw new Error('Invalid Signature-Input format: missing component list')
  }

  const componentsStr = componentsMatch[1]
  const components = componentsStr
    .split(/\s+/)
    .map(c => c.replace(/"/g, ''))
    .filter(c => c.length > 0)

  // Extract parameters after the component list
  const paramsStr = rest.substring(componentsMatch.index! + componentsMatch[0].length)

  // Parse created
  const createdMatch = paramsStr.match(/created=(\d+)/)
  if (!createdMatch) {
    throw new Error('Invalid Signature-Input format: missing created')
  }
  const created = parseInt(createdMatch[1], 10)

  // Parse expires
  const expiresMatch = paramsStr.match(/expires=(\d+)/)
  if (!expiresMatch) {
    throw new Error('Invalid Signature-Input format: missing expires')
  }
  const expires = parseInt(expiresMatch[1], 10)

  // Parse keyid
  const keyidMatch = paramsStr.match(/keyid="([^"]+)"/)
  if (!keyidMatch) {
    throw new Error('Invalid Signature-Input format: missing keyid')
  }
  const keyid = keyidMatch[1]

  // Parse alg
  const algMatch = paramsStr.match(/alg="([^"]+)"/)
  if (!algMatch) {
    throw new Error('Invalid Signature-Input format: missing alg')
  }
  const alg = algMatch[1]

  return {
    label,
    params: {
      components,
      created,
      expires,
      keyid,
      alg,
    },
  }
}
