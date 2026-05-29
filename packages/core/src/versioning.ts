import {
  FIDES_PROTOCOL_VERSION,
  FIDES_SUPPORTED_PROTOCOL_VERSIONS,
  type FidesProtocolVersion,
} from './protocol.js'
import { createErrorEnvelope, type ErrorEnvelope } from './errors.js'

export interface VersionNegotiationRecord {
  schema_version: 'fides.version_negotiation.v1'
  supported_versions: string[]
  required_versions?: string[]
  peer_supported_versions: string[]
  peer_required_versions?: string[]
  negotiated_version?: string
  compatible: boolean
  errors: ErrorEnvelope[]
}

export interface VersionNegotiationInput {
  localSupported?: readonly string[]
  localRequired?: readonly string[]
  peerSupported: readonly string[]
  peerRequired?: readonly string[]
}

export function negotiateProtocolVersion(input: VersionNegotiationInput): VersionNegotiationRecord {
  const localSupported = [...(input.localSupported ?? FIDES_SUPPORTED_PROTOCOL_VERSIONS)]
  const localRequired = input.localRequired ? [...input.localRequired] : undefined
  const peerSupported = [...input.peerSupported]
  const peerRequired = input.peerRequired ? [...input.peerRequired] : undefined
  const common = localSupported.filter(version => peerSupported.includes(version))
  const negotiated = common[0]
  const requiredCompatible = requiredVersionsCompatible(localSupported, peerRequired) &&
    requiredVersionsCompatible(peerSupported, localRequired)
  const compatible = Boolean(negotiated) && requiredCompatible
  const errors = compatible
    ? []
    : [createErrorEnvelope('VERSION_INCOMPATIBLE', {
        details: {
          localSupported,
          localRequired,
          peerSupported,
          peerRequired,
        },
      })]

  const record: VersionNegotiationRecord = {
    schema_version: 'fides.version_negotiation.v1',
    supported_versions: localSupported,
    peer_supported_versions: peerSupported,
    compatible,
    errors,
  }

  if (localRequired !== undefined) record.required_versions = localRequired
  if (peerRequired !== undefined) record.peer_required_versions = peerRequired
  if (negotiated !== undefined && compatible) record.negotiated_version = negotiated

  return record
}

export function isSupportedProtocolVersion(version: string): version is FidesProtocolVersion {
  return (FIDES_SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(version)
}

export function defaultVersionNegotiationRecord(peerSupported: readonly string[]): VersionNegotiationRecord {
  return negotiateProtocolVersion({
    localSupported: FIDES_SUPPORTED_PROTOCOL_VERSIONS,
    localRequired: [FIDES_PROTOCOL_VERSION],
    peerSupported,
  })
}

function requiredVersionsCompatible(
  supported: string[],
  required: string[] | undefined
): boolean {
  if (!required || required.length === 0) return true
  return required.every(version => supported.includes(version))
}
