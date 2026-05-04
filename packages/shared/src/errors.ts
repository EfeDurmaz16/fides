export class FidesError extends Error {
  constructor(message: string, public code: string) {
    super(message)
    this.name = 'FidesError'
  }
}

export class SignatureError extends FidesError {
  constructor(message: string) {
    super(message, 'SIGNATURE_ERROR')
    this.name = 'SignatureError'
  }
}

export class DiscoveryError extends FidesError {
  constructor(message: string) {
    super(message, 'DISCOVERY_ERROR')
    this.name = 'DiscoveryError'
  }
}

export class TrustError extends FidesError {
  constructor(message: string) {
    super(message, 'TRUST_ERROR')
    this.name = 'TrustError'
  }
}

export class KeyError extends FidesError {
  constructor(message: string) {
    super(message, 'KEY_ERROR')
    this.name = 'KeyError'
  }
}

export class CapabilityError extends FidesError {
  constructor(message: string) {
    super(message, 'CAPABILITY_ERROR')
    this.name = 'CapabilityError'
  }
}

export class ExecutionError extends FidesError {
  constructor(message: string) {
    super(message, 'EXECUTION_ERROR')
    this.name = 'ExecutionError'
  }
}

export class EconomicError extends FidesError {
  constructor(message: string) {
    super(message, 'ECONOMIC_ERROR')
    this.name = 'EconomicError'
  }
}

export class SettlementError extends FidesError {
  constructor(message: string) {
    super(message, 'SETTLEMENT_ERROR')
    this.name = 'SettlementError'
  }
}

export class VersioningError extends FidesError {
  constructor(message: string) {
    super(message, 'VERSIONING_ERROR')
    this.name = 'VersioningError'
  }
}

export class PolicyError extends FidesError {
  constructor(message: string) {
    super(message, 'POLICY_ERROR')
    this.name = 'PolicyError'
  }
}

export class EvidenceError extends FidesError {
  constructor(message: string) {
    super(message, 'EVIDENCE_ERROR')
    this.name = 'EvidenceError'
  }
}

export class RuntimeError extends FidesError {
  constructor(message: string) {
    super(message, 'RUNTIME_ERROR')
    this.name = 'RuntimeError'
  }
}
