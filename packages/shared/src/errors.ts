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
