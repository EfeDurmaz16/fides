import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Command } from 'commander';
import * as sdk from '@fides/sdk';

const ORIGINAL_FIDES_API_KEY = process.env.FIDES_API_KEY;

// Mock the SDK
vi.mock('@fides/sdk', () => ({
  generateKeyPair: vi.fn(),
  generateDID: vi.fn(),
  signRequest: vi.fn(),
  verifyRequest: vi.fn(),
  createAttestation: vi.fn(),
  FileKeyStore: vi.fn(),
  DiscoveryClient: vi.fn(),
  TrustClient: vi.fn(),
  TrustLevel: {
    NONE: 0,
    LOW: 25,
    MEDIUM: 50,
    HIGH: 75,
    ABSOLUTE: 100,
  },
}));

// Mock fs and os
vi.mock('node:fs', () => ({
  default: {
    existsSync: vi.fn(() => false),
    readFileSync: vi.fn(),
    writeFileSync: vi.fn(),
    mkdirSync: vi.fn(),
  },
}));

vi.mock('node:os', () => ({
  default: {
    homedir: vi.fn(() => '/tmp/test-home'),
  },
}));

// Mock chalk and ora
vi.mock('chalk', () => ({
  default: {
    green: vi.fn((s) => s),
    red: vi.fn((s) => s),
    blue: vi.fn((s) => s),
    yellow: vi.fn((s) => s),
  },
}));

vi.mock('ora', () => ({
  default: vi.fn(() => ({
    start: vi.fn().mockReturnThis(),
    succeed: vi.fn().mockReturnThis(),
    warn: vi.fn().mockReturnThis(),
    fail: vi.fn().mockReturnThis(),
  })),
}));

describe('CLI Commands', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.FIDES_API_KEY;
    // Suppress console output in tests
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    if (ORIGINAL_FIDES_API_KEY) {
      process.env.FIDES_API_KEY = ORIGINAL_FIDES_API_KEY;
    } else {
      delete process.env.FIDES_API_KEY;
    }
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  describe('init command', () => {
    it('should create identity and save config', async () => {
      const mockKeyPair = {
        publicKey: new Uint8Array(32),
        privateKey: new Uint8Array(64),
      };
      const mockDid = 'did:fides:test123';

      vi.mocked(sdk.generateKeyPair).mockResolvedValue(mockKeyPair);
      vi.mocked(sdk.generateDID).mockReturnValue(mockDid);

      const mockKeyStore = {
        save: vi.fn().mockResolvedValue(undefined),
        load: vi.fn(),
      };
      vi.mocked(sdk.FileKeyStore).mockImplementation(() => mockKeyStore as any);

      const mockDiscoveryClient = {
        register: vi.fn().mockResolvedValue({ did: mockDid }),
        resolve: vi.fn(),
      };
      vi.mocked(sdk.DiscoveryClient).mockImplementation(() => mockDiscoveryClient as any);

      const { createInitCommand } = await import('../src/commands/init.js');
      const cmd = createInitCommand();

      await cmd.parseAsync(['--name', 'test-agent'], { from: 'user' });

      expect(sdk.generateKeyPair).toHaveBeenCalled();
      expect(sdk.generateDID).toHaveBeenCalledWith(mockKeyPair.publicKey);
      expect(mockKeyStore.save).toHaveBeenCalledWith(mockDid, mockKeyPair);
    });
  });

  describe('sign command', () => {
    it('should produce signed request output', async () => {
      const mockKeyPair = {
        publicKey: new Uint8Array(32),
        privateKey: new Uint8Array(64),
      };
      const mockDid = 'did:fides:test123';

      const mockKeyStore = {
        load: vi.fn().mockResolvedValue(mockKeyPair),
        store: vi.fn(),
      };
      vi.mocked(sdk.FileKeyStore).mockImplementation(() => mockKeyStore as any);

      const mockSignedRequest = {
        method: 'GET',
        url: 'https://api.example.com',
        headers: {
          'Signature': 'sig1=:abc123:',
          'Signature-Input': 'sig1=("@method" "@target-uri");keyid="did:fides:test123"',
        },
      };
      vi.mocked(sdk.signRequest).mockResolvedValue(mockSignedRequest);

      // Mock fs to return config with activeDid
      const fs = await import('node:fs');
      vi.mocked(fs.default.existsSync).mockReturnValue(true);
      vi.mocked(fs.default.readFileSync).mockReturnValue(
        JSON.stringify({ activeDid: mockDid })
      );

      const { createSignCommand } = await import('../src/commands/sign.js');
      const cmd = createSignCommand();

      await cmd.parseAsync(['https://api.example.com'], { from: 'user' });

      expect(mockKeyStore.load).toHaveBeenCalledWith(mockDid);
      expect(sdk.signRequest).toHaveBeenCalled();
    });
  });

  describe('verify command', () => {
    it('should validate signatures', async () => {
      const mockIdentity = {
        did: 'did:fides:test123',
        publicKey: Buffer.from(new Uint8Array(32)).toString('hex'),
        algorithm: 'ed25519',
        createdAt: new Date().toISOString(),
      };

      const mockDiscoveryClient = {
        resolve: vi.fn().mockResolvedValue(mockIdentity),
        register: vi.fn(),
      };
      vi.mocked(sdk.DiscoveryClient).mockImplementation(() => mockDiscoveryClient as any);

      vi.mocked(sdk.verifyRequest).mockResolvedValue({
        valid: true,
        keyId: 'did:fides:test123',
      });

      const { createVerifyCommand } = await import('../src/commands/verify.js');
      const cmd = createVerifyCommand();

      await cmd.parseAsync([
        'https://api.example.com',
        '--signature',
        'sig1=:abc:',
        '--signature-input',
        'sig1=("@method");keyid="did:fides:test123"',
      ], { from: 'user' });

      expect(mockDiscoveryClient.resolve).toHaveBeenCalledWith('did:fides:test123');
      expect(sdk.verifyRequest).toHaveBeenCalled();
    });
  });

  describe('trust command', () => {
    it('should create attestation', async () => {
      const mockDid = 'did:fides:issuer';
      const mockSubjectDid = 'did:fides:subject';
      const mockKeyPair = {
        publicKey: new Uint8Array(32),
        privateKey: new Uint8Array(64),
      };

      const mockKeyStore = {
        load: vi.fn().mockResolvedValue(mockKeyPair),
        store: vi.fn(),
      };
      vi.mocked(sdk.FileKeyStore).mockImplementation(() => mockKeyStore as any);

      const mockAttestation = {
        id: 'att-123',
        issuerDid: mockDid,
        subjectDid: mockSubjectDid,
        trustLevel: 50,
        issuedAt: new Date().toISOString(),
        signature: 'sig123',
        payload: 'payload',
      };
      vi.mocked(sdk.createAttestation).mockResolvedValue(mockAttestation);

      const mockTrustClient = {
        attest: vi.fn().mockResolvedValue({ id: 'att-123' }),
        getScore: vi.fn(),
        getPath: vi.fn(),
      };
      vi.mocked(sdk.TrustClient).mockImplementation(() => mockTrustClient as any);

      // Mock fs to return config with activeDid
      const fs = await import('node:fs');
      vi.mocked(fs.default.existsSync).mockReturnValue(true);
      vi.mocked(fs.default.readFileSync).mockReturnValue(
        JSON.stringify({ activeDid: mockDid })
      );

      const { createTrustCommand } = await import('../src/commands/trust.js');
      const cmd = createTrustCommand();

      await cmd.parseAsync([mockSubjectDid, '--level', 'medium'], {
        from: 'user',
      });

      expect(sdk.createAttestation).toHaveBeenCalledWith(
        mockDid,
        mockSubjectDid,
        50,
        mockKeyPair.privateKey
      );
      expect(mockTrustClient.attest).toHaveBeenCalled();
    });
  });

  describe('discover command', () => {
    it('should resolve identity', async () => {
      const mockIdentity = {
        did: 'did:fides:test123',
        publicKey: Buffer.from(new Uint8Array(32)).toString('hex'),
        algorithm: 'ed25519',
        createdAt: new Date().toISOString(),
        metadata: { name: 'Test Agent' },
      };

      const mockDiscoveryClient = {
        resolve: vi.fn().mockResolvedValue(mockIdentity),
        register: vi.fn(),
      };
      vi.mocked(sdk.DiscoveryClient).mockImplementation(() => mockDiscoveryClient as any);

      const mockTrustClient = {
        getScore: vi.fn().mockResolvedValue({
          did: mockIdentity.did,
          score: 0.8,
          directTrusters: 5,
          transitiveTrusters: 20,
          lastComputed: new Date().toISOString(),
        }),
        attest: vi.fn(),
        getPath: vi.fn(),
      };
      vi.mocked(sdk.TrustClient).mockImplementation(() => mockTrustClient as any);

      const { createDiscoverCommand } = await import('../src/commands/discover.js');
      const cmd = createDiscoverCommand();

      await cmd.parseAsync(['did:fides:test123'], { from: 'user' });

      expect(mockDiscoveryClient.resolve).toHaveBeenCalledWith('did:fides:test123');
      expect(mockTrustClient.getScore).toHaveBeenCalledWith(mockIdentity.did);
    });
  });

  describe('status command', () => {
    it('should show current state', async () => {
      const mockDid = 'did:fides:test123';
      const mockKeyPair = {
        publicKey: new Uint8Array(32),
        privateKey: new Uint8Array(64),
      };

      const mockKeyStore = {
        load: vi.fn().mockResolvedValue(mockKeyPair),
        store: vi.fn(),
      };
      vi.mocked(sdk.FileKeyStore).mockImplementation(() => mockKeyStore as any);

      const mockTrustClient = {
        getScore: vi.fn().mockResolvedValue({
          did: mockDid,
          score: 0.75,
          directTrusters: 3,
          transitiveTrusters: 10,
          lastComputed: new Date().toISOString(),
        }),
        attest: vi.fn(),
        getPath: vi.fn(),
      };
      vi.mocked(sdk.TrustClient).mockImplementation(() => mockTrustClient as any);

      // Mock fs to return config with activeDid
      const fs = await import('node:fs');
      vi.mocked(fs.default.existsSync).mockReturnValue(true);
      vi.mocked(fs.default.readFileSync).mockReturnValue(
        JSON.stringify({ activeDid: mockDid })
      );

      const { createStatusCommand } = await import('../src/commands/status.js');
      const cmd = createStatusCommand();

      await cmd.parseAsync([], { from: 'user' });

      expect(mockKeyStore.load).toHaveBeenCalledWith(mockDid);
      expect(mockTrustClient.getScore).toHaveBeenCalledWith(mockDid);
    });
  });

  describe('authority commands', () => {
    it('delegate create should emit a DelegationToken', async () => {
      const { createDelegateCommand } = await import('../src/commands/delegate.js');
      const cmd = createDelegateCommand();

      await cmd.parseAsync([
        'create',
        '--delegator',
        'did:fides:principal',
        '--delegatee',
        'did:fides:agent',
        '--capabilities',
        'payments.execute,tools.call',
        '--max-actions',
        '3',
        '--json',
      ], { from: 'user' });

      const output = JSON.parse(vi.mocked(console.log).mock.calls[0][0] as string);
      expect(output.delegator).toBe('did:fides:principal');
      expect(output.delegatee).toBe('did:fides:agent');
      expect(output.capabilities).toEqual(['payments.execute', 'tools.call']);
      expect(output.constraints.maxActions).toBe(3);
    });

    it('session create should call agentd with a DelegationToken', async () => {
      process.env.FIDES_API_KEY = 'cli-api-key'
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        session: { id: 'sess-1', sessionKey: 'redacted' },
      }), { status: 201, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const token = {
        id: 'tok-1',
        delegator: 'did:fides:principal',
        delegatee: 'did:fides:agent',
        capabilities: ['payments.execute'],
        constraints: {},
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        nonce: 'nonce-1',
        audience: ['agentd'],
        signature: 'sig',
      };

      const { createSessionCommand } = await import('../src/commands/session.js');
      const cmd = createSessionCommand();

      await cmd.parseAsync([
        'create',
        '--agentd-url',
        'http://agentd.test',
        '--capability',
        'payments.execute',
        '--token-json',
        JSON.stringify(token),
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://agentd.test/v1/sessions',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'X-API-Key': 'cli-api-key',
          }),
        })
      );
    });

    it('session create should send a delegator public key when provided', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        session: { id: 'sess-1', sessionKey: 'redacted' },
      }), { status: 201, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const token = {
        id: 'tok-1',
        delegator: 'did:fides:principal',
        delegatee: 'did:fides:agent',
        capabilities: ['payments.execute'],
        constraints: {},
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        nonce: 'nonce-1',
        audience: ['agentd'],
        signature: 'sig',
      };
      const delegatorPublicKey = '11'.repeat(32);

      const { createSessionCommand } = await import('../src/commands/session.js');
      const cmd = createSessionCommand();

      await cmd.parseAsync([
        'create',
        '--agentd-url',
        'http://agentd.test',
        '--capability',
        'payments.execute',
        '--token-json',
        JSON.stringify(token),
        '--delegator-public-key',
        delegatorPublicKey,
        '--json',
      ], { from: 'user' });

      const [, init] = mockFetch.mock.calls[0];
      expect(JSON.parse(init.body as string)).toMatchObject({
        token,
        capabilityId: 'payments.execute',
        audience: 'agentd',
        delegatorPublicKey,
      });
    });

    it('revoke agent should call agentd revocations', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({ recorded: true }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createRevokeCommand } = await import('../src/commands/revoke.js');
      const cmd = createRevokeCommand();

      await cmd.parseAsync([
        'agent',
        'did:fides:agent',
        '--agentd-url',
        'http://agentd.test',
        '--revoked-by',
        'did:fides:principal',
        '--reason',
        'disabled',
        '--private-key-hex',
        '01'.repeat(32),
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://agentd.test/v1/revocations',
        expect.objectContaining({ method: 'POST' })
      );
      const [, init] = mockFetch.mock.calls[0];
      const body = JSON.parse(init.body as string);
      expect(body.record.did).toBe('did:fides:agent');
      expect(body.revokerPublicKey).toMatch(/^[0-9a-f]{64}$/);
    });

    it('incident report should call agentd incidents', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({ recorded: true }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createIncidentCommand } = await import('../src/commands/incident.js');
      const cmd = createIncidentCommand();

      await cmd.parseAsync([
        'report',
        '--agentd-url',
        'http://agentd.test',
        '--actor',
        'did:fides:agent',
        '--type',
        'policy_violation',
        '--severity',
        'high',
        '--description',
        'merchant policy bypass',
        '--reporter',
        'did:fides:principal',
        '--private-key-hex',
        '01'.repeat(32),
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://agentd.test/v1/incidents',
        expect.objectContaining({ method: 'POST' })
      );
      const [, init] = mockFetch.mock.calls[0];
      const body = JSON.parse(init.body as string);
      expect(body.record.actor).toBe('did:fides:agent');
      expect(body.reporterPublicKey).toMatch(/^[0-9a-f]{64}$/);
    });

    it('propagation pending should list due authority outbox records', async () => {
      process.env.FIDES_API_KEY = 'cli-api-key';
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        count: 1,
        propagations: [{ id: 'prop-1', status: 'pending' }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createPropagationCommand } = await import('../src/commands/propagation.js');
      const cmd = createPropagationCommand();

      await cmd.parseAsync([
        'pending',
        '--agentd-url',
        'http://agentd.test',
        '--limit',
        '5',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://agentd.test/v1/authority/propagations/pending?limit=5',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'X-API-Key': 'cli-api-key',
          }),
        })
      );
    });

    it('propagation retry should retry due authority outbox records', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        attempted: 1,
        results: [{ id: 'prop-1', ok: true, outboxStatus: 'confirmed' }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createPropagationCommand } = await import('../src/commands/propagation.js');
      const cmd = createPropagationCommand();

      await cmd.parseAsync([
        'retry',
        '--agentd-url',
        'http://agentd.test',
        '--limit',
        '3',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://agentd.test/v1/authority/propagations/retry',
        expect.objectContaining({ method: 'POST' })
      );
      const [, init] = mockFetch.mock.calls[0];
      expect(JSON.parse(init.body as string)).toEqual({ limit: 3 });
    });

    it('authorize check should call agentd authorization endpoint', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        decision: 'allow',
        explanation: 'allowed',
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createAuthorizeCommand } = await import('../src/commands/authorize.js');
      const cmd = createAuthorizeCommand();

      await cmd.parseAsync([
        'check',
        '--agentd-url',
        'http://agentd.test',
        '--agent-did',
        'did:fides:agent',
        '--capability',
        'payments.execute',
        '--session-id',
        'sess-1',
        '--audience',
        'agentd',
        '--context-json',
        '{"amount":"12.00"}',
        '--requires-approval',
        '--approval-granted',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://agentd.test/v1/authorize',
        expect.objectContaining({ method: 'POST' })
      );
      const [, init] = mockFetch.mock.calls[0];
      expect(JSON.parse(init.body as string)).toMatchObject({
        agentDid: 'did:fides:agent',
        capabilityId: 'payments.execute',
        sessionId: 'sess-1',
        audience: 'agentd',
        context: { amount: '12.00' },
        requiresApproval: true,
        approvalGranted: true,
      });
    });
  });
});
