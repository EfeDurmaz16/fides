import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Command } from 'commander';
import * as sdk from '@fides/sdk';

const ORIGINAL_FIDES_API_KEY = process.env.FIDES_API_KEY;
const ORIGINAL_SERVICE_API_KEY = process.env.SERVICE_API_KEY;

// Mock the SDK
vi.mock('@fides/sdk', () => ({
  generateKeyPair: vi.fn(),
  generateDID: vi.fn(),
  signRequest: vi.fn(),
  verifyRequest: vi.fn(),
  createAttestation: vi.fn(),
  FileKeyStore: vi.fn(),
  DiscoveryClient: vi.fn(),
  AgentdClient: vi.fn(),
  RegistryClient: vi.fn(),
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
  existsSync: vi.fn(() => false),
  readFileSync: vi.fn(),
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  openSync: vi.fn(() => 1),
  rmSync: vi.fn(),
  default: {
    existsSync: vi.fn(() => false),
    readFileSync: vi.fn(),
    writeFileSync: vi.fn(),
    mkdirSync: vi.fn(),
    openSync: vi.fn(() => 1),
    rmSync: vi.fn(),
  },
}));

vi.mock('node:child_process', () => ({
  spawn: vi.fn(() => ({
    pid: 12345,
    unref: vi.fn(),
  })),
}));

vi.mock('node:dns/promises', () => ({
  resolveTxt: vi.fn(),
}));

vi.mock('node:os', () => ({
  homedir: vi.fn(() => '/tmp/test-home'),
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
    delete process.env.SERVICE_API_KEY;
    process.exitCode = undefined;
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
    if (ORIGINAL_SERVICE_API_KEY) {
      process.env.SERVICE_API_KEY = ORIGINAL_SERVICE_API_KEY;
    } else {
      delete process.env.SERVICE_API_KEY;
    }
    process.exitCode = undefined;
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  describe('binary name inference', () => {
    it('uses agentd when invoked through the agentd workspace script or binary', async () => {
      const { inferCliName } = await import('../src/cli-name.js');

      expect(inferCliName(['/usr/local/bin/node', '/repo/packages/cli/dist/index.js'], 'agentd')).toBe('agentd');
      expect(inferCliName(['/usr/local/bin/node', '/usr/local/bin/agentd'])).toBe('agentd');
    });

    it('defaults to fides for the fides binary and direct node execution', async () => {
      const { inferCliName } = await import('../src/cli-name.js');

      expect(inferCliName(['/usr/local/bin/node', '/usr/local/bin/fides'])).toBe('fides');
      expect(inferCliName(['/usr/local/bin/node', '/repo/packages/cli/dist/index.js'])).toBe('fides');
    });
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
      process.env.FIDES_API_KEY = 'cli-discovery-key';
      vi.mocked(sdk.DiscoveryClient).mockImplementation(() => mockDiscoveryClient as any);

      const { createInitCommand } = await import('../src/commands/init.js');
      const cmd = createInitCommand();

      await cmd.parseAsync(['--name', 'test-agent'], { from: 'user' });

      expect(sdk.generateKeyPair).toHaveBeenCalled();
      expect(sdk.generateDID).toHaveBeenCalledWith(mockKeyPair.publicKey);
      expect(sdk.DiscoveryClient).toHaveBeenCalledWith(expect.objectContaining({
        apiKey: 'cli-discovery-key',
      }));
      expect(mockKeyStore.save).toHaveBeenCalledWith(mockDid, mockKeyPair);
    });
  });

  describe('v2 command surface', () => {
    it('exposes registry, agents, dht, evidence, attest, demo, simulate, and invoke commands', async () => {
      const { createRegistryCommand } = await import('../src/commands/registry.js');
      const { createAgentsCommand, createRegisterCommand } = await import('../src/commands/agents.js');
      const { createDhtCommand } = await import('../src/commands/dht.js');
      const { createEvidenceCommand } = await import('../src/commands/evidence.js');
      const { createAttestCommand } = await import('../src/commands/attest.js');
      const { createDemoCommand } = await import('../src/commands/demo.js');
      const { createSimulateCommand } = await import('../src/commands/simulate.js');
      const { createInvokeCommand } = await import('../src/commands/invoke.js');

      expect(createRegistryCommand().name()).toBe('registry');
      expect(createRegisterCommand().name()).toBe('register');
      expect(createAgentsCommand().name()).toBe('agents');
      expect(createDhtCommand().name()).toBe('dht');
      expect(createEvidenceCommand().name()).toBe('evidence');
      expect(createAttestCommand().name()).toBe('attest');
      expect(createDemoCommand().name()).toBe('demo');
      expect(createSimulateCommand().name()).toBe('simulate');
      expect(createInvokeCommand().name()).toBe('invoke');
    });
  });

  describe('invoke command', () => {
    it('creates a session from agent and capability before invoking', async () => {
      const calls: Array<{ url: string; init?: RequestInit }> = [];
      vi.stubGlobal('fetch', vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        calls.push({ url: String(url), init });
        if (String(url).endsWith('/sessions')) {
          return new Response(JSON.stringify({
            authorityGranted: true,
            session: { session_id: 'sess_cli' },
          }), { status: 201, headers: { 'Content-Type': 'application/json' } });
        }
        return new Response(JSON.stringify({
          authorityGranted: true,
          result: { status: 'completed' },
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }));

      const { createInvokeCommand } = await import('../src/commands/invoke.js');
      const cmd = createInvokeCommand();

      await cmd.parseAsync([
        'did:fides:agent',
        '--capability',
        'invoice.reconcile',
        '--input-json',
        '{"invoiceId":"inv_123"}',
        '--requested-scopes',
        'read:invoices,write:evidence',
        '--principal-id',
        'did:fides:principal',
        '--requester-agent-id',
        'did:fides:requester',
        '--json',
      ], { from: 'user' });

      expect(calls.map(call => call.url)).toEqual([
        'http://localhost:7345/sessions',
        'http://localhost:7345/invoke',
      ]);
      expect(JSON.parse(calls[0].init?.body as string)).toEqual({
        agentId: 'did:fides:agent',
        capability: 'invoice.reconcile',
        requestedScopes: ['read:invoices', 'write:evidence'],
        principalId: 'did:fides:principal',
        requesterAgentId: 'did:fides:requester',
      });
      expect(JSON.parse(calls[1].init?.body as string)).toEqual({
        sessionId: 'sess_cli',
        input: { invoiceId: 'inv_123' },
      });
    });
  });

  describe('card registry commands', () => {
    it('publishes a validated AgentCard to the registry', async () => {
      const fs = await import('node:fs');
      const card = {
        id: 'did:fides:agent',
        identity: {
          did: 'did:fides:agent',
          publicKey: Array(32).fill(0),
          keyType: 'Ed25519',
          createdAt: '2026-01-01T00:00:00.000Z',
        },
        capabilities: [],
        endpoints: [],
        policies: [{ requiresRuntimeAttestation: false, requiresApproval: false }],
        createdAt: '2026-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
      };
      vi.mocked(fs.default.readFileSync).mockReturnValue(JSON.stringify(card));
      vi.mocked(fs.readFileSync).mockReturnValue(JSON.stringify(card));

      const mockRegistryClient = {
        register: vi.fn().mockResolvedValue({
          success: true,
          did: 'did:fides:agent',
          registeredAt: '2026-01-01T00:00:00.000Z',
        }),
        getCard: vi.fn(),
        search: vi.fn(),
        setMode: vi.fn(),
        updateMetadata: vi.fn(),
      };
      vi.mocked(sdk.RegistryClient).mockImplementation(() => mockRegistryClient as any);

      const { createCardCommand } = await import('../src/commands/card.js');
      const cmd = createCardCommand();

      await cmd.parseAsync(['publish', 'agent-card.json', '--registry-url', 'http://registry.test', '--api-key', 'test-key'], { from: 'user' });

      expect(sdk.RegistryClient).toHaveBeenCalledWith({
        baseUrl: 'http://registry.test',
        apiKey: 'test-key',
      });
      expect(mockRegistryClient.register).toHaveBeenCalledWith(card);
    }, 10000);

    it('searches registry cards', async () => {
      const mockRegistryClient = {
        register: vi.fn(),
        getCard: vi.fn(),
        search: vi.fn().mockResolvedValue({
          results: [{ did: 'did:fides:agent', name: 'Agent', capabilities: ['payments.execute'] }],
          count: 1,
          query: 'Agent',
        }),
        setMode: vi.fn(),
        updateMetadata: vi.fn(),
      };
      vi.mocked(sdk.RegistryClient).mockImplementation(() => mockRegistryClient as any);

      const { createCardCommand } = await import('../src/commands/card.js');
      const cmd = createCardCommand();

      await cmd.parseAsync(['search', 'Agent'], { from: 'user' });

      expect(mockRegistryClient.search).toHaveBeenCalledWith('Agent');
    });

    it('reads cards through the agentd registry proxy', async () => {
      const mockAgentdClient = {
        getCard: vi.fn().mockResolvedValue({
          did: 'did:fides:agent',
          card: {
            id: 'did:fides:agent',
            name: 'Agent',
          },
        }),
      };
      vi.mocked(sdk.AgentdClient).mockImplementation(() => mockAgentdClient as any);

      const { createCardCommand } = await import('../src/commands/card.js');
      const cmd = createCardCommand();

      await cmd.parseAsync(['proxy', 'did:fides:agent', '--agentd-url', 'http://agentd.test', '--api-key', 'agentd-key'], { from: 'user' });

      expect(sdk.AgentdClient).toHaveBeenCalledWith({
        baseUrl: 'http://agentd.test',
        apiKey: 'agentd-key',
      });
      expect(mockAgentdClient.getCard).toHaveBeenCalledWith('did:fides:agent');
      expect(console.log).toHaveBeenCalledWith(JSON.stringify({
        id: 'did:fides:agent',
        name: 'Agent',
      }, null, 2));
    });

    it('uses the root AgentCard API for local create, sign, inspect, and verify', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        card: { id: 'did:fides:agent' },
        signed: { payload: { id: 'did:fides:agent' } },
        valid: true,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createCardCommand } = await import('../src/commands/card.js');
      const cmd = createCardCommand();

      await cmd.parseAsync([
        'create',
        '--did',
        'did:fides:agent',
        '--name',
        'Invoice Agent',
        '--capabilities',
        '[{"id":"invoice.reconcile"}]',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });
      await cmd.parseAsync(['sign', 'did:fides:agent', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });
      await cmd.parseAsync(['inspect', 'did:fides:agent', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });
      await cmd.parseAsync(['verify', 'did:fides:agent', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });

      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        'http://agentd.test/agent-cards',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            agentId: 'did:fides:agent',
            name: 'Invoice Agent',
            capabilities: [{ id: 'invoice.reconcile' }],
          }),
        })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        'http://agentd.test/agent-cards/did%3Afides%3Aagent/sign',
        expect.objectContaining({ method: 'POST' })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        3,
        'http://agentd.test/agent-cards/did%3Afides%3Aagent',
        expect.objectContaining({ method: 'GET' })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        4,
        'http://agentd.test/agent-cards/did%3Afides%3Aagent/verify',
        expect.objectContaining({ method: 'POST' })
      );
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

    it('discovers capabilities through a selected local agentd provider', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        provider: 'registry',
        authorityGranted: false,
        records: [{ agentId: 'did:fides:agent' }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createDiscoverCommand } = await import('../src/commands/discover.js');
      const cmd = createDiscoverCommand();

      await cmd.parseAsync([
        'reconcile invoices',
        '--capability',
        'invoice.reconcile',
        '--provider',
        'registry',
        '--constraints',
        '{"tenant":"acme"}',
        '--supported-versions',
        'fides.v2.0,fides.v2.1',
        '--required-versions',
        'fides.v2.0',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://agentd.test/discover/registry',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            intent: 'reconcile invoices',
            capability: 'invoice.reconcile',
            constraints: { tenant: 'acme' },
            supported_versions: ['fides.v2.0', 'fides.v2.1'],
            required_versions: ['fides.v2.0'],
          }),
        })
      );
    });

    it('discovers capabilities through every local agentd provider', async () => {
      const mockFetch = vi.fn(async (url: string | URL | Request) => new Response(JSON.stringify({
        provider: String(url).split('/').at(-1),
        authorityGranted: false,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createDiscoverCommand } = await import('../src/commands/discover.js');
      const cmd = createDiscoverCommand();

      await cmd.parseAsync([
        '--capability',
        'calendar.schedule',
        '--all-providers',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        'http://agentd.test/discover/local',
        expect.objectContaining({ method: 'POST' })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        'http://agentd.test/discover/well-known',
        expect.objectContaining({ method: 'POST' })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        3,
        'http://agentd.test/discover/registry',
        expect.objectContaining({ method: 'POST' })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        4,
        'http://agentd.test/discover/relay',
        expect.objectContaining({ method: 'POST' })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        5,
        'http://agentd.test/discover/dht',
        expect.objectContaining({ method: 'POST' })
      );
    });
  });

  describe('identity domain commands', () => {
    it('prints a domain verification challenge as JSON', async () => {
      const { createIdentityCommand } = await import('../src/commands/identity.js');
      const cmd = createIdentityCommand();

      await cmd.parseAsync(['domain', 'challenge', 'Example.COM.', 'did:fides:agent123', '--json'], { from: 'user' });

      expect(JSON.parse(vi.mocked(console.log).mock.calls[0][0] as string)).toEqual({
        domain: 'example.com',
        did: 'did:fides:agent123',
        recordName: '_fides.example.com',
        recordValue: 'fides-did=did:fides:agent123',
      });
    });

    it('verifies a domain DID binding through DNS TXT records', async () => {
      const dns = await import('node:dns/promises');
      vi.mocked(dns.resolveTxt).mockResolvedValue([['fides-did=', 'did:fides:agent123']]);

      const { createIdentityCommand } = await import('../src/commands/identity.js');
      const cmd = createIdentityCommand();

      await cmd.parseAsync(['domain', 'verify', 'example.com', 'did:fides:agent123', '--json'], { from: 'user' });

      expect(dns.resolveTxt).toHaveBeenCalledWith('_fides.example.com');
      expect(JSON.parse(vi.mocked(console.log).mock.calls[0][0] as string)).toEqual({
        domain: 'example.com',
        did: 'did:fides:agent123',
        recordName: '_fides.example.com',
        verified: true,
      });
      expect(process.exitCode).toBeUndefined();
    });

    it('returns non-zero exit code when domain verification fails', async () => {
      const dns = await import('node:dns/promises');
      vi.mocked(dns.resolveTxt).mockResolvedValue(['other=value']);

      const { createIdentityCommand } = await import('../src/commands/identity.js');
      const cmd = createIdentityCommand();

      await cmd.parseAsync(['domain', 'verify', 'example.com', 'did:fides:agent123', '--json'], { from: 'user' });

      expect(JSON.parse(vi.mocked(console.log).mock.calls[0][0] as string)).toEqual({
        domain: 'example.com',
        did: 'did:fides:agent123',
        recordName: '_fides.example.com',
        verified: false,
        reason: 'record-not-found',
      });
      expect(process.exitCode).toBe(1);
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

  describe('daemon command', () => {
    it('should start agentd as a background process', async () => {
      const fs = await import('node:fs');
      const childProcess = await import('node:child_process');
      vi.mocked(fs.default.existsSync).mockReturnValue(false);

      const { createDaemonCommand } = await import('../src/commands/daemon.js');
      const cmd = createDaemonCommand();

      await cmd.parseAsync([
        'start',
        '--port',
        '7444',
        '--pid-file',
        '/tmp/fides-agentd.pid',
        '--log-file',
        '/tmp/fides-agentd.log',
      ], { from: 'user' });

      expect(childProcess.spawn).toHaveBeenCalledWith('pnpm', ['--filter', '@fides/agentd', 'dev'], expect.objectContaining({
        detached: true,
        stdio: ['ignore', 1, 1],
        env: expect.objectContaining({ AGENTD_PORT: '7444' }),
      }));
      expect(fs.default.writeFileSync).toHaveBeenCalledWith('/tmp/fides-agentd.pid', '12345', 'utf-8');
    });

    it('should stop agentd from the pid file', async () => {
      const fs = await import('node:fs');
      vi.mocked(fs.default.existsSync).mockReturnValue(true);
      vi.mocked(fs.default.readFileSync).mockReturnValue('12345');
      const killSpy = vi.spyOn(process, 'kill').mockReturnValue(true);

      const { createDaemonCommand } = await import('../src/commands/daemon.js');
      const cmd = createDaemonCommand();

      await cmd.parseAsync(['stop', '--pid-file', '/tmp/fides-agentd.pid'], { from: 'user' });

      expect(killSpy).toHaveBeenCalledWith(12345, 0);
      expect(killSpy).toHaveBeenCalledWith(12345, 'SIGTERM');
      expect(fs.default.rmSync).toHaveBeenCalledWith('/tmp/fides-agentd.pid', { force: true });
    });

    it('should check agentd health status', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        status: 'healthy',
        service: 'agentd',
        uptime: 12,
        checks: {
          discovery: 'connected',
          trustGraph: 'connected',
          registry: 'connected',
          authorityStore: 'ready',
          localStateStore: 'ready',
        },
        authorityStore: {
          kind: 'file',
          ok: true,
        },
        localStateStore: {
          kind: 'sqlite',
          ok: true,
          path: '/tmp/fides.sqlite',
        },
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createDaemonCommand } = await import('../src/commands/daemon.js');
      const cmd = createDaemonCommand();

      await cmd.parseAsync(['status', '--agentd-url', 'http://localhost:7345'], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith('http://localhost:7345/health');
      const output = vi.mocked(console.log).mock.calls.map(call => String(call[0])).join('\n');
      expect(output).toContain('Local State Store:');
      expect(output).toContain('sqlite (ready)');
      expect(process.exitCode).toBeUndefined();
    });

    it('should emit json and non-zero exit code for degraded agentd health', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        status: 'degraded',
        service: 'agentd',
        checks: {
          discovery: 'unreachable',
          trustGraph: 'connected',
          registry: 'connected',
          authorityStore: 'ready',
          localStateStore: 'ready',
        },
        authorityStore: {
          kind: 'postgres',
          ok: true,
        },
        localStateStore: {
          kind: 'sqlite',
          ok: true,
          path: '/tmp/fides.sqlite',
        },
      }), { status: 503, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createDaemonCommand } = await import('../src/commands/daemon.js');
      const cmd = createDaemonCommand();

      await cmd.parseAsync(['status', '--agentd-url', 'http://localhost:7345/', '--json'], { from: 'user' });

      const output = JSON.parse(vi.mocked(console.log).mock.calls[0][0] as string);
      expect(output.status).toBe('degraded');
      expect(output.localStateStore).toMatchObject({ kind: 'sqlite', ok: true });
      expect(process.exitCode).toBe(1);
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

    it('root revoke commands should record and inspect v2 revocations', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        record: { id: 'rev_1' },
        records: [{ id: 'rev_1' }],
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createRevokeCommand } = await import('../src/commands/revoke.js');
      const cmd = createRevokeCommand();

      await cmd.parseAsync([
        'agent',
        'did:fides:agent',
        '--agentd-url',
        'http://agentd.test/',
        '--issuer',
        'did:fides:operator',
        '--reason',
        'disabled',
        '--json',
      ], { from: 'user' });
      await cmd.parseAsync([
        'session',
        'sess_1',
        '--agentd-url',
        'http://agentd.test/',
        '--reason',
        'replay risk',
        '--json',
      ], { from: 'user' });
      await cmd.parseAsync(['list', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });
      await cmd.parseAsync(['inspect', 'rev_1', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });

      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        'http://agentd.test/revocations',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            targetType: 'agent',
            targetId: 'did:fides:agent',
            reason: 'disabled',
            issuer: 'did:fides:operator',
          }),
        })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        'http://agentd.test/revocations',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            targetType: 'session',
            targetId: 'sess_1',
            reason: 'replay risk',
          }),
        })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(3, 'http://agentd.test/revocations', expect.objectContaining({ method: 'GET' }));
      expect(mockFetch).toHaveBeenNthCalledWith(4, 'http://agentd.test/revocations/rev_1', expect.objectContaining({ method: 'GET' }));
    });

    it('attest runtime should issue a root v2 runtime attestation', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        attestation: { attestation_id: 'att_1' },
        evidenceRefs: ['evt_1'],
        authorityGranted: false,
      }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' },
      })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createAttestCommand } = await import('../src/commands/attest.js');
      const cmd = createAttestCommand();

      await cmd.parseAsync([
        'runtime',
        '--agent',
        'did:fides:agent',
        '--code-hash',
        'sha256:code',
        '--runtime-hash',
        'sha256:runtime',
        '--policy-hash',
        'sha256:policy',
        '--enclave-measurement',
        'sha256:measurement',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://agentd.test/attestations',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            agentId: 'did:fides:agent',
            codeHash: 'sha256:code',
            runtimeHash: 'sha256:runtime',
            policyHash: 'sha256:policy',
            enclaveMeasurement: 'sha256:measurement',
          }),
        })
      );
    });

    it('attest show and verify should inspect root v2 runtime attestations', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        attestation: { attestation_id: 'att_1' },
        valid: true,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createAttestCommand } = await import('../src/commands/attest.js');
      const cmd = createAttestCommand();

      await cmd.parseAsync(['show', 'att_1', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });
      await cmd.parseAsync(['verify', 'att_1', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });

      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        'http://agentd.test/attestations/att_1',
        expect.objectContaining({ method: 'GET' })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        'http://agentd.test/attestations/att_1/verify',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({}),
        })
      );
    });

    it('register and agents commands should manage local discovery candidates', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        registered: true,
        agentId: 'did:fides:agent',
        agents: [{ agentId: 'did:fides:agent' }],
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createRegisterCommand, createAgentsCommand } = await import('../src/commands/agents.js');
      const register = createRegisterCommand();
      const agents = createAgentsCommand();

      await register.parseAsync(['card_1', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });
      await agents.parseAsync(['list', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });
      await agents.parseAsync(['inspect', 'did:fides:agent', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });

      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        'http://agentd.test/agents/register',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ agentCardId: 'card_1' }),
        })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(2, 'http://agentd.test/agents', expect.objectContaining({ method: 'GET' }));
      expect(mockFetch).toHaveBeenNthCalledWith(
        3,
        'http://agentd.test/agents/did%3Afides%3Aagent',
        expect.objectContaining({ method: 'GET' })
      );
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

    it('relay send should submit messages with API key auth', async () => {
      process.env.FIDES_API_KEY = 'relay-key';
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        accepted: true,
        relayId: 'relay-1',
      }), { status: 201, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createRelayCommand } = await import('../src/commands/relay.js');
      const cmd = createRelayCommand();

      await cmd.parseAsync([
        'send',
        '--relay-url',
        'http://relay.test/',
        '--to',
        'did:fides:receiver',
        '--from',
        'did:fides:sender',
        '--payload-json',
        '{"hello":"world"}',
        '--ttl-ms',
        '60000',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://relay.test/v1/relay',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'X-API-Key': 'relay-key',
          }),
        })
      );
      const [, init] = mockFetch.mock.calls[0];
      expect(JSON.parse(init.body as string)).toEqual({
        to: 'did:fides:receiver',
        from: 'did:fides:sender',
        payload: { hello: 'world' },
        ttlMs: 60000,
      });
    });

    it('relay poll should read queued messages for a DID', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        count: 1,
        messages: [{ id: 'relay-1', payload: { hello: 'world' } }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createRelayCommand } = await import('../src/commands/relay.js');
      const cmd = createRelayCommand();

      await cmd.parseAsync([
        'poll',
        'did:fides:receiver',
        '--relay-url',
        'http://relay.test',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://relay.test/v1/relay/did%3Afides%3Areceiver/messages',
        expect.objectContaining({ method: 'GET' })
      );
    });

    it('relay register and discover should use local agentd aliases', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        authorityGranted: false,
        records: [{ agentId: 'did:fides:agent' }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createRelayCommand } = await import('../src/commands/relay.js');
      const cmd = createRelayCommand();

      await cmd.parseAsync([
        'start',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });
      await cmd.parseAsync([
        'register',
        'did:fides:agent',
        '--endpoint-hints',
        'local://agent',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });
      await cmd.parseAsync([
        'discover',
        '--capability',
        'invoice.reconcile',
        '--supported-versions',
        'fides.v2.0',
        '--required-versions',
        'fides.v2.0',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        'http://agentd.test/relay/start',
        expect.objectContaining({ method: 'POST' })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        'http://agentd.test/relay/register',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            agentId: 'did:fides:agent',
            endpointHints: ['local://agent'],
          }),
        })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        3,
        'http://agentd.test/relay/discover',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            capability: 'invoice.reconcile',
            supported_versions: ['fides.v2.0'],
            required_versions: ['fides.v2.0'],
          }),
        })
      );
    });

    it('registry publish and search should use local agentd aliases', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        authorityGranted: false,
        records: [{ agentId: 'did:fides:agent' }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createRegistryCommand } = await import('../src/commands/registry.js');
      const cmd = createRegistryCommand();

      await cmd.parseAsync([
        'start',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });
      await cmd.parseAsync([
        'publish',
        'did:fides:agent',
        '--mode',
        'private',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });
      await cmd.parseAsync([
        'search',
        '--capability',
        'invoice.reconcile',
        '--supported-versions',
        'fides.v2.0',
        '--required-versions',
        'fides.v2.0',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        'http://agentd.test/registry/start',
        expect.objectContaining({ method: 'POST' })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        'http://agentd.test/registry/publish',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ agentCardId: 'did:fides:agent', mode: 'private' }),
        })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        3,
        'http://agentd.test/registry/search',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            capability: 'invoice.reconcile',
            supported_versions: ['fides.v2.0'],
            required_versions: ['fides.v2.0'],
          }),
        })
      );
    });

    it('dht publish supports signed local pointer inputs without an AgentCard URL', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        accepted: true,
        pointer: {
          capability: 'invoice.reconcile',
          agentId: 'did:fides:agent',
          signed: true,
          authorityGranted: false,
        },
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createDhtCommand } = await import('../src/commands/dht.js');
      const cmd = createDhtCommand();

      await cmd.parseAsync([
        'publish',
        '--capability',
        'invoice.reconcile',
        '--agent-id',
        'did:fides:agent',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://agentd.test/dht/publish',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            capability: 'invoice.reconcile',
            agentId: 'did:fides:agent',
          }),
        })
      );
    });

    it('demo run should call the agentd demo endpoint', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        status: 'executed',
        authority: { discoveryGrantsAuthority: false },
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createDemoCommand } = await import('../src/commands/demo.js');
      const cmd = createDemoCommand();

      await cmd.parseAsync([
        'run',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://agentd.test/demo/run',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({}),
        })
      );
    });

    it('simulate adversarial should call the agentd simulation endpoint', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        status: 'detected',
        authority: { discoveryGrantsAuthority: false },
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createSimulateCommand } = await import('../src/commands/simulate.js');
      const cmd = createSimulateCommand();

      await cmd.parseAsync([
        'adversarial',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://agentd.test/simulate/adversarial',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({}),
        })
      );
    });

    it('session request and verify should use root agentd session endpoints', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        authorized: true,
        session: { session_id: 'sess_cli' },
        valid: true,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createSessionCommand } = await import('../src/commands/session.js');
      const cmd = createSessionCommand();

      await cmd.parseAsync([
        'request',
        'did:fides:agent',
        '--capability',
        'invoice.reconcile',
        '--requested-scopes',
        'read:invoices,write:evidence',
        '--principal-id',
        'did:fides:principal',
        '--requester-agent-id',
        'did:fides:requester',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });
      await cmd.parseAsync([
        'verify',
        'sess_cli',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        'http://agentd.test/sessions',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            agentId: 'did:fides:agent',
            capability: 'invoice.reconcile',
            requestedScopes: ['read:invoices', 'write:evidence'],
            principalId: 'did:fides:principal',
            requesterAgentId: 'did:fides:requester',
          }),
        })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(
        2,
        'http://agentd.test/sessions/sess_cli/verify',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({}),
        })
      );
    });

    it('incident list inspect and resolve should use root agentd incident endpoints', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        record: { id: 'inc_1' },
        records: [{ id: 'inc_1' }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createIncidentCommand } = await import('../src/commands/incident.js');
      const cmd = createIncidentCommand();

      await cmd.parseAsync([
        'report',
        'did:fides:agent',
        '--severity',
        'high',
        '--category',
        'unauthorized_action',
        '--description',
        'policy bypass',
        '--reporter',
        'did:fides:principal',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });
      await cmd.parseAsync(['list', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });
      await cmd.parseAsync(['inspect', 'inc_1', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });
      await cmd.parseAsync(['resolve', 'inc_1', '--status', 'resolved', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });

      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        'http://agentd.test/incidents',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            targetAgentId: 'did:fides:agent',
            severity: 'high',
            category: 'unauthorized_action',
            description: 'policy bypass',
            reporter: 'did:fides:principal',
            evidenceRefs: [],
          }),
        })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(2, 'http://agentd.test/incidents', expect.objectContaining({ method: 'GET' }));
      expect(mockFetch).toHaveBeenNthCalledWith(3, 'http://agentd.test/incidents/inc_1', expect.objectContaining({ method: 'GET' }));
      expect(mockFetch).toHaveBeenNthCalledWith(
        4,
        'http://agentd.test/incidents/inc_1/resolve',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ status: 'resolved' }),
        })
      );
    });

    it('killswitch enable disable and list should use root agentd kill switch endpoints', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        rule: { id: 'ks_1' },
        rules: [{ id: 'ks_1' }],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createKillswitchCommand } = await import('../src/commands/killswitch.js');
      const cmd = createKillswitchCommand();

      await cmd.parseAsync([
        'enable',
        '--capability',
        'payments.prepare',
        '--reason',
        'incident response',
        '--issuer',
        'did:fides:operator',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });
      await cmd.parseAsync(['list', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });
      await cmd.parseAsync(['disable', 'ks_1', '--agentd-url', 'http://agentd.test/', '--json'], { from: 'user' });

      expect(mockFetch).toHaveBeenNthCalledWith(
        1,
        'http://agentd.test/killswitch',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            targetType: 'capability',
            target: 'payments.prepare',
            reason: 'incident response',
            issuer: 'did:fides:operator',
          }),
        })
      );
      expect(mockFetch).toHaveBeenNthCalledWith(2, 'http://agentd.test/killswitch', expect.objectContaining({ method: 'GET' }));
      expect(mockFetch).toHaveBeenNthCalledWith(3, 'http://agentd.test/killswitch/ks_1', expect.objectContaining({ method: 'DELETE' }));
    });

    it('relay delete should remove messages by relay ID', async () => {
      process.env.SERVICE_API_KEY = 'relay-service-key';
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        deleted: true,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createRelayCommand } = await import('../src/commands/relay.js');
      const cmd = createRelayCommand();

      await cmd.parseAsync([
        'delete',
        'relay-1',
        '--relay-url',
        'http://relay.test',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://relay.test/v1/relay/relay-1',
        expect.objectContaining({
          method: 'DELETE',
          headers: expect.objectContaining({
            'X-API-Key': 'relay-service-key',
          }),
        })
      );
    });

    it('evidence export should pass privacy and metadata options to agentd', async () => {
      const mockFetch = vi.fn(async () => new Response(JSON.stringify({
        format: 'json',
        valid: true,
        events: [],
      }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as unknown as typeof fetch;
      vi.stubGlobal('fetch', mockFetch);

      const { createEvidenceCommand } = await import('../src/commands/evidence.js');
      const cmd = createEvidenceCommand();

      await cmd.parseAsync([
        'export',
        '--privacy-mode',
        'hash-only',
        '--no-metadata',
        '--agentd-url',
        'http://agentd.test/',
        '--json',
      ], { from: 'user' });

      expect(mockFetch).toHaveBeenCalledWith(
        'http://agentd.test/evidence/export',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({
            privacy_mode: 'hash_only',
            include_metadata: false,
          }),
        })
      );
    });
  });
});
