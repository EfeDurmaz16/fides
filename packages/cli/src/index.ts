#!/usr/bin/env node

import { Command } from 'commander';
import { createInitCommand } from './commands/init.js';
import { createSignCommand } from './commands/sign.js';
import { createVerifyCommand } from './commands/verify.js';
import { createTrustCommand } from './commands/trust.js';
import { createGraphCommand } from './commands/graph.js';
import { createReputationCommand } from './commands/reputation.js';
import { createDiscoverCommand } from './commands/discover.js';
import { createStatusCommand } from './commands/status.js';
import { createCardCommand } from './commands/card.js';
import { createPolicyCommand } from './commands/policy.js';
import { createApprovalCommand } from './commands/approval.js';
import { createRuntimeCommand } from './commands/runtime.js';
import { createKillswitchCommand } from './commands/killswitch.js';
import { createDaemonCommand } from './commands/daemon.js';
import { createDelegateCommand } from './commands/delegate.js';
import { createSessionCommand } from './commands/session.js';
import { createRevokeCommand } from './commands/revoke.js';
import { createIncidentCommand } from './commands/incident.js';
import { createAttestCommand } from './commands/attest.js';
import { createPropagationCommand } from './commands/propagation.js';
import { createAuthorizeCommand } from './commands/authorize.js';
import { createRelayCommand } from './commands/relay.js';
import { createRegistryCommand } from './commands/registry.js';
import { createIdentityCommand } from './commands/identity.js';
import { createAgentsCommand, createRegisterCommand } from './commands/agents.js';
import { createDhtCommand } from './commands/dht.js';
import { createEvidenceCommand } from './commands/evidence.js';
import { createDemoCommand } from './commands/demo.js';
import { createSimulateCommand } from './commands/simulate.js';
import { createInvokeCommand } from './commands/invoke.js';
import { inferCliName } from './cli-name.js';
import packageJson from '../package.json' with { type: 'json' };

const program = new Command();

program
  .name(inferCliName())
  .version(packageJson.version)
  .description('FIDES v2 - Agent Trust Fabric');

// Register commands
program.addCommand(createInitCommand());
program.addCommand(createSignCommand());
program.addCommand(createVerifyCommand());
program.addCommand(createTrustCommand());
program.addCommand(createGraphCommand());
program.addCommand(createReputationCommand());
program.addCommand(createDiscoverCommand());
program.addCommand(createStatusCommand());
program.addCommand(createCardCommand());
program.addCommand(createPolicyCommand());
program.addCommand(createApprovalCommand());
program.addCommand(createRuntimeCommand());
program.addCommand(createKillswitchCommand());
program.addCommand(createDaemonCommand());
program.addCommand(createDelegateCommand());
program.addCommand(createSessionCommand());
program.addCommand(createRevokeCommand());
program.addCommand(createIncidentCommand());
program.addCommand(createAttestCommand());
program.addCommand(createPropagationCommand());
program.addCommand(createAuthorizeCommand());
program.addCommand(createRelayCommand());
program.addCommand(createRegistryCommand());
program.addCommand(createIdentityCommand());
program.addCommand(createRegisterCommand());
program.addCommand(createAgentsCommand());
program.addCommand(createDhtCommand());
program.addCommand(createEvidenceCommand());
program.addCommand(createDemoCommand());
program.addCommand(createSimulateCommand());
program.addCommand(createInvokeCommand());

program.parse();
