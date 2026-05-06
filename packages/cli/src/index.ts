#!/usr/bin/env node

import { Command } from 'commander';
import { createInitCommand } from './commands/init.js';
import { createSignCommand } from './commands/sign.js';
import { createVerifyCommand } from './commands/verify.js';
import { createTrustCommand } from './commands/trust.js';
import { createDiscoverCommand } from './commands/discover.js';
import { createStatusCommand } from './commands/status.js';
import { createCardCommand } from './commands/card.js';
import { createPolicyCommand } from './commands/policy.js';
import { createRuntimeCommand } from './commands/runtime.js';
import { createKillswitchCommand } from './commands/killswitch.js';
import { createDaemonCommand } from './commands/daemon.js';
import { createDelegateCommand } from './commands/delegate.js';
import { createSessionCommand } from './commands/session.js';
import { createRevokeCommand } from './commands/revoke.js';
import { createIncidentCommand } from './commands/incident.js';
import { createPropagationCommand } from './commands/propagation.js';
import { createAuthorizeCommand } from './commands/authorize.js';
import { createRelayCommand } from './commands/relay.js';
import { createIdentityCommand } from './commands/identity.js';
import packageJson from '../package.json' with { type: 'json' };

const program = new Command();

program
  .name('fides')
  .version(packageJson.version)
  .description('FIDES v2 - Agent Trust Fabric');

// Register commands
program.addCommand(createInitCommand());
program.addCommand(createSignCommand());
program.addCommand(createVerifyCommand());
program.addCommand(createTrustCommand());
program.addCommand(createDiscoverCommand());
program.addCommand(createStatusCommand());
program.addCommand(createCardCommand());
program.addCommand(createPolicyCommand());
program.addCommand(createRuntimeCommand());
program.addCommand(createKillswitchCommand());
program.addCommand(createDaemonCommand());
program.addCommand(createDelegateCommand());
program.addCommand(createSessionCommand());
program.addCommand(createRevokeCommand());
program.addCommand(createIncidentCommand());
program.addCommand(createPropagationCommand());
program.addCommand(createAuthorizeCommand());
program.addCommand(createRelayCommand());
program.addCommand(createIdentityCommand());

program.parse();
