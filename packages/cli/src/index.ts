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

const program = new Command();

program
  .name('fides')
  .version('0.2.0')
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

program.parse();
