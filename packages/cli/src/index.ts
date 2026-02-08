#!/usr/bin/env node

import { Command } from 'commander';
import { createInitCommand } from './commands/init.js';
import { createSignCommand } from './commands/sign.js';
import { createVerifyCommand } from './commands/verify.js';
import { createTrustCommand } from './commands/trust.js';
import { createDiscoverCommand } from './commands/discover.js';
import { createStatusCommand } from './commands/status.js';

const program = new Command();

program
  .name('fides')
  .version('0.1.0')
  .description('FIDES - Federated Identity and Distributed Evaluation System');

// Register commands
program.addCommand(createInitCommand());
program.addCommand(createSignCommand());
program.addCommand(createVerifyCommand());
program.addCommand(createTrustCommand());
program.addCommand(createDiscoverCommand());
program.addCommand(createStatusCommand());

program.parse();
