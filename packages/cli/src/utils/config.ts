import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export interface FidesConfig {
  discoveryUrl: string;
  trustUrl: string;
  activeDid?: string;
  keyDir: string;
}

const DEFAULT_CONFIG: FidesConfig = {
  discoveryUrl: 'http://localhost:3100',
  trustUrl: 'http://localhost:3200',
  keyDir: path.join(os.homedir(), '.fides', 'keys'),
};

export function getConfigPath(): string {
  return path.join(os.homedir(), '.fides', 'config.json');
}

export function loadConfig(): FidesConfig {
  try {
    const configPath = getConfigPath();
    if (!fs.existsSync(configPath)) {
      return { ...DEFAULT_CONFIG };
    }
    const data = fs.readFileSync(configPath, 'utf-8');
    const config = JSON.parse(data);
    return { ...DEFAULT_CONFIG, ...config };
  } catch (error) {
    return { ...DEFAULT_CONFIG };
  }
}

export function saveConfig(config: FidesConfig): void {
  const configPath = getConfigPath();
  const configDir = path.dirname(configPath);

  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }

  fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
}
