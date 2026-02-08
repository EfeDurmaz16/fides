import chalk from 'chalk';

export function success(msg: string): void {
  console.log(chalk.green('✓') + ' ' + msg);
}

export function error(msg: string): void {
  console.error(chalk.red('✗') + ' ' + msg);
}

export function info(msg: string): void {
  console.log(chalk.blue('ℹ') + ' ' + msg);
}

export function warn(msg: string): void {
  console.log(chalk.yellow('⚠') + ' ' + msg);
}

export function formatDid(did: string): string {
  if (did.length <= 20) {
    return did;
  }
  return did.substring(0, 20) + '...';
}

export function formatScore(score: number): string {
  const percentage = (score * 100).toFixed(1) + '%';
  if (score > 0.7) {
    return chalk.green(percentage);
  } else if (score > 0.4) {
    return chalk.yellow(percentage);
  } else {
    return chalk.red(percentage);
  }
}

export function formatTable(rows: string[][]): void {
  if (rows.length === 0) return;

  // Calculate column widths
  const colWidths = rows[0].map((_, colIndex) =>
    Math.max(...rows.map(row => (row[colIndex] || '').length))
  );

  // Print rows
  for (const row of rows) {
    const line = row.map((cell, i) => cell.padEnd(colWidths[i])).join('  ');
    console.log(line);
  }
}
