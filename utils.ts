// --- Minimal CLI args parser ---
import fs from 'fs';
import path from 'path';

export function parseArgs(): {
  to: string;
  value: number;
  nonce: number;
  gasPrice: bigint;
  gasLimit: number;
  chainId: number;
  mnemonic?: string;
} {
  const args = process.argv.slice(2);
  const result: any = {
    gasPrice: BigInt('20000000000'),
    gasLimit: 21000,
    chainId: 1
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    const val = args[i + 1];

    if (['to'].includes(key)) result[key] = val;
    else if (['value', 'nonce', 'gasLimit', 'chainId'].includes(key)) result[key] = Number(val);
    else if (key === 'gasPrice') result[key] = BigInt(val);
    else if (key === 'mnemonic') result[key] = val;
  }

  if (!result.to || result.value === undefined || result.nonce === undefined) {
    throw new Error(`Missing required arguments. Usage:
  --to 0x...         recipient address
  --value 0.1        amount in ETH
  --nonce 0          account nonce
  [--gasPrice]       (default: 20000000000)
  [--gasLimit]       (default: 21000)
  [--chainId]        (default: 1)
  [--mnemonic path|phrase] (optional)`);
  }
  if (result.mnemonic) {
    const maybePath = path.resolve(result.mnemonic);
    if (fs.existsSync(maybePath)) {
      result.mnemonic = fs.readFileSync(maybePath, 'utf-8').trim();
    } else {
      result.mnemonic = result.mnemonic.trim();
    }
  }

  return result;
}