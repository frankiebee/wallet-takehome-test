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
  endpoint?: string;
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
    else if (key === 'endpoint') result[key] = val;
  }

  if (!result.to || result.value === undefined || result.nonce === undefined) {
    throw new Error(`Missing required arguments. Usage:
  --to 0x...         recipient address
  --value 0.1        amount in ETH
  --nonce 0          account nonce
  [--gasPrice]       (default: 20000000000)
  [--gasLimit]       (default: 21000)
  [--chainId]        (default: 1)
  [--mnemonic path|phrase] (optional)
  [--endpoint] (optional)`);
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

/**
 * Converts a number, bigint, or Buffer to a minimal buffer (no leading zeroes unless required).
 */
export function toBuffer(value: number | bigint | Buffer): Buffer {
  if (Buffer.isBuffer(value)) return value;

  if (typeof value === 'number') {
    value = BigInt(value);
  }

  if (typeof value === 'bigint') {
    if (value === 0n) return Buffer.alloc(0);

    let hex = value.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    return Buffer.from(hex, 'hex');
  }

  throw new TypeError('Invalid type passed to toBuffer');
}


export async function broadcastTransaction(endpoint: string, rawTx: string): Promise<string> {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'eth_sendRawTransaction',
      params: [rawTx],
      id: 1
    })
  });

  const json = await response.json();

  if (json.error) {
    throw new Error(`RPC Error: ${json.error.message}`);
  }

  return json.result;
}

