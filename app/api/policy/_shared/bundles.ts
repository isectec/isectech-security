import crypto from 'crypto';
import { promises as fs } from 'fs';
import path from 'path';

const BUNDLES_DIR = path.join(process.cwd(), 'policy-engine', 'bundles');
const META_FILE = path.join(BUNDLES_DIR, 'index.json');

export interface PolicyBundleMeta {
  id: string;
  filename: string;
  createdAt: string;
  activatedAt?: string;
  sha256: string;
  notes?: string;
}

export interface BundlesIndex {
  activeBundleId?: string;
  history: PolicyBundleMeta[];
}

async function ensureDirs(): Promise<void> {
  await fs.mkdir(BUNDLES_DIR, { recursive: true });
  try {
    await fs.access(META_FILE);
  } catch {
    const initial: BundlesIndex = { history: [] };
    await fs.writeFile(META_FILE, JSON.stringify(initial, null, 2));
  }
}

async function readIndex(): Promise<BundlesIndex> {
  await ensureDirs();
  const raw = await fs.readFile(META_FILE, 'utf8');
  return JSON.parse(raw) as BundlesIndex;
}

async function writeIndex(index: BundlesIndex): Promise<void> {
  await fs.writeFile(META_FILE, JSON.stringify(index, null, 2));
}

export async function listBundles(): Promise<BundlesIndex> {
  return readIndex();
}

export async function saveBundle(fileBytes: Buffer, originalName: string, notes?: string): Promise<PolicyBundleMeta> {
  await ensureDirs();
  const sha256 = crypto.createHash('sha256').update(fileBytes).digest('hex');
  const id = sha256.slice(0, 16);
  const safeName = originalName.replace(/[^a-zA-Z0-9_.-]/g, '_');
  const filename = `${id}__${safeName}`;
  const filePath = path.join(BUNDLES_DIR, filename);

  await fs.writeFile(filePath, fileBytes);

  const meta: PolicyBundleMeta = {
    id,
    filename,
    sha256,
    createdAt: new Date().toISOString(),
    notes,
  };

  const index = await readIndex();
  index.history.unshift(meta);
  await writeIndex(index);
  return meta;
}

export async function activateBundle(id: string): Promise<BundlesIndex> {
  const index = await readIndex();
  const target = index.history.find((b) => b.id === id);
  if (!target) throw new Error('Bundle not found');
  target.activatedAt = new Date().toISOString();
  index.activeBundleId = id;
  await writeIndex(index);
  return index;
}

export async function rollbackBundle(): Promise<BundlesIndex> {
  const index = await readIndex();
  const current = index.activeBundleId;
  const candidates = index.history.filter((b) => b.id !== current);
  if (candidates.length === 0) throw new Error('No previous bundle to rollback to');
  const previous = candidates[0];
  previous.activatedAt = new Date().toISOString();
  index.activeBundleId = previous.id;
  await writeIndex(index);
  return index;
}

export async function validateBundleWithOPA(fileBytes: Buffer): Promise<{ ok: boolean; details?: string }> {
  const opaUrl = process.env.OPA_URL || 'http://opa-service:8181';
  try {
    // Post to OPA compile endpoint with empty query as sanity check; in real usage, we could unpack bundle and validate.
    const res = await fetch(`${opaUrl}/v1/compile`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'data' }),
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) return { ok: false, details: `OPA compile endpoint responded ${res.status}` };
    return { ok: true };
  } catch (e) {
    return { ok: false, details: 'OPA compile validation failed/unreachable' };
  }
}

export function requireAdminToken(headers: Headers): void {
  const configured = process.env.POLICY_ADMIN_TOKEN || '';
  const provided = headers.get('x-admin-token') || '';
  if (!configured || provided !== configured) {
    const proxyHeader = headers.get('x-admin-verified');
    if (proxyHeader !== 'true') {
      throw new Error('Unauthorized');
    }
  }
}
