export interface TrustScoreResult {
  trust_score: number; // 0 - 100
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  bucket: string; // e.g., b0-9, b10-19, ... b90-100
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function toBucket(score: number): string {
  const bucketStart = Math.floor(score / 10) * 10;
  const bucketEnd = bucketStart === 100 ? 100 : bucketStart + 9;
  return `b${bucketStart}-${bucketEnd}`;
}

export async function computeTrustScore(input: any): Promise<TrustScoreResult> {
  // Optional remote trust scoring service
  const remoteUrl = process.env.TRUST_SCORE_ENDPOINT;
  if (remoteUrl) {
    try {
      const res = await fetch(remoteUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input }),
        signal: AbortSignal.timeout(1500),
      });
      if (res.ok) {
        const data = await res.json();
        const score = clamp(Number(data?.trust_score ?? 0), 0, 100);
        const bucket = toBucket(score);
        const risk: TrustScoreResult['risk_level'] =
          score >= 80 ? 'low' : score >= 60 ? 'medium' : score >= 40 ? 'high' : 'critical';
        return { trust_score: score, risk_level: risk, bucket };
      }
    } catch {
      // fall back to local model
    }
  }

  // Local deterministic scoring model (signals from request)
  let score = 50;
  const user = input?.user || {};
  const ctx = input?.context || {};
  const device = input?.device || {};

  if (user.authenticated) score += 10;
  if (user.mfa?.verified) score += 10;
  if (user.status && user.status !== 'active') score -= 20;
  if (Array.isArray(user.roles) && user.roles.length > 0) score += 5;

  if (device.status === 'trusted') score += 5;
  if (device.status === 'compromised' || device.status === 'suspicious') score -= 30;

  if (ctx.access_type === 'emergency') score -= 25;
  if (ctx.high_risk_authorized) score += 5;

  // Very naive IP heuristic (placeholder for geo-velocity / ASN checks)
  if (typeof ctx.ip_address === 'string' && ctx.ip_address.startsWith('10.')) score += 5;

  score = clamp(score, 0, 100);
  const bucket = toBucket(score);
  const risk: TrustScoreResult['risk_level'] =
    score >= 80 ? 'low' : score >= 60 ? 'medium' : score >= 40 ? 'high' : 'critical';
  return { trust_score: score, risk_level: risk, bucket };
}

