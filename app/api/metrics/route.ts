import { NextResponse } from 'next/server';
import { register } from '../policy/_shared/metrics';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const metrics = await register.metrics();
    return new NextResponse(metrics, {
      status: 200,
      headers: { 'Content-Type': register.contentType },
    });
  } catch (error) {
    return NextResponse.json({ success: false, error: 'Unable to render metrics' }, { status: 500 });
  }
}
