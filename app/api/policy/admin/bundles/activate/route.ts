import { NextRequest, NextResponse } from 'next/server';
import { activateBundle, requireAdminToken } from '../../../_shared/bundles';

export async function POST(req: NextRequest) {
  try {
    requireAdminToken(req.headers);
  } catch (e) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }
  try {
    const { id } = (await req.json()) as { id: string };
    if (!id) return NextResponse.json({ success: false, error: 'Missing id' }, { status: 400 });
    const index = await activateBundle(id);
    return NextResponse.json({ success: true, data: index }, { status: 200 });
  } catch (e) {
    return NextResponse.json({ success: false, error: 'Activation failed' }, { status: 500 });
  }
}
