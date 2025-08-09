import { NextRequest, NextResponse } from 'next/server';
import { requireAdminToken, rollbackBundle } from '../../../_shared/bundles';

export async function POST(req: NextRequest) {
  try {
    requireAdminToken(req.headers);
  } catch (e) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }
  try {
    const index = await rollbackBundle();
    return NextResponse.json({ success: true, data: index }, { status: 200 });
  } catch (e) {
    return NextResponse.json({ success: false, error: 'Rollback failed' }, { status: 500 });
  }
}
