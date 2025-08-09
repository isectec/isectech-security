import { NextRequest, NextResponse } from 'next/server';
import { listBundles, requireAdminToken, saveBundle, validateBundleWithOPA } from '../../_shared/bundles';

export async function GET(req: NextRequest) {
  try {
    requireAdminToken(req.headers);
    const index = await listBundles();
    return NextResponse.json({ success: true, data: index }, { status: 200 });
  } catch (e) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }
}

export async function POST(req: NextRequest) {
  try {
    requireAdminToken(req.headers);
  } catch (e) {
    return NextResponse.json({ success: false, error: 'Unauthorized' }, { status: 401 });
  }

  try {
    const contentType = req.headers.get('content-type') || '';
    if (contentType.startsWith('multipart/form-data')) {
      const form = await req.formData();
      const file = form.get('bundle');
      const notes = form.get('notes')?.toString();
      if (!(file instanceof File)) {
        return NextResponse.json({ success: false, error: 'Missing bundle file' }, { status: 400 });
      }
      const bytes = Buffer.from(await file.arrayBuffer());
      const validation = await validateBundleWithOPA(bytes);
      if (!validation.ok) {
        return NextResponse.json(
          { success: false, error: `Bundle validation failed: ${validation.details}` },
          { status: 400 }
        );
      }
      const meta = await saveBundle(bytes, file.name, notes);
      return NextResponse.json({ success: true, data: meta }, { status: 201 });
    }
    return NextResponse.json({ success: false, error: 'Unsupported content type' }, { status: 415 });
  } catch (error) {
    return NextResponse.json({ success: false, error: 'Upload failed' }, { status: 500 });
  }
}
