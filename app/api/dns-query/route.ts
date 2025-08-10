import { NextRequest, NextResponse } from 'next/server';
import dns from 'dns/promises';

/**
 * DNS Query API Endpoint
 * Performs server-side DNS queries for domain validation
 */
export async function POST(request: NextRequest) {
  try {
    const { name, type } = await request.json();

    if (!name || !type) {
      return NextResponse.json(
        { error: 'Name and type are required' },
        { status: 400 }
      );
    }

    let records: string[] = [];

    try {
      switch (type.toLowerCase()) {
        case 'a':
          records = await dns.resolve4(name);
          break;
        case 'cname':
          records = await dns.resolveCname(name);
          break;
        case 'txt':
          const txtRecords = await dns.resolveTxt(name);
          records = txtRecords.flat();
          break;
        default:
          return NextResponse.json(
            { error: `Unsupported DNS record type: ${type}` },
            { status: 400 }
          );
      }
    } catch (dnsError) {
      // DNS query failed, return empty records (common for non-existent records)
      records = [];
    }

    return NextResponse.json({ records });
  } catch (error) {
    console.error('DNS query API error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}