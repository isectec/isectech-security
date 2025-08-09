'use client';
import React, { useEffect, useState } from 'react';

interface BundleMeta {
  id: string;
  filename: string;
  createdAt: string;
  activatedAt?: string;
  sha256: string;
  notes?: string;
}

interface IndexData {
  activeBundleId?: string;
  history: BundleMeta[];
}

export default function PoliciesAdminPage() {
  const [data, setData] = useState<IndexData>({ history: [] });
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [notes, setNotes] = useState<string>('');
  const adminToken = typeof window !== 'undefined' ? localStorage.getItem('policy_admin_token') || '' : '';

  async function fetchIndex() {
    setLoading(true);
    try {
      const res = await fetch('/api/policy/admin/bundles', { headers: { 'x-admin-token': adminToken } });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || 'Failed to load');
      setData(json.data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchIndex();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function onUpload(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const input = form.elements.namedItem('bundle') as HTMLInputElement;
    if (!input.files || input.files.length === 0) return;
    const fd = new FormData();
    fd.append('bundle', input.files[0]);
    if (notes) fd.append('notes', notes);
    const res = await fetch('/api/policy/admin/bundles', {
      method: 'POST',
      headers: { 'x-admin-token': adminToken },
      body: fd,
    });
    const json = await res.json();
    if (!res.ok) {
      alert(`Upload failed: ${json.error || 'unknown'}`);
      return;
    }
    setNotes('');
    (form.reset as any)?.();
    await fetchIndex();
  }

  async function activate(id: string) {
    const res = await fetch('/api/policy/admin/bundles/activate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-admin-token': adminToken },
      body: JSON.stringify({ id }),
    });
    if (!res.ok) {
      const j = await res.json();
      alert(`Activation failed: ${j.error || 'unknown'}`);
      return;
    }
    await fetchIndex();
  }

  async function rollback() {
    const res = await fetch('/api/policy/admin/bundles/rollback', {
      method: 'POST',
      headers: { 'x-admin-token': adminToken },
    });
    if (!res.ok) {
      const j = await res.json();
      alert(`Rollback failed: ${j.error || 'unknown'}`);
      return;
    }
    await fetchIndex();
  }

  return (
    <main className="mx-auto max-w-5xl p-6">
      <h1 className="text-2xl font-semibold mb-4">Policy Bundles</h1>

      <section className="mb-8">
        <h2 className="text-lg font-medium mb-2">Upload Bundle</h2>
        <form onSubmit={onUpload} className="flex flex-col gap-3">
          <input name="bundle" type="file" accept=".tar,.tar.gz,.tgz,.zip" required />
          <input
            name="notes"
            type="text"
            placeholder="Release notes (optional)"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            className="border rounded p-2"
          />
          <button type="submit" className="bg-blue-600 text-white rounded px-4 py-2 w-max">
            Upload
          </button>
        </form>
      </section>

      <section>
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-lg font-medium">History</h2>
          <button onClick={rollback} className="bg-amber-600 text-white rounded px-3 py-1">
            Rollback
          </button>
        </div>
        {loading ? (
          <p>Loading...</p>
        ) : error ? (
          <p className="text-red-600">{error}</p>
        ) : (
          <table className="w-full text-left border-collapse">
            <thead>
              <tr>
                <th className="border-b p-2">ID</th>
                <th className="border-b p-2">File</th>
                <th className="border-b p-2">Created</th>
                <th className="border-b p-2">Active</th>
                <th className="border-b p-2">SHA256</th>
                <th className="border-b p-2">Notes</th>
                <th className="border-b p-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.history.map((b) => (
                <tr key={b.id}>
                  <td className="border-b p-2 font-mono">{b.id}</td>
                  <td className="border-b p-2">{b.filename}</td>
                  <td className="border-b p-2">{new Date(b.createdAt).toLocaleString()}</td>
                  <td className="border-b p-2">{data.activeBundleId === b.id ? 'Yes' : 'No'}</td>
                  <td className="border-b p-2 font-mono truncate max-w-[12rem]" title={b.sha256}>
                    {b.sha256}
                  </td>
                  <td className="border-b p-2">{b.notes || ''}</td>
                  <td className="border-b p-2">
                    {data.activeBundleId !== b.id && (
                      <button onClick={() => activate(b.id)} className="bg-green-600 text-white rounded px-3 py-1">
                        Activate
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </main>
  );
}
