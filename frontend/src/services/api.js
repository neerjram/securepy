/**
 * SecurePy Frontend API Client
 */

const API_BASE = '/api';

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error(`Health check failed with status ${res.status}`);
  return res.json();
}

export async function scanSnippet(code, targetName = 'snippet.py') {
  const res = await fetch(`${API_BASE}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, target_name: targetName }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail?.message || errorData.detail || 'Scan failed.');
  }
  return res.json();
}

export async function uploadAndScan(file) {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/scans/upload`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || 'File upload failed.');
  }
  return res.json();
}

export async function fetchScans(limit = 50) {
  const res = await fetch(`${API_BASE}/scans?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to retrieve scan history.');
  return res.json();
}

export async function fetchScanDetail(scanId) {
  const res = await fetch(`${API_BASE}/scans/${scanId}`);
  if (!res.ok) throw new Error(`Failed to retrieve scan ${scanId}.`);
  return res.json();
}

export async function fetchScanFindings(scanId, filters = {}) {
  const params = new URLSearchParams();
  if (filters.severity) params.append('severity', filters.severity);
  if (filters.status) params.append('status', filters.status);
  if (filters.category) params.append('category', filters.category);

  const url = `${API_BASE}/scans/${scanId}/findings${params.toString() ? '?' + params.toString() : ''}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to retrieve findings.');
  return res.json();
}

export async function updateFindingStatus(findingId, newStatus) {
  const res = await fetch(`${API_BASE}/findings/${findingId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status: newStatus }),
  });
  if (!res.ok) throw new Error('Failed to update finding status.');
  return res.json();
}

export async function fetchScanReport(scanId) {
  const res = await fetch(`${API_BASE}/scans/${scanId}/report`);
  if (!res.ok) throw new Error('Failed to download scan report.');
  return res.json();
}
