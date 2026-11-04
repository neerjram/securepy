import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import React from 'react';
import App from './App';

describe('SecurePy App Integration', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders application navbar and dashboard overview', async () => {
    global.fetch = vi.fn().mockImplementation((url) => {
      if (url.includes('/api/health')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ status: 'healthy', version: '0.1.0' }),
        });
      }
      if (url.includes('/api/scans')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([
            {
              scan_id: 'scan-1',
              target_name: 'test.py',
              target_type: 'SNIPPET',
              status: 'COMPLETED',
              file_count: 1,
              total_lines: 10,
              risk_score: 40,
              findings_count: 2,
              created_at: '2026-11-03T12:00:00Z',
            },
          ]),
        });
      }
      return Promise.reject(new Error(`Unhandled URL: ${url}`));
    });

    render(<App />);

    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(/SecurePy/i);
    expect(screen.getByText(/Explainable Security Analysis for Python/i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText(/API Connected/i)).toBeInTheDocument();
      expect(screen.getByText('test.py')).toBeInTheDocument();
    });
  });

  it('switches between tabs (Dashboard, New Scan, Scan History)', async () => {
    global.fetch = vi.fn().mockImplementation((url) => {
      if (url.includes('/api/health')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ status: 'healthy', version: '0.1.0' }),
        });
      }
      if (url.includes('/api/scans')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([]),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });

    render(<App />);

    // Click New Scan tab
    const newScanBtn = screen.getByRole('button', { name: /New Scan/i });
    fireEvent.click(newScanBtn);

    await waitFor(() => {
      expect(screen.getByText(/Start New Security Scan/i)).toBeInTheDocument();
      expect(screen.getByText(/Snippet Editor/i)).toBeInTheDocument();
    });

    // Click Scan History tab
    const historyBtn = screen.getByRole('button', { name: /Scan History/i });
    fireEvent.click(historyBtn);

    await waitFor(() => {
      expect(screen.getByPlaceholderText(/Search by target or ID/i)).toBeInTheDocument();
    });
  });
});
