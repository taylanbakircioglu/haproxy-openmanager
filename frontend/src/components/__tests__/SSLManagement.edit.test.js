/**
 * Issue #79: an ACME wildcard certificate is named `le-*.<domain>`. The Edit form re-checked that
 * locked name against the create-time pattern and never submitted, so the certificate could not
 * be updated. These drive the real form: open Edit, press Update, and check what reaches the API.
 */
import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import axios from 'axios';
import { SSLManagement } from '../SSLManagement';

jest.setTimeout(30000);

jest.mock('axios');
jest.mock('react-router-dom', () => ({ useSearchParams: () => [new URLSearchParams()] }));
// Stable objects: SSLManagement refetches whenever `selectedCluster` changes identity.
const mockCluster = { id: 1, name: 'Default' };
const mockClusterContext = { selectedCluster: mockCluster, clusters: [mockCluster], loading: false };
jest.mock('../../contexts/ClusterContext', () => ({ useCluster: () => mockClusterContext }));
jest.mock('../../contexts/ProgressContext', () => ({ useProgress: () => ({}) }));
jest.mock('../EntitySyncStatus', () => ({ __esModule: true, default: () => null }));
jest.mock('../ACMEAutomation', () => ({ __esModule: true, default: () => null }));
jest.mock('../CSRManagement', () => ({ __esModule: true, default: () => null }));

const PEM_CERT = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';
const PEM_KEY = '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----';

const LIST_ROW = {
  id: 7, name: 'le-*.example.test', domain: '*.example.test', ssl_type: 'Cluster-specific',
  usage_type: 'frontend', source: 'letsencrypt', last_config_status: 'APPLIED',
  expiry_date: '2027-01-01T00:00:00', created_at: '2026-10-01T00:00:00', updated_at: '2026-10-01T00:00:00',
};
const DETAIL = {
  ...LIST_ROW,
  certificate_content: PEM_CERT, private_key_content: PEM_KEY, chain_content: PEM_CERT,
  is_global: false, cluster_ids: [1],
};

beforeEach(() => {
  jest.clearAllMocks();
  axios.get.mockImplementation((url) => {
    if (url.startsWith('/api/ssl/certificates?')) return Promise.resolve({ data: { certificates: [LIST_ROW] } });
    if (url === '/api/ssl/certificates/7') return Promise.resolve({ data: DETAIL });
    if (url.endsWith('/config-versions')) return Promise.resolve({ data: { config_versions: [] } });
    return Promise.resolve({ data: {} });
  });
  // What PUT returns for an ACME certificate: content is never sent, so nothing is re-rendered.
  axios.put.mockResolvedValue({
    data: {
      message: 'SSL certificate updated successfully', content_updated: false, affected_clusters: 1,
      sync_results: [{ message: 'SSL metadata updated (no content change, no config version needed)' }],
    },
  });
  axios.post.mockResolvedValue({ data: { sync_results: [] } });
});

const modal = () => document.querySelector('.ant-modal-content');

async function openEdit() {
  render(<SSLManagement />);
  await screen.findByText('le-*.example.test');
  await act(async () => {
    fireEvent.click(screen.getByLabelText('edit').closest('button'));
  });
  await screen.findByText('Edit SSL Certificate');
}

test('an ACME wildcard certificate can be updated from the Edit form', async () => {
  await openEdit();
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /Update Certificate/i }));
  });

  await waitFor(() => expect(axios.put).toHaveBeenCalled());
  const [url, body] = axios.put.mock.calls[0];
  expect(url).toBe('/api/ssl/certificates/7');
  expect(body.name).toBe('le-*.example.test');
  // ACME-managed content is never sent from the form (the backend rejects manual content edits).
  expect(body).not.toHaveProperty('certificate_content');
  expect(await screen.findByText('SSL certificate updated (no configuration change needed)')).toBeInTheDocument();
  expect(screen.queryByText(/updated with warnings/)).not.toBeInTheDocument();
});

test('scope and target clusters are read-only on edit and say why', async () => {
  await openEdit();
  expect(document.getElementById('ssl_type').closest('.ant-select')).toHaveClass('ant-select-disabled');
  expect(document.getElementById('cluster_ids').closest('.ant-select')).toHaveClass('ant-select-disabled');
  expect(modal().textContent).toContain('Scope and target clusters cannot be changed on edit');
  expect(modal().textContent).toContain('Updating it here does not renew it');
});

test('a new certificate still has to use the safe name pattern', async () => {
  render(<SSLManagement />);
  await screen.findByText('le-*.example.test');
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /Add Certificate/i }));
  });
  await screen.findByText('Add SSL Certificate');
  fireEvent.change(document.getElementById('name'), { target: { value: 'le-*.example.test' } });
  await act(async () => {
    fireEvent.click(screen.getAllByRole('button', { name: /Add Certificate/i }).pop());
  });

  expect(await screen.findByText('Only alphanumeric, dot, underscore and dash allowed')).toBeInTheDocument();
  expect(axios.post).not.toHaveBeenCalled();
  expect(document.getElementById('ssl_type').closest('.ant-select')).not.toHaveClass('ant-select-disabled');
});
