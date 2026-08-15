/**
 * v1.11.0 regression tests for the Request Log page.
 *
 * Three properties matter here and none of them are visible from a snapshot:
 *
 *  1. Pagination is SERVER-side. Every other table in this app fetches once and
 *     slices in the browser; this table can hold millions of rows, so changing
 *     the page MUST issue a new request with a new offset. A client-side slice
 *     would look identical on a two-row fixture and fall over in production.
 *  2. The page gates itself on requestlog.read. The sidebar and the router are
 *     unconditional (App.js has no hook access at module level), so this
 *     component is the only gate — and it must not even call the API when the
 *     caller lacks the permission.
 *  3. Redacted values are what the modal shows. A test that only asserted the
 *     modal opens would still pass if the UI un-redacted anything.
 */
import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import axios from 'axios';
import RequestLog from '../RequestLog';

// Rendering the antd Table + filter row + modal is slow; keep the limit here so
// plain `npm test` passes as shipped rather than needing --testTimeout.
jest.setTimeout(30000);

jest.mock('axios');

let mockPermissions = { read: true, manage: true, admin: false };
jest.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({
    hasPermission: (resource, action) =>
      resource === 'requestlog' && Boolean(mockPermissions[action]),
    isAdmin: () => mockPermissions.admin,
  }),
}));

const INBOUND_ROW = {
  id: 2,
  request_id: 'abc123',
  direction: 'inbound',
  target: null,
  method: 'POST',
  url: '/api/letsencrypt/certificates',
  path: '/api/letsencrypt/certificates',
  status_code: 500,
  status_class: 5,
  duration_ms: 2431,
  user_id: 1,
  username: 'admin',
  client_ip: '10.0.0.5',
  error: null,
  request_body_bytes: 120,
  response_body_bytes: 88,
  truncated: false,
  created_at: '2026-08-11T09:00:00+00:00',
};

const OUTBOUND_ROW = {
  id: 1,
  request_id: 'abc123',
  direction: 'outbound',
  target: 'acme',
  method: 'POST',
  url: 'https://acme-v02.api.letsencrypt.org/acme/new-order',
  path: '/acme/new-order',
  status_code: 429,
  status_class: 4,
  duration_ms: 812,
  user_id: null,
  username: null,
  client_ip: null,
  error: null,
  request_body_bytes: 0,
  response_body_bytes: 210,
  truncated: false,
  created_at: '2026-08-11T09:00:01+00:00',
};

const LIST_RESPONSE = {
  logs: [INBOUND_ROW, OUTBOUND_ROW],
  total: 2,
  total_is_estimate: false,
  limit: 50,
  offset: 0,
  scoped_to_self: false,
};

const DETAIL_RESPONSE = {
  log: {
    ...INBOUND_ROW,
    query_params: null,
    request_headers: { 'content-type': 'application/json', authorization: '***REDACTED***' },
    request_body: { domains: ['example.com'], eab_hmac_key: '***REDACTED***' },
    response_headers: { 'content-type': 'application/json' },
    response_body: { error: { message: 'ACME rate limited' } },
  },
  related: [OUTBOUND_ROW],
};

const STATS_RESPONSE = {
  window_hours: 24,
  by_direction: [
    { direction: 'inbound', total: 120, errors: 3, avg_duration_ms: 45, max_duration_ms: 2431 },
    { direction: 'outbound', total: 18, errors: 1, avg_duration_ms: 300, max_duration_ms: 812 },
  ],
  by_status_class: [],
  by_target: [],
  total_rows: 138,
  oldest_at: '2026-08-04T09:00:00+00:00',
  newest_at: '2026-08-11T09:00:01+00:00',
  sink: { queued: 0, queue_capacity: 2000, written: 138, dropped: 0, failed_batches: 0, running: 1 },
  retention: { success_retention_days: 7, error_retention_days: 30, max_rows: 500000 },
};

const listCalls = () => axios.get.mock.calls.filter((c) => c[0] === '/api/request-logs');

beforeEach(() => {
  jest.clearAllMocks();
  mockPermissions = { read: true, manage: true, admin: false };
  axios.get.mockImplementation((url) => {
    if (url === '/api/request-logs') return Promise.resolve({ data: LIST_RESPONSE });
    if (url === '/api/request-logs/stats') return Promise.resolve({ data: STATS_RESPONSE });
    if (url.startsWith('/api/request-logs/')) return Promise.resolve({ data: DETAIL_RESPONSE });
    return Promise.resolve({ data: {} });
  });
  axios.post.mockResolvedValue({ data: { removed: { success: 1, error: 0, overflow: 0 } } });
});

async function renderPage() {
  render(<RequestLog />);
  await waitFor(() => expect(listCalls().length).toBeGreaterThan(0));
  await act(async () => {});
}

test('renders both directions of a request from the list endpoint', async () => {
  await renderPage();

  expect(await screen.findByText('/api/letsencrypt/certificates')).toBeInTheDocument();
  expect(screen.getByText('https://acme-v02.api.letsencrypt.org/acme/new-order')).toBeInTheDocument();
  // Inbound shows the user; outbound shows the target it called.
  expect(screen.getByText('admin')).toBeInTheDocument();
  expect(screen.getByText('acme')).toBeInTheDocument();
  expect(screen.getByText('500')).toBeInTheDocument();
  expect(screen.getByText('429')).toBeInTheDocument();
});

test('a caller without requestlog.read sees a denial and the API is never called', async () => {
  mockPermissions = { read: false, manage: false, admin: false };

  render(<RequestLog />);

  expect(await screen.findByText('Access denied')).toBeInTheDocument();
  expect(axios.get).not.toHaveBeenCalled();
});

test('an admin without an explicit grant still gets in', async () => {
  mockPermissions = { read: false, manage: false, admin: true };
  await renderPage();
  expect(await screen.findByText('/api/letsencrypt/certificates')).toBeInTheDocument();
});

test('the errors-only switch is sent to the server, not applied in the browser', async () => {
  await renderPage();
  const before = listCalls().length;

  await act(async () => {
    fireEvent.click(document.querySelector('.ant-switch'));
  });

  await waitFor(() => expect(listCalls().length).toBeGreaterThan(before));
  const params = listCalls()[listCalls().length - 1][1].params;
  expect(params.errors_only).toBe(true);
});

test('the direction filter is sent as a query parameter', async () => {
  await renderPage();
  const before = listCalls().length;

  await act(async () => {
    fireEvent.mouseDown(document.querySelectorAll('.ant-select-selector')[0]);
  });
  await act(async () => {
    const option = Array.from(document.querySelectorAll('.ant-select-item-option'))
      .find((el) => el.textContent.includes('Outbound'));
    fireEvent.click(option);
  });

  await waitFor(() => expect(listCalls().length).toBeGreaterThan(before));
  const params = listCalls()[listCalls().length - 1][1].params;
  expect(params.direction).toBe('outbound');
});

test('the first request asks for a bounded page, not the whole table', async () => {
  await renderPage();
  const params = listCalls()[0][1].params;
  expect(params.limit).toBe(50);
  expect(params.offset).toBe(0);
});

test('opening a row fetches the detail and shows the REDACTED body', async () => {
  await renderPage();

  await act(async () => {
    fireEvent.click(screen.getAllByText('Detail')[0]);
  });

  await waitFor(() =>
    expect(axios.get).toHaveBeenCalledWith(expect.stringMatching(/\/api\/request-logs\/\d+$/))
  );

  const modal = await waitFor(() => document.querySelector('.ant-modal-content'));
  expect(modal.textContent).toContain('***REDACTED***');
  // The redaction happens server-side; the UI must not attempt to show a raw value.
  expect(modal.textContent).not.toContain('eab_hmac_key":"');
  expect(modal.textContent).toContain('ACME rate limited');
});

test('the detail modal lists the outbound calls triggered by the same request', async () => {
  await renderPage();

  await act(async () => {
    fireEvent.click(screen.getAllByText('Detail')[0]);
  });

  const modal = await waitFor(() => document.querySelector('.ant-modal-content'));
  await waitFor(() => expect(modal.textContent).toContain('Calls triggered by this request'));
  expect(modal.textContent).toContain('acme');
});

test('a self-scoped response explains why the list is narrower', async () => {
  axios.get.mockImplementation((url) => {
    if (url === '/api/request-logs') {
      return Promise.resolve({ data: { ...LIST_RESPONSE, scoped_to_self: true } });
    }
    if (url === '/api/request-logs/stats') return Promise.resolve({ data: STATS_RESPONSE });
    return Promise.resolve({ data: {} });
  });

  await renderPage();
  expect(await screen.findByText('Showing your own requests only')).toBeInTheDocument();
});

test('dropped rows are surfaced as a warning', async () => {
  axios.get.mockImplementation((url) => {
    if (url === '/api/request-logs') return Promise.resolve({ data: LIST_RESPONSE });
    if (url === '/api/request-logs/stats') {
      return Promise.resolve({ data: { ...STATS_RESPONSE, sink: { ...STATS_RESPONSE.sink, dropped: 42 } } });
    }
    return Promise.resolve({ data: {} });
  });

  await renderPage();
  expect(await screen.findByText(/42 row\(s\) dropped/)).toBeInTheDocument();
});

test('a failed load surfaces the server message instead of a blank table', async () => {
  axios.get.mockImplementation((url) => {
    if (url === '/api/request-logs') {
      return Promise.reject({
        response: { status: 500, data: { error: { message: 'Failed to list request logs' } } },
      });
    }
    return Promise.resolve({ data: STATS_RESPONSE });
  });

  await renderPage();
  expect(await screen.findByText('Failed to list request logs')).toBeInTheDocument();
});

test('the retention button is hidden without requestlog.manage', async () => {
  mockPermissions = { read: true, manage: false, admin: false };
  await renderPage();
  expect(screen.queryByText('Apply retention now')).not.toBeInTheDocument();
});
