/**
 * Issue #79: the renewal task checks the global Enable Auto-Renewal setting (default off) before a
 * certificate's own Auto-Renew, but the Renewal Schedule showed "Enabled" regardless, so
 * certificates expired while renewal looked on. These render the schedule from the API rows and
 * check what the operator sees, plus the Renew Now action.
 */
import React from 'react';
import { render, screen, fireEvent, waitFor, act, within } from '@testing-library/react';
import axios from 'axios';
import ACMEAutomation from '../ACMEAutomation';

jest.setTimeout(30000);

jest.mock('axios');
jest.mock('react-router-dom', () => ({ useNavigate: () => jest.fn() }));
jest.mock('../../contexts/ClusterContext', () => ({
  useCluster: () => ({ clusters: [], selectCluster: jest.fn() }),
}));

const inDays = (n) => new Date(Date.now() + n * 24 * 3600 * 1000).toISOString();

// What a v1.12.1 backend returns: no global setting, no order link.
const LEGACY_ROW = {
  id: 11, name: 'le-*.example.test', primary_domain: '*.example.test', expiry_date: inDays(20),
  auto_renew: true, days_until_expiry: 20, challenge_type: 'dns-01', dns_provider: 'cloudflare',
};
const row = (over = {}) => ({
  ...LEGACY_ROW,
  letsencrypt_order_id: 5,
  order_domains: ['*.example.test', 'example.test'],
  account_status: 'valid',
  global_auto_renew_enabled: true,
  renew_before_days: 30,
  renewal_due_date: '2031-03-09',
  last_renewal_issue: null,
  ...over,
});
// The date the UI must show for renewal_due_date, whatever the test machine's timezone.
const DUE_TEXT = new Date(2031, 2, 9).toLocaleDateString();
const ORDER_5 = {
  id: 5, status: 'valid', domains: ['*.example.test', 'example.test'], ssl_certificate_id: 11,
  challenge_type: 'dns-01', dns_provider: 'cloudflare', created_at: inDays(-70),
};

function mockApi({ schedule, orders = [ORDER_5], dns01Enabled = true }) {
  const routes = {
    '/api/letsencrypt/orders': orders,
    '/api/letsencrypt/accounts': [],
    '/api/letsencrypt/renewal-schedule': schedule,
    '/api/clusters': { clusters: [] },
    '/api/letsencrypt/prerequisites': { steps: [] },
    '/api/letsencrypt/dns-providers': { dns01_enabled: dns01Enabled, providers: [] },
  };
  axios.get.mockImplementation((url) =>
    Promise.resolve({ data: Object.prototype.hasOwnProperty.call(routes, url) ? routes[url] : {} })
  );
}

beforeEach(() => {
  jest.clearAllMocks();
  axios.post.mockResolvedValue({ data: { message: 'Renewal order created', new_order_id: 99 } });
});

async function renderSchedule() {
  render(<ACMEAutomation />);
  await waitFor(() => expect(axios.get).toHaveBeenCalledWith('/api/letsencrypt/renewal-schedule'));
  await screen.findAllByText('le-*.example.test');
  await act(async () => {});
}

const scheduleCard = () => screen.getByText('Renewal Schedule').closest('.ant-card');
const scheduleRow = () => within(scheduleCard()).getByText('le-*.example.test').closest('tr');
const nextRenewalCard = () => screen.getByText('Next Renewal').closest('.ant-card');

test('global auto-renewal off: the certificate is shown as paused, with a warning', async () => {
  mockApi({ schedule: [row({ global_auto_renew_enabled: false })] });
  await renderSchedule();

  expect(within(scheduleRow()).getByText('Paused (global off)')).toBeInTheDocument();
  expect(within(scheduleRow()).queryByText('Enabled')).not.toBeInTheDocument();
  expect(within(scheduleCard()).getByText('Automatic renewal is turned off')).toBeInTheDocument();
  expect(within(nextRenewalCard()).getByText('Off')).toBeInTheDocument();
});

test('global auto-renewal on: Enabled, Renewal Due date, no warning', async () => {
  mockApi({ schedule: [row()] });
  await renderSchedule();

  expect(within(scheduleRow()).getByText('Enabled')).toBeInTheDocument();
  expect(within(scheduleCard()).queryByText('Automatic renewal is turned off')).not.toBeInTheDocument();
  expect(within(scheduleRow()).getByText(DUE_TEXT)).toBeInTheDocument();
  expect(within(nextRenewalCard()).getByText('20d')).toBeInTheDocument();
});

test('no Renewal Due date for a certificate the task never renews', async () => {
  mockApi({ schedule: [row({ dns_provider: 'manual' })] });
  await renderSchedule();

  expect(within(scheduleRow()).getByText('Manual (re-publish TXT)')).toBeInTheDocument();
  expect(within(scheduleRow()).queryByText(DUE_TEXT)).not.toBeInTheDocument();
});

test('a certificate without an ACME order is not renewable and has no Renewal Due date', async () => {
  mockApi({ schedule: [row({ letsencrypt_order_id: null, order_domains: null, account_status: null })] });
  await renderSchedule();

  expect(within(scheduleRow()).getByText('Not renewable')).toBeInTheDocument();
  expect(within(scheduleRow()).queryByRole('button', { name: /Renew Now/i })).not.toBeInTheDocument();
  expect(within(nextRenewalCard()).getByText('N/A')).toBeInTheDocument();
  expect(within(scheduleRow()).queryByText(DUE_TEXT)).not.toBeInTheDocument();
});

test('a certificate without an expiry date is not renewable (the task skips it)', async () => {
  mockApi({ schedule: [row({ expiry_date: null, renewal_due_date: null })] });
  await renderSchedule();

  expect(within(scheduleRow()).getByText('Not renewable')).toBeInTheDocument();
  expect(within(scheduleRow()).queryByText('Enabled')).not.toBeInTheDocument();
});

test('an older backend without the new fields renders as before', async () => {
  mockApi({ schedule: [LEGACY_ROW] });
  await renderSchedule();

  expect(within(scheduleRow()).getByText('Enabled')).toBeInTheDocument();
  expect(within(scheduleRow()).queryByText('Paused (global off)')).not.toBeInTheDocument();
  expect(within(scheduleRow()).queryByRole('button', { name: /Renew Now/i })).not.toBeInTheDocument();
  expect(within(scheduleCard()).queryByText('Automatic renewal is turned off')).not.toBeInTheDocument();
  expect(within(nextRenewalCard()).getByText('20d')).toBeInTheDocument();
});

test('a deactivated issuing account is shown as blocked and Renew Now is disabled', async () => {
  mockApi({ schedule: [row({ account_status: 'deactivated' })] });
  await renderSchedule();

  expect(within(scheduleRow()).getByText('Blocked (account deactivated)')).toBeInTheDocument();
  expect(within(scheduleRow()).getByRole('button', { name: /Renew Now/i })).toBeDisabled();
});

test('the last reason the renewal task gave is shown', async () => {
  mockApi({
    schedule: [row({
      last_renewal_issue: {
        event_type: 'acme.renewal.failed', severity: 'ERROR',
        message: 'Automatic renewal failed: unauthorized', created_at: inDays(-0.1),
      },
    })],
  });
  await renderSchedule();
  expect(within(scheduleRow()).getByText('Last renewal failed')).toBeInTheDocument();
});

test('Renew Now asks first, then calls the renew endpoint of the certificate order', async () => {
  mockApi({ schedule: [row()] });
  await renderSchedule();

  await act(async () => {
    fireEvent.click(within(scheduleRow()).getByRole('button', { name: /Renew Now/i }));
  });
  await screen.findAllByText('Renew Certificate Now');
  expect(axios.post).not.toHaveBeenCalled();
  const confirm = document.querySelector('.ant-modal-confirm');
  const okButton = within(confirm).getByRole('button', { name: /Renew Now/i });
  await act(async () => {
    fireEvent.click(okButton);
  });

  await waitFor(() => expect(axios.post).toHaveBeenCalledWith('/api/letsencrypt/orders/5/renew'));
  expect(axios.post).toHaveBeenCalledTimes(1);
});

test('Renew Now is disabled while an order for the same domains is in progress', async () => {
  const inFlight = { ...ORDER_5, id: 6, status: 'pending', ssl_certificate_id: null, created_at: inDays(-0.01) };
  mockApi({ schedule: [row()], orders: [ORDER_5, inFlight] });
  await renderSchedule();

  expect(within(scheduleRow()).getByRole('button', { name: /Renew Now/i })).toBeDisabled();
});

test('with DNS-01 disabled in Settings, Renew Now is disabled for a DNS-01 certificate only', async () => {
  const http = row({
    id: 12, name: 'le-a.example.test', primary_domain: 'a.example.test', challenge_type: 'http-01',
    dns_provider: null, letsencrypt_order_id: 7, order_domains: ['a.example.test'],
  });
  mockApi({ schedule: [row(), http], dns01Enabled: false });
  await renderSchedule();

  expect(within(scheduleRow()).getByRole('button', { name: /Renew Now/i })).toBeDisabled();
  const httpRow = within(scheduleCard()).getByText('le-a.example.test').closest('tr');
  expect(within(httpRow).getByRole('button', { name: /Renew Now/i })).not.toBeDisabled();
});

test('if the DNS-01 setting cannot be read, Renew Now is not blocked by it', async () => {
  mockApi({ schedule: [row()] });
  const base = axios.get.getMockImplementation();
  axios.get.mockImplementation((url) => (url === '/api/letsencrypt/dns-providers'
    ? Promise.reject(new Error('network')) : base(url)));
  await renderSchedule();

  expect(within(scheduleRow()).getByRole('button', { name: /Renew Now/i })).not.toBeDisabled();
});

test('an order for other domains does not block Renew Now', async () => {
  const other = { ...ORDER_5, id: 6, status: 'pending', ssl_certificate_id: null, domains: ['other.example.test'] };
  mockApi({ schedule: [row()], orders: [ORDER_5, other] });
  await renderSchedule();

  expect(within(scheduleRow()).getByRole('button', { name: /Renew Now/i })).not.toBeDisabled();
});
