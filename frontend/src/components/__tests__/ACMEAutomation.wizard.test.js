/**
 * v1.10.3 regression tests: with more than one ACME account, the certificate wizard must honour the
 * account the operator picked — on the Review step AND in the request it submits.
 *
 * These drive the real component through all three wizard steps rather than testing a helper,
 * because the bug was invisible until the wizard ADVANCED PAST the step that owns the account
 * Select: Form.useWatch reports only fields that are currently rendered, so on Review the selection
 * read `undefined` and the wizard silently reverted to the default account. A unit test of any
 * single function would have passed the whole time.
 */
import React from 'react';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import axios from 'axios';
import ACMEAutomation from '../ACMEAutomation';

jest.mock('axios');
jest.mock('react-router-dom', () => ({ useNavigate: () => jest.fn() }));
jest.mock('../../contexts/ClusterContext', () => ({
  useCluster: () => ({ clusters: [], selectCluster: jest.fn() }),
}));

// The account list arrives ORDER BY id while the backend's default is ORDER BY created_at DESC, so
// this fixture is deliberately the shape that made the two disagree: the DNS-01 account is BOTH the
// lower id and the older account, the HTTP-01 account is the newest. Picking the first valid entry
// (as the UI used to) yields the DNS-01 account; the backend would have used the HTTP-01 one.
const DNS_ACCOUNT = {
  id: 1, email: 'dns@example.com', status: 'valid',
  challenge_type: 'dns-01', dns_provider: 'godaddy',
  created_at: '2026-05-06T00:00:00Z', directory_url: 'https://acme.zerossl.com/v2/DV90',
};
const HTTP_ACCOUNT = {
  id: 2, email: 'http@example.com', status: 'valid',
  challenge_type: 'http-01', dns_provider: null,
  created_at: '2026-08-08T00:00:00Z', directory_url: 'https://acme.zerossl.com/v2/DV90',
};

const GET_ROUTES = {
  '/api/letsencrypt/orders': [],
  '/api/letsencrypt/accounts': [DNS_ACCOUNT, HTTP_ACCOUNT],
  '/api/letsencrypt/renewal-schedule': [],
  '/api/clusters': { clusters: [{ id: 10, name: 'cluster-a', acme_enabled: true, is_active: true }] },
  '/api/letsencrypt/prerequisites': { steps: [] },
  '/api/letsencrypt/dns-providers': {
    dns01_enabled: true,
    providers: [
      { name: 'manual', label: 'Manual', automated: false, credential_fields: [] },
      {
        name: 'godaddy', label: 'GoDaddy', automated: true,
        credential_fields: [
          { key: 'api_key', label: 'API Key', type: 'password', required: true, max_length: 200, help: 'Production key' },
          { key: 'api_secret', label: 'API Secret', type: 'password', required: false, max_length: 200, help: 'Blank for a PAT' },
        ],
      },
    ],
  },
};

beforeEach(() => {
  jest.clearAllMocks();
  axios.get.mockImplementation((url) =>
    Promise.resolve({ data: Object.prototype.hasOwnProperty.call(GET_ROUTES, url) ? GET_ROUTES[url] : {} })
  );
  axios.post.mockResolvedValue({ data: { message: 'ok', order_id: 99 } });
});

const modal = () => document.querySelector('.ant-modal-content');

/** Open the wizard and wait for the Domains step. */
async function openWizard() {
  render(<ACMEAutomation />);
  // Settle the initial fetch on a signal that does NOT depend on which account the component picks
  // as its default — that choice is one of the things under test, so waiting on an account address
  // here would make every test fail at the same early point instead of at its own assertion.
  await waitFor(() => expect(axios.get).toHaveBeenCalledWith('/api/letsencrypt/accounts'));
  await act(async () => {});
  fireEvent.click(screen.getByRole('button', { name: /Request Certificate/i }));
  await screen.findByText('Domain Names');
}

/** antd wires the Form.Item name onto the inner input's id, which is the only stable handle. */
function typeDomain(domain) {
  const input = document.getElementById('domains');
  fireEvent.change(input, { target: { value: domain } });
  fireEvent.keyDown(input, { key: 'Enter', keyCode: 13 });
}

async function selectAccount(email) {
  await act(async () => {
    fireEvent.mouseDown(document.getElementById('account_id'));
  });
  const option = [...document.querySelectorAll('.ant-select-item-option')]
    .find((o) => o.textContent.includes(email));
  if (!option) throw new Error(`account option not found: ${email}`);
  await act(async () => {
    fireEvent.click(option);
  });
}

const next = async () => {
  await act(async () => {
    fireEvent.click(screen.getByRole('button', { name: /^Next$/ }));
  });
};
const submitButton = () => screen.getByRole('button', { name: /Submit Request/i });

async function gotoReview({ domain = 'example.com', account } = {}) {
  await openWizard();
  typeDomain(domain);
  await next();
  // Wait for the Configuration step to actually MOUNT. The transition is async (validateFields
  // returns a promise) and the text "ACME Account" also appears on the dashboard card behind the
  // modal, so waiting on that text can resolve while the wizard is still on step 1.
  await waitFor(() => expect(document.getElementById('account_id')).toBeTruthy());
  if (account) await selectAccount(account);
  await next();
  await screen.findByText('Prerequisite Check');
}

/** The Review step's rendered text. Compared as a whole string on purpose: the assertions must
 *  describe BEHAVIOUR, not the markup this change happens to use, so that a failure means the
 *  wizard resolved the wrong account rather than that a wrapper element moved. */
const reviewText = () => modal().textContent;

async function submitAndGetBody() {
  fireEvent.click(submitButton());
  await waitFor(() => expect(axios.post).toHaveBeenCalled());
  const [url, body] = axios.post.mock.calls[0];
  expect(url).toBe('/api/letsencrypt/certificates');
  return body;
}

describe('certificate wizard with multiple ACME accounts', () => {
  test('an explicitly picked HTTP-01 account survives the step change and is what gets submitted', async () => {
    await gotoReview({ account: HTTP_ACCOUNT.email });

    // The payload is the real evidence. account_id used to come from the form store while
    // challenge_type came from an account object that had reverted to the default, so the API got
    // "HTTP-01 account + dns-01" and answered 422 "no DNS provider configured for DNS-01".
    const body = await submitAndGetBody();
    expect(body.account_id).toBe(HTTP_ACCOUNT.id);
    expect(body.challenge_type).toBe('http-01');
  });

  test('the Review step describes the picked HTTP-01 account, not the default', async () => {
    await gotoReview({ account: HTTP_ACCOUNT.email });

    expect(reviewText()).toContain(HTTP_ACCOUNT.email);
    expect(reviewText()).not.toContain(DNS_ACCOUNT.email);
    // "Challenge Method" and the provider name only render on the DNS-01 branch.
    expect(reviewText()).not.toContain('Challenge Method');
    expect(reviewText()).not.toContain('godaddy');
  });

  test('an explicitly picked DNS-01 account is described and submitted as DNS-01', async () => {
    // Positive control: the DNS-01 path must keep working. This one passed before the fix too,
    // because the default the wizard fell back to happened to be the DNS-01 account.
    await gotoReview({ account: DNS_ACCOUNT.email });

    expect(reviewText()).toContain(DNS_ACCOUNT.email);
    expect(reviewText()).toContain('Challenge Method');
    expect(reviewText()).toContain('godaddy');

    const body = await submitAndGetBody();
    expect(body.account_id).toBe(DNS_ACCOUNT.id);
    expect(body.challenge_type).toBe('dns-01');
  });

  test('with no explicit pick the wizard previews and sends the same default the backend would use', async () => {
    // The backend takes the NEWEST valid account; the UI used to preview the oldest entry of a
    // list ordered by id, so Review described an account the request never went to.
    await gotoReview();

    expect(reviewText()).toContain(HTTP_ACCOUNT.email);
    expect(reviewText()).not.toContain(DNS_ACCOUNT.email);

    const body = await submitAndGetBody();
    // Sent explicitly rather than left to the backend to guess a second time.
    expect(body.account_id).toBe(HTTP_ACCOUNT.id);
    expect(body.challenge_type).toBe('http-01');
  });

  test('the wildcard guard still applies on the Review step, where Submit lives', async () => {
    // Same root cause as the account bug: `domains` is entered on the first step, so a
    // non-preserving useWatch read undefined from Review onward and the guard evaporated at exactly
    // the point it had to hold.
    await gotoReview({ domain: '*.example.com', account: HTTP_ACCOUNT.email });

    expect(reviewText()).toContain('Wildcard requires a DNS-01 account');
    expect(submitButton()).toBeDisabled();
    fireEvent.click(submitButton());
    expect(axios.post).not.toHaveBeenCalled();
  });
});
