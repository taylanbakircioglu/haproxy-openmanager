import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Card, Table, Button, Tag, Space, Modal, Form, Input, Select, Steps,
  message, Row, Col, Statistic, Alert, Tooltip, Switch, theme, Segmented, Collapse,
  Tabs, Timeline, Spin, Empty, Typography, Divider
} from 'antd';
import {
  SafetyCertificateOutlined, PlusOutlined, ReloadOutlined,
  CheckCircleOutlined, ClockCircleOutlined, ExclamationCircleOutlined,
  SyncOutlined, CloseCircleOutlined,
  DeleteOutlined, EyeOutlined,
  CloudDownloadOutlined, UserOutlined, InfoCircleOutlined,
  RocketOutlined, ExperimentOutlined, KeyOutlined
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { useCluster } from '../contexts/ClusterContext';
import axios from 'axios';

const { Option } = Select;

const getErrorMsg = (err, fallback) => {
  const data = err?.response?.data;
  // FastAPI/Pydantic 422s wrap the specific field message in error.details.validation_errors[];
  // the top-level error.message is generic ("Validation error in request data"), so prefer the
  // field-level message (e.g. the EAB base64 hint) when present.
  const fieldMsg = data?.error?.details?.validation_errors?.[0]?.message;
  return fieldMsg || data?.error?.message || data?.detail || fallback;
};

// Issue #35: humanize the dotted event_type tokens emitted for DNS-01 orders so the diagnostics
// timeline reads as a step-by-step progress log rather than raw machine strings. Unknown types
// fall back to the raw token.
const EVENT_LABELS = {
  'acme.dns01.publish': 'Published DNS TXT record',
  'acme.dns01.responded': 'Asked the CA to validate',
  'acme.dns01.validation': 'DNS-01 validation result',
  'acme.dns01.cleanup': 'Removed DNS TXT record',
  'acme.order.requested': 'Certificate requested',
};
const humanizeEventType = (t) => EVENT_LABELS[t] || t;

// Render letsencrypt_orders.error_detail (TEXT column). Backend now writes
// structured JSON-strings (stage / http_status / ca_response / timestamp) for
// CA-side failures, but legacy rows may still contain plain strings.
// Attempt JSON parse first; otherwise fall back to literal text.
const renderErrorDetail = (raw) => {
  if (!raw) return null;
  let parsed = null;
  if (typeof raw === 'string' && raw.trim().startsWith('{')) {
    try { parsed = JSON.parse(raw); } catch (_e) { parsed = null; }
  } else if (typeof raw === 'object') {
    parsed = raw;
  }
  if (!parsed || typeof parsed !== 'object') {
    return <span style={{ whiteSpace: 'pre-wrap' }}>{String(raw)}</span>;
  }
  const stage = parsed.stage || parsed.step || 'error';
  const httpStatus = parsed.http_status;
  const reason = parsed.reason;
  const caRespRaw = parsed.ca_response;
  const caRespText = caRespRaw == null
    ? null
    : (typeof caRespRaw === 'string' ? caRespRaw : JSON.stringify(caRespRaw, null, 2));
  const ts = parsed.timestamp;
  return (
    <div style={{ fontSize: 13 }}>
      <div><strong>Stage:</strong> {stage}{httpStatus ? ` (HTTP ${httpStatus})` : ''}</div>
      {reason && <div><strong>Reason:</strong> {reason}</div>}
      {ts && <div><strong>At:</strong> {ts}</div>}
      {caRespText && (
        <details style={{ marginTop: 6 }}>
          <summary style={{ cursor: 'pointer' }}>CA response</summary>
          <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', marginTop: 6 }}>
            {caRespText}
          </pre>
        </details>
      )}
    </div>
  );
};

const ACMEAutomation = () => {
  const navigate = useNavigate();
  const { clusters: allClusters, selectCluster } = useCluster();
  const [orders, setOrders] = useState([]);
  const [accounts, setAccounts] = useState([]);
  const [renewalSchedule, setRenewalSchedule] = useState([]);
  const [prerequisites, setPrerequisites] = useState(null);
  const [loading, setLoading] = useState(false);
  const [wizardVisible, setWizardVisible] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);
  const [wizardForm] = Form.useForm();
  const [submitting, setSubmitting] = useState(false);
  const [clusters, setClusters] = useState([]);
  const [orderDetail, setOrderDetail] = useState(null);
  const [detailVisible, setDetailVisible] = useState(false);
  const [registerVisible, setRegisterVisible] = useState(false);
  const [registerForm] = Form.useForm();
  const [registering, setRegistering] = useState(false);
  const [accountDetailVisible, setAccountDetailVisible] = useState(false);
  const [orderFilter, setOrderFilter] = useState('active');
  const { token } = theme.useToken();

  // Issue #35: DNS-01 provider catalog + global enable flag (from GET /dns-providers).
  const [dnsProviders, setDnsProviders] = useState([]);
  const [dns01Enabled, setDns01Enabled] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const regChallengeType = Form.useWatch('challenge_type', registerForm);
  const regDnsProvider = Form.useWatch('dns_provider', registerForm);
  const wizardAccountId = Form.useWatch('account_id', wizardForm);
  const wizardDomains = Form.useWatch('domains', wizardForm);
  const selectedDnsProvider = dnsProviders.find(p => p.name === regDnsProvider) || null;

  // Issue #35: per-account DNS credential management (view/replace/clear after creation).
  const [credModalVisible, setCredModalVisible] = useState(false);
  const [credAccount, setCredAccount] = useState(null);
  const [credMeta, setCredMeta] = useState(null);
  const [credLoading, setCredLoading] = useState(false);
  const [credSaving, setCredSaving] = useState(false);
  const [credForm] = Form.useForm();
  const credProvider = credAccount ? (dnsProviders.find(p => p.name === credAccount.dns_provider) || null) : null;

  // v1.5.0 Issue #13: ACME Diagnostic Panel state
  const [diagVisible, setDiagVisible] = useState(false);
  const [diagOrderId, setDiagOrderId] = useState(null);
  const [diagOrder, setDiagOrder] = useState(null);
  const [diagChecks, setDiagChecks] = useState([]);
  const [diagHumanizedError, setDiagHumanizedError] = useState(null);
  const [diagEvents, setDiagEvents] = useState([]);
  const [diagLoading, setDiagLoading] = useState(false);
  const [diagRunningCheckId, setDiagRunningCheckId] = useState(null);
  // Bulgu #94 (Round-25 audit): the diagnostic panel's job is to make
  // failures visible. We now keep dedicated error envelopes for the
  // diagnostics POST and the /events GET so the modal can render them
  // inline instead of silently dropping them like the v1.5.1 build did.
  const [diagRunError, setDiagRunError] = useState(null);
  const [diagEventsError, setDiagEventsError] = useState(null);
  const [diagMeta, setDiagMeta] = useState(null);
  const diagPollRef = useRef(null);
  const diagPollFailCountRef = useRef(0);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [ordersRes, accountsRes, renewalRes, clustersRes, prereqRes, dnsRes] = await Promise.allSettled([
        axios.get('/api/letsencrypt/orders'),
        axios.get('/api/letsencrypt/accounts'),
        axios.get('/api/letsencrypt/renewal-schedule'),
        axios.get('/api/clusters'),
        axios.get('/api/letsencrypt/prerequisites'),
        axios.get('/api/letsencrypt/dns-providers'),
      ]);
      if (ordersRes.status === 'fulfilled') setOrders(ordersRes.value.data || []);
      if (accountsRes.status === 'fulfilled') setAccounts(accountsRes.value.data || []);
      if (prereqRes.status === 'fulfilled') setPrerequisites(prereqRes.value.data);
      if (renewalRes.status === 'fulfilled') setRenewalSchedule(renewalRes.value.data || []);
      if (clustersRes.status === 'fulfilled') setClusters(clustersRes.value.data?.clusters || []);
      if (dnsRes.status === 'fulfilled') {
        setDnsProviders(dnsRes.value.data?.providers || []);
        setDns01Enabled(!!dnsRes.value.data?.dns01_enabled);
      }
    } catch (err) {
      console.error('Error loading ACME data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Commit 8b (Audit Tur 3): conditional UI polling — auto-refresh every 30s
  // when there are any in-progress or stuck orders, so the user sees Auto-Completion
  // task results without manually clicking Refresh. Pauses when nothing is pending.
  const hasInProgress = orders.some(o =>
    o.status === 'pending' || o.status === 'processing' || o.status === 'ready' ||
    (o.status === 'valid' && !o.ssl_certificate_id)
  );
  // Track the order whose detail modal is open so the poll can refresh it WITHOUT
  // making the interval depend on orderDetail (which would recreate it every poll).
  const openDetailIdRef = useRef(null);
  const detailRefetchInFlightRef = useRef(false);
  useEffect(() => {
    openDetailIdRef.current = (detailVisible && orderDetail?.id) ? orderDetail.id : null;
  }, [detailVisible, orderDetail]);
  useEffect(() => {
    if (!hasInProgress) return undefined;
    const interval = setInterval(() => {
      fetchData();
      // Keep an open order-detail modal (e.g. a manual DNS-01 order awaiting validation)
      // in sync so its status / TXT block / Verify button cannot go stale. Skip if a prior
      // refetch is still in flight so slow backends don't pile up overlapping requests.
      const oid = openDetailIdRef.current;
      if (oid && !detailRefetchInFlightRef.current) {
        detailRefetchInFlightRef.current = true;
        axios.get(`/api/letsencrypt/orders/${oid}`)
          .then((r) => setOrderDetail((prev) => (prev && prev.id === oid ? r.data : prev)))
          .catch(() => { /* transient; the next poll retries */ })
          .finally(() => { detailRefetchInFlightRef.current = false; });
      }
    }, 30000);
    return () => clearInterval(interval);
  }, [hasInProgress, fetchData]);

  const acmeCerts = renewalSchedule.length;
  const calcDaysLeft = (expiryDate) => {
    if (!expiryDate) return null;
    return Math.ceil((new Date(expiryDate) - new Date()) / (1000 * 60 * 60 * 24));
  };
  // Manual DNS-01 certs are not auto-renewed (even a legacy row left at auto_renew=TRUE), so they
  // must not drive the "Next Renewal" countdown, which implies an automated event.
  const isManualDnsCert = (c) => c.challenge_type === 'dns-01' && (c.dns_provider || 'manual') === 'manual';
  const nextRenewal = renewalSchedule.find(c => c.auto_renew && !isManualDnsCert(c) && calcDaysLeft(c.expiry_date) > 0);
  const nextRenewalDays = nextRenewal ? calcDaysLeft(nextRenewal.expiry_date) : null;
  // Issue #11/#12: an order is "in progress" if it's pre-valid OR valid-but-not-downloaded (stuck).
  // Including 'ready' here ensures the dashboard counter & UI auto-refresh react to all in-flight states.
  const isOrderStuck = (o) => o.status === 'valid' && !o.ssl_certificate_id;
  const pendingOrders = orders.filter(o =>
    o.status === 'pending' || o.status === 'processing' || o.status === 'ready' || isOrderStuck(o)
  );
  const activeAccount = accounts.find(a => a.status === 'valid') || null;
  const acmeAccount = activeAccount || (accounts.length > 0 ? accounts[accounts.length - 1] : null);
  const acmeEnabledClusters = clusters.filter(c => c.acme_enabled && c.is_active);
  // Issue #35: the cert wizard adapts to the selected account's challenge method.
  const wizardAccount = accounts.find(a => a.id === wizardAccountId) || activeAccount || acmeAccount;
  const wizardIsDns01 = (wizardAccount?.challenge_type === 'dns-01');
  const wizardDnsManual = wizardIsDns01 && (wizardAccount?.dns_provider === 'manual');
  // Wildcard certificates can only be issued over DNS-01. Catch this client-side so the user is
  // told their mistake up front instead of waiting for a CA-side rejection.
  const wizardHasWildcard = (wizardDomains || []).some(d => typeof d === 'string' && d.trim().startsWith('*.'));
  const wizardWildcardBlocked = wizardHasWildcard && !wizardIsDns01;
  // A DNS-01 account can exist while the global kill-switch is off (e.g. an admin disabled it later).
  // Issuing would be rejected by the backend, so block it in the wizard with a clear reason.
  const wizardDns01Disabled = wizardIsDns01 && !dns01Enabled;
  // Surface a direct credentials shortcut on the dashboard card when the primary account uses an
  // automated DNS provider (manual providers need no credentials).
  const acmeAccountProvider = acmeAccount ? dnsProviders.find(p => p.name === acmeAccount.dns_provider) : null;
  const acmeAccountNeedsCreds = acmeAccount?.challenge_type === 'dns-01' && (acmeAccountProvider?.credential_fields || []).length > 0;

  const filteredOrders = orders.filter(o => {
    if (orderFilter === 'active') return !['cancelled', 'invalid', 'valid'].includes(o.status);
    if (orderFilter === 'completed') return o.status === 'valid';
    if (orderFilter === 'failed') return o.status === 'cancelled' || o.status === 'invalid';
    return true;
  });

  const handleRequestCert = async () => {
    try {
      const values = wizardForm.getFieldsValue(true);
      if (!values.domains || values.domains.length === 0) {
        message.error('At least one domain is required');
        return;
      }
      // Defense-in-depth: the Submit button is already disabled for these, but guard here too.
      if (wizardWildcardBlocked) {
        message.error('Wildcard certificates require a DNS-01 account. Select a DNS-01 account or remove the wildcard domain.');
        return;
      }
      if (wizardDns01Disabled) {
        message.error('DNS-01 is disabled by an administrator. Enable it in Settings > ACME to issue this certificate.');
        return;
      }
      setSubmitting(true);
      // Resolve the chosen account's challenge method so DNS-01/wildcard requests are explicit.
      // Use the same resolution as the wizard description (wizardAccount) so what the user reviewed
      // matches what is sent.
      const challengeType = wizardAccount?.challenge_type;  // 'http-01' | 'dns-01' | undefined
      // Manual DNS-01 can't auto-renew (the wizard shows the switch off+disabled). Send false to
      // match the displayed state rather than relying only on the backend to override it.
      const autoRenew = wizardDnsManual ? false : (values.auto_renew !== false);
      const res = await axios.post('/api/letsencrypt/certificates', {
        domains: values.domains,
        cluster_ids: values.cluster_ids || [],
        auto_renew: autoRenew,
        account_id: values.account_id || null,
        challenge_type: challengeType || undefined,
      });
      message.success(res.data?.message || 'Certificate request submitted');
      if (res.data?.warnings?.length > 0) {
        res.data.warnings.forEach(w => message.warning(w, 8));
      }
      setWizardVisible(false);
      setWizardStep(0);
      wizardForm.resetFields();
      fetchData();
      // For a manual DNS-01 order the user must publish the TXT record(s) next, so open the
      // order detail straight away instead of leaving them to hunt for it.
      if (res.data?.challenge_type === 'dns-01'
          && (res.data?.dns_provider || 'manual') === 'manual'
          && res.data?.order_id) {
        handleViewOrder(res.data.order_id);
      } else if (res.data?.challenge_type === 'dns-01') {
        // Automated DNS-01 (e.g. Cloudflare): reassure the user it is hands-off.
        message.info('Automated DNS-01: the TXT records will be published and validated automatically. No action needed.', 6);
      }
    } catch (err) {
      message.error(getErrorMsg(err, 'Failed to request certificate'));
    } finally {
      setSubmitting(false);
    }
  };

  const handleRetry = async (orderId) => {
    try {
      const res = await axios.post(`/api/letsencrypt/orders/${orderId}/retry`);
      // Backend may signal that the auto-completion task is already processing
      // this order — show as info (not success) so the user understands no
      // duplicate work is needed. UI auto-refresh will pick up the result.
      const msg = res.data?.message || 'Retry submitted';
      if (res.data?.in_progress) {
        message.info(msg, 6);
      } else {
        message.success(msg);
      }
      fetchData();
    } catch (err) {
      message.error(getErrorMsg(err, 'Retry failed'));
    }
  };

  const handleCancel = (orderId) => {
    Modal.confirm({
      title: 'Cancel Order',
      content: 'Are you sure you want to cancel this certificate order? This action cannot be undone.',
      okText: 'Cancel Order',
      okButtonProps: { danger: true },
      onOk: async () => {
        try {
          await axios.delete(`/api/letsencrypt/orders/${orderId}`);
          message.success('Order cancelled');
          fetchData();
        } catch (err) {
          message.error(getErrorMsg(err, 'Cancel failed'));
        }
      },
    });
  };

  const handleViewOrder = async (orderId) => {
    try {
      const res = await axios.get(`/api/letsencrypt/orders/${orderId}`);
      setOrderDetail(res.data);
      setDetailVisible(true);
    } catch (err) {
      message.error(getErrorMsg(err, 'Failed to load order details'));
    }
  };

  // v1.5.0 Issue #13: open diagnostics modal for an order
  // Bulgu #94 (Round-25 audit): the modal is the operator's last line
  // of defence when ACME goes sideways — it MUST render failure causes
  // verbatim instead of swallowing them. We capture both the
  // diagnostics POST and the events GET errors into dedicated state
  // and stop the auto-tail poll after consecutive failures so the
  // network tab does not get spammed with /events 500s every 5s.
  const handleDiagnose = async (orderId) => {
    setDiagOrderId(orderId);
    setDiagVisible(true);
    setDiagLoading(true);
    setDiagChecks([]);
    setDiagHumanizedError(null);
    setDiagEvents([]);
    setDiagRunError(null);
    setDiagEventsError(null);
    setDiagMeta(null);
    diagPollFailCountRef.current = 0;
    try {
      const [orderRes, diagRes] = await Promise.allSettled([
        axios.get(`/api/letsencrypt/orders/${orderId}`),
        axios.post(`/api/letsencrypt/orders/${orderId}/diagnostics`),
      ]);
      if (orderRes.status === 'fulfilled') setDiagOrder(orderRes.value.data);
      if (diagRes.status === 'fulfilled') {
        const data = diagRes.value.data || {};
        setDiagChecks(data.checks || []);
        setDiagHumanizedError(data.humanized_error || null);
        setDiagMeta(data.meta || null);
        // Bulgu #94 follow-up: the Round-25 backend now returns HTTP 200
        // with `status: 'diagnostics_unavailable'` + `meta.error_stage`
        // instead of HTTP 500 when the diagnostic runner itself crashes
        // (e.g. `column a.last_heartbeat does not exist` on a stale
        // deploy). The fulfilled branch must therefore detect the
        // envelope and surface the structured failure alert — otherwise
        // the operator would only see one `diagnostics_runner` row in
        // the table without the prominent red banner that explains the
        // crash + correlation_id. This is exactly the "panel renders
        // but doesn't visibly say WHY" trap we're trying to avoid.
        if (data.status === 'diagnostics_unavailable' || data?.meta?.error_stage) {
          setDiagRunError({
            status: 200,
            message: data?.meta?.error_message
              || data?.checks?.[0]?.message
              || 'Diagnostic runner failed',
            correlation_id: data?.meta?.correlation_id || null,
            error_stage: data?.meta?.error_stage || null,
            error_type: data?.meta?.error_type || null,
          });
        }
      } else if (diagRes.status === 'rejected') {
        const resp = diagRes.reason?.response;
        const detail = resp?.data?.detail
          || resp?.data?.error?.message
          || diagRes.reason?.message
          || 'Diagnostics failed';
        setDiagRunError({
          status: resp?.status || 0,
          message: detail,
          correlation_id: resp?.data?.error?.correlation_id || resp?.headers?.['x-correlation-id'] || null,
        });
        message.error(detail);
      }
      // Best-effort merged event log fetch — bug #95: server-side schema
      // drift used to return 500; we now surface that in the modal so
      // the operator sees "events unavailable because <reason>".
      try {
        const evRes = await axios.get(`/api/letsencrypt/orders/${orderId}/events`);
        setDiagEvents(evRes.data?.events || []);
        if (evRes.data?.meta?.errors?.length) {
          setDiagEventsError({
            kind: 'partial',
            errors: evRes.data.meta.errors,
            correlation_id: evRes.data.meta.correlation_id,
          });
        }
      } catch (evErr) {
        const resp = evErr?.response;
        setDiagEventsError({
          kind: 'fatal',
          status: resp?.status || 0,
          message: resp?.data?.detail
            || resp?.data?.error?.message
            || evErr?.message
            || 'Event log unavailable',
          correlation_id: resp?.data?.error?.correlation_id || null,
        });
      }
    } finally {
      setDiagLoading(false);
    }
  };

  const handleRerunCheck = async (checkId) => {
    if (!diagOrderId) return;
    setDiagRunningCheckId(checkId);
    try {
      const res = await axios.post(
        `/api/letsencrypt/orders/${diagOrderId}/diagnostics/${checkId}/rerun`
      );
      const updated = res.data?.check;
      if (updated) {
        setDiagChecks((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
      }
    } catch (err) {
      message.error(err?.response?.data?.detail || 'Re-run failed');
    } finally {
      setDiagRunningCheckId(null);
    }
  };

  // Auto-tail event log every 5s while modal open + order is in flight
  useEffect(() => {
    if (!diagVisible || !diagOrderId) {
      if (diagPollRef.current) {
        clearInterval(diagPollRef.current);
        diagPollRef.current = null;
      }
      return undefined;
    }
    const inFlight =
      diagOrder &&
      (['pending', 'processing', 'ready', 'wizard_staged'].includes(diagOrder.status) ||
        (diagOrder.status === 'valid' && !diagOrder.ssl_certificate_id));
    if (!inFlight) return undefined;
    diagPollRef.current = setInterval(async () => {
      try {
        const evRes = await axios.get(`/api/letsencrypt/orders/${diagOrderId}/events`);
        setDiagEvents(evRes.data?.events || []);
        diagPollFailCountRef.current = 0;
        if (evRes.data?.meta?.errors?.length) {
          setDiagEventsError({
            kind: 'partial',
            errors: evRes.data.meta.errors,
            correlation_id: evRes.data.meta.correlation_id,
          });
        } else {
          setDiagEventsError(null);
        }
      } catch (e) {
        // Bulgu #94 (Round-25): stop the auto-tail after 3 consecutive
        // failures so a broken backend doesn't drown the user's
        // network tab in 500s. Operator can re-open the modal to retry.
        diagPollFailCountRef.current += 1;
        if (diagPollFailCountRef.current >= 3) {
          if (diagPollRef.current) {
            clearInterval(diagPollRef.current);
            diagPollRef.current = null;
          }
          const resp = e?.response;
          setDiagEventsError({
            kind: 'fatal',
            status: resp?.status || 0,
            message: resp?.data?.detail
              || resp?.data?.error?.message
              || e?.message
              || 'Event log polling stopped after repeated failures',
            correlation_id: resp?.data?.error?.correlation_id || null,
            polling_stopped: true,
          });
        }
      }
    }, 5000);
    return () => {
      if (diagPollRef.current) {
        clearInterval(diagPollRef.current);
        diagPollRef.current = null;
      }
    };
  }, [diagVisible, diagOrderId, diagOrder]);

  const closeDiagModal = () => {
    setDiagVisible(false);
    setDiagOrderId(null);
    setDiagOrder(null);
    setDiagChecks([]);
    setDiagHumanizedError(null);
    setDiagEvents([]);
    setDiagRunError(null);
    setDiagEventsError(null);
    setDiagMeta(null);
    diagPollFailCountRef.current = 0;
    if (diagPollRef.current) {
      clearInterval(diagPollRef.current);
      diagPollRef.current = null;
    }
  };

  const checkStatusToTag = (status) => {
    if (status === 'ok') return <Tag color="success" icon={<CheckCircleOutlined />}>OK</Tag>;
    if (status === 'warn') return <Tag color="warning" icon={<ExclamationCircleOutlined />}>WARN</Tag>;
    if (status === 'fail') return <Tag color="error" icon={<CloseCircleOutlined />}>FAIL</Tag>;
    if (status === 'skipped') return <Tag>SKIPPED</Tag>;
    return <Tag>{(status || '').toUpperCase()}</Tag>;
  };

  const handleImportCAChain = async () => {
    Modal.confirm({
      title: 'Import Let\'s Encrypt CA Chain',
      content: 'This will download and store the latest Let\'s Encrypt root and intermediate certificates. Continue?',
      onOk: async () => {
        try {
          const res = await axios.post('/api/letsencrypt/import-ca-chain');
          message.success(res.data?.message || 'CA chain imported');
        } catch (err) {
          message.error(getErrorMsg(err, 'Import failed'));
        }
      },
    });
  };

  const handleRegisterAccount = async () => {
    try {
      const values = await registerForm.validateFields();
      setRegistering(true);
      const challengeType = dns01Enabled ? (values.challenge_type || 'http-01') : 'http-01';
      const dnsProvider = challengeType === 'dns-01' ? (values.dns_provider || null) : null;
      const res = await axios.post('/api/letsencrypt/accounts', {
        email: values.email,
        tos_agreed: values.tos_agreed,
        challenge_type: challengeType,
        dns_provider: dnsProvider,
        // EAB for CAs that require it (ZeroSSL/Google). Empty → backend falls back to global Settings.
        eab_kid: (values.eab_kid || '').trim() || undefined,
        eab_hmac_key: (values.eab_hmac_key || '').trim() || undefined,
      });
      const accountId = res.data?.id;
      // For an automated DNS-01 provider, store the entered credentials (verified server-side).
      const provider = dnsProviders.find(p => p.name === dnsProvider);
      let credFailed = false;
      if (challengeType === 'dns-01' && accountId && provider && (provider.credential_fields || []).length > 0) {
        const creds = {};
        (provider.credential_fields || []).forEach(f => {
          const v = values[`cred_${f.key}`];
          if (v != null && v !== '') creds[f.key] = v;
        });
        try {
          const r2 = await axios.put(`/api/letsencrypt/accounts/${accountId}/dns-credentials`, {
            dns_provider: dnsProvider,
            credentials: creds,
          });
          message.success(r2.data?.detail || 'DNS provider credentials saved');
        } catch (credErr) {
          credFailed = true;
          message.warning(getErrorMsg(credErr, `Account "${res.data?.email || values.email}" registered, but the DNS credentials could not be saved. You can fix them from the account's DNS credentials action.`), 8);
        }
      }
      // Only close + reset on full success. On a credential-save failure, keep the modal open with
      // the entered values so the user can correct the token and re-submit (the account already
      // exists and the PUT re-verifies) — avoids discarding input, a dead-end, and a misleading
      // success toast (Finding 7). The warning toast above explains what to fix.
      if (!credFailed) {
        message.success(`ACME account registered: ${res.data?.email || values.email}`);
        setRegisterVisible(false);
        registerForm.resetFields();
      }
      fetchData();
    } catch (err) {
      // Inline field-validation rejections already render under each field; don't also
      // fire a generic error toast (mirrors handleSaveDnsCreds).
      if (err?.errorFields) return;
      message.error(getErrorMsg(err, 'Account registration failed'));
    } finally {
      setRegistering(false);
    }
  };

  // Issue #35: manual DNS-01 — user asserts the TXT records are published; tell the CA to validate.
  const handleDnsConfirm = async (orderId) => {
    if (confirming) return;  // guard the leading-edge double-click (loading alone does not block a synchronous re-fire)
    try {
      setConfirming(true);
      const res = await axios.post(`/api/letsencrypt/orders/${orderId}/dns-confirm`);
      message.success(res.data?.message || 'DNS-01 confirmation submitted; the CA will validate shortly.');
      // Refresh the orders list AND the open detail modal so the user sees the new state
      // (otherwise the modal shows a stale TXT block + an active Verify button).
      fetchData();
      try {
        const fresh = await axios.get(`/api/letsencrypt/orders/${orderId}`);
        // Only repopulate if the same order's detail is still open (the user may have
        // closed it or navigated to another order while the request was in flight).
        setOrderDetail((prev) => (prev && prev.id === orderId ? fresh.data : prev));
      } catch (_e) { /* list refresh already happened; modal stays as-is */ }
    } catch (err) {
      message.error(getErrorMsg(err, 'Failed to confirm DNS-01'));
    } finally {
      setConfirming(false);
    }
  };

  // Issue #35: view / replace / clear an account's DNS provider credentials after creation.
  const openDnsCredsModal = async (account) => {
    setCredAccount(account);
    setCredMeta(null);
    credForm.resetFields();
    setCredModalVisible(true);
    setCredLoading(true);
    try {
      const res = await axios.get(`/api/letsencrypt/accounts/${account.id}/dns-credentials`);
      setCredMeta(res.data);
    } catch (err) {
      message.error(getErrorMsg(err, 'Failed to load DNS credentials'));
    } finally {
      setCredLoading(false);
    }
  };

  const handleSaveDnsCreds = async () => {
    if (!credAccount || !credProvider) return;
    try {
      const values = await credForm.validateFields();
      setCredSaving(true);
      const creds = {};
      (credProvider.credential_fields || []).forEach(f => {
        const v = values[`cred_${f.key}`];
        if (v != null && v !== '') creds[f.key] = v;
      });
      const res = await axios.put(`/api/letsencrypt/accounts/${credAccount.id}/dns-credentials`, {
        dns_provider: credAccount.dns_provider,
        credentials: creds,
      });
      message.success(res.data?.detail || 'DNS provider credentials saved and verified');
      setCredModalVisible(false);
      credForm.resetFields();
      fetchData();
    } catch (err) {
      if (err?.errorFields) return;  // antd validation errors shown inline
      message.error(getErrorMsg(err, 'Failed to save DNS credentials'));
    } finally {
      setCredSaving(false);
    }
  };

  const handleClearDnsCreds = () => {
    if (!credAccount) return;
    Modal.confirm({
      title: 'Clear DNS credentials',
      content: `Remove the stored DNS provider credentials for ${credAccount.email}? Automated DNS-01 issuance/renewal will stop working until you re-enter them.`,
      okText: 'Clear',
      okButtonProps: { danger: true },
      onOk: async () => {
        try {
          await axios.delete(`/api/letsencrypt/accounts/${credAccount.id}/dns-credentials`);
          message.success('DNS credentials cleared');
          setCredModalVisible(false);
          fetchData();
        } catch (err) {
          message.error(getErrorMsg(err, 'Failed to clear DNS credentials'));
        }
      },
    });
  };

  const handleDeactivateAccount = (accountId, email) => {
    Modal.confirm({
      title: 'Deactivate ACME Account',
      content: (
        <div>
          <p>Are you sure you want to deactivate the account <strong>{email}</strong>?</p>
          <p style={{ color: '#ff4d4f' }}>
            This will permanently deactivate the account at the Certificate Authority.
            Active orders using this account should be completed or cancelled first.
          </p>
        </div>
      ),
      okText: 'Deactivate',
      okButtonProps: { danger: true },
      onOk: async () => {
        try {
          await axios.delete(`/api/letsencrypt/accounts/${accountId}`);
          message.success('Account deactivated successfully');
          fetchData();
        } catch (err) {
          message.error(getErrorMsg(err, 'Failed to deactivate account'));
        }
      },
    });
  };

  const handleRemoveAccount = (accountId, email) => {
    Modal.confirm({
      title: 'Permanently Remove Account',
      content: (
        <div>
          <p>Are you sure you want to permanently remove <strong>{email}</strong> from the database?</p>
          <p style={{ color: '#ff4d4f' }}>
            This will delete the account record and all associated orders from the local database.
            This action cannot be undone.
          </p>
        </div>
      ),
      okText: 'Remove Permanently',
      okButtonProps: { danger: true },
      onOk: async () => {
        try {
          await axios.delete(`/api/letsencrypt/accounts/${accountId}/permanent`);
          message.success('Account permanently removed');
          fetchData();
        } catch (err) {
          message.error(getErrorMsg(err, 'Failed to remove account'));
        }
      },
    });
  };

  const statusTag = (status, record) => {
    // v1.5.0: clicking the status tag opens diagnostics for table rows.
    const clickable = record && record.id;
    const onClick = clickable ? () => handleDiagnose(record.id) : undefined;
    const cursor = clickable ? { cursor: 'pointer' } : undefined;

    // Issue #12 / Commit 4a: highlight "valid but not downloaded" stuck orders prominently.
    if (record && record.status === 'valid' && !record.ssl_certificate_id) {
      return (
        <Tag color="warning" icon={<ExclamationCircleOutlined />} style={cursor} onClick={onClick}>
          PENDING DOWNLOAD
        </Tag>
      );
    }
    const map = {
      pending: { color: 'processing', icon: <ClockCircleOutlined /> },
      processing: { color: 'processing', icon: <SyncOutlined spin /> },
      ready: { color: 'warning', icon: <ExclamationCircleOutlined /> },
      valid: { color: 'success', icon: <CheckCircleOutlined /> },
      invalid: { color: 'error', icon: <CloseCircleOutlined /> },
      cancelled: { color: 'default', icon: <CloseCircleOutlined /> },
      wizard_staged: { color: 'cyan', icon: <ClockCircleOutlined /> },
    };
    const cfg = map[status] || { color: 'default', icon: null };
    return (
      <Tag color={cfg.color} icon={cfg.icon} style={cursor} onClick={onClick}>
        {(status || 'unknown').toUpperCase()}
      </Tag>
    );
  };

  const orderColumns = [
    {
      title: 'ID', dataIndex: 'id', key: 'id', width: 60,
    },
    {
      title: 'Domains', dataIndex: 'domains', key: 'domains',
      render: (domains) => (domains || []).map(d => <Tag key={d}>{d}</Tag>),
    },
    {
      title: 'Status', dataIndex: 'status', key: 'status',
      render: (status, record) => statusTag(status, record),
    },
    {
      title: 'Method', key: 'method', width: 170,
      render: (_, record) => {
        const ct = record.challenge_type || 'http-01';
        if (ct !== 'dns-01') return <Tag>HTTP-01</Tag>;
        const prov = record.dns_provider || 'manual';
        const needsAction = prov === 'manual' && (record.status === 'pending' || record.status === 'processing');
        return needsAction
          ? <Tag color="warning" icon={<ExclamationCircleOutlined />}>DNS-01 (manual): action needed</Tag>
          : <Tag>DNS-01 ({prov})</Tag>;
      },
    },
    {
      title: 'Account', dataIndex: 'account_email', key: 'account_email', ellipsis: true,
      render: (e) => e || '-',
    },
    {
      title: 'Created', dataIndex: 'created_at', key: 'created_at',
      render: (d) => d ? new Date(d).toLocaleString() : '-',
    },
    {
      title: 'Actions', key: 'actions',
      render: (_, record) => {
        const stuck = isOrderStuck(record);
        const showRetry = record.status === 'pending' || record.status === 'processing' || record.status === 'ready';
        const showComplete = stuck;
        // Cancel: any non-final state (incl. stuck), but not for fully-completed valid orders.
        const showCancel = (record.status !== 'valid' && record.status !== 'cancelled') || stuck;
        return (
          <Space>
            <Tooltip title="View Details">
              <Button icon={<EyeOutlined />} size="small" onClick={() => handleViewOrder(record.id)} />
            </Tooltip>
            <Tooltip title="Diagnose (pre-flight checks + event log)">
              <Button
                icon={<ExperimentOutlined />}
                size="small"
                onClick={() => handleDiagnose(record.id)}
              />
            </Tooltip>
            {showRetry && (
              <Tooltip title="Retry / Finalize">
                <Button icon={<ReloadOutlined />} size="small" type="primary" ghost onClick={() => handleRetry(record.id)} />
              </Tooltip>
            )}
            {showComplete && (
              <Tooltip title="Complete (download certificate)">
                <Button icon={<CheckCircleOutlined />} size="small" type="primary" onClick={() => handleRetry(record.id)}>
                  Complete
                </Button>
              </Tooltip>
            )}
            {showCancel && (
              <Tooltip title={stuck ? "Cancel stuck order" : "Cancel"}>
                <Button icon={<DeleteOutlined />} size="small" danger onClick={() => handleCancel(record.id)} />
              </Tooltip>
            )}
          </Space>
        );
      },
    },
  ];

  const renewalColumns = [
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Domain', dataIndex: 'primary_domain', key: 'primary_domain' },
    {
      title: 'Expiry', dataIndex: 'expiry_date', key: 'expiry_date',
      render: (d) => d ? new Date(d).toLocaleDateString() : '-',
    },
    {
      title: 'Days Left', key: 'days_left',
      render: (_, record) => {
        const d = calcDaysLeft(record.expiry_date);
        if (d === null) return '-';
        const color = d <= 7 ? 'red' : d <= 30 ? 'orange' : 'green';
        return <Tag color={color}>{d} days</Tag>;
      },
    },
    {
      title: 'Method', key: 'method', width: 130,
      render: (_, record) => {
        const ct = record.challenge_type || 'http-01';
        if (ct !== 'dns-01') return <Tag>HTTP-01</Tag>;
        return <Tag>DNS-01 ({record.dns_provider || 'manual'})</Tag>;
      },
    },
    {
      title: 'Auto-Renew', dataIndex: 'auto_renew', key: 'auto_renew',
      render: (v, record) => {
        const isManualDns = record.challenge_type === 'dns-01' && (record.dns_provider || 'manual') === 'manual';
        if (isManualDns) {
          return (
            <Tooltip title="Manual DNS-01 cannot auto-renew unattended. Re-publish the TXT record and request renewal before expiry.">
              <Tag color="warning" icon={<ExclamationCircleOutlined />}>Manual (re-publish TXT)</Tag>
            </Tooltip>
          );
        }
        return v ? <Tag color="green">Enabled</Tag> : <Tag>Disabled</Tag>;
      },
    },
  ];

  const wizardSteps = [
    {
      title: 'Domains',
      content: (
        <>
          <Form.Item
            name="domains"
            label="Domain Names"
            rules={[{ required: true, message: 'Enter at least one domain' }]}
          >
            <Select
              mode="tags"
              placeholder="e.g. example.com, www.example.com"
              tokenSeparators={[',', ' ']}
            />
          </Form.Item>
          <Alert
            type="info"
            showIcon
            message={wizardIsDns01
              ? "DNS-01: validated via a DNS TXT record, so no public port 80 is needed. Wildcards (*.example.com) are supported. Note that a wildcard does not cover the bare apex (example.com); add it as a separate domain if you need both."
              : "Each domain must resolve to an HAProxy node with ACME challenge routing enabled (HTTP-01)."}
          />
          {wizardWildcardBlocked && (
            <Alert
              type="warning"
              showIcon
              style={{ marginTop: 12 }}
              message="Wildcard requires a DNS-01 account"
              description="A wildcard domain (*.example.com) can only be validated over DNS-01. The currently selected account uses HTTP-01. Choose a DNS-01 account in the next step, or remove the wildcard domain."
            />
          )}
        </>
      ),
    },
    {
      title: 'Configuration',
      content: (
        <>
          <Form.Item name="cluster_ids" label="Target Clusters (optional)">
            <Select mode="multiple" placeholder="Leave empty for global certificate" allowClear>
              {clusters.map(c => (
                <Option key={c.id} value={c.id}>
                  {c.name} {wizardIsDns01 ? '' : (c.acme_enabled ? '' : '(ACME not enabled)')}
                </Option>
              ))}
            </Select>
          </Form.Item>
          {wizardIsDns01 && (
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 16 }}
              message="DNS-01 needs no ACME Challenge Routing. Any active cluster works."
              description={wizardDnsManual
                ? "This account uses a manual DNS provider: after submitting, open the order and publish the shown TXT record, then confirm."
                : "The DNS TXT record(s) will be published automatically."}
            />
          )}
          {wizardDnsManual ? (
            // Manual DNS-01 cannot auto-renew (the backend forces it off); show the control off and
            // disabled so it matches the outcome rather than implying an automated renewal.
            <Form.Item label="Auto-Renew">
              <Switch checked={false} disabled />
            </Form.Item>
          ) : (
            <Form.Item name="auto_renew" label="Auto-Renew" valuePropName="checked" initialValue={true}>
              <Switch />
            </Form.Item>
          )}
          {wizardDnsManual && (
            <Alert
              type="warning"
              showIcon
              style={{ marginTop: -8, marginBottom: 16 }}
              message="Manual DNS-01 cannot auto-renew unattended. You will need to re-publish the TXT record at renewal time."
            />
          )}
          {accounts.length > 1 && (
            <Form.Item
              name="account_id"
              label="ACME Account"
              extra={<span style={{ fontSize: 12, color: token.colorTextSecondary }}>The validation method (HTTP-01 or DNS-01) is set by the chosen account. To use DNS-01, pick a DNS-01 account.</span>}
            >
              <Select placeholder="Use default account" optionLabelProp="label">
                {accounts.map(a => {
                  // Match the parenthesized "DNS-01 (provider)" form used in the tables and order detail.
                  const methodLabel = a.challenge_type === 'dns-01'
                    ? `DNS-01 (${a.dns_provider || 'manual'})`
                    : 'HTTP-01';
                  return (
                    <Option key={a.id} value={a.id} label={`${a.email} · ${methodLabel}`}>
                      <span>{a.email}{' '}
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          {methodLabel} · {a.directory_url}
                        </Typography.Text>
                      </span>
                    </Option>
                  );
                })}
              </Select>
            </Form.Item>
          )}
        </>
      ),
    },
    {
      title: 'Review',
      content: (
        <>
          {!activeAccount && (
            <Alert
              type="error"
              showIcon
              message="No Active ACME Account"
              description={
                <span>
                  Please register an active ACME account.{' '}
                  <Button type="link" size="small" style={{ padding: 0 }} onClick={() => navigate('/settings?tab=acme')}>Go to Settings &gt; ACME</Button>
                  {' '}or use the ACME Account card below.
                </span>
              }
              style={{ marginBottom: 16 }}
            />
          )}
          {wizardDns01Disabled && (
            <Alert
              type="error"
              showIcon
              message="DNS-01 is disabled"
              description={
                <span>
                  This account uses DNS-01, but DNS-01 is currently disabled by an administrator.{' '}
                  <Button type="link" size="small" style={{ padding: 0 }} onClick={() => navigate('/settings?tab=acme')}>Enable it in Settings &gt; ACME</Button>
                  {' '}to issue this certificate.
                </span>
              }
              style={{ marginBottom: 16 }}
            />
          )}
          {wizardWildcardBlocked && (
            <Alert
              type="error"
              showIcon
              message="Wildcard requires a DNS-01 account"
              description="Remove the wildcard domain or select a DNS-01 account in the Configuration step."
              style={{ marginBottom: 16 }}
            />
          )}
          {!wizardIsDns01 && acmeEnabledClusters.length === 0 && (
            <Alert
              type="warning"
              showIcon
              message="No Clusters with ACME Enabled"
              description={
                <span>
                  Enable ACME challenge routing on at least one cluster.{' '}
                  <Button type="link" size="small" style={{ padding: 0 }} onClick={() => navigate('/clusters')}>Go to Cluster Management</Button>
                  {' '}then{' '}
                  <Button type="link" size="small" style={{ padding: 0 }} onClick={() => navigate('/apply-management')}>Apply Changes</Button>.
                </span>
              }
              style={{ marginBottom: 16 }}
            />
          )}
          {!wizardIsDns01 && prerequisites?.steps?.find(s => s.key === 'config_applied' && s.ok === false) && (() => {
            const configStep = prerequisites.steps.find(s => s.key === 'config_applied');
            const pendingNames = (configStep?.pending_clusters || []).map(c => c.name).join(', ');
            return (
              <Alert
                type="warning"
                showIcon
                message="Configuration Not Applied"
                description={
                  <span>
                    ACME routing rules have not been pushed to HAProxy yet. Certificate validation will fail without this.
                    {pendingNames && <> Pending on cluster: <strong>{pendingNames}</strong>.</>}{' '}
                    <Button type="link" size="small" style={{ padding: 0 }} onClick={() => {
                      if (configStep?.pending_clusters?.length) {
                        const target = allClusters.find(c => c.id === configStep.pending_clusters[0].id);
                        if (target) selectCluster(target);
                      }
                      navigate('/apply-management');
                    }}>Go to Apply Management</Button>
                  </span>
                }
                style={{ marginBottom: 16 }}
              />
            );
          })()}
          <Alert
            type="info"
            showIcon
            message="Prerequisite Check"
            description={
              <ul style={{ margin: 0, paddingLeft: 20 }}>
                <li>ACME Account: {activeAccount ? <Tag color="success">Active ({activeAccount.email})</Tag> : <Tag color="error">No active account</Tag>}</li>
                {wizardIsDns01 ? (
                  <>
                    <li>Challenge Method: <Tag>DNS-01</Tag> (TXT record; no port 80 / ACME routing needed)</li>
                    <li>DNS provider: <Tag>{wizardAccount?.dns_provider || 'manual'}</Tag></li>
                  </>
                ) : (
                  <>
                    <li>ACME-enabled Clusters: {acmeEnabledClusters.length > 0 ? <Tag color="success">{acmeEnabledClusters.map(c => c.name).join(', ')}</Tag> : <Tag color="warning">None</Tag>}</li>
                    <li>Domains must resolve to HAProxy node IPs for HTTP-01 validation</li>
                  </>
                )}
              </ul>
            }
          />
        </>
      ),
    },
  ];

  return (
    <div>
      {prerequisites && !prerequisites.ready && (
        <Card
          size="small"
          title={<span><RocketOutlined /> ACME Setup Guide</span>}
          style={{ marginBottom: 16, borderColor: '#faad14' }}
        >
          <Steps
            size="small"
            direction="vertical"
            items={(prerequisites.steps || []).map((step) => ({
              title: (
                <span>
                  {step.title}
                  {step.navigate && (
                    <Button type="link" size="small" onClick={() => {
                      if (step.pending_clusters?.length) {
                        const target = allClusters.find(c => c.id === step.pending_clusters[0].id);
                        if (target) selectCluster(target);
                      }
                      navigate(step.navigate);
                    }} style={{ marginLeft: 8, padding: 0 }}>
                      {step.ok === 'pending' || step.navigate === '/apply-management' ? 'Apply Changes' : 'Configure'}
                    </Button>
                  )}
                  {step.action === 'register_account' && !step.ok && (
                    <Button type="link" size="small" onClick={() => setRegisterVisible(true)} style={{ marginLeft: 8, padding: 0 }}>
                      Register Account
                    </Button>
                  )}
                </span>
              ),
              description: step.detail,
              status: step.ok === true ? 'finish' : step.ok === false ? 'error' : step.ok === 'pending' ? 'process' : 'wait',
            }))}
          />
        </Card>
      )}

      {pendingOrders.length > 0 && (() => {
        const stuckCount = pendingOrders.filter(isOrderStuck).length;
        // Manual DNS-01 orders are waiting on the USER to publish a TXT record, not on the CA —
        // call them out separately so the action item is visible without scanning the table.
        const manualDnsAwaiting = pendingOrders.filter(o =>
          o.challenge_type === 'dns-01' && (o.dns_provider || 'manual') === 'manual'
          && (o.status === 'pending' || o.status === 'processing')).length;
        const inFlightCount = pendingOrders.length - stuckCount - manualDnsAwaiting;
        const parts = [];
        if (inFlightCount > 0) parts.push(`${inFlightCount} awaiting validation`);
        if (manualDnsAwaiting > 0) parts.push(`${manualDnsAwaiting} manual DNS-01 awaiting your TXT record${manualDnsAwaiting > 1 ? 's' : ''}`);
        if (stuckCount > 0) parts.push(`${stuckCount} pending download (auto-retrying every 60s)`);
        return (
          <Alert
            type="warning"
            showIcon
            icon={<ExclamationCircleOutlined />}
            message={`${pendingOrders.length} certificate order(s) in progress: ${parts.join(', ')}`}
            description={manualDnsAwaiting > 0
              ? "Open a manual DNS-01 order to see the TXT record to publish, then confirm it."
              : stuckCount > 0
                ? "Stuck orders will auto-complete via the background task. You can also click \"Complete\" to retry immediately."
                : undefined}
            style={{ marginBottom: 16 }}
          />
        );
      })()}

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={12} sm={12} md={6}>
          <Card>
            <Statistic
              title="ACME Certificates"
              value={acmeCerts}
              prefix={<SafetyCertificateOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={12} md={6}>
          <Card>
            <Statistic
              title="Next Renewal"
              value={nextRenewalDays !== null ? `${nextRenewalDays}d` : 'N/A'}
              prefix={<ClockCircleOutlined />}
              valueStyle={{ color: nextRenewalDays !== null && nextRenewalDays <= 7 ? '#ff4d4f' : '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={12} sm={12} md={6}>
          <Card>
            <Statistic
              title="ACME Account"
              value={activeAccount ? 'Active' : acmeAccount ? 'Inactive' : 'None'}
              prefix={activeAccount ? <CheckCircleOutlined /> : <ExclamationCircleOutlined />}
              valueStyle={{ color: activeAccount ? '#52c41a' : '#faad14' }}
            />
            {acmeAccount && (
              <div style={{ fontSize: 12, color: token.colorTextSecondary, marginTop: 4 }}>{acmeAccount.email}</div>
            )}
            <div style={{ marginTop: 8, display: 'flex', gap: 4 }}>
              <Button type="link" size="small" style={{ padding: 0 }} onClick={() => setRegisterVisible(true)}>
                {acmeAccount ? 'New Account' : 'Register'}
              </Button>
              {acmeAccount && (
                <Button type="link" size="small" style={{ padding: 0 }} onClick={() => setAccountDetailVisible(true)}>
                  <InfoCircleOutlined /> Manage
                </Button>
              )}
              {acmeAccountNeedsCreds && (
                <Button type="link" size="small" style={{ padding: 0 }} onClick={() => openDnsCredsModal(acmeAccount)}>
                  <KeyOutlined /> DNS credentials
                </Button>
              )}
            </div>
          </Card>
        </Col>
        <Col xs={12} sm={12} md={6}>
          <Card>
            <Statistic
              title="Active Orders"
              value={pendingOrders.length}
              prefix={<SyncOutlined />}
              valueStyle={{ color: pendingOrders.length > 0 ? '#faad14' : '#52c41a' }}
            />
          </Card>
        </Col>
      </Row>

      <Card
        title="Certificate Orders"
        extra={
          <Space>
            <Button icon={<CloudDownloadOutlined />} onClick={handleImportCAChain}>
              Import LE CA Chain
            </Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setWizardVisible(true)}>
              Request Certificate
            </Button>
            <Button icon={<ReloadOutlined />} onClick={fetchData} loading={loading}>
              Refresh
            </Button>
          </Space>
        }
        style={{ marginBottom: 24 }}
      >
        <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 12 }}>
          <Segmented
            value={orderFilter}
            onChange={setOrderFilter}
            options={[
              { label: `Active (${orders.filter(o => !['cancelled','invalid','valid'].includes(o.status)).length})`, value: 'active' },
              { label: `Completed (${orders.filter(o => o.status === 'valid').length})`, value: 'completed' },
              { label: `Failed / Cancelled (${orders.filter(o => o.status === 'cancelled' || o.status === 'invalid').length})`, value: 'failed' },
              { label: `All (${orders.length})`, value: 'all' },
            ]}
            size="small"
          />
        </div>
        <Table
          columns={orderColumns}
          dataSource={filteredOrders}
          rowKey="id"
          loading={loading}
          pagination={{ pageSize: 10, showSizeChanger: true, showTotal: (total) => `${total} orders` }}
          size="small"
          rowClassName={(record) =>
            record.status === 'cancelled' || record.status === 'invalid' ? 'acme-order-terminal' : ''
          }
        />
      </Card>

      <Card title="Renewal Schedule">
        <Table
          columns={renewalColumns}
          dataSource={renewalSchedule}
          rowKey="id"
          loading={loading}
          pagination={{ pageSize: 10 }}
          size="small"
          locale={{ emptyText: 'No ACME-managed certificates yet' }}
        />
      </Card>

      {/* Request Certificate Wizard */}
      <Modal
        title="Request ACME Certificate"
        open={wizardVisible}
        onCancel={() => { setWizardVisible(false); setWizardStep(0); wizardForm.resetFields(); }}
        footer={null}
        width={680}
      >
        <Steps current={wizardStep} style={{ marginBottom: 24 }} items={wizardSteps.map(s => ({ title: s.title }))} />
        <Form form={wizardForm} layout="vertical">
          {wizardSteps[wizardStep]?.content}
        </Form>
        <div style={{ marginTop: 24, textAlign: 'right' }}>
          {wizardStep > 0 && (
            <Button style={{ marginRight: 8 }} onClick={() => setWizardStep(wizardStep - 1)}>
              Back
            </Button>
          )}
          {wizardStep < wizardSteps.length - 1 && (
            <Button type="primary" onClick={async () => {
              try {
                if (wizardStep === 0) await wizardForm.validateFields(['domains']);
                setWizardStep(wizardStep + 1);
              } catch { /* validation errors shown inline */ }
            }}>
              Next
            </Button>
          )}
          {wizardStep === wizardSteps.length - 1 && (
            <Button type="primary" onClick={handleRequestCert} loading={submitting} disabled={!activeAccount || wizardWildcardBlocked || wizardDns01Disabled || (!wizardIsDns01 && acmeEnabledClusters.length === 0)}>
              Submit Request
            </Button>
          )}
        </div>
      </Modal>

      {/* Order Detail Modal */}
      <Modal
        title={`Order #${orderDetail?.id} Details`}
        open={detailVisible}
        onCancel={() => setDetailVisible(false)}
        footer={<Button onClick={() => setDetailVisible(false)}>Close</Button>}
        width={700}
      >
        {orderDetail && (
          <>
            <p><strong>Status:</strong> {statusTag(orderDetail.status, orderDetail)}</p>
            <p><strong>Domains:</strong> {(orderDetail.domains || []).map(d => <Tag key={d}>{d}</Tag>)}</p>
            <p><strong>Account:</strong> {orderDetail.account_email}</p>
            {/* Issue #12 / Commit 4b: explicit completion state for the order */}
            <p>
              <strong>Certificate:</strong>{' '}
              {orderDetail.ssl_certificate_id ? (
                <Tag color="success" icon={<CheckCircleOutlined />}>
                  Completed (Cert #{orderDetail.ssl_certificate_id})
                </Tag>
              ) : orderDetail.status === 'valid' ? (
                <Tag color="warning" icon={<ExclamationCircleOutlined />}>
                  Pending download. Auto-completion task will retry every 60s
                </Tag>
              ) : orderDetail.status === 'invalid' || orderDetail.status === 'cancelled' ? (
                <Tag color="default">Not issued</Tag>
              ) : (
                <Tag color="processing" icon={<SyncOutlined spin />}>Awaiting CA validation</Tag>
              )}
            </p>
            {orderDetail.error_detail && (
              <Alert
                type="error"
                message="Error"
                description={renderErrorDetail(orderDetail.error_detail)}
                style={{ marginBottom: 16 }}
              />
            )}
            {orderDetail.challenge_type === 'dns-01'
              && !(orderDetail.challenges || []).some(c => c.challenge_type === 'dns-01')
              && (orderDetail.status === 'pending' || orderDetail.status === 'processing') && (
              <Alert
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
                message="Preparing DNS-01 challenge"
                description="The TXT record(s) for this order are being provisioned. They will appear here shortly; this view refreshes automatically."
              />
            )}
            {orderDetail.challenge_type === 'dns-01' && (orderDetail.challenges || []).some(c => c.challenge_type === 'dns-01') && (() => {
              const dnsChallenges = (orderDetail.challenges || []).filter(c => c.challenge_type === 'dns-01');
              const isManual = (orderDetail.dns_provider || 'manual') === 'manual';
              const canConfirm = isManual && (orderDetail.status === 'pending' || orderDetail.status === 'processing');
              return (
                <Alert
                  type={isManual ? 'warning' : 'info'}
                  showIcon
                  style={{ marginBottom: 16 }}
                  message={isManual
                    ? 'DNS-01 (manual): publish these TXT record(s), then verify'
                    : 'DNS-01 (automated): the TXT record(s) are published for you'}
                  description={
                    <div>
                      <div style={{ marginBottom: 8 }}>
                        Add the following DNS TXT record{dnsChallenges.length > 1 ? 's' : ''} at your DNS provider:
                      </div>
                      <Table
                        size="small"
                        pagination={false}
                        dataSource={dnsChallenges}
                        rowKey="id"
                        scroll={{ x: 'max-content' }}
                        columns={[
                          { title: 'Record name', dataIndex: 'dns_record_name', key: 'name',
                            render: (v) => v ? <Typography.Text code copyable style={{ wordBreak: 'break-all' }}>{v}</Typography.Text> : <Typography.Text type="secondary">-</Typography.Text> },
                          { title: 'Type', key: 'type', width: 60, render: () => 'TXT' },
                          { title: 'Value', dataIndex: 'dns_txt_value', key: 'val',
                            render: (v) => v ? <Typography.Text code copyable style={{ wordBreak: 'break-all' }}>{v}</Typography.Text> : <Typography.Text type="secondary">-</Typography.Text> },
                        ]}
                      />
                      {canConfirm && (
                        <>
                          <div style={{ marginTop: 12, fontSize: 12, color: token.colorTextSecondary }}>
                            DNS changes can take a few minutes to propagate. If verification fails,
                            wait a short while and try again. The order keeps retrying in the background.
                          </div>
                          <Button
                            type="primary"
                            size="small"
                            loading={confirming}
                            disabled={confirming}
                            style={{ marginTop: 8 }}
                            onClick={() => handleDnsConfirm(orderDetail.id)}
                          >
                            I've added the record(s), verify now
                          </Button>
                        </>
                      )}
                    </div>
                  }
                />
              );
            })()}
            {orderDetail.challenges?.length > 0 && (
              <>
                <h4>Challenges</h4>
                <Table
                  size="small"
                  pagination={false}
                  dataSource={orderDetail.challenges}
                  rowKey="id"
                  columns={[
                    { title: 'Domain', dataIndex: 'domain', key: 'domain' },
                    { title: 'Method', dataIndex: 'challenge_type', key: 'method', width: 90,
                      render: (ct) => <Tag>{(ct || 'http-01') === 'dns-01' ? 'DNS-01' : 'HTTP-01'}</Tag> },
                    { title: 'Token', dataIndex: 'token', key: 'token', ellipsis: true,
                      render: (t, r) => (r.challenge_type === 'dns-01') ? <Typography.Text type="secondary">TXT-based (see above)</Typography.Text> : t },
                    { title: 'Status', dataIndex: 'status', key: 'status', render: (s) => statusTag(s) },
                  ]}
                />
              </>
            )}
          </>
        )}
      </Modal>
      {/* ACME Account Management Modal */}
      <Modal
        title={<span><UserOutlined /> ACME Accounts</span>}
        open={accountDetailVisible}
        onCancel={() => setAccountDetailVisible(false)}
        footer={<Button onClick={() => setAccountDetailVisible(false)}>Close</Button>}
        width={700}
      >
        {accounts.length === 0 ? (
          <Alert type="info" showIcon message="No ACME accounts registered yet." />
        ) : (
          <Table
            size="small"
            pagination={false}
            dataSource={accounts}
            rowKey="id"
            columns={[
              {
                title: 'Email', dataIndex: 'email', key: 'email', ellipsis: true,
                render: (email) => <strong>{email}</strong>,
              },
              {
                title: 'Status', dataIndex: 'status', key: 'status',
                render: (s) => (
                  <Tag color={s === 'valid' ? 'green' : s === 'deactivated' ? 'default' : 'orange'}>
                    {(s || 'unknown').toUpperCase()}
                  </Tag>
                ),
              },
              {
                title: 'Provider', dataIndex: 'directory_url', key: 'provider',
                render: (url) => {
                  if (!url) return '-';
                  if (url.includes('letsencrypt')) return url.includes('staging') ? 'LE Staging' : 'Let\'s Encrypt';
                  if (url.includes('zerossl')) return 'ZeroSSL';
                  if (url.includes('google')) return 'Google Trust';
                  return 'Custom';
                },
              },
              {
                title: 'Registered', dataIndex: 'created_at', key: 'created_at',
                render: (d) => d ? new Date(d).toLocaleDateString() : '-',
              },
              {
                title: 'Actions', key: 'actions', width: 100,
                render: (_, record) => (
                  <Space>
                    <Tooltip title="View Details">
                      <Button
                        icon={<EyeOutlined />}
                        size="small"
                        onClick={() => {
                          Modal.info({
                            title: `Account: ${record.email}`,
                            width: 560,
                            content: (
                              <div style={{ marginTop: 12 }}>
                                <p><strong>ID:</strong> {record.id}</p>
                                <p><strong>Email:</strong> {record.email}</p>
                                <p><strong>Status:</strong> {record.status}</p>
                                <p><strong>Directory URL:</strong><br />
                                  <code style={{ fontSize: 11, wordBreak: 'break-all' }}>{record.directory_url}</code>
                                </p>
                                {record.account_url && (
                                  <p><strong>Account URL:</strong><br />
                                    <code style={{ fontSize: 11, wordBreak: 'break-all' }}>{record.account_url}</code>
                                  </p>
                                )}
                                {record.eab_kid && <p><strong>EAB Key ID:</strong> {record.eab_kid}</p>}
                                <p><strong>Challenge Method:</strong> {(record.challenge_type || 'http-01') === 'dns-01' ? 'DNS-01' : 'HTTP-01'}</p>
                                {(record.challenge_type === 'dns-01') && (
                                  <p><strong>DNS Provider:</strong> {record.dns_provider || 'manual'}</p>
                                )}
                                <p><strong>ToS Accepted:</strong> {record.tos_agreed ? 'Yes' : 'No'}</p>
                                <p><strong>Registered:</strong> {record.created_at ? new Date(record.created_at).toLocaleString() : '-'}</p>
                              </div>
                            ),
                          });
                        }}
                      />
                    </Tooltip>
                    {record.challenge_type === 'dns-01'
                      && (dnsProviders.find(p => p.name === record.dns_provider)?.credential_fields || []).length > 0 && (
                      <Tooltip title="DNS Provider Credentials">
                        <Button
                          icon={<KeyOutlined />}
                          size="small"
                          onClick={() => openDnsCredsModal(record)}
                        />
                      </Tooltip>
                    )}
                    {record.status !== 'deactivated' ? (
                      <Tooltip title="Deactivate">
                        <Button
                          icon={<DeleteOutlined />}
                          size="small"
                          danger
                          onClick={() => handleDeactivateAccount(record.id, record.email)}
                        />
                      </Tooltip>
                    ) : (
                      <Tooltip title="Remove from database">
                        <Button
                          icon={<DeleteOutlined />}
                          size="small"
                          danger
                          type="text"
                          onClick={() => handleRemoveAccount(record.id, record.email)}
                        />
                      </Tooltip>
                    )}
                  </Space>
                ),
              },
            ]}
          />
        )}
        <div style={{ marginTop: 16 }}>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => { setAccountDetailVisible(false); setRegisterVisible(true); }}>
            Register New Account
          </Button>
        </div>
      </Modal>

      {/* Register ACME Account Modal */}
      <Modal
        title="Register ACME Account"
        open={registerVisible}
        onCancel={() => { setRegisterVisible(false); registerForm.resetFields(); }}
        onOk={handleRegisterAccount}
        confirmLoading={registering}
        okText="Register"
      >
        <Alert
          type="info"
          showIcon
          message="ACME account will be registered with the directory URL configured in Settings > ACME."
          style={{ marginBottom: 16 }}
        />
        <Form form={registerForm} layout="vertical" preserve={false}>
          <Form.Item
            name="email"
            label="Contact Email"
            rules={[
              { required: true, message: 'Email is required' },
              { type: 'email', message: 'Enter a valid email address' },
            ]}
          >
            <Input placeholder="admin@yourcompany.com" />
          </Form.Item>
          <Form.Item
            name="tos_agreed"
            label="Terms of Service"
            valuePropName="checked"
            initialValue={false}
            rules={[{ validator: (_, v) => v ? Promise.resolve() : Promise.reject('You must accept the Terms of Service') }]}
          >
            <Switch checkedChildren="Accepted" unCheckedChildren="Not Accepted" aria-label="Accept Terms of Service" />
          </Form.Item>
          <div style={{ fontSize: 12, color: token.colorTextSecondary }}>
            By accepting, you agree to the ACME CA's Terms of Service (e.g.{' '}
            <a href="https://letsencrypt.org/repository/" target="_blank" rel="noopener noreferrer">
              Let's Encrypt Subscriber Agreement
            </a>).
          </div>
          {/* Issue #35: External Account Binding — required by ZeroSSL / Google Trust Services. */}
          <Collapse
            ghost
            style={{ marginTop: 12 }}
            items={[{
              key: 'eab',
              label: 'External Account Binding (EAB)',
              children: (
                <>
                  <Alert
                    type="info"
                    showIcon
                    style={{ marginBottom: 12 }}
                    message="Required by some CAs (ZeroSSL, Google Trust Services). Copy the Key ID and HMAC Key from your CA account. Re-enter them on each registration; the HMAC key is not stored."
                  />
                  <Form.Item
                    name="eab_kid"
                    label="EAB Key ID"
                    dependencies={['eab_hmac_key']}
                    rules={[({ getFieldValue }) => ({
                      validator(_, value) {
                        const kid = (value || '').trim();
                        const hmac = (getFieldValue('eab_hmac_key') || '').trim();
                        if (!kid && hmac) {
                          return Promise.reject(new Error('EAB Key ID is required when an HMAC Key is entered.'));
                        }
                        return Promise.resolve();
                      },
                    })]}
                  >
                    <Input placeholder="EAB Key Identifier" autoComplete="off" />
                  </Form.Item>
                  <Form.Item
                    name="eab_hmac_key"
                    label="EAB HMAC Key"
                    dependencies={['eab_kid']}
                    rules={[({ getFieldValue }) => ({
                      validator(_, value) {
                        const kid = (getFieldValue('eab_kid') || '').trim();
                        const hmac = (value || '').trim();
                        if (kid && !hmac) {
                          return Promise.reject(new Error('EAB HMAC Key is required when a Key ID is entered.'));
                        }
                        return Promise.resolve();
                      },
                    })]}
                  >
                    <Input.Password placeholder="EAB HMAC Key (base64url)" autoComplete="new-password" />
                  </Form.Item>
                </>
              ),
            }]}
          />
          {dns01Enabled && (
            <>
              <Divider style={{ margin: '16px 0 12px' }} />
              <Form.Item
                name="challenge_type"
                label="Challenge Method"
                initialValue="http-01"
                tooltip="HTTP-01 validates over port 80. DNS-01 validates via a DNS TXT record. It works for internal/isolated clusters (no public port 80) and supports wildcards."
              >
                <Select>
                  <Option value="http-01">HTTP-01 (default)</Option>
                  <Option value="dns-01">DNS-01 (TXT record)</Option>
                </Select>
              </Form.Item>
              {regChallengeType === 'dns-01' && (
                <>
                  {dnsProviders.length === 0 ? (
                    <Alert
                      type="warning"
                      showIcon
                      message="No DNS providers are available"
                      description="DNS-01 appears enabled, but no provider catalog was returned. Confirm DNS-01 is enabled in Settings and that the backend is reachable, then reopen this dialog."
                    />
                  ) : (
                  <Form.Item
                    name="dns_provider"
                    label="DNS Provider"
                    rules={[{ required: true, message: 'Select a DNS provider' }]}
                  >
                    <Select placeholder="Select a DNS provider">
                      {dnsProviders.map(p => (
                        <Option key={p.name} value={p.name}>{p.label}</Option>
                      ))}
                    </Select>
                  </Form.Item>
                  )}
                  {selectedDnsProvider && (selectedDnsProvider.credential_fields || []).length > 0 && (
                    <>
                      <Alert
                        type="info"
                        showIcon
                        style={{ marginBottom: 12 }}
                        message="Provider credentials are encrypted at rest and verified before they are saved. The token needs permission to create and delete TXT records in your domain's DNS zone."
                      />
                      {(selectedDnsProvider.credential_fields || []).map(f => (
                        <Form.Item
                          key={f.key}
                          name={`cred_${f.key}`}
                          label={f.label}
                          extra={f.help ? <span style={{ fontSize: 12, color: token.colorTextSecondary }}>{f.help}</span> : null}
                          rules={f.required ? [{ required: true, message: `${f.label} is required` }] : []}
                        >
                          {f.type === 'password'
                            ? <Input.Password placeholder={f.label} maxLength={f.max_length || undefined} />
                            : <Input placeholder={f.label} maxLength={f.max_length || undefined} />}
                        </Form.Item>
                      ))}
                    </>
                  )}
                  {selectedDnsProvider && !selectedDnsProvider.automated && (
                    <Alert
                      type="warning"
                      showIcon
                      message="Manual DNS provider"
                      description="You will publish the DNS TXT record yourself and confirm it. Manual DNS-01 certificates cannot auto-renew unattended."
                    />
                  )}
                </>
              )}
            </>
          )}
        </Form>
      </Modal>

      {/* Issue #35: DNS provider credentials for an existing DNS-01 account (view / replace / clear) */}
      <Modal
        title={<span><KeyOutlined /> DNS Provider Credentials{credAccount ? `: ${credAccount.email}` : ''}</span>}
        open={credModalVisible}
        onCancel={() => { setCredModalVisible(false); credForm.resetFields(); }}
        width={560}
        footer={[
          <Button key="clear" danger onClick={handleClearDnsCreds} disabled={!credMeta?.configured || credSaving}>
            Clear credentials
          </Button>,
          <Button key="cancel" onClick={() => { setCredModalVisible(false); credForm.resetFields(); }}>
            Cancel
          </Button>,
          <Button key="save" type="primary" loading={credSaving} onClick={handleSaveDnsCreds}>
            Save & verify
          </Button>,
        ]}
      >
        {credLoading ? (
          <div style={{ textAlign: 'center', padding: 24 }}><Spin /></div>
        ) : (
          <>
            <p style={{ marginBottom: 4 }}>
              <strong>Provider:</strong> {credAccount?.dns_provider || '-'}
            </p>
            <p style={{ marginTop: 0, fontSize: 12, color: token.colorTextSecondary }}>
              {credMeta?.configured
                ? `Configured: ${(credMeta.credential_fields_present || []).join(', ') || '(none)'}${credMeta.updated_at ? ` · updated ${new Date(credMeta.updated_at).toLocaleString()}` : ''}`
                : 'No credentials are stored yet for this account.'}
            </p>
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 16 }}
              message="Existing values are never shown. Enter the values to (re)store them; they are verified against the provider and encrypted at rest. The token needs permission to create and delete TXT records in your domain's DNS zone."
            />
            <Form form={credForm} layout="vertical">
              {(credProvider?.credential_fields || []).map(f => (
                <Form.Item
                  key={f.key}
                  name={`cred_${f.key}`}
                  label={f.label}
                  rules={f.required ? [{ required: true, message: `${f.label} is required` }] : []}
                  extra={f.help ? <span style={{ fontSize: 12, color: token.colorTextSecondary }}>{f.help}</span> : null}
                >
                  {f.type === 'password'
                    ? <Input.Password placeholder={f.label} maxLength={f.max_length || undefined} />
                    : <Input placeholder={f.label} maxLength={f.max_length || undefined} />}
                </Form.Item>
              ))}
              {(credProvider?.credential_fields || []).length === 0 && (
                <Alert type="warning" showIcon message="This provider needs no credentials (manual mode)." />
              )}
            </Form>
          </>
        )}
      </Modal>

      {/* v1.5.0 Issue #13: ACME Diagnostic Panel modal */}
      <Modal
        title={diagOrderId ? `Diagnostics: Order #${diagOrderId}` : 'Diagnostics'}
        open={diagVisible}
        onCancel={closeDiagModal}
        width={920}
        footer={[
          <Button key="close" onClick={closeDiagModal}>Close</Button>,
        ]}
      >
        {diagLoading ? (
          <div style={{ textAlign: 'center', padding: 40 }}><Spin /></div>
        ) : (
          <Tabs
            items={[
              {
                key: 'checks',
                label: 'Pre-flight Checks',
                children: (
                  <div>
                    {/* Bulgu #94 (Round-25): expose backend failures so the
                        operator can act on them — not just see a blank panel. */}
                    {diagRunError && (
                      <Alert
                        type="error"
                        showIcon
                        style={{ marginBottom: 12 }}
                        message={`Diagnostic runner failed${diagRunError.status && diagRunError.status !== 200 ? ` (HTTP ${diagRunError.status})` : ''}`}
                        description={
                          <div>
                            <div>{diagRunError.message}</div>
                            {(diagRunError.error_stage || diagRunError.error_type) && (
                              <div style={{ marginTop: 6, fontSize: 12, color: '#666' }}>
                                {diagRunError.error_stage && <span>Stage: <code>{diagRunError.error_stage}</code> </span>}
                                {diagRunError.error_type && <span>· Type: <code>{diagRunError.error_type}</code></span>}
                              </div>
                            )}
                            {diagRunError.correlation_id && (
                              <div style={{ marginTop: 6, fontSize: 12, color: '#666' }}>
                                Correlation ID: <code>{diagRunError.correlation_id}</code>
                              </div>
                            )}
                            <div style={{ marginTop: 6, fontSize: 12, color: '#666' }}>
                              Share this correlation ID with the platform team; the full traceback is in the API log.
                            </div>
                          </div>
                        }
                      />
                    )}
                    {diagMeta?.correlation_id && (diagMeta.checks_failed > 0 || diagMeta.checks_warn > 0) && !diagRunError && (
                      <Alert
                        type={diagMeta.checks_failed > 0 ? 'warning' : 'info'}
                        showIcon
                        style={{ marginBottom: 12 }}
                        message={`${diagMeta.checks_failed} check(s) failed, ${diagMeta.checks_warn} warning(s)`}
                        description={
                          <span style={{ fontSize: 12, color: '#666' }}>
                            Correlation ID: <code>{diagMeta.correlation_id}</code>
                          </span>
                        }
                      />
                    )}
                    {diagChecks.length === 0 ? (
                      <Empty description={diagRunError ? 'Diagnostic runner did not return any check' : 'No diagnostic checks available'} />
                    ) : (
                      <Table
                        size="small"
                        rowKey="id"
                        pagination={false}
                        dataSource={diagChecks}
                        columns={[
                          { title: 'Check', dataIndex: 'label', key: 'label' },
                          {
                            title: 'Status', dataIndex: 'status', key: 'status', width: 110,
                            render: (s) => checkStatusToTag(s),
                          },
                          { title: 'Message', dataIndex: 'message', key: 'message' },
                          {
                            title: 'Duration', dataIndex: 'duration_ms', key: 'duration_ms', width: 100,
                            render: (d) => (d != null ? `${d} ms` : '-'),
                          },
                          {
                            title: 'Re-run', key: 'rerun', width: 90,
                            render: (_, record) => (
                              // A skipped check (e.g. port 80 / routing for a DNS-01 order) has no
                              // transient cause to re-test, so re-running just reproduces "skipped".
                              record.status === 'skipped'
                                ? <Typography.Text type="secondary">-</Typography.Text>
                                : (
                                  <Tooltip title="Re-run this check">
                                    <Button
                                      size="small"
                                      aria-label="Re-run this check"
                                      icon={<ReloadOutlined />}
                                      loading={diagRunningCheckId === record.id}
                                      onClick={() => handleRerunCheck(record.id)}
                                    />
                                  </Tooltip>
                                )
                            ),
                          },
                        ]}
                        expandable={{
                          rowExpandable: (r) => r.details && Object.keys(r.details).length > 0,
                          expandedRowRender: (r) => (
                            <pre style={{ fontSize: 11, margin: 0, whiteSpace: 'pre-wrap' }}>
                              {JSON.stringify(r.details, null, 2)}
                            </pre>
                          ),
                        }}
                      />
                    )}
                  </div>
                ),
              },
              {
                key: 'events',
                label: `Event Log (${diagEvents.length})`,
                children: (
                  <div>
                    {/* Bulgu #95 (Round-25): /events used to 500 because of
                        a schema-drift bug (`status` column did not exist).
                        Now the response carries `meta.errors[]` for partial
                        failures and a `kind: fatal` envelope for total
                        failure — both render here so the operator never
                        wonders why the timeline is empty. */}
                    {diagEventsError?.kind === 'fatal' && (
                      <Alert
                        type="error"
                        showIcon
                        style={{ marginBottom: 12 }}
                        message={`Event log unavailable${diagEventsError.status ? ` (HTTP ${diagEventsError.status})` : ''}`}
                        description={
                          <div>
                            <div>{diagEventsError.message}</div>
                            {diagEventsError.correlation_id && (
                              <div style={{ marginTop: 6, fontSize: 12, color: '#666' }}>
                                Correlation ID: <code>{diagEventsError.correlation_id}</code>
                              </div>
                            )}
                            {diagEventsError.polling_stopped && (
                              <div style={{ marginTop: 6, fontSize: 12, color: '#666' }}>
                                Auto-refresh stopped after repeated failures. Re-open the panel to retry.
                              </div>
                            )}
                          </div>
                        }
                      />
                    )}
                    {diagEventsError?.kind === 'partial' && (
                      <Alert
                        type="warning"
                        showIcon
                        style={{ marginBottom: 12 }}
                        message="Event log partial: one or more sources failed"
                        description={
                          <div>
                            <ul style={{ margin: '4px 0 4px 16px' }}>
                              {diagEventsError.errors.map((err, i) => (
                                <li key={i}>
                                  <strong>{err.section}</strong>: {err.exception_type}: {err.message}
                                </li>
                              ))}
                            </ul>
                            {diagEventsError.correlation_id && (
                              <div style={{ fontSize: 12, color: '#666' }}>
                                Correlation ID: <code>{diagEventsError.correlation_id}</code>
                              </div>
                            )}
                          </div>
                        }
                      />
                    )}
                    {diagEvents.length === 0 ? (
                      <Empty description={diagEventsError?.kind === 'fatal'
                        ? 'No events could be loaded (see error above)'
                        : 'No events recorded for this order'} />
                    ) : (
                      <Timeline
                        items={diagEvents.map((ev) => ({
                          color:
                            (ev.severity || '').toUpperCase() === 'ERROR' ? 'red' :
                            (ev.severity || '').toUpperCase() === 'WARN' ? 'orange' : 'blue',
                          children: (
                            <div>
                              <div style={{ fontSize: 12, color: '#888' }}>{ev.created_at} · {ev.source}</div>
                              <div><strong>{humanizeEventType(ev.event_type)}</strong></div>
                              {ev.message && <div>{ev.message}</div>}
                            </div>
                          ),
                        }))}
                      />
                    )}
                  </div>
                ),
              },
              {
                key: 'raw',
                label: 'Raw Error',
                children: (
                  <div>
                    {diagHumanizedError ? (
                      <Alert
                        type={
                          diagOrder?.status === 'invalid' ? 'error' :
                          diagOrder?.status === 'valid' ? 'success' : 'info'
                        }
                        showIcon
                        message={diagHumanizedError.title}
                        description={
                          <div>
                            {diagHumanizedError.message && <p>{diagHumanizedError.message}</p>}
                            {diagHumanizedError.hint && (
                              <p style={{ color: '#666' }}><em>{diagHumanizedError.hint}</em></p>
                            )}
                            {diagHumanizedError.subproblems?.length > 0 && (
                              <ul>
                                {diagHumanizedError.subproblems.map((sp, i) => (
                                  <li key={i}>
                                    <code>{sp.identifier}</code>: {sp.detail || sp.type}
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                        }
                      />
                    ) : (
                      <Empty description="No error detail" />
                    )}
                    {diagOrder?.error_detail && (
                      <details style={{ marginTop: 12 }}>
                        <summary>Raw error_detail</summary>
                        {renderErrorDetail(diagOrder.error_detail)}
                      </details>
                    )}
                  </div>
                ),
              },
            ]}
          />
        )}
      </Modal>
    </div>
  );
};

export default ACMEAutomation;
