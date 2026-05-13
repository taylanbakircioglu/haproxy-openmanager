import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { Card, Table, Button, Space, Tag, message, Modal, Empty, Alert, Tooltip, Progress, Spin, Descriptions, theme } from 'antd';
import {
  DeleteOutlined, ReloadOutlined, ArrowRightOutlined, ClockCircleOutlined,
  EyeOutlined, SafetyCertificateOutlined, WarningOutlined,
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

import { extractApiError } from '../utils/apiError';
import { getSSLExpiryInfo } from '../utils/colors';
import { useCluster } from '../contexts/ClusterContext';

const calcDaysUntil = (expiresAt) => {
  if (!expiresAt) return null;
  return Math.ceil((new Date(expiresAt) - new Date()) / (1000 * 60 * 60 * 24));
};

// R18c round 8 (Bulgu A): backend may send `payload` as either a parsed
// object (post-fix) or a raw JSON string (pre-fix / asyncpg JSONB codec
// not registered). Normalize once on ingest so every render and the
// Resume / Preview handlers can rely on `draft.payload` being a dict.
// Dropping a malformed payload yields {} which the column renders treat
// as empty (Array.isArray + null guards already in place) — much safer
// than letting `string.domains` silently propagate.
const normalizePayload = (p) => {
  if (p == null) return {};
  if (typeof p === 'string') {
    try {
      const parsed = JSON.parse(p);
      return (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) ? parsed : {};
    } catch (_e) {
      return {};
    }
  }
  if (typeof p === 'object' && !Array.isArray(p)) return p;
  return {};
};

const normalizeDraft = (d) => ({
  ...d,
  payload: normalizePayload(d?.payload),
});

// R18c round 9: sessionStorage key migration. New code uses
// `site_wizard_draft`; we also write the legacy key for one release
// window so a tab that still has the old SiteWizard (cached JS) reads
// from the legacy key on resume. SiteWizard itself reads BOTH keys
// and clears BOTH after a successful hydrate.
const WIZARD_DRAFT_SESSION_KEY = 'site_wizard_draft';
const LEGACY_WIZARD_DRAFT_SESSION_KEY = 'proxied_host_wizard_draft';

const SiteDrafts = () => {
  const navigate = useNavigate();
  const { token } = theme.useToken();
  const { clusters } = useCluster();
  const [drafts, setDrafts] = useState([]);
  const [loading, setLoading] = useState(false);

  // Phase K Phase D follow-up — operator feedback: the Site Drafts
  // table previously rendered the raw `cluster_id` (e.g. "1") in the
  // Cluster column and the Preview modal's "Cluster ID" label. That
  // integer is opaque to operators who think in cluster names. Build
  // a small id → display lookup once per render and fall back to the
  // numeric id (in muted text) when the cluster has been deleted or
  // is not yet hydrated by the auth-gated /api/clusters fetch.
  const clusterById = useMemo(() => {
    const map = new Map();
    (clusters || []).forEach((c) => {
      if (c && c.id != null) {
        map.set(Number(c.id), c);
      }
    });
    return map;
  }, [clusters]);

  const renderClusterLabel = useCallback((cid) => {
    if (cid === undefined || cid === null || cid === '') return '-';
    const c = clusterById.get(Number(cid));
    if (c && c.name) {
      return (
        <Tooltip title={`Cluster ID: ${cid}`}>
          <span>{c.name}</span>
        </Tooltip>
      );
    }
    // Cluster not (yet) in the context — could be deleted, or
    // /api/clusters still loading. Show the id but flag it so the
    // operator knows the name resolution failed instead of silently
    // displaying a bare integer.
    return (
      <Tooltip
        title={
          (clusters || []).length === 0
            ? 'Cluster list still loading'
            : `Cluster #${cid} not found in cluster list — it may have been deleted.`
        }
      >
        <Tag color="default" style={{ marginInlineEnd: 0 }}>{`#${cid}`}</Tag>
      </Tooltip>
    );
  }, [clusterById, clusters]);

  // R18c round 7 (Bulgu 3): Preview action — call /api/sites/preview
  // with the draft payload and render the would_create + warnings response
  // in a modal so operators can audit a draft BEFORE resuming.
  const [previewModalOpen, setPreviewModalOpen] = useState(false);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewData, setPreviewData] = useState(null);
  const [previewError, setPreviewError] = useState(null);
  const [previewDraftTitle, setPreviewDraftTitle] = useState('');

  const fetchDrafts = useCallback(async () => {
    setLoading(true);
    try {
      const res = await axios.get('/api/sites/drafts');
      const raw = Array.isArray(res.data?.drafts) ? res.data.drafts : [];
      // R18c round 8: normalize payload once on ingest. See normalizePayload.
      setDrafts(raw.map(normalizeDraft));
    } catch (err) {
      message.error(extractApiError(err, 'Failed to load drafts'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchDrafts(); }, [fetchDrafts]);

  // R18b audit fix (C): refetch drafts when the user returns to this
  // tab. Wizard saves are append-only (each save creates a new
  // wizard_drafts row) so a second tab editing the "same" draft can
  // diverge silently. By refreshing on visibility/focus we surface
  // the latest snapshot without forcing the operator to click
  // Refresh manually after every external change.
  useEffect(() => {
    const onVisible = () => {
      if (document.visibilityState === 'visible') {
        fetchDrafts();
      }
    };
    document.addEventListener('visibilitychange', onVisible);
    window.addEventListener('focus', onVisible);
    return () => {
      document.removeEventListener('visibilitychange', onVisible);
      window.removeEventListener('focus', onVisible);
    };
  }, [fetchDrafts]);

  const handleResume = (draft) => {
    // SiteWizard reads from sessionStorage on mount when present.
    // R18c round 8: payload is already normalized to a dict on ingest, so
    // JSON.stringify here always produces a valid JSON object string the
    // wizard's hydrate effect can JSON.parse back into a populated form.
    // (Pre-fix the backend returned a raw JSON string, JSON.stringify
    // double-encoded it, and the wizard parsed back to a string — no
    // hydration happened.)
    // R18c round 9: write under the new `site_wizard_draft` key AND the
    // legacy `proxied_host_wizard_draft` key so a stale tab still
    // running pre-rename JS picks it up too. Both are cleared by
    // SiteWizard once consumed.
    const safePayload = normalizePayload(draft?.payload);
    try {
      const serialized = JSON.stringify(safePayload);
      sessionStorage.setItem(WIZARD_DRAFT_SESSION_KEY, serialized);
      sessionStorage.setItem(LEGACY_WIZARD_DRAFT_SESSION_KEY, serialized);
    } catch (_e) { /* noop */ }
    navigate('/sites/new');
  };

  const handleDelete = (draft) => {
    Modal.confirm({
      title: 'Delete draft?',
      content: `This will permanently delete '${draft.title || `draft #${draft.id}`}'.`,
      okType: 'danger',
      onOk: async () => {
        try {
          await axios.delete(`/api/sites/drafts/${draft.id}`);
          message.success('Draft deleted');
          fetchDrafts();
        } catch (err) {
          message.error(extractApiError(err, 'Delete failed'));
        }
      },
    });
  };

  const handlePreview = async (draft) => {
    setPreviewModalOpen(true);
    setPreviewLoading(true);
    setPreviewData(null);
    setPreviewError(null);
    setPreviewDraftTitle(draft.title || `draft #${draft.id}`);
    try {
      // /preview re-runs the same Pydantic validation that POST / does, so
      // legacy drafts saved before a schema tightening will surface a 422
      // here. We render the message inline (operator can Resume to migrate).
      const payload = normalizePayload(draft?.payload);
      const res = await axios.post('/api/sites/preview', payload);
      setPreviewData(res.data || null);
    } catch (err) {
      setPreviewError(extractApiError(err, 'Preview failed'));
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleClosePreview = () => {
    // Stale-data guard: clear ALL preview state on close so the next open
    // doesn't briefly show the previous draft's results.
    setPreviewModalOpen(false);
    setPreviewLoading(false);
    setPreviewData(null);
    setPreviewError(null);
    setPreviewDraftTitle('');
  };

  const ttlSoonCount = drafts.filter((d) => {
    const days = calcDaysUntil(d.expires_at);
    return days != null && days <= 3;
  }).length;

  // R18c round 7 (Bulgu 4): SSL/TLS column — mirrors FrontendManagement's
  // SSL/TLS column (utils/colors.js getSSLExpiryInfo) so operators see
  // the actual referenced cert's name + status + expiry, instead of
  // mistaking the draft TTL for a cert TTL.
  const renderSslColumn = (record) => {
    const mode = record?.payload?.ssl?.mode;
    if (!mode || mode === 'none') {
      return <Tag color="default">No SSL</Tag>;
    }
    if (mode === 'acme') {
      return (
        <Tooltip title="Cert is issued at apply time via ACME / Let's Encrypt">
          <Tag color="orange" icon={<ClockCircleOutlined />}>ACME (deferred)</Tag>
        </Tooltip>
      );
    }
    if (mode === 'upload') {
      return (
        <Tooltip title="PEM material will be uploaded when this draft is applied">
          <Tag color="blue" icon={<SafetyCertificateOutlined />}>Upload at apply</Tag>
        </Tooltip>
      );
    }
    if (mode === 'existing') {
      const summary = record?.ssl_cert_summary;
      if (!summary) {
        return <Tag color="default">Existing</Tag>;
      }
      if (summary.deleted) {
        return (
          <Tooltip title="The selected certificate has been deleted or deactivated. Resume the draft to choose a new one.">
            <Tag color="red" icon={<WarningOutlined />}>Cert deleted</Tag>
          </Tooltip>
        );
      }
      const expiryInfo = getSSLExpiryInfo(summary.expiry_date);
      const label = summary.domain || summary.name;
      return (
        <div style={{ minWidth: 140 }}>
          <Tooltip
            title={
              <div>
                <div><strong>{label}</strong></div>
                {summary.name && summary.domain && summary.name !== summary.domain && (
                  <div>Name: {summary.name}</div>
                )}
                <div>Status: {expiryInfo.status}</div>
                {summary.expiry_date && (
                  <div>Expires: {new Date(summary.expiry_date).toLocaleDateString('tr-TR', {
                    day: '2-digit', month: '2-digit', year: 'numeric',
                  })}</div>
                )}
              </div>
            }
            placement="top"
          >
            <Tag
              color={expiryInfo.tagColor}
              icon={<SafetyCertificateOutlined />}
              style={{ marginBottom: 4, fontSize: 11 }}
            >
              {label}
            </Tag>
            <Progress
              percent={expiryInfo.progress}
              size="small"
              strokeColor={expiryInfo.color}
              trailColor={token.colorBorderSecondary}
              showInfo={false}
              strokeWidth={4}
              style={{ cursor: 'help' }}
            />
            <div style={{ fontSize: 10, color: token.colorTextSecondary, marginTop: 2 }}>
              {expiryInfo.status}
            </div>
          </Tooltip>
        </div>
      );
    }
    return <Tag>{String(mode)}</Tag>;
  };

  const renderPreviewBody = () => {
    if (previewLoading) {
      return <div style={{ textAlign: 'center', padding: 32 }}><Spin /></div>;
    }
    if (previewError) {
      return (
        <Alert
          type="error"
          showIcon
          message="Preview failed"
          description={
            <>
              <div>{previewError}</div>
              <div style={{ marginTop: 8, fontSize: 12 }}>
                Tip: legacy drafts saved before a schema change may need to be Resumed and re-saved to migrate.
              </div>
            </>
          }
        />
      );
    }
    if (!previewData) {
      return <Empty description="No preview data" />;
    }
    const wc = previewData.would_create || {};
    const warnings = Array.isArray(previewData.warnings) ? previewData.warnings : [];
    const fhttps = wc.frontend_https;
    const fhttp = wc.frontend_http || {};
    const be = wc.backend || {};
    const servers = Array.isArray(wc.servers) ? wc.servers : [];
    const redirects = Array.isArray(wc.https_redirect_rules) ? wc.https_redirect_rules : [];
    const hsts = wc.hsts || {};
    const domains = Array.isArray(wc.domains) ? wc.domains : [];
    // Phase K Phase D (Bulgu #4): only render fields the operator
    // actually customised (non-default, non-null, non-empty). Pre-
    // fix the preview hid most fields ALWAYS — the user could not
    // see whether their per-server timing, frontend maxconn,
    // backend cookie persistence, or HSTS settings would land on
    // disk. Now we surface every non-default value AND hide
    // defaults so the modal stays scannable. Defaults are
    // intentionally permissive: undefined / null / '' / 0 / false
    // are treated as "not set" — but only after merging against
    // the wizard's known initialValues defaults where they exist.
    const isMeaningful = (v) =>
      v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && v.length === 0);
    const renderItem = (label, value, render) => {
      if (!isMeaningful(value)) return null;
      return (
        <Descriptions.Item label={label} key={label}>
          {render ? render(value) : String(value)}
        </Descriptions.Item>
      );
    };
    return (
      <div>
        <Descriptions title="Cluster & Domains" size="small" column={1} bordered style={{ marginBottom: 16 }}>
          <Descriptions.Item label="Cluster">
            {renderClusterLabel(wc.cluster_id ?? be.cluster_id)}
          </Descriptions.Item>
          {domains.length > 0 && (
            <Descriptions.Item label={`Domains (${domains.length})`}>
              <Space size={[4, 4]} wrap>
                {domains.map((d) => <Tag key={d}>{d}</Tag>)}
              </Space>
            </Descriptions.Item>
          )}
          <Descriptions.Item label="Apply immediately">
            <Tag color={previewData.apply_immediately ? 'green' : 'default'}>
              {previewData.apply_immediately ? 'Yes' : 'No (PENDING)'}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label="SSL Mode">
            <Tag>{wc.ssl_mode || 'none'}</Tag>
          </Descriptions.Item>
        </Descriptions>

        <Descriptions title="Would Create — Backend" size="small" column={1} bordered style={{ marginBottom: 16 }}>
          <Descriptions.Item label="Name">{be.name || '-'}</Descriptions.Item>
          <Descriptions.Item label="Mode">{be.mode || '-'}</Descriptions.Item>
          <Descriptions.Item label="Balance">{be.balance_method || '-'}</Descriptions.Item>
          {renderItem('Cookie persistence (name)', be.cookie_name)}
          {renderItem('timeout connect', be.timeout_connect)}
          {renderItem('timeout server', be.timeout_server)}
          {renderItem('http-check method', be.http_check_method)}
          {renderItem('http-check URI', be.http_check_uri)}
          {renderItem('Raw options', be.options, (v) => (
            <pre style={{ margin: 0, fontSize: 12, whiteSpace: 'pre-wrap' }}>{v}</pre>
          ))}
          <Descriptions.Item label="Servers">{servers.length}</Descriptions.Item>
        </Descriptions>

        {servers.length > 0 && (
          <Card
            size="small"
            title="Would Create — Servers"
            style={{ marginBottom: 16 }}
            type="inner"
          >
            {servers.map((s, idx) => (
              <Descriptions
                key={idx}
                size="small"
                column={2}
                bordered
                style={{ marginBottom: idx === servers.length - 1 ? 0 : 12 }}
                title={
                  <span style={{ fontWeight: 500 }}>
                    {s.server_name || `srv${idx + 1}`}
                    {' '}
                    <span style={{ color: '#888', fontWeight: 400 }}>
                      ({s.server_address}:{s.server_port})
                    </span>
                  </span>
                }
              >
                <Descriptions.Item label="weight">{s.weight ?? '-'}</Descriptions.Item>
                <Descriptions.Item label="check">
                  <Tag color={s.check_enabled ? 'green' : 'default'}>
                    {s.check_enabled ? 'On' : 'Off'}
                  </Tag>
                </Descriptions.Item>
                {renderItem('maxconn', s.max_connections)}
                {renderItem('inter', s.inter)}
                {renderItem('fall', s.fall)}
                {renderItem('rise', s.rise)}
                {renderItem('check port', s.check_port)}
                {s.backup_server && (
                  <Descriptions.Item label="backup"><Tag>Yes</Tag></Descriptions.Item>
                )}
                {renderItem('sticky cookie value', s.cookie_value)}
                {s.ssl_enabled && (
                  <>
                    <Descriptions.Item label="SSL to backend">
                      <Tag color="blue">Enabled</Tag>
                    </Descriptions.Item>
                    {renderItem('ssl_verify', s.ssl_verify)}
                    {renderItem('SNI', s.ssl_sni)}
                    {renderItem('CA bundle cert id', s.ssl_certificate_id)}
                    {renderItem('TLS min', s.ssl_min_ver)}
                    {renderItem('TLS max', s.ssl_max_ver)}
                    {renderItem('ciphers', s.ssl_ciphers)}
                  </>
                )}
              </Descriptions>
            ))}
          </Card>
        )}

        <Descriptions title="Would Create — HTTP Frontend" size="small" column={1} bordered style={{ marginBottom: 16 }}>
          <Descriptions.Item label="Name">{fhttp.name || '-'}</Descriptions.Item>
          <Descriptions.Item label="Bind">{fhttp.bind || '-'}</Descriptions.Item>
          <Descriptions.Item label="Mode">{fhttp.mode || '-'}</Descriptions.Item>
          {fhttp.https_redirect && (
            <Descriptions.Item label="HTTP → HTTPS redirect"><Tag color="green">Enabled</Tag></Descriptions.Item>
          )}
          {renderItem('maxconn', fhttp.maxconn)}
          {renderItem('timeout client', fhttp.timeout_client)}
          {renderItem('timeout http-request', fhttp.timeout_http_request)}
          {fhttp.compression_enabled && (
            <Descriptions.Item label="Compression"><Tag>Enabled</Tag></Descriptions.Item>
          )}
          {renderItem('monitor URI', fhttp.monitor_uri)}
          <Descriptions.Item label="ACL rules">
            {(fhttp.acl_rules_count || 0) + ' ACL · '
              + (fhttp.use_backend_rules_count || 0) + ' use_backend · '
              + (fhttp.redirect_rules_count || redirects.length || 0) + ' redirect'}
          </Descriptions.Item>
          {renderItem('Raw options', fhttp.options, (v) => (
            <pre style={{ margin: 0, fontSize: 12, whiteSpace: 'pre-wrap' }}>{v}</pre>
          ))}
        </Descriptions>

        {fhttps && (
          <Descriptions title="Would Create — HTTPS Frontend" size="small" column={1} bordered style={{ marginBottom: 16 }}>
            <Descriptions.Item label="Name">{fhttps.name || '-'}</Descriptions.Item>
            <Descriptions.Item label="Bind">{fhttps.bind || '-'}</Descriptions.Item>
            <Descriptions.Item
              label={
                <Tooltip title="ACME flow: HTTPS frontend is created AFTER Let's Encrypt issues the cert (deferred). Upload / Existing flows: HTTPS frontend is created immediately at apply time.">
                  <span>Created at</span>
                </Tooltip>
              }
            >
              <Tag color={fhttps.deferred ? 'orange' : 'default'}>
                {fhttps.deferred ? 'After ACME cert issuance' : 'Immediately at apply'}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="ALPN">{fhttps.ssl_alpn || '-'}</Descriptions.Item>
            <Descriptions.Item label="TLS min/max">
              {(fhttps.ssl_min_ver || '-') + ' / ' + (fhttps.ssl_max_ver || '-')}
            </Descriptions.Item>
            <Descriptions.Item label="Strict SNI">
              <Tag color={fhttps.ssl_strict_sni ? 'green' : 'default'}>
                {fhttps.ssl_strict_sni ? 'On' : 'Off'}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Verify (mTLS)">{fhttps.ssl_verify ?? 'none'}</Descriptions.Item>
            <Descriptions.Item label="Existing cert id">{fhttps.ssl_certificate_id ?? '-'}</Descriptions.Item>
            {renderItem('ciphers', fhttps.ssl_ciphers)}
            {renderItem('ciphersuites (TLS 1.3)', fhttps.ssl_ciphersuites)}
          </Descriptions>
        )}

        {hsts.enabled && (
          <Descriptions title="Would Create — HSTS" size="small" column={1} bordered style={{ marginBottom: 16 }}>
            <Descriptions.Item label="max-age">{hsts.max_age ?? '-'}</Descriptions.Item>
            <Descriptions.Item label="includeSubdomains">
              <Tag color={hsts.include_subdomains ? 'green' : 'default'}>
                {hsts.include_subdomains ? 'Yes' : 'No'}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="preload">
              <Tag color={hsts.preload ? 'green' : 'default'}>
                {hsts.preload ? 'Yes' : 'No'}
              </Tag>
            </Descriptions.Item>
          </Descriptions>
        )}

        {warnings.length > 0 && (
          <Alert
            type="warning"
            showIcon
            message={`Warnings (${warnings.length})`}
            description={
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                {warnings.map((w, i) => <li key={i}>{String(w)}</li>)}
              </ul>
            }
            style={{ marginTop: 8 }}
          />
        )}
      </div>
    );
  };

  return (
    <Card
      title="Site Drafts"
      extra={
        <Space>
          <Button icon={<ReloadOutlined />} onClick={fetchDrafts} loading={loading}>Refresh</Button>
          <Button type="primary" onClick={() => navigate('/sites/new')}>
            New Site
          </Button>
        </Space>
      }
    >
      {ttlSoonCount > 0 && (
        <Alert
          type="warning"
          showIcon
          icon={<ClockCircleOutlined />}
          message={`${ttlSoonCount} draft(s) expire within 3 days`}
          description="Drafts are automatically pruned after 30 days. Resume or save them as PENDING configuration to preserve your work."
          style={{ marginBottom: 16 }}
        />
      )}
      {drafts.length === 0 && !loading ? (
        <Empty description="No drafts saved" />
      ) : (
        <Table
          rowKey="id"
          loading={loading}
          dataSource={drafts}
          pagination={false}
          columns={[
            { title: 'Title', dataIndex: 'title', key: 'title', render: (t) => t || <em>untitled</em> },
            {
              title: 'Domains', key: 'domains',
              render: (_, r) => {
                // R18b audit fix (round 3 #6): defend the table render
                // against a malformed payload (e.g. operator hand-edited
                // the JSONB column or a future schema change). Pre-fix
                // a non-array payload.domains threw "ds.slice is not a
                // function" inside the column render, which Ant Design
                // surfaces as a fully blank Table — taking the entire
                // drafts page down. Treat anything non-array as empty.
                const raw = r?.payload?.domains;
                const ds = Array.isArray(raw) ? raw : [];
                return ds.slice(0, 3).map((d) => <Tag key={String(d)}>{String(d)}</Tag>).concat(
                  ds.length > 3 ? [<Tag key="more">+{ds.length - 3}</Tag>] : []
                );
              },
            },
            {
              title: 'Cluster', key: 'cluster',
              render: (_, r) => renderClusterLabel(r?.payload?.cluster_id),
            },
            {
              title: 'SSL/TLS', key: 'ssl_tls',
              render: (_, r) => renderSslColumn(r),
            },
            {
              title: 'Updated', dataIndex: 'updated_at', key: 'updated_at',
              render: (d) => d ? new Date(d).toLocaleString() : '-',
            },
            {
              // R18c round 7 (Bulgu 4): renamed from "Expires" to
              // "Draft Expires" to make it unambiguous that this
              // counter is the draft TTL (created_at + 30 days), NOT
              // the SSL certificate's validity. The new SSL/TLS
              // column carries the cert expiry separately.
              title: 'Draft Expires', dataIndex: 'expires_at', key: 'expires_at',
              render: (d) => {
                const days = calcDaysUntil(d);
                if (days == null) return '-';
                const color = days <= 3 ? 'orange' : days <= 7 ? 'gold' : 'green';
                return <Tag color={color}>{days} days</Tag>;
              },
            },
            {
              title: 'Actions', key: 'actions',
              render: (_, r) => (
                <Space>
                  <Button icon={<ArrowRightOutlined />} size="small" type="primary" onClick={() => handleResume(r)}>
                    Resume
                  </Button>
                  <Button icon={<EyeOutlined />} size="small" onClick={() => handlePreview(r)}>
                    Preview
                  </Button>
                  <Button icon={<DeleteOutlined />} size="small" danger onClick={() => handleDelete(r)} />
                </Space>
              ),
            },
          ]}
        />
      )}

      <Modal
        open={previewModalOpen}
        onCancel={handleClosePreview}
        title={`Preview — ${previewDraftTitle}`}
        footer={[<Button key="close" onClick={handleClosePreview}>Close</Button>]}
        width={720}
        destroyOnClose
      >
        {renderPreviewBody()}
      </Modal>
    </Card>
  );
};

export default SiteDrafts;
