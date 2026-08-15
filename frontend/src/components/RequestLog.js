/**
 * v1.11.0 — Request Log.
 *
 * One timeline for both directions of HTTP traffic:
 *   - inbound:  which user called which API endpoint, with what result
 *   - outbound: which CA / DNS provider / agent this backend called, and what
 *               came back
 *
 * Both live in the same table, so opening one inbound request shows the
 * outbound calls it triggered (they share a request_id) — that "related" list
 * is the whole point of the page. Bodies are captured redacted and size-capped
 * by the backend; nothing is unredacted here.
 *
 * Pagination is SERVER-side (a first for this frontend — every other table
 * filters an already-fetched array). The table can hold millions of rows, so
 * fetching them to slice client-side is not an option.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert, Button, Card, DatePicker, Descriptions, Empty, Input, Modal, Select,
  Space, Spin, Statistic, Switch, Table, Tag, Tooltip, Typography, message, theme
} from 'antd';
import {
  ApiOutlined, ClockCircleOutlined, CloudDownloadOutlined, DeleteOutlined,
  EyeOutlined, ReloadOutlined, UserOutlined, WarningOutlined
} from '@ant-design/icons';
import axios from 'axios';

import { extractApiError } from '../utils/apiError';
import { useAuth } from '../contexts/AuthContext';

const { Text, Paragraph } = Typography;

const DIRECTION_OPTIONS = [
  { label: 'Inbound (API calls to us)', value: 'inbound' },
  { label: 'Outbound (calls we made)', value: 'outbound' },
];

const STATUS_OPTIONS = [
  { label: '2xx Success', value: 2 },
  { label: '3xx Redirect', value: 3 },
  { label: '4xx Client error', value: 4 },
  { label: '5xx Server error', value: 5 },
  { label: 'No response (transport error)', value: 0 },
];

const METHOD_OPTIONS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].map((m) => ({
  label: m, value: m,
}));

// Mirrors utils/http_instrumentation.py's TARGET_* constants.
const TARGET_LABELS = {
  acme: "ACME / Let's Encrypt",
  acme_diag: 'ACME diagnostics probe',
  letsencrypt_ca: "Let's Encrypt CA chain",
  dns_cloudflare: 'Cloudflare DNS',
  dns_godaddy: 'GoDaddy DNS',
  agent: 'HAProxy agent',
  haproxy_stats: 'HAProxy stats',
  settings_probe: 'ACME directory probe',
};

const statusColor = (statusClass) => {
  if (statusClass === 2) return 'green';
  if (statusClass === 3) return 'blue';
  if (statusClass === 4) return 'orange';
  if (statusClass >= 5) return 'red';
  return 'red';
};

const isFailure = (row) => row?.status_class === 0 || row?.status_class >= 4;

const formatTime = (value) => {
  if (!value) return '—';
  // created_at is TIMESTAMPTZ, so the ISO string already carries an offset —
  // no manual 'Z' suffix needed here (unlike the naive-TIMESTAMP columns
  // elsewhere in this app).
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleString();
};

const JsonBlock = ({ value, token }) => {
  if (value === null || value === undefined) {
    return <Text type="secondary">Not captured</Text>;
  }
  return (
    <pre
      style={{
        fontSize: 11,
        margin: 0,
        maxHeight: 260,
        overflow: 'auto',
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        background: token.colorFillQuaternary,
        border: `1px solid ${token.colorBorderSecondary}`,
        borderRadius: token.borderRadius,
        padding: 8,
      }}
    >
      {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
    </pre>
  );
};

const RequestLog = () => {
  const { token } = theme.useToken();
  const { hasPermission, isAdmin } = useAuth();

  const canRead = hasPermission('requestlog', 'read') || isAdmin();
  const canManage = hasPermission('requestlog', 'manage') || isAdmin();

  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [totalIsEstimate, setTotalIsEstimate] = useState(false);
  const [scopedToSelf, setScopedToSelf] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState(null);

  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);

  const [direction, setDirection] = useState(undefined);
  const [statusClass, setStatusClass] = useState(undefined);
  const [methods, setMethods] = useState([]);
  const [target, setTarget] = useState(undefined);
  const [errorsOnly, setErrorsOnly] = useState(false);
  const [range, setRange] = useState(null);
  const [searchTyped, setSearchTyped] = useState('');
  const [search, setSearch] = useState('');

  const [stats, setStats] = useState(null);
  const [purging, setPurging] = useState(false);

  const [detailOpen, setDetailOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState(null);
  const [detail, setDetail] = useState(null);

  const params = useMemo(() => {
    const p = { limit: pageSize, offset: (page - 1) * pageSize };
    if (direction) p.direction = direction;
    if (statusClass !== undefined && statusClass !== null) p.status_class = statusClass;
    // The API takes one method; a single selection is the common case and
    // keeps the query index-friendly.
    if (methods.length === 1) p.method = methods[0];
    if (target) p.target = target;
    if (errorsOnly) p.errors_only = true;
    if (search) p.q = search;
    if (range && range[0]) p.since = range[0].toISOString();
    if (range && range[1]) p.until = range[1].toISOString();
    return p;
  }, [page, pageSize, direction, statusClass, methods, target, errorsOnly, search, range]);

  const fetchLogs = useCallback(async () => {
    if (!canRead) return;
    setLoading(true);
    setLoadError(null);
    try {
      const res = await axios.get('/api/request-logs', { params });
      setRows(res.data?.logs || []);
      setTotal(res.data?.total || 0);
      setTotalIsEstimate(Boolean(res.data?.total_is_estimate));
      setScopedToSelf(Boolean(res.data?.scoped_to_self));
    } catch (err) {
      const msg = extractApiError(err, 'Failed to load request logs');
      setLoadError(msg);
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [canRead, params]);

  const fetchStats = useCallback(async () => {
    if (!canRead) return;
    try {
      const res = await axios.get('/api/request-logs/stats', { params: { hours: 24 } });
      setStats(res.data || null);
    } catch (err) {
      // Stats are a nice-to-have header; a failure here must not hide the table.
      setStats(null);
    }
  }, [canRead]);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);
  useEffect(() => { fetchStats(); }, [fetchStats]);

  const openDetail = useCallback(async (id) => {
    setDetailOpen(true);
    setDetailLoading(true);
    setDetailError(null);
    setDetail(null);
    try {
      const res = await axios.get(`/api/request-logs/${id}`);
      setDetail(res.data || null);
    } catch (err) {
      setDetailError(extractApiError(err, 'Failed to load this request'));
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const runPurge = useCallback(() => {
    Modal.confirm({
      title: 'Apply retention now?',
      icon: <DeleteOutlined />,
      content:
        'This runs the configured retention immediately instead of waiting for the next ' +
        'scheduled pass. It removes rows that are already past their retention window or ' +
        'beyond the row cap — it does not delete everything.',
      okText: 'Run retention pass',
      onOk: async () => {
        setPurging(true);
        try {
          const res = await axios.post('/api/request-logs/purge');
          const removed = res.data?.removed || {};
          const count = (removed.success || 0) + (removed.error || 0) + (removed.overflow || 0);
          message.success(`Retention pass completed — ${count} row(s) removed`);
          fetchLogs();
          fetchStats();
        } catch (err) {
          message.error(extractApiError(err, 'Retention pass failed'));
        } finally {
          setPurging(false);
        }
      },
    });
  }, [fetchLogs, fetchStats]);

  const columns = useMemo(() => ([
    {
      title: 'Time',
      dataIndex: 'created_at',
      width: 180,
      render: (v) => <Text style={{ fontSize: 12 }}>{formatTime(v)}</Text>,
    },
    {
      title: 'Direction',
      dataIndex: 'direction',
      width: 110,
      render: (v) => (
        <Tag color={v === 'inbound' ? 'blue' : 'purple'}>{v === 'inbound' ? 'IN' : 'OUT'}</Tag>
      ),
    },
    {
      title: 'Method',
      dataIndex: 'method',
      width: 90,
      render: (v) => <Tag>{v}</Tag>,
    },
    {
      title: 'URL',
      dataIndex: 'url',
      ellipsis: true,
      render: (v) => (
        <Tooltip title={v} placement="topLeft">
          <Text style={{ fontSize: 12 }} ellipsis>{v}</Text>
        </Tooltip>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status_code',
      width: 100,
      render: (v, row) => (
        <Tag color={statusColor(row.status_class)}>{v ?? 'ERR'}</Tag>
      ),
    },
    {
      title: 'Duration',
      dataIndex: 'duration_ms',
      width: 110,
      render: (v) => (
        // 1000ms matches the backend's slow-request threshold, so "red here"
        // means "logged as slow there".
        <Text type={v > 1000 ? 'danger' : undefined} style={{ fontSize: 12 }}>{v} ms</Text>
      ),
    },
    {
      title: 'Who / Where',
      key: 'who',
      width: 200,
      render: (_, row) => {
        if (row.direction === 'inbound') {
          return (
            <Space size={4}>
              <UserOutlined />
              <Text style={{ fontSize: 12 }}>{row.username || (row.user_id ? `#${row.user_id}` : 'anonymous')}</Text>
            </Space>
          );
        }
        return (
          <Tooltip title={TARGET_LABELS[row.target] || row.target}>
            <Tag icon={<ApiOutlined />}>{row.target || '—'}</Tag>
          </Tooltip>
        );
      },
    },
    {
      title: 'Error',
      dataIndex: 'error',
      width: 200,
      ellipsis: true,
      render: (v) => (v ? (
        <Tooltip title={v}><Text type="danger" style={{ fontSize: 12 }}>{v}</Text></Tooltip>
      ) : <Text type="secondary">—</Text>),
    },
    {
      title: '',
      key: 'actions',
      width: 90,
      fixed: 'right',
      render: (_, row) => (
        <Button size="small" icon={<EyeOutlined />} onClick={() => openDetail(row.id)}>
          Detail
        </Button>
      ),
    },
  ]), [openDetail]);

  if (!canRead) {
    return (
      <Card>
        <Alert
          type="error"
          showIcon
          message="Access denied"
          description="You need the requestlog.read permission to view the request log."
        />
      </Card>
    );
  }

  const inboundStats = stats?.by_direction?.find((d) => d.direction === 'inbound');
  const outboundStats = stats?.by_direction?.find((d) => d.direction === 'outbound');
  const dropped = stats?.sink?.dropped || 0;

  const detailRow = detail?.log;

  return (
    <div>
      <Card
        title={<Space><ClockCircleOutlined />Request Log</Space>}
        extra={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => { fetchLogs(); fetchStats(); }} loading={loading}>
              Refresh
            </Button>
            {canManage && (
              <Button icon={<DeleteOutlined />} onClick={runPurge} loading={purging}>
                Apply retention now
              </Button>
            )}
          </Space>
        }
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="Every API call in, and every HTTP call out"
          description={
            <>
              Inbound rows show which user called which endpoint and what came back.
              Outbound rows show which CA, DNS provider or agent this backend contacted.
              Bodies are captured <strong>redacted and size-capped</strong> — credentials,
              tokens, private keys and ACME signatures are never stored. Retention is
              configured in <Text code>Settings → Request Log</Text>.
            </>
          }
        />

        {scopedToSelf && (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 16 }}
            message="Showing your own requests only"
            description="Seeing every user's traffic, and all outbound calls, requires the requestlog.manage permission."
          />
        )}

        {dropped > 0 && (
          <Alert
            type="warning"
            showIcon
            icon={<WarningOutlined />}
            style={{ marginBottom: 16 }}
            message={`${dropped} row(s) dropped by this worker`}
            description="The writer queue filled up. Lower the sampling rate, turn off body capture, or raise REQUEST_LOG_QUEUE_MAX."
          />
        )}

        {stats && (
          <Space size="large" wrap style={{ marginBottom: 16 }}>
            <Statistic
              title="Inbound (24h)"
              value={inboundStats?.total || 0}
              suffix={inboundStats?.errors ? <Text type="danger" style={{ fontSize: 14 }}>{`/ ${inboundStats.errors} failed`}</Text> : null}
            />
            <Statistic
              title="Outbound (24h)"
              value={outboundStats?.total || 0}
              suffix={outboundStats?.errors ? <Text type="danger" style={{ fontSize: 14 }}>{`/ ${outboundStats.errors} failed`}</Text> : null}
            />
            <Statistic title="Rows stored" value={stats.total_rows || 0} />
            <Statistic title="Oldest entry" valueRender={() => <span style={{ fontSize: 16 }}>{formatTime(stats.oldest_at)}</span>} />
          </Space>
        )}

        <Space style={{ marginBottom: 16 }} wrap>
          <Select
            placeholder="All directions"
            allowClear
            style={{ width: 220 }}
            value={direction}
            onChange={(v) => { setDirection(v); setPage(1); }}
            options={DIRECTION_OPTIONS}
          />
          <Select
            placeholder="All statuses"
            allowClear
            style={{ width: 210 }}
            value={statusClass}
            onChange={(v) => { setStatusClass(v); setPage(1); }}
            options={STATUS_OPTIONS}
          />
          <Select
            placeholder="All methods"
            allowClear
            mode="multiple"
            maxTagCount={1}
            style={{ width: 180 }}
            value={methods}
            onChange={(v) => { setMethods(v); setPage(1); }}
            options={METHOD_OPTIONS}
          />
          <Select
            placeholder="All targets"
            allowClear
            style={{ width: 220 }}
            value={target}
            disabled={direction === 'inbound'}
            onChange={(v) => { setTarget(v); setPage(1); }}
            options={Object.entries(TARGET_LABELS).map(([value, label]) => ({ value, label }))}
          />
          <DatePicker.RangePicker
            showTime
            value={range}
            onChange={(v) => { setRange(v); setPage(1); }}
          />
          <Input.Search
            placeholder="Search URL…"
            allowClear
            enterButton
            style={{ width: 300 }}
            value={searchTyped}
            onChange={(e) => setSearchTyped(e.target.value)}
            onSearch={(v) => { setSearch(v); setPage(1); }}
          />
          <Space size={4}>
            <Switch
              checked={errorsOnly}
              onChange={(v) => { setErrorsOnly(v); setPage(1); }}
              checkedChildren="Errors"
              unCheckedChildren="All"
            />
          </Space>
        </Space>

        {loadError && (
          <Alert type="error" showIcon style={{ marginBottom: 16 }} message={loadError} />
        )}

        <Table
          rowKey="id"
          size="small"
          loading={loading}
          dataSource={rows}
          columns={columns}
          scroll={{ x: 1400 }}
          rowClassName={(row) => (isFailure(row) ? 'request-log-error-row' : '')}
          locale={{
            emptyText: <Empty description="No requests match these filters" />,
          }}
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            pageSizeOptions: ['25', '50', '100', '200'],
            showTotal: (t, r) => `${r[0]}-${r[1]} of ${totalIsEstimate ? `${t}+` : t} requests`,
            onChange: (p, ps) => { setPage(p); setPageSize(ps); },
          }}
        />
      </Card>

      <Modal
        open={detailOpen}
        onCancel={() => setDetailOpen(false)}
        width={960}
        destroyOnClose
        title="Request detail"
        footer={<Button onClick={() => setDetailOpen(false)}>Close</Button>}
      >
        {detailLoading ? (
          <div style={{ textAlign: 'center', padding: 48 }}><Spin /></div>
        ) : detailError ? (
          <Alert type="error" showIcon message={detailError} />
        ) : !detailRow ? (
          <Empty description="Nothing to show" />
        ) : (
          <Space direction="vertical" size="middle" style={{ width: '100%' }}>
            <Descriptions size="small" column={2} bordered>
              <Descriptions.Item label="Time">{formatTime(detailRow.created_at)}</Descriptions.Item>
              <Descriptions.Item label="Direction">
                <Tag color={detailRow.direction === 'inbound' ? 'blue' : 'purple'}>{detailRow.direction}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Method"><Tag>{detailRow.method}</Tag></Descriptions.Item>
              <Descriptions.Item label="Status">
                <Tag color={statusColor(detailRow.status_class)}>{detailRow.status_code ?? 'no response'}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="URL" span={2}>
                <Text copyable style={{ fontSize: 12 }}>{detailRow.url}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="Duration">{detailRow.duration_ms} ms</Descriptions.Item>
              <Descriptions.Item label="Target">
                {detailRow.target ? (TARGET_LABELS[detailRow.target] || detailRow.target) : '—'}
              </Descriptions.Item>
              <Descriptions.Item label="User">
                {detailRow.username || (detailRow.user_id ? `#${detailRow.user_id}` : 'anonymous')}
              </Descriptions.Item>
              <Descriptions.Item label="Client IP">{detailRow.client_ip || '—'}</Descriptions.Item>
              <Descriptions.Item label="Request id" span={2}>
                <Text code copyable style={{ fontSize: 11 }}>{detailRow.request_id}</Text>
              </Descriptions.Item>
              {detailRow.error && (
                <Descriptions.Item label="Error" span={2}>
                  <Text type="danger">{detailRow.error}</Text>
                </Descriptions.Item>
              )}
            </Descriptions>

            {detailRow.truncated && (
              <Alert
                type="warning"
                showIcon
                message="Body truncated"
                description={
                  `Only the first part of the body was captured (request ${detailRow.request_body_bytes} bytes, ` +
                  `response ${detailRow.response_body_bytes} bytes on the wire). Raise the body cap in ` +
                  `Settings → Request Log if you need more.`
                }
              />
            )}

            <Card size="small" title="Request headers">
              <JsonBlock value={detailRow.request_headers} token={token} />
            </Card>
            <Card size="small" title="Request body">
              <JsonBlock value={detailRow.request_body} token={token} />
            </Card>
            <Card size="small" title="Response headers">
              <JsonBlock value={detailRow.response_headers} token={token} />
            </Card>
            <Card size="small" title="Response body">
              <JsonBlock value={detailRow.response_body} token={token} />
            </Card>

            <Card
              size="small"
              title={<Space><CloudDownloadOutlined />Calls triggered by this request</Space>}
            >
              {detail?.related?.length ? (
                <Table
                  rowKey="id"
                  size="small"
                  pagination={false}
                  dataSource={detail.related}
                  columns={[
                    { title: 'Dir', dataIndex: 'direction', width: 70,
                      render: (v) => <Tag color={v === 'inbound' ? 'blue' : 'purple'}>{v === 'inbound' ? 'IN' : 'OUT'}</Tag> },
                    { title: 'Target', dataIndex: 'target', width: 140, render: (v) => v || '—' },
                    { title: 'Method', dataIndex: 'method', width: 80 },
                    { title: 'URL', dataIndex: 'url', ellipsis: true },
                    { title: 'Status', dataIndex: 'status_code', width: 80,
                      render: (v, r) => <Tag color={statusColor(r.status_class)}>{v ?? 'ERR'}</Tag> },
                    { title: '', key: 'go', width: 70,
                      render: (_, r) => <Button size="small" type="link" onClick={() => openDetail(r.id)}>Open</Button> },
                  ]}
                />
              ) : (
                <Paragraph type="secondary" style={{ margin: 0 }}>
                  No other calls share this request id.
                </Paragraph>
              )}
            </Card>
          </Space>
        )}
      </Modal>
    </div>
  );
};

export default RequestLog;
