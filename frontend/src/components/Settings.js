import React, { useEffect, useState } from 'react';
import { Card, Form, Switch, Button, InputNumber, message, Tabs, Input, Select, Collapse, Space, Alert, Tag, Spin, Tooltip } from 'antd';
import { SafetyCertificateOutlined, ApiOutlined, CheckCircleOutlined, CloseCircleOutlined, InfoCircleOutlined, FileSearchOutlined } from '@ant-design/icons';
import { useSearchParams } from 'react-router-dom';
import axios from 'axios';

const { Option } = Select;

const ACME_PROVIDERS = {
  letsencrypt: {
    label: "Let's Encrypt",
    directory: 'https://acme-v02.api.letsencrypt.org/directory',
    staging: 'https://acme-staging-v02.api.letsencrypt.org/directory',
    requiresEAB: false,
  },
  zerossl: {
    label: 'ZeroSSL',
    directory: 'https://acme.zerossl.com/v2/DV90',
    staging: null,
    requiresEAB: true,
  },
  google: {
    label: 'Google Trust Services',
    directory: 'https://dv.acme-v02.api.pki.goog/directory',
    staging: 'https://dv.acme-v02.test-api.pki.goog/directory',
    requiresEAB: true,
  },
  custom: {
    label: 'Custom ACME CA',
    directory: '',
    staging: null,
    requiresEAB: false,
  },
};

const Settings = () => {
  const [searchParams] = useSearchParams();
  const defaultTab = searchParams.get('tab') || 'general';
  const [form] = Form.useForm();
  const [acmeForm] = Form.useForm();
  const [acmeLoading, setAcmeLoading] = useState(false);
  const [acmeSaving, setAcmeSaving] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  // v1.11.0 — request/response log retention. Read/written through
  // /api/request-logs/settings, NOT the generic /api/settings/{category}: that
  // endpoint stringifies values with str(), which turns True into 'True' and
  // fails the ::jsonb cast.
  const [rlForm] = Form.useForm();
  const [rlLoading, setRlLoading] = useState(false);
  const [rlSaving, setRlSaving] = useState(false);
  const [rlDenied, setRlDenied] = useState(false);

  const onFinish = (values) => {
    try {
      localStorage.setItem('app_settings', JSON.stringify({
        autoRefresh: values.autoRefresh,
        refreshInterval: values.refreshInterval,
        notifications: values.notifications
      }));
    } catch (error) {
      console.error('Error saving settings:', error);
    }
    message.success('Settings saved successfully');
  };

  useEffect(() => {
    try {
      const savedSettings = localStorage.getItem('app_settings');
      if (savedSettings) {
        const settings = JSON.parse(savedSettings);
        form.setFieldsValue(settings);
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  }, [form]);

  useEffect(() => {
    loadAcmeSettings();
    loadRequestLogSettings();
  }, []);

  const loadRequestLogSettings = async () => {
    setRlLoading(true);
    try {
      const res = await axios.get('/api/request-logs/settings');
      rlForm.setFieldsValue(res.data?.settings || {});
      setRlDenied(false);
    } catch (err) {
      // A viewer can open Settings but has no requestlog.manage — show the tab
      // read-only-with-explanation rather than a scary console error.
      if (err?.response?.status === 403) {
        setRlDenied(true);
      } else {
        console.error('Error loading request log settings:', err);
      }
    } finally {
      setRlLoading(false);
    }
  };

  const onRequestLogSave = async (values) => {
    setRlSaving(true);
    try {
      const res = await axios.put('/api/request-logs/settings', {
        ...values,
        // Values come back from the InputNumber controls as numbers already;
        // the endpoint is properly typed, so no per-value JSON.stringify here
        // (unlike the ACME form above, which talks to the legacy endpoint).
        exclude_paths: values.exclude_paths || [],
      });
      // Show what the server ACTUALLY applied, not what was typed. Values are
      // clamped server-side, and clearing the exclude list does not mean "log
      // everything": normalize_exclude_paths() falls back to the shipped
      // defaults so the log viewer and the raw-body heartbeat stay excluded.
      // Without this the form would keep displaying an empty list that is not
      // in effect.
      const applied = res?.data?.settings;
      if (applied) {
        rlForm.setFieldsValue(applied);
        const typed = values.exclude_paths || [];
        if (typed.length === 0 && (applied.exclude_paths || []).length > 0) {
          message.warning(
            'An empty exclude list is not applied as "log everything" — the shipped defaults were restored.'
          );
        }
      }
      message.success('Request log settings saved');
    } catch (err) {
      message.error(err?.response?.data?.detail || 'Failed to save request log settings');
    } finally {
      setRlSaving(false);
    }
  };

  const loadAcmeSettings = async () => {
    setAcmeLoading(true);
    try {
      const res = await axios.get('/api/settings/acme');
      const settings = res.data?.settings || {};
      const formValues = {};
      Object.entries(settings).forEach(([key, obj]) => {
        let val = obj.value;
        if (typeof val === 'string') {
          try { val = JSON.parse(val); } catch { /* keep as-is */ }
        }
        formValues[key] = val;
      });
      acmeForm.setFieldsValue(formValues);
    } catch (err) {
      if (err?.response?.status !== 403) {
        console.error('Error loading ACME settings:', err);
      }
    } finally {
      setAcmeLoading(false);
    }
  };

  const onAcmeSave = async (values) => {
    setAcmeSaving(true);
    try {
      const payload = {};
      Object.entries(values).forEach(([key, val]) => {
        payload[key] = JSON.stringify(val);
      });
      await axios.put('/api/settings/acme', { settings: payload });
      message.success('ACME settings saved successfully');
      setTestResult(null);
    } catch (err) {
      message.error(err?.response?.data?.detail || 'Failed to save ACME settings');
    } finally {
      setAcmeSaving(false);
    }
  };

  const handleProviderChange = (provider) => {
    const info = ACME_PROVIDERS[provider];
    if (info) {
      const staging = acmeForm.getFieldValue('staging_mode');
      acmeForm.setFieldsValue({
        directory_url: staging && info.staging ? info.staging : info.directory,
      });
    }
  };

  const handleStagingChange = (checked) => {
    const provider = acmeForm.getFieldValue('provider');
    const info = ACME_PROVIDERS[provider];
    if (info) {
      if (checked && info.staging) {
        acmeForm.setFieldsValue({ directory_url: info.staging });
      } else {
        acmeForm.setFieldsValue({ directory_url: info.directory });
      }
    }
  };

  const testConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const currentUrl = acmeForm.getFieldValue('directory_url');
      const params = currentUrl ? { directory_url: currentUrl } : {};
      const res = await axios.get('/api/settings/acme/test-connection', { params });
      setTestResult(res.data);
    } catch (err) {
      setTestResult({ success: false, error: err?.response?.data?.detail || 'Connection test failed' });
    } finally {
      setTesting(false);
    }
  };

  const tabItems = [
    {
      key: 'general',
      label: 'General Settings',
      children: (
        <Card>
          <Form
            form={form}
            layout="vertical"
            onFinish={onFinish}
            initialValues={{
              autoRefresh: true,
              refreshInterval: 5,
              notifications: true,
            }}
          >
            <Form.Item name="autoRefresh" label="Auto Refresh Dashboard" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="refreshInterval" label="Refresh Interval (seconds)">
              <InputNumber min={1} max={60} />
            </Form.Item>
            <Form.Item name="notifications" label="Enable Notifications" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item>
              <Button type="primary" htmlType="submit">Save Settings</Button>
            </Form.Item>
          </Form>
        </Card>
      ),
    },
    {
      key: 'acme',
      label: (
        <span><SafetyCertificateOutlined /> ACME / SSL Automation</span>
      ),
      children: (
        <Spin spinning={acmeLoading}>
          <Card>
            <Alert
              message="ACME Automated Certificate Management"
              description="Configure automatic SSL certificate issuance and renewal via ACME protocol (Let's Encrypt, ZeroSSL, Google Trust Services, or any ACME-compatible CA)."
              type="info"
              showIcon
              icon={<SafetyCertificateOutlined />}
              style={{ marginBottom: 24 }}
            />
            <Form
              form={acmeForm}
              layout="vertical"
              onFinish={onAcmeSave}
              initialValues={{
                provider: 'letsencrypt',
                directory_url: 'https://acme-v02.api.letsencrypt.org/directory',
                staging_mode: false,
                auto_renew_enabled: false,
                renew_before_days: 30,
                tos_accepted: false,
                contact_email: '',
                eab_kid: '',
                eab_hmac_key: '',
                challenge_backend_url: '',
                dns01_enabled: false,
              }}
            >
              <Form.Item name="provider" label="ACME Provider">
                <Select onChange={handleProviderChange}>
                  {Object.entries(ACME_PROVIDERS).map(([key, info]) => (
                    <Option key={key} value={key}>{info.label}</Option>
                  ))}
                </Select>
              </Form.Item>

              <Form.Item
                name="directory_url"
                label={<span>Directory URL <Tooltip title="The ACME directory endpoint of your CA"><InfoCircleOutlined /></Tooltip></span>}
                rules={[{ required: true, message: 'Directory URL is required' }]}
              >
                <Input placeholder="https://acme-v02.api.letsencrypt.org/directory" />
              </Form.Item>

              <Form.Item
                name="contact_email"
                label="Contact Email"
                rules={[{ type: 'email', message: 'Please enter a valid email' }]}
              >
                <Input placeholder="admin@example.com" />
              </Form.Item>

              <Form.Item name="staging_mode" label="Staging Mode" valuePropName="checked">
                <Switch onChange={handleStagingChange} />
              </Form.Item>
              <div style={{ marginTop: -16, marginBottom: 16 }}>
                <Tag color="orange">Staging mode issues test certificates that are NOT trusted by browsers</Tag>
              </div>

              {/* Commit 5f: optional staging URL override for non-LE CAs (Pebble, custom test ACME). */}
              <Form.Item
                name="staging_url_override"
                label="Custom Staging Directory URL (optional)"
                tooltip="When Staging Mode is on, use this URL instead of the default Let's Encrypt staging endpoint. Useful for testing with Pebble or a private ACME test CA."
              >
                <Input placeholder="https://pebble.example.local:14000/dir" allowClear />
              </Form.Item>

              <Form.Item name="tos_accepted" label="Terms of Service Accepted" valuePropName="checked">
                <Switch />
              </Form.Item>

              <Card size="small" title="Auto-Renewal" style={{ marginBottom: 24 }}>
                <Form.Item name="auto_renew_enabled" label="Enable Auto-Renewal" valuePropName="checked">
                  <Switch />
                </Form.Item>
                <Form.Item name="renew_before_days" label="Renew Before Expiry (days)">
                  <InputNumber min={1} max={90} />
                </Form.Item>
              </Card>

              <Collapse
                ghost
                items={[{
                  key: 'eab',
                  label: 'External Account Binding (EAB)',
                  children: (
                    <>
                      <Alert
                        message="Required for ZeroSSL and Google Trust Services"
                        type="warning"
                        showIcon
                        style={{ marginBottom: 16 }}
                      />
                      <Form.Item name="eab_kid" label="EAB Key ID">
                        <Input placeholder="EAB Key Identifier" />
                      </Form.Item>
                      <Form.Item name="eab_hmac_key" label="EAB HMAC Key">
                        <Input.Password placeholder="EAB HMAC Key" />
                      </Form.Item>
                    </>
                  ),
                }]}
              />

              <Collapse
                ghost
                style={{ marginTop: 16 }}
                items={[{
                  key: 'advanced',
                  label: 'Advanced Settings',
                  children: (
                    <Form.Item
                      name="challenge_backend_url"
                      label={<span>Challenge Backend URL <Tooltip title="Override the URL HAProxy uses to reach this management backend for ACME challenges. Leave empty for auto-detection."><InfoCircleOutlined /></Tooltip></span>}
                    >
                      <Input placeholder="Auto-detect (leave empty)" />
                    </Form.Item>
                  ),
                }]}
              />

              {/* Issue #35: DNS-01 challenge support (global kill-switch). Per-account DNS provider
                  credentials are configured on each ACME account in ACME Automation. */}
              <Collapse
                ghost
                style={{ marginTop: 16 }}
                items={[{
                  key: 'dns01',
                  label: 'DNS-01 Challenge (Advanced)',
                  children: (
                    <>
                      <Alert
                        type="info"
                        showIcon
                        style={{ marginBottom: 16 }}
                        message="DNS-01 validates certificates via a DNS TXT record instead of HTTP on port 80."
                        description="Use it for internal/isolated clusters with no public inbound port 80, or for wildcard certificates. When enabled, choose DNS-01 and a DNS provider per ACME account in ACME Automation. Leaving this off keeps the default HTTP-01 behavior unchanged."
                      />
                      <Form.Item
                        name="dns01_enabled"
                        label="Enable DNS-01 Challenge"
                        valuePropName="checked"
                        tooltip="Master switch. While off, DNS-01 options are hidden and no DNS-01 orders can be created."
                      >
                        <Switch />
                      </Form.Item>
                    </>
                  ),
                }]}
              />

              <div style={{ marginTop: 24, display: 'flex', gap: 12 }}>
                <Button type="primary" htmlType="submit" loading={acmeSaving}>
                  Save ACME Settings
                </Button>
                <Button
                  icon={<ApiOutlined />}
                  onClick={testConnection}
                  loading={testing}
                >
                  Test Connection
                </Button>
              </div>

              {testResult && (
                <Alert
                  style={{ marginTop: 16 }}
                  type={testResult.success ? 'success' : 'error'}
                  showIcon
                  icon={testResult.success ? <CheckCircleOutlined /> : <CloseCircleOutlined />}
                  message={testResult.success ? 'Connection Successful' : 'Connection Failed'}
                  description={
                    testResult.success
                      ? `Connected to ${testResult.directory}. Available endpoints: ${testResult.endpoints?.join(', ')}`
                      : testResult.error
                  }
                />
              )}
            </Form>
          </Card>
        </Spin>
      ),
    },
    {
      key: 'requestlog',
      label: (
        <span><FileSearchOutlined /> Request Log</span>
      ),
      children: (
        <Spin spinning={rlLoading}>
          <Card>
            <Alert
              message="Request / Response Log"
              description="Records every inbound API call and every outbound HTTP call this backend makes (ACME, DNS providers, agents), with redacted and size-capped request and response bodies. Browse it under Request Log in the sidebar."
              type="info"
              showIcon
              icon={<FileSearchOutlined />}
              style={{ marginBottom: 24 }}
            />

            {rlDenied && (
              <Alert
                message="Read-only"
                description="Changing the request log policy requires the requestlog.manage permission."
                type="warning"
                showIcon
                style={{ marginBottom: 24 }}
              />
            )}

            <Form
              form={rlForm}
              layout="vertical"
              onFinish={onRequestLogSave}
              disabled={rlDenied}
              initialValues={{
                enabled: true,
                capture_inbound: true,
                capture_outbound: true,
                capture_get: true,
                capture_bodies: true,
                max_body_bytes: 8192,
                sample_rate: 1.0,
                success_retention_days: 7,
                error_retention_days: 30,
                max_rows: 500000,
                prune_interval_minutes: 60,
                exclude_paths: [],
              }}
            >
              <Card size="small" title="Capture" style={{ marginBottom: 24 }}>
                <Form.Item
                  name="enabled"
                  label="Enable request log"
                  valuePropName="checked"
                  tooltip="Turning this off stops all capture immediately, without a restart. To remove the middleware entirely set REQUEST_LOG_ENABLED=false in the backend environment."
                >
                  <Switch />
                </Form.Item>
                <Form.Item name="capture_inbound" label="Log inbound API calls" valuePropName="checked">
                  <Switch />
                </Form.Item>
                <Form.Item
                  name="capture_outbound"
                  label="Log outbound HTTP calls"
                  valuePropName="checked"
                  tooltip="Calls this backend makes to Let's Encrypt / ACME, Cloudflare, GoDaddy, agents and HAProxy stats."
                >
                  <Switch />
                </Form.Item>
                <Form.Item
                  name="capture_get"
                  label="Include GET requests"
                  valuePropName="checked"
                  tooltip="GETs are the bulk of the traffic. Turning this off keeps writes and errors only."
                >
                  <Switch />
                </Form.Item>
                <Form.Item
                  name="capture_agent_success"
                  label="Include successful agent polls"
                  valuePropName="checked"
                  tooltip="Each agent writes about 9,800 rows a day just saying nothing changed, so on a large fleet this fills the row cap in hours and shortens retention for everything else. FAILED agent calls are always logged regardless. Turn this on only while debugging a specific node, and turn it back off."
                >
                  <Switch />
                </Form.Item>
                <Form.Item
                  name="capture_bodies"
                  label="Capture bodies (redacted)"
                  valuePropName="checked"
                  tooltip="Passwords, tokens, API keys, private-key PEMs and ACME signatures are never stored, whatever this is set to."
                >
                  <Switch />
                </Form.Item>
                <Form.Item name="max_body_bytes" label="Maximum body size captured (bytes)">
                  <InputNumber min={0} max={262144} step={1024} style={{ width: 200 }} />
                </Form.Item>
                <Form.Item
                  name="sample_rate"
                  label="Sampling rate for successful requests"
                  tooltip="1.0 logs everything. Errors are always captured at 100%, whatever this is set to."
                >
                  <InputNumber min={0} max={1} step={0.05} style={{ width: 200 }} />
                </Form.Item>
              </Card>

              <Card size="small" title="Retention" style={{ marginBottom: 24 }}>
                <Alert
                  type="warning"
                  showIcon
                  style={{ marginBottom: 16 }}
                  message="Whichever limit is reached first wins"
                  description="Rows are removed when they pass their retention window OR when the table exceeds the row cap — the cap is the backstop for a sudden traffic spike."
                />
                <Form.Item name="success_retention_days" label="Keep successful requests for (days)">
                  <InputNumber min={1} max={365} style={{ width: 200 }} />
                </Form.Item>
                <Form.Item
                  name="error_retention_days"
                  label="Keep failed requests for (days)"
                  tooltip="4xx, 5xx and calls that got no response at all. Usually set longer than the success window."
                >
                  <InputNumber min={1} max={365} style={{ width: 200 }} />
                </Form.Item>
                <Form.Item name="max_rows" label="Maximum stored rows">
                  <InputNumber min={1000} max={50000000} step={10000} style={{ width: 200 }} />
                </Form.Item>
                <Form.Item name="prune_interval_minutes" label="Minimum interval between prune passes (minutes)">
                  <InputNumber min={5} max={1440} style={{ width: 200 }} />
                </Form.Item>
              </Card>

              <Card size="small" title="Excluded paths" style={{ marginBottom: 24 }}>
                <Form.Item
                  name="exclude_paths"
                  label="Never log these path prefixes"
                  tooltip="Health checks, the API docs, the ACME challenge endpoint and the agent heartbeat are excluded by default. The log viewer's own endpoints are always excluded and cannot be re-enabled."
                >
                  <Select
                    mode="tags"
                    tokenSeparators={[',', ' ']}
                    placeholder="/api/health"
                    style={{ width: '100%' }}
                  />
                </Form.Item>
              </Card>

              <Button type="primary" htmlType="submit" loading={rlSaving} disabled={rlDenied}>
                Save Request Log Settings
              </Button>
            </Form>
          </Card>
        </Spin>
      ),
    },
  ];

  return (
    <div>
      <Tabs items={tabItems} defaultActiveKey={defaultTab} />
    </div>
  );
};

export { Settings };
