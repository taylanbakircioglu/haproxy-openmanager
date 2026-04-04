import React, { useEffect, useState } from 'react';
import { Card, Form, Switch, Button, InputNumber, message, Tabs, Input, Select, Collapse, Space, Alert, Tag, Spin, Tooltip } from 'antd';
import { SafetyCertificateOutlined, ApiOutlined, CheckCircleOutlined, CloseCircleOutlined, InfoCircleOutlined } from '@ant-design/icons';
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
  }, []);

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
  ];

  return (
    <div>
      <Tabs items={tabItems} defaultActiveKey={defaultTab} />
    </div>
  );
};

export { Settings };
