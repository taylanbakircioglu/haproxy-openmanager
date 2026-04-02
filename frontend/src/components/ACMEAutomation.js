import React, { useState, useEffect, useCallback } from 'react';
import {
  Card, Table, Button, Tag, Space, Modal, Form, Input, Select, Steps,
  message, Row, Col, Statistic, Alert, Tooltip, Switch, theme
} from 'antd';
import {
  SafetyCertificateOutlined, PlusOutlined, ReloadOutlined,
  CheckCircleOutlined, ClockCircleOutlined, ExclamationCircleOutlined,
  SyncOutlined, CloseCircleOutlined,
  DeleteOutlined, EyeOutlined,
  CloudDownloadOutlined, UserOutlined, InfoCircleOutlined
} from '@ant-design/icons';
import axios from 'axios';

const { Option } = Select;

const ACMEAutomation = () => {
  const [orders, setOrders] = useState([]);
  const [accounts, setAccounts] = useState([]);
  const [renewalSchedule, setRenewalSchedule] = useState([]);
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
  const { token } = theme.useToken();

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [ordersRes, accountsRes, renewalRes, clustersRes] = await Promise.allSettled([
        axios.get('/api/letsencrypt/orders'),
        axios.get('/api/letsencrypt/accounts'),
        axios.get('/api/letsencrypt/renewal-schedule'),
        axios.get('/api/clusters'),
      ]);
      if (ordersRes.status === 'fulfilled') setOrders(ordersRes.value.data || []);
      if (accountsRes.status === 'fulfilled') setAccounts(accountsRes.value.data || []);
      if (renewalRes.status === 'fulfilled') setRenewalSchedule(renewalRes.value.data || []);
      if (clustersRes.status === 'fulfilled') setClusters(clustersRes.value.data?.clusters || []);
    } catch (err) {
      console.error('Error loading ACME data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const acmeCerts = renewalSchedule.length;
  const calcDaysLeft = (expiryDate) => {
    if (!expiryDate) return null;
    return Math.ceil((new Date(expiryDate) - new Date()) / (1000 * 60 * 60 * 24));
  };
  const nextRenewal = renewalSchedule.find(c => c.auto_renew && calcDaysLeft(c.expiry_date) > 0);
  const nextRenewalDays = nextRenewal ? calcDaysLeft(nextRenewal.expiry_date) : null;
  const pendingOrders = orders.filter(o => o.status === 'pending' || o.status === 'processing');
  const activeAccount = accounts.find(a => a.status === 'valid') || null;
  const acmeAccount = activeAccount || (accounts.length > 0 ? accounts[accounts.length - 1] : null);

  const handleRequestCert = async () => {
    try {
      const values = wizardForm.getFieldsValue(true);
      if (!values.domains || values.domains.length === 0) {
        message.error('At least one domain is required');
        return;
      }
      setSubmitting(true);
      const res = await axios.post('/api/letsencrypt/certificates', {
        domains: values.domains,
        cluster_ids: values.cluster_ids || [],
        auto_renew: values.auto_renew !== false,
        account_id: values.account_id || null,
      });
      message.success(res.data?.message || 'Certificate request submitted');
      setWizardVisible(false);
      setWizardStep(0);
      wizardForm.resetFields();
      fetchData();
    } catch (err) {
      message.error(err?.response?.data?.detail || 'Failed to request certificate');
    } finally {
      setSubmitting(false);
    }
  };

  const handleRetry = async (orderId) => {
    try {
      const res = await axios.post(`/api/letsencrypt/orders/${orderId}/retry`);
      message.success(res.data?.message || 'Retry submitted');
      fetchData();
    } catch (err) {
      message.error(err?.response?.data?.detail || 'Retry failed');
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
          message.error(err?.response?.data?.detail || 'Cancel failed');
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
      message.error('Failed to load order details');
    }
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
          message.error(err?.response?.data?.detail || 'Import failed');
        }
      },
    });
  };

  const handleRegisterAccount = async () => {
    try {
      const values = await registerForm.validateFields();
      setRegistering(true);
      const res = await axios.post('/api/letsencrypt/accounts', {
        email: values.email,
        tos_agreed: values.tos_agreed,
      });
      message.success(`ACME account registered: ${res.data?.email || values.email}`);
      setRegisterVisible(false);
      registerForm.resetFields();
      fetchData();
    } catch (err) {
      message.error(err?.response?.data?.detail || 'Account registration failed');
    } finally {
      setRegistering(false);
    }
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
          message.error(err?.response?.data?.detail || 'Failed to deactivate account');
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
          message.error(err?.response?.data?.detail || 'Failed to remove account');
        }
      },
    });
  };

  const statusTag = (status) => {
    const map = {
      pending: { color: 'processing', icon: <ClockCircleOutlined /> },
      processing: { color: 'processing', icon: <SyncOutlined spin /> },
      ready: { color: 'warning', icon: <ExclamationCircleOutlined /> },
      valid: { color: 'success', icon: <CheckCircleOutlined /> },
      invalid: { color: 'error', icon: <CloseCircleOutlined /> },
      cancelled: { color: 'default', icon: <CloseCircleOutlined /> },
    };
    const cfg = map[status] || { color: 'default', icon: null };
    return <Tag color={cfg.color} icon={cfg.icon}>{status?.toUpperCase()}</Tag>;
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
      render: statusTag,
    },
    {
      title: 'Account', dataIndex: 'account_email', key: 'account_email',
      render: (e) => e || '-',
    },
    {
      title: 'Created', dataIndex: 'created_at', key: 'created_at',
      render: (d) => d ? new Date(d).toLocaleString() : '-',
    },
    {
      title: 'Actions', key: 'actions',
      render: (_, record) => (
        <Space>
          <Tooltip title="View Details">
            <Button icon={<EyeOutlined />} size="small" onClick={() => handleViewOrder(record.id)} />
          </Tooltip>
          {(record.status === 'pending' || record.status === 'ready') && (
            <Tooltip title="Retry / Finalize">
              <Button icon={<ReloadOutlined />} size="small" type="primary" ghost onClick={() => handleRetry(record.id)} />
            </Tooltip>
          )}
          {record.status !== 'valid' && record.status !== 'cancelled' && (
            <Tooltip title="Cancel">
              <Button icon={<DeleteOutlined />} size="small" danger onClick={() => handleCancel(record.id)} />
            </Tooltip>
          )}
        </Space>
      ),
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
      title: 'Auto-Renew', dataIndex: 'auto_renew', key: 'auto_renew',
      render: (v) => v ? <Tag color="green">Enabled</Tag> : <Tag>Disabled</Tag>,
    },
  ];

  const acmeEnabledClusters = clusters.filter(c => c.acme_enabled);

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
            message="Each domain must resolve to an HAProxy node with ACME challenge routing enabled."
          />
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
                  {c.name} {c.acme_enabled ? '' : '(ACME not enabled)'}
                </Option>
              ))}
            </Select>
          </Form.Item>
          <Form.Item name="auto_renew" label="Auto-Renew" valuePropName="checked" initialValue={true}>
            <Switch defaultChecked />
          </Form.Item>
          {accounts.length > 1 && (
            <Form.Item name="account_id" label="ACME Account">
              <Select placeholder="Use default account">
                {accounts.map(a => (
                  <Option key={a.id} value={a.id}>{a.email} ({a.directory_url})</Option>
                ))}
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
              description="Please register an active ACME account in Settings > ACME or from the ACME Account card."
              style={{ marginBottom: 16 }}
            />
          )}
          {acmeEnabledClusters.length === 0 && (
            <Alert
              type="warning"
              showIcon
              message="No Clusters with ACME Enabled"
              description="Enable ACME challenge routing on at least one cluster in Cluster Management."
              style={{ marginBottom: 16 }}
            />
          )}
          <Alert
            type="info"
            showIcon
            message="Prerequisite Check"
            description={
              <ul style={{ margin: 0, paddingLeft: 20 }}>
                <li>ACME Account: {activeAccount ? <Tag color="success">Active ({activeAccount.email})</Tag> : <Tag color="error">No active account</Tag>}</li>
                <li>ACME-enabled Clusters: {acmeEnabledClusters.length > 0 ? <Tag color="success">{acmeEnabledClusters.map(c => c.name).join(', ')}</Tag> : <Tag color="warning">None</Tag>}</li>
                <li>Domains must resolve to HAProxy node IPs for HTTP-01 validation</li>
              </ul>
            }
          />
        </>
      ),
    },
  ];

  return (
    <div>
      {pendingOrders.length > 0 && (
        <Alert
          type="warning"
          showIcon
          icon={<ExclamationCircleOutlined />}
          message={`${pendingOrders.length} certificate order(s) awaiting validation or Apply`}
          style={{ marginBottom: 16 }}
        />
      )}

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
        <Table
          columns={orderColumns}
          dataSource={orders}
          rowKey="id"
          loading={loading}
          pagination={{ pageSize: 10 }}
          size="small"
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
            <Button type="primary" onClick={handleRequestCert} loading={submitting} disabled={!activeAccount}>
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
            <p><strong>Status:</strong> {statusTag(orderDetail.status)}</p>
            <p><strong>Domains:</strong> {(orderDetail.domains || []).map(d => <Tag key={d}>{d}</Tag>)}</p>
            <p><strong>Account:</strong> {orderDetail.account_email}</p>
            {orderDetail.error_detail && (
              <Alert type="error" message="Error" description={orderDetail.error_detail} style={{ marginBottom: 16 }} />
            )}
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
                    { title: 'Token', dataIndex: 'token', key: 'token', ellipsis: true },
                    { title: 'Status', dataIndex: 'status', key: 'status', render: statusTag },
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
                title: 'Email', dataIndex: 'email', key: 'email',
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
                                <p><strong>ToS Accepted:</strong> {record.tos_agreed ? 'Yes' : 'No'}</p>
                                <p><strong>Registered:</strong> {record.created_at ? new Date(record.created_at).toLocaleString() : '-'}</p>
                              </div>
                            ),
                          });
                        }}
                      />
                    </Tooltip>
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
        <Form form={registerForm} layout="vertical">
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
            valuePropName="checked"
            initialValue={false}
            rules={[{ validator: (_, v) => v ? Promise.resolve() : Promise.reject('You must accept the Terms of Service') }]}
          >
            <Switch checkedChildren="Accepted" unCheckedChildren="Not Accepted" />
          </Form.Item>
          <div style={{ fontSize: 12, color: token.colorTextSecondary }}>
            By accepting, you agree to the ACME CA's Terms of Service (e.g.{' '}
            <a href="https://letsencrypt.org/repository/" target="_blank" rel="noopener noreferrer">
              Let's Encrypt Subscriber Agreement
            </a>).
          </div>
        </Form>
      </Modal>
    </div>
  );
};

export default ACMEAutomation;
