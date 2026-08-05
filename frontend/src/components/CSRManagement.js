import React, { useState, useEffect, useCallback } from 'react';
import {
  Card, Table, Button, Modal, Form, Input, Space, message,
  Popconfirm, Tag, Tooltip, Row, Col, Typography, Alert, Select,
  Collapse, Descriptions, Badge
} from 'antd';
import {
  PlusOutlined, ReloadOutlined, DeleteOutlined, EyeOutlined,
  DownloadOutlined, CopyOutlined, FileProtectOutlined, ImportOutlined,
  KeyOutlined
} from '@ant-design/icons';
import axios from 'axios';
import { useCluster } from '../contexts/ClusterContext';
import { extractApiError } from '../utils/apiError';
import { antdDomainRule, antdDomainsListRule } from '../utils/validation';

const { Text } = Typography;
const { TextArea } = Input;

const KEY_ALGORITHM_OPTIONS = [
  { value: 'rsa-2048', label: 'RSA 2048 (recommended)' },
  { value: 'rsa-4096', label: 'RSA 4096' },
  { value: 'ecdsa-p256', label: 'ECDSA P-256' },
  { value: 'ecdsa-p384', label: 'ECDSA P-384' },
];

const KEY_ALGORITHM_LABELS = {
  'rsa-2048': 'RSA 2048',
  'rsa-4096': 'RSA 4096',
  'ecdsa-p256': 'ECDSA P-256',
  'ecdsa-p384': 'ECDSA P-384',
};

// CSR creation (v1.9.0): generate the private key + CSR server-side, submit
// the CSR to an external CA, then import the signed certificate. The private
// key never leaves the backend — this component only ever handles the CSR
// PEM and the CA's certificate response.
const CSRManagement = ({ onCertificateImported }) => {
  const { clusters } = useCluster();
  const [csrs, setCsrs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [viewCsr, setViewCsr] = useState(null);
  const [importCsr, setImportCsr] = useState(null);
  const [importing, setImporting] = useState(false);
  const [createForm] = Form.useForm();
  const [importForm] = Form.useForm();

  const fetchCsrs = useCallback(async () => {
    setLoading(true);
    try {
      const response = await axios.get('/api/ssl/csrs', {
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache',
        },
      });
      setCsrs(Array.isArray(response.data) ? response.data : []);
    } catch (error) {
      console.error('Error fetching CSRs:', error);
      message.error(extractApiError(error, 'Failed to fetch CSRs'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchCsrs();
  }, [fetchCsrs]);

  const handleCreate = async (values) => {
    setCreating(true);
    try {
      const payload = {
        name: values.name,
        common_name: values.common_name,
        sans: values.sans || [],
        key_algorithm: values.key_algorithm || 'rsa-2048',
        organization: values.organization || null,
        organizational_unit: values.organizational_unit || null,
        locality: values.locality || null,
        state: values.state || null,
        country: values.country || null,
        email: values.email || null,
      };
      const response = await axios.post('/api/ssl/csrs', payload);
      message.success(
        <div>
          <strong>CSR '{values.name}' created</strong>
          <br />
          <small>Submit the CSR to your Certificate Authority for signing.</small>
        </div>,
        5
      );
      setCreateModalOpen(false);
      createForm.resetFields();
      fetchCsrs();
      // Open the view modal immediately so the operator can copy/download
      // the CSR PEM in one round trip.
      if (response.data?.csr) {
        setViewCsr(response.data.csr);
      }
    } catch (error) {
      console.error('Error creating CSR:', error);
      message.error(extractApiError(error, 'Failed to create CSR'));
    } finally {
      setCreating(false);
    }
  };

  const handleView = async (record) => {
    try {
      const response = await axios.get(`/api/ssl/csrs/${record.id}`);
      setViewCsr(response.data);
    } catch (error) {
      console.error('Error fetching CSR details:', error);
      message.error(extractApiError(error, 'Failed to fetch CSR details'));
    }
  };

  const handleDuplicate = (record) => {
    const subject = record.subject || {};
    createForm.setFieldsValue({
      name: `${record.name}-new`,
      common_name: record.common_name,
      sans: (record.sans || []).filter((s) => s !== record.common_name),
      key_algorithm: record.key_algorithm || 'rsa-2048',
      organization: subject.O || undefined,
      organizational_unit: subject.OU || undefined,
      locality: subject.L || undefined,
      state: subject.ST || undefined,
      country: subject.C || undefined,
      email: subject.emailAddress || undefined,
    });
    setCreateModalOpen(true);
  };

  const handleDelete = async (record) => {
    try {
      const response = await axios.delete(`/api/ssl/csrs/${record.id}`);
      message.success(response.data?.message || `CSR '${record.name}' deleted`);
      fetchCsrs();
    } catch (error) {
      console.error('Error deleting CSR:', error);
      message.error(extractApiError(error, 'Failed to delete CSR'));
    }
  };

  const handleImport = async (values) => {
    if (!importCsr) return;
    setImporting(true);
    try {
      const isGlobal = values.ssl_type === 'global';
      const payload = {
        certificate_content: values.certificate_content,
        chain_content: values.chain_content || null,
        usage_type: values.usage_type || 'frontend',
        is_global: isGlobal,
        cluster_ids: isGlobal ? null : values.cluster_ids,
        name: values.name_override ? values.name_override.trim() : null,
      };
      const response = await axios.post(
        `/api/ssl/csrs/${importCsr.id}/import`,
        payload
      );
      const warnings = response.data?.warnings || [];
      if (warnings.length > 0) {
        Modal.warning({
          title: 'Certificate imported with warnings',
          width: 560,
          content: (
            <ul style={{ paddingLeft: 18, marginTop: 8 }}>
              {warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          ),
        });
      }
      message.success(
        <div>
          <strong>Certificate imported successfully</strong>
          <br />
          <small>Go to Apply Management to deploy it to the cluster(s).</small>
        </div>,
        6
      );
      setImportCsr(null);
      importForm.resetFields();
      fetchCsrs();
      if (onCertificateImported) {
        onCertificateImported();
      }
    } catch (error) {
      console.error('Error importing signed certificate:', error);
      message.error(extractApiError(error, 'Failed to import certificate'));
    } finally {
      setImporting(false);
    }
  };

  const downloadCsrPem = (csr) => {
    if (!csr?.csr_pem) return;
    const blob = new Blob([csr.csr_pem], { type: 'application/pkcs10;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${csr.name}.csr`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const copyCsrPem = (csr) => {
    if (!csr?.csr_pem) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard
        .writeText(csr.csr_pem)
        .then(() => message.success('CSR PEM copied to clipboard'))
        .catch(() => message.error('Failed to copy CSR PEM'));
    } else {
      message.warning('Clipboard is not available in this browser');
    }
  };

  const columns = [
    {
      title: 'CSR',
      dataIndex: 'name',
      key: 'name',
      render: (text, record) => (
        <Space>
          <FileProtectOutlined style={{ color: '#1677ff' }} />
          <div>
            <strong>{text}</strong>
            <br />
            <Text type="secondary" style={{ fontSize: 12 }}>
              {record.common_name}
            </Text>
          </div>
        </Space>
      ),
    },
    {
      title: 'SANs',
      dataIndex: 'sans',
      key: 'sans',
      render: (sans) => {
        const list = Array.isArray(sans) ? sans : [];
        if (list.length === 0) return <Text type="secondary">-</Text>;
        const visible = list.slice(0, 2);
        const rest = list.slice(2);
        return (
          <Space size={4} wrap>
            {visible.map((d) => (
              <Tag key={d}>{d}</Tag>
            ))}
            {rest.length > 0 && (
              <Tooltip title={rest.join(', ')}>
                <Tag>+{rest.length}</Tag>
              </Tooltip>
            )}
          </Space>
        );
      },
    },
    {
      title: 'Key',
      dataIndex: 'key_algorithm',
      key: 'key_algorithm',
      render: (algo) => (
        <Tag icon={<KeyOutlined />} color="geekblue">
          {KEY_ALGORITHM_LABELS[algo] || algo}
        </Tag>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status, record) => {
        if (status === 'completed') {
          return (
            <div>
              <Badge status="success" text="Imported" />
              {record.certificate_name && (
                <>
                  <br />
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    → {record.certificate_name}
                  </Text>
                </>
              )}
            </div>
          );
        }
        return <Badge status="processing" text="Awaiting certificate" />;
      },
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date, record) => (
        <div>
          {date
            ? new Date(date).toLocaleString(undefined, {
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
              })
            : '-'}
          {record.created_by_username && (
            <>
              <br />
              <Text type="secondary" style={{ fontSize: 12 }}>
                by {record.created_by_username}
              </Text>
            </>
          )}
        </div>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space size="small">
          <Tooltip title="View / download CSR">
            <Button
              type="text"
              size="small"
              icon={<EyeOutlined />}
              onClick={() => handleView(record)}
            />
          </Tooltip>
          {record.status === 'pending' && (
            <Tooltip title="Import signed certificate">
              <Button
                type="primary"
                size="small"
                icon={<ImportOutlined />}
                onClick={() => {
                  importForm.resetFields();
                  setImportCsr(record);
                }}
              >
                Import
              </Button>
            </Tooltip>
          )}
          <Tooltip title="Duplicate (pre-fill a new CSR)">
            <Button
              type="text"
              size="small"
              icon={<CopyOutlined />}
              onClick={() => handleDuplicate(record)}
            />
          </Tooltip>
          <Popconfirm
            title="Delete this CSR?"
            description={
              record.status === 'pending'
                ? 'The private key will be permanently destroyed — any certificate later signed from this CSR becomes unusable.'
                : 'Only the CSR history entry is removed — the imported certificate is not affected.'
            }
            onConfirm={() => handleDelete(record)}
            okText="Delete"
            okType="danger"
            cancelText="Cancel"
          >
            <Tooltip title="Delete CSR">
              <Button type="text" size="small" danger icon={<DeleteOutlined />} />
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const pendingCount = csrs.filter((c) => c.status === 'pending').length;

  return (
    <div>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="Certificate Signing Requests for external CAs"
        description="Generate a private key and CSR here, submit the CSR to your Certificate Authority, then import the signed certificate. The private key never leaves the server; the imported certificate goes through the normal Apply Management deployment flow."
      />
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col flex="auto">
          {pendingCount > 0 && (
            <Text type="secondary">
              {pendingCount} CSR{pendingCount > 1 ? 's' : ''} awaiting a signed
              certificate
            </Text>
          )}
        </Col>
        <Col>
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetchCsrs} loading={loading}>
              Refresh
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => {
                createForm.resetFields();
                setCreateModalOpen(true);
              }}
            >
              Create CSR
            </Button>
          </Space>
        </Col>
      </Row>

      <Card>
        <Table
          columns={columns}
          dataSource={csrs}
          rowKey="id"
          loading={loading}
          pagination={{
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total) => `Total ${total} CSRs`,
          }}
        />
      </Card>

      {/* Create CSR Modal */}
      <Modal
        title="Create Certificate Signing Request"
        open={createModalOpen}
        onCancel={() => {
          setCreateModalOpen(false);
          createForm.resetFields();
        }}
        footer={null}
        width={700}
        forceRender
      >
        <Form form={createForm} layout="vertical" onFinish={handleCreate}>
          <Form.Item
            name="name"
            label="Name"
            rules={[
              { required: true, message: 'Please enter a CSR name' },
              {
                pattern: /^[a-zA-Z0-9_.-]+$/,
                message:
                  'Only letters, digits, underscore, hyphen and dot are allowed',
              },
              { max: 100, message: 'Name must be 100 characters or fewer' },
              {
                validator: (_, value) => {
                  if (!value) return Promise.resolve();
                  if (value.includes('..')) {
                    return Promise.reject(new Error('Name must not contain ".."'));
                  }
                  if (value.startsWith('.') || value.startsWith('-')) {
                    return Promise.reject(
                      new Error('Name must not start with "." or "-"')
                    );
                  }
                  return Promise.resolve();
                },
              },
            ]}
            extra="Becomes the certificate name and file path at import: /etc/ssl/haproxy/{name}.pem"
          >
            <Input placeholder="e.g. www-example-com" />
          </Form.Item>

          <Form.Item
            name="common_name"
            label="Common Name (CN)"
            rules={[
              { required: true, message: 'Please enter the Common Name' },
              antdDomainRule,
              { max: 64, message: 'Common Name must be 64 characters or fewer' },
            ]}
            extra="The primary domain, e.g. www.example.com or *.example.com"
          >
            <Input placeholder="www.example.com" />
          </Form.Item>

          <Form.Item
            name="sans"
            label="Subject Alternative Names (SANs)"
            rules={[antdDomainsListRule]}
            extra="Additional DNS names — the Common Name is included automatically"
          >
            <Select
              mode="tags"
              tokenSeparators={[',', ' ']}
              placeholder="api.example.com, cdn.example.com"
              open={false}
              suffixIcon={null}
            />
          </Form.Item>

          <Form.Item
            name="key_algorithm"
            label="Key Algorithm"
            initialValue="rsa-2048"
            rules={[{ required: true }]}
          >
            <Select options={KEY_ALGORITHM_OPTIONS} />
          </Form.Item>

          <Collapse
            style={{ marginBottom: 16 }}
            items={[
              {
                key: 'subject',
                label: 'Subject details (optional)',
                children: (
                  <>
                    <Row gutter={12}>
                      <Col span={12}>
                        <Form.Item
                          name="organization"
                          label="Organization (O)"
                          rules={[{ max: 64 }]}
                        >
                          <Input placeholder="Example Corp" />
                        </Form.Item>
                      </Col>
                      <Col span={12}>
                        <Form.Item
                          name="organizational_unit"
                          label="Organizational Unit (OU)"
                          rules={[{ max: 64 }]}
                        >
                          <Input placeholder="IT Department" />
                        </Form.Item>
                      </Col>
                    </Row>
                    <Row gutter={12}>
                      <Col span={8}>
                        <Form.Item name="locality" label="Locality (L)" rules={[{ max: 64 }]}>
                          <Input placeholder="Istanbul" />
                        </Form.Item>
                      </Col>
                      <Col span={8}>
                        <Form.Item name="state" label="State / Province (ST)" rules={[{ max: 64 }]}>
                          <Input placeholder="Marmara" />
                        </Form.Item>
                      </Col>
                      <Col span={8}>
                        <Form.Item
                          name="country"
                          label="Country (C)"
                          rules={[
                            {
                              pattern: /^[A-Za-z]{2}$/,
                              message: 'Exactly 2 letters (e.g. TR, US)',
                            },
                          ]}
                        >
                          <Input placeholder="TR" maxLength={2} />
                        </Form.Item>
                      </Col>
                    </Row>
                    <Form.Item
                      name="email"
                      label="Email"
                      rules={[{ type: 'email', message: 'Invalid email address' }]}
                    >
                      <Input placeholder="ops@example.com" />
                    </Form.Item>
                  </>
                ),
              },
            ]}
          />

          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
            message="🔐 The private key is generated and stored server-side"
            description="You will only receive the CSR to hand to your CA. After the signed certificate is imported, the key is available on the certificate itself."
          />

          <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}>
            <Space>
              <Button
                onClick={() => {
                  setCreateModalOpen(false);
                  createForm.resetFields();
                }}
              >
                Cancel
              </Button>
              <Button type="primary" htmlType="submit" loading={creating}>
                Generate CSR
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* View CSR Modal */}
      <Modal
        title={
          <Space>
            <FileProtectOutlined />
            {viewCsr ? `CSR: ${viewCsr.name}` : 'CSR'}
          </Space>
        }
        open={!!viewCsr}
        onCancel={() => setViewCsr(null)}
        width={760}
        footer={[
          <Button key="close" onClick={() => setViewCsr(null)}>
            Close
          </Button>,
        ]}
      >
        {viewCsr && (
          <div>
            <Descriptions size="small" column={2} bordered style={{ marginBottom: 12 }}>
              <Descriptions.Item label="Common Name" span={2}>
                {viewCsr.common_name}
              </Descriptions.Item>
              <Descriptions.Item label="Key">
                {KEY_ALGORITHM_LABELS[viewCsr.key_algorithm] || viewCsr.key_algorithm}
              </Descriptions.Item>
              <Descriptions.Item label="Status">
                {viewCsr.status === 'completed' ? (
                  <Badge status="success" text="Imported" />
                ) : (
                  <Badge status="processing" text="Awaiting certificate" />
                )}
              </Descriptions.Item>
              {viewCsr.subject && Object.keys(viewCsr.subject).length > 0 && (
                <Descriptions.Item label="Subject" span={2}>
                  {Object.entries(viewCsr.subject)
                    .map(([k, v]) => `${k}=${v}`)
                    .join(', ')}
                </Descriptions.Item>
              )}
            </Descriptions>

            {Array.isArray(viewCsr.sans) && viewCsr.sans.length > 0 && (
              <div style={{ marginBottom: 12 }}>
                <Text strong>SANs: </Text>
                <Space size={4} wrap>
                  {viewCsr.sans.map((d) => (
                    <Tag key={d}>{d}</Tag>
                  ))}
                </Space>
              </div>
            )}

            <Row justify="space-between" align="middle" style={{ marginBottom: 8 }}>
              <Col>
                <Text strong>CSR (PEM)</Text>
              </Col>
              <Col>
                <Space>
                  <Button
                    size="small"
                    icon={<CopyOutlined />}
                    onClick={() => copyCsrPem(viewCsr)}
                  >
                    Copy
                  </Button>
                  <Button
                    size="small"
                    type="primary"
                    icon={<DownloadOutlined />}
                    onClick={() => downloadCsrPem(viewCsr)}
                  >
                    Download .csr
                  </Button>
                </Space>
              </Col>
            </Row>
            <TextArea
              value={viewCsr.csr_pem}
              rows={12}
              readOnly
              style={{ fontFamily: 'monospace', fontSize: 12 }}
            />
            {viewCsr.status !== 'completed' && (
              <Alert
                type="info"
                showIcon
                style={{ marginTop: 12 }}
                message="Next step"
                description="Submit this CSR to your Certificate Authority. When you receive the signed certificate, come back and click Import on this CSR."
              />
            )}
          </div>
        )}
      </Modal>

      {/* Import Signed Certificate Modal */}
      <Modal
        title={
          <Space>
            <ImportOutlined />
            {importCsr ? `Import Signed Certificate — ${importCsr.name}` : 'Import'}
          </Space>
        }
        open={!!importCsr}
        onCancel={() => {
          setImportCsr(null);
          importForm.resetFields();
        }}
        footer={null}
        width={800}
      >
        {importCsr && (
          <div>
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 16 }}
              message={`CSR: ${importCsr.name} (CN: ${importCsr.common_name})`}
              description="Paste the certificate your CA issued for this CSR. It will be verified against the stored private key before anything is saved."
            />
            <Form
              form={importForm}
              layout="vertical"
              onFinish={handleImport}
              initialValues={{ ssl_type: 'cluster', usage_type: 'frontend' }}
            >
              <Row gutter={12}>
                <Col span={12}>
                  <Form.Item
                    name="usage_type"
                    label="Usage Type"
                    rules={[{ required: true }]}
                  >
                    <Select
                      options={[
                        { value: 'frontend', label: 'Frontend SSL (HTTPS termination)' },
                        { value: 'server', label: 'Server SSL (backend verification)' },
                      ]}
                    />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item name="ssl_type" label="Scope" rules={[{ required: true }]}>
                    <Select
                      options={[
                        { value: 'global', label: 'Global (all clusters)' },
                        { value: 'cluster', label: 'Cluster-specific' },
                      ]}
                    />
                  </Form.Item>
                </Col>
              </Row>

              <Form.Item
                noStyle
                shouldUpdate={(prev, cur) => prev.ssl_type !== cur.ssl_type}
              >
                {({ getFieldValue }) =>
                  getFieldValue('ssl_type') === 'cluster' && (
                    <Form.Item
                      name="cluster_ids"
                      label="Clusters"
                      rules={[
                        { required: true, message: 'Select at least one cluster' },
                      ]}
                    >
                      <Select
                        mode="multiple"
                        placeholder="Select cluster(s)"
                        options={(clusters || []).map((c) => ({
                          value: c.id,
                          label: c.name,
                        }))}
                      />
                    </Form.Item>
                  )
                }
              </Form.Item>

              <Form.Item
                name="certificate_content"
                label="Signed Certificate (PEM)"
                rules={[
                  { required: true, message: 'Please paste the signed certificate' },
                  {
                    validator: (_, value) => {
                      if (!value) return Promise.resolve();
                      if (
                        value.includes('-----BEGIN CERTIFICATE-----') &&
                        value.includes('-----END CERTIFICATE-----')
                      ) {
                        return Promise.resolve();
                      }
                      return Promise.reject(
                        new Error('Certificate must be in PEM format')
                      );
                    },
                  },
                ]}
              >
                <TextArea
                  rows={8}
                  placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'}
                  style={{ fontFamily: 'monospace', fontSize: 12 }}
                />
              </Form.Item>

              <Form.Item
                name="name_override"
                label="Certificate name override (optional)"
                rules={[
                  {
                    pattern: /^[a-zA-Z0-9_.-]+$/,
                    message:
                      'Only letters, digits, underscore, hyphen and dot are allowed',
                  },
                  { max: 100, message: 'Name must be 100 characters or fewer' },
                ]}
                extra={`Leave empty to use the CSR name ('${importCsr.name}'). Use this only if that name is now taken by another certificate.`}
              >
                <Input placeholder={importCsr.name} />
              </Form.Item>

              <Form.Item
                name="chain_content"
                label="Certificate Chain (PEM, optional)"
                rules={[
                  {
                    validator: (_, value) => {
                      if (!value || !value.trim()) return Promise.resolve();
                      if (
                        value.includes('-----BEGIN CERTIFICATE-----') &&
                        value.includes('-----END CERTIFICATE-----')
                      ) {
                        return Promise.resolve();
                      }
                      return Promise.reject(
                        new Error('Certificate chain must be in PEM format')
                      );
                    },
                  },
                ]}
              >
                <TextArea
                  rows={4}
                  placeholder={'-----BEGIN CERTIFICATE-----\n(intermediate CA)\n-----END CERTIFICATE-----'}
                  style={{ fontFamily: 'monospace', fontSize: 12 }}
                />
              </Form.Item>

              <Form.Item style={{ textAlign: 'right', marginBottom: 0 }}>
                <Space>
                  <Button
                    onClick={() => {
                      setImportCsr(null);
                      importForm.resetFields();
                    }}
                  >
                    Cancel
                  </Button>
                  <Button type="primary" htmlType="submit" loading={importing}>
                    Import Certificate
                  </Button>
                </Space>
              </Form.Item>
            </Form>
          </div>
        )}
      </Modal>
    </div>
  );
};

export default CSRManagement;
