import React, { useState, useContext } from 'react';
import {
  Card,
  Input,
  Button,
  Alert,
  Spin,
  Typography,
  Space,
  Divider,
  Table,
  Tag,
  Modal,
  message,
  Descriptions,
  Collapse,
  Tooltip
} from 'antd';
import {
  UploadOutlined,
  FileTextOutlined,
  CheckCircleOutlined,
  WarningOutlined,
  InfoCircleOutlined,
  QuestionCircleOutlined
} from '@ant-design/icons';
import { ClusterContext } from '../contexts/ClusterContext';
import { api } from '../utils/api';

const { TextArea } = Input;
const { Title, Text, Paragraph } = Typography;
const { Panel } = Collapse;

const BulkConfigImport = () => {
  const { selectedCluster } = useContext(ClusterContext);
  const [configContent, setConfigContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [parseResult, setParseResult] = useState(null);
  const [errors, setErrors] = useState([]);
  const [warnings, setWarnings] = useState([]);
  const [creating, setCreating] = useState(false);
  const [exampleModalVisible, setExampleModalVisible] = useState(false);

  const exampleConfig = `frontend web-frontend
    bind *:80
    mode http
    default_backend web-backend
 
backend web-backend
    mode http
    balance roundrobin
    server web1 192.168.1.10:8080 check
    server web2 192.168.1.11:8080 check
    server web3 192.168.1.12:8080 check`;

  const handleParseConfig = async () => {
    if (!selectedCluster) {
      message.error('Please select a cluster first');
      return;
    }

    if (!configContent.trim()) {
      message.error('Please enter HAProxy configuration');
      return;
    }

    setLoading(true);
    setErrors([]);
    setWarnings([]);
    setParseResult(null);

    try {
      const response = await api.post('/api/config/parse-bulk', {
        config_content: configContent,
        cluster_id: selectedCluster.id
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to parse configuration');
      }

      if (data.errors && data.errors.length > 0) {
        setErrors(data.errors);
      }

      if (data.warnings && data.warnings.length > 0) {
        setWarnings(data.warnings);
      }

      setParseResult(data);
      
      // Build multi-line success message showing only NEW entities
      // "Existing" entities are shown in table, no need to clutter message
      const totalCount = data.summary.frontends_count + data.summary.backends_count + data.summary.total_servers_count;
      
      const messageLines = [`Parsed ${totalCount} entities successfully`];
      
      // Only show NEW entities in success message (cleaner, focused on changes)
      if (data.summary.new_frontends > 0) {
        messageLines.push(`✓ Frontends: ${data.summary.new_frontends} new`);
      }
      if (data.summary.new_backends > 0) {
        messageLines.push(`✓ Backends: ${data.summary.new_backends} new`);
      }
      if (data.summary.new_servers > 0) {
        messageLines.push(`✓ Servers: ${data.summary.new_servers} new`);
      }
      
      // Show multi-line message (each line visible)
      messageLines.forEach((line, index) => {
        setTimeout(() => message.success(line, 4), index * 100);
      });
    } catch (error) {
      console.error('Parse error:', error);
      message.error(error.message || 'Failed to parse configuration');
      setErrors([error.message]);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateEntities = async () => {
    if (!parseResult) {
      message.error('No parsed configuration available');
      return;
    }

    setCreating(true);

    try {
      const response = await api.post('/api/config/bulk-create', {
        cluster_id: selectedCluster.id,
        frontends: parseResult.frontends,
        backends: parseResult.backends
      });

      const data = await response.json();

      if (!response.ok) {
        // Handle conflict error (409) - pending apply exists
        if (response.status === 409) {
          Modal.error({
            title: 'Pending Changes Detected',
            content: (
              <div>
                <p>{data.detail}</p>
                <Alert 
                  type="warning" 
                  message="Action Required"
                  description="Please apply or discard existing changes before performing bulk import to avoid conflicts."
                  style={{ marginTop: 12 }}
                />
              </div>
            ),
            okText: 'Go to Apply Management',
            onOk: () => {
              window.location.href = '/apply-management';
            }
          });
          return;
        }
        throw new Error(data.detail || 'Failed to create entities');
      }

      message.success(data.message);
      
      // Show detailed summary with new/update breakdown
      Modal.success({
        title: 'Bulk Import Completed Successfully',
        width: 600,
        content: (
          <div>
            {/* Created entities */}
            {(data.summary.frontends > 0 || data.summary.backends > 0 || data.summary.servers > 0) && (
              <>
                <p><strong>✨ Created (New):</strong></p>
                <ul>
                  <li>Frontends: {data.summary.frontends}</li>
                  <li>Backends: {data.summary.backends}</li>
                  <li>Servers: {data.summary.servers}</li>
                </ul>
              </>
            )}
            
            {/* Updated entities */}
            {(data.summary.updated_frontends > 0 || data.summary.updated_backends > 0) && (
              <>
                <p><strong>🔄 Updated (Existing):</strong></p>
                <ul>
                  {data.summary.updated_frontends > 0 && (
                    <li>Frontends: {data.summary.updated_frontends}</li>
                  )}
                  {data.summary.updated_backends > 0 && (
                    <li>Backends: {data.summary.updated_backends}</li>
                  )}
                </ul>
              </>
            )}
            
            <Divider style={{ margin: '12px 0' }} />
            
            <p><strong>Config Version:</strong> <Tag color="blue">{data.config_version}</Tag></p>
            
            <Alert 
              type="info" 
              message="Merge Strategy Applied"
              description="Existing entities were updated with new values. Unspecified fields were preserved. SSL and ACL configurations were not modified."
              style={{ marginTop: 12, marginBottom: 12 }}
            />
            
            <Alert 
              type="warning" 
              message="Please go to Apply Changes page to activate these configurations"
              style={{ marginTop: 12 }}
            />
          </div>
        ),
        okText: 'Go to Apply Changes',
        onOk: () => {
          window.location.href = '/apply-management';
        }
      });

      // Reset form
      setConfigContent('');
      setParseResult(null);
      setErrors([]);
      setWarnings([]);
    } catch (error) {
      console.error('Create error:', error);
      message.error(error.message || 'Failed to create entities');
    } finally {
      setCreating(false);
    }
  };

  const frontendColumns = [
    {
      title: 'Status',
      key: 'status',
      width: 120,
      render: (_, record) => {
        if (record._isNew) {
          return <Tag color="green">NEW</Tag>;
        } else if (record._isUpdate) {
          return (
            <Tooltip title="Existing frontend - values will be compared and updated fields will be saved">
              <Tag color="orange">UPDATE</Tag>
            </Tooltip>
          );
        } else {
          return <Tag color="default">-</Tag>;
        }
      }
    },
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (text) => <Text strong>{text}</Text>
    },
    {
      title: 'Bind',
      key: 'bind',
      render: (_, record) => `${record.bind_address}:${record.bind_port}`
    },
    {
      title: 'Default Backend',
      dataIndex: 'default_backend',
      key: 'default_backend',
      render: (text) => text ? <Tag color="blue">{text}</Tag> : <Tag>None</Tag>
    },
    {
      title: 'Mode',
      dataIndex: 'mode',
      key: 'mode',
      render: (text) => <Tag color={text === 'tcp' ? 'purple' : 'green'}>{text.toUpperCase()}</Tag>
    },
    {
      title: 'SSL',
      key: 'ssl',
      render: (_, record) => {
        if (record.ssl_enabled && record.ssl_certificate_ids && record.ssl_certificate_ids.length > 0) {
          return (
            <div>
              <Tag color="green">SSL Enabled</Tag>
              <div style={{ fontSize: '11px', marginTop: 4 }}>
                <Text type="secondary">Auto-matched ({record.ssl_certificate_ids.length} cert)</Text>
              </div>
            </div>
          );
        } else if (record.ssl_enabled) {
          return <Tag color="orange">SSL (No Match)</Tag>;
        } else {
          return <Tag color="default">No SSL</Tag>;
        }
      }
    },
    {
      title: 'Details',
      key: 'details',
      render: (_, record) => (
        <Space size="small">
          {record.request_headers && <Tag color="blue">Req Headers</Tag>}
          {record.response_headers && <Tag color="green">Resp Headers</Tag>}
          {record.tcp_request_rules && <Tag color="purple">TCP Rules</Tag>}
          {record.acl_rules && record.acl_rules.length > 0 && <Tag color="orange">{record.acl_rules.length} ACLs</Tag>}
          {record.use_backend_rules && record.use_backend_rules.length > 0 && <Tag color="cyan">{record.use_backend_rules.length} Routes</Tag>}
        </Space>
      )
    }
  ];

  const backendColumns = [
    {
      title: 'Status',
      key: 'status',
      width: 120,
      render: (_, record) => {
        if (record._isNew) {
          return <Tag color="green">NEW</Tag>;
        } else if (record._isUpdate) {
          return (
            <Tooltip title="Existing backend - values will be compared and updated fields will be saved">
              <Tag color="orange">UPDATE</Tag>
            </Tooltip>
          );
        } else {
          return <Tag color="default">-</Tag>;
        }
      }
    },
    {
      title: 'Name',
      dataIndex: 'name',
      key: 'name',
      render: (text) => <Text strong>{text}</Text>
    },
    {
      title: 'Mode',
      dataIndex: 'mode',
      key: 'mode',
      render: (text) => <Tag color={text === 'tcp' ? 'purple' : 'green'}>{text.toUpperCase()}</Tag>
    },
    {
      title: 'Balance',
      dataIndex: 'balance_method',
      key: 'balance_method',
      render: (text) => <Tag>{text}</Tag>
    },
    {
      title: 'Health Check',
      key: 'health_check',
      render: (_, record) => (
        <Space size="small" direction="vertical" style={{ fontSize: '12px' }}>
          {record.health_check_uri && <Text type="secondary">URI: {record.health_check_uri}</Text>}
          {record.health_check_expected_status && <Tag color="green">Status: {record.health_check_expected_status}</Tag>}
        </Space>
      )
    },
    {
      title: 'Advanced',
      key: 'advanced',
      render: (_, record) => (
        <Space size="small">
          {record.fullconn && <Tag color="blue">Fullconn: {record.fullconn}</Tag>}
          {record.cookie_name && <Tag color="orange">Cookie: {record.cookie_name}</Tag>}
          {record.request_headers && <Tag color="cyan">Req Headers</Tag>}
          {record.response_headers && <Tag color="green">Resp Headers</Tag>}
        </Space>
      )
    },
    {
      title: 'Servers',
      dataIndex: 'servers',
      key: 'servers',
      render: (servers) => <Tag color="blue">{servers?.length || 0} servers</Tag>
    }
  ];

  const serverColumns = [
    {
      title: 'Status',
      key: 'status',
      width: 90,
      render: (_, record) => {
        if (record._isNew) {
          return <Tag color="green">New</Tag>;
        } else {
          return <Tag color="blue">Exists</Tag>;
        }
      }
    },
    {
      title: 'Server Name',
      dataIndex: 'server_name',
      key: 'server_name',
      render: (text) => <Text strong>{text}</Text>
    },
    {
      title: 'Address',
      key: 'address',
      render: (_, record) => (
        <Space direction="vertical" size="small" style={{ fontSize: '12px' }}>
          <Text>{record.server_address}:{record.server_port}</Text>
          {record.check_port && <Text type="secondary">Check Port: {record.check_port}</Text>}
        </Space>
      )
    },
    {
      title: 'Weight',
      dataIndex: 'weight',
      key: 'weight'
    },
    {
      title: 'Health Check',
      key: 'health_check',
      render: (_, record) => (
        <Space size="small" direction="vertical">
          {record.check_enabled ? 
            <Tag color="green"><CheckCircleOutlined /> Enabled</Tag> : 
            <Tag>Disabled</Tag>
          }
          {record.inter && <Text type="secondary" style={{ fontSize: '11px' }}>Interval: {record.inter}ms</Text>}
          {record.fall && record.rise && (
            <Text type="secondary" style={{ fontSize: '11px' }}>Fall/Rise: {record.fall}/{record.rise}</Text>
          )}
        </Space>
      )
    },
    {
      title: 'Flags',
      key: 'flags',
      render: (_, record) => (
        <Space size="small" wrap>
          {record.backup_server && <Tag color="orange">Backup</Tag>}
          {record.ssl_enabled && <Tag color="gold">SSL</Tag>}
          {record.ssl_verify && <Tag color="purple">Verify: {record.ssl_verify}</Tag>}
          {record.ssl_certificate_name && <Tag color="green">SSL Cert: {record.ssl_certificate_name}</Tag>}
          {record.cookie_value && <Tag color="cyan">Cookie: {record.cookie_value}</Tag>}
        </Space>
      )
    }
  ];

  return (
    <div style={{ padding: '24px' }}>
      <Card>
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          {/* Header */}
          <div>
            <Title level={3}>
              <FileTextOutlined /> Bulk HAProxy Config Import
            </Title>
            <Alert
              message="Import Backend and Frontend Definitions"
              description={
                <div>
                  <p>This bulk import feature allows you to quickly import HAProxy backend and frontend definitions.</p>
                  <ul>
                    <li><strong>Note:</strong> Only backend and frontend definitions can be imported via bulk import</li>
                    <li>SSL certificate and WAF configurations should be configured separately through their respective pages</li>
                    <li>After parsing, review the entities and confirm to create them</li>
                    <li>Created entities will be in PENDING status and require Apply Changes to activate</li>
                  </ul>
                  <Button 
                    type="link" 
                    icon={<QuestionCircleOutlined />}
                    onClick={() => setExampleModalVisible(true)}
                  >
                    View Example Config
                  </Button>
                </div>
              }
              type="info"
              showIcon
              style={{ marginBottom: 16 }}
            />
            
            <Alert
              message="Smart SSL Auto-Assignment"
              description={
                <div>
                  <p><strong>Tip for faster import:</strong> If your configuration includes SSL certificates, you can automate SSL assignment:</p>
                  <ol style={{ marginBottom: 8 }}>
                    <li>First, go to <strong>SSL Management</strong> page</li>
                    <li>Create SSL certificates by entering PEM content with the <strong>exact same name</strong> as in your config</li>
                    <li>Click <strong>Apply Changes</strong> and wait for SYNCED status</li>
                    <li>Then perform bulk import - SSL will be automatically assigned</li>
                  </ol>
                  <div style={{ background: '#f0f2f5', padding: '8px 12px', borderRadius: '4px', marginTop: 8 }}>
                    <Text strong>Example:</Text>
                    <div style={{ marginTop: 4 }}>
                      <Text code style={{ fontSize: '11px' }}>bind :443 ssl crt /etc/ssl/haproxy/demo-global.pem</Text>
                      <br />
                      <Text code style={{ fontSize: '11px' }}>server s1 ... ca-file /etc/ssl/haproxy/elastic.pem</Text>
                    </div>
                    <div style={{ marginTop: 8 }}>
                      <Text type="secondary" style={{ fontSize: '12px' }}>
                        → Upload certificates named: <Tag>demo-global</Tag> <Tag>elastic</Tag>
                        <br />
                        → Apply and wait for SYNCED
                        <br />
                        → Bulk import will auto-assign these SSL certificates
                        <br />
                        → No manual edit needed after import!
                      </Text>
                    </div>
                  </div>
                  <div style={{ marginTop: 8 }}>
                    <Text type="warning" style={{ fontSize: '12px' }}>
                      <WarningOutlined /> If SSL names don't match, import will work without SSL (you can assign manually later)
                    </Text>
                  </div>
                </div>
              }
              type="success"
              showIcon
              icon={<CheckCircleOutlined />}
              style={{ marginBottom: 16 }}
            />

            {selectedCluster && (
              <Alert
                message={`Selected Cluster: ${selectedCluster.name}`}
                type="success"
                style={{ marginBottom: 16 }}
              />
            )}

            {!selectedCluster && (
              <Alert
                message="Please select a cluster from the cluster selector above"
                type="warning"
                showIcon
                style={{ marginBottom: 16 }}
              />
            )}
          </div>

          {/* Config Input */}
          <Card title="Step 1: Enter HAProxy Configuration" size="small">
            <Space direction="vertical" size="middle" style={{ width: '100%' }}>
              <Alert
                message="Supported Sections"
                description={
                  <div>
                    <Text strong>✅ Supported:</Text> <code>frontend</code> and <code>backend</code> sections only.
                    <br />
                    <Text strong>❌ Not Supported:</Text> <code>global</code>, <code>defaults</code>, and <code>listen</code> sections will be ignored.
                    <br />
                    <Text type="secondary" style={{ fontSize: '12px' }}>
                      Global and default settings are managed at the cluster level.
                      Convert any <code>listen</code> sections to separate <code>frontend</code> and <code>backend</code> sections.
                    </Text>
                  </div>
                }
                type="info"
                showIcon
                icon={<InfoCircleOutlined />}
                style={{ marginBottom: 12 }}
              />
              <TextArea
                rows={12}
                placeholder="Paste your HAProxy configuration here (frontend and backend sections)..."
                value={configContent}
                onChange={(e) => setConfigContent(e.target.value)}
                style={{ fontFamily: 'monospace', fontSize: '13px' }}
              />
              <Button
                type="primary"
                icon={<UploadOutlined />}
                onClick={handleParseConfig}
                loading={loading}
                disabled={!selectedCluster || !configContent.trim()}
                size="large"
              >
                Parse Configuration
              </Button>
            </Space>
          </Card>

          {/* Errors and Warnings */}
          {errors.length > 0 && (
            <Alert
              message="Parsing Errors"
              description={
                <ul>
                  {errors.map((error, index) => (
                    <li key={index}>{error}</li>
                  ))}
                </ul>
              }
              type="error"
              showIcon
              icon={<WarningOutlined />}
            />
          )}

          {warnings.length > 0 && (
            <Card 
              title={
                <Space>
                  <InfoCircleOutlined style={{ color: '#faad14' }} />
                  <Text strong>Configuration Notices & Recommendations</Text>
                </Space>
              }
              size="small"
              style={{ 
                borderColor: '#faad14',
                boxShadow: '0 2px 8px rgba(250, 173, 20, 0.15)'
              }}
            >
              <Space direction="vertical" size="small" style={{ width: '100%' }}>
                {/* SSL Certificate Warnings */}
                {warnings.filter(w => w.toLowerCase().includes('ssl certificate')).length > 0 && (
                  <Alert
                    message={
                      <Space>
                        <span style={{ fontSize: '16px' }}>🔒</span>
                        <Text strong>SSL Certificate Management</Text>
                      </Space>
                    }
                    description={
                      <div>
                        <div style={{ marginBottom: 12 }}>
                          {warnings
                            .filter(w => w.toLowerCase().includes('ssl certificate'))
                            .map((warning, index) => (
                              <div key={index} style={{ marginBottom: 4 }}>
                                <Text type="secondary" style={{ fontSize: '13px' }}>
                                  {warning}
                                </Text>
                              </div>
                            ))}
                        </div>
                        <div style={{
                          padding: 12,
                          backgroundColor: '#fff7e6',
                          borderRadius: 4,
                          border: '1px solid #ffd591',
                          lineHeight: '1.8'
                        }}>
                          <Text strong style={{ color: '#d46b08', fontSize: '13px' }}>
                            📌 How to handle SSL certificates:
                          </Text>
                          <div style={{ marginTop: 8, fontSize: '13px' }}>
                            • Frontends will be created <strong>WITHOUT SSL enabled</strong> to avoid validation errors
                            <br />
                            • Navigate to <strong>SSL Management</strong> page and upload your certificate files
                            <br />
                            • Return to <strong>Frontend Management</strong> and enable SSL for each frontend
                            <br />
                            • Assign the uploaded certificates to the corresponding frontends
                          </div>
                        </div>
                      </div>
                    }
                    type="warning"
                    showIcon={false}
                    style={{ marginBottom: 8 }}
                  />
                )}
                
                {/* Invalid/Unknown Options */}
                {warnings.filter(w => w.toLowerCase().includes('unknown or invalid option')).length > 0 && (
                  <Alert
                    message={
                      <Space>
                        <span style={{ fontSize: '16px' }}>⚠️</span>
                        <Text strong>Invalid Configuration Directives</Text>
                      </Space>
                    }
                    description={
                      <div>
                        {warnings
                          .filter(w => w.toLowerCase().includes('unknown or invalid option'))
                          .map((warning, index) => (
                            <div key={index} style={{ marginBottom: 4 }}>
                              <Text style={{ fontSize: '13px', color: '#d48806' }}>
                                {warning}
                              </Text>
                            </div>
                          ))}
                        <Text type="secondary" style={{ fontSize: '12px', fontStyle: 'italic', marginTop: 8, display: 'block' }}>
                          These directives have been automatically removed from your configuration to ensure compatibility.
                        </Text>
                      </div>
                    }
                    type="warning"
                    showIcon={false}
                    style={{ marginBottom: 8 }}
                  />
                )}
                
                {/* Missing Ports (TCP Backends) */}
                {warnings.filter(w => (w.toLowerCase().includes('servers without port') || w.toLowerCase().includes('have been excluded')) && w.includes('TCP mode')).length > 0 && (
                  <Alert
                    message={
                      <Space>
                        <span style={{ fontSize: '16px' }}>🔌</span>
                        <Text strong>TCP Backend - Servers Excluded</Text>
                      </Space>
                    }
                    description={
                      <div>
                        {warnings
                          .filter(w => (w.toLowerCase().includes('servers without port') || w.toLowerCase().includes('have been excluded')) && w.includes('TCP mode'))
                          .map((warning, index) => (
                            <div key={index} style={{ marginBottom: 4 }}>
                              <Text style={{ fontSize: '13px', color: '#d48806' }}>
                                {warning}
                              </Text>
                            </div>
                          ))}
                        <div style={{
                          marginTop: 8,
                          padding: 8,
                          backgroundColor: '#fffbe6',
                          borderRadius: 4,
                          fontSize: '12px'
                        }}>
                          <Text type="warning" strong>Post-Import Action:</Text> Backends have been created. 
                          Add servers with port numbers via <strong>Backend Management</strong> page after import completes.
                        </div>
                      </div>
                    }
                    type="warning"
                    showIcon={false}
                    style={{ marginBottom: 8 }}
                  />
                )}
                
                {/* Capture Directives (Advanced Feature) */}
                {warnings.filter(w => w.toLowerCase().includes('capture directive') || w.toLowerCase().includes('capture reference')).length > 0 && (
                  <Alert
                    message={
                      <Space>
                        <span style={{ fontSize: '16px' }}>📸</span>
                        <Text strong>Advanced Capture Directives</Text>
                      </Space>
                    }
                    description={
                      <div>
                        {warnings
                          .filter(w => w.toLowerCase().includes('capture directive') || w.toLowerCase().includes('capture reference'))
                          .map((warning, index) => (
                            <div key={index} style={{ marginBottom: 4 }}>
                              <Text style={{ fontSize: '13px', color: '#d48806' }}>
                                {warning}
                              </Text>
                            </div>
                          ))}
                        <div style={{
                          marginTop: 8,
                          padding: 8,
                          backgroundColor: '#fffbe6',
                          borderRadius: 4,
                          fontSize: '12px'
                        }}>
                          <Text type="warning" strong>Note:</Text> Request/response capture requires explicit setup 
                          with <code>http-request capture</code> directive. These advanced features should be 
                          configured manually after import via HAProxy configuration file.
                        </div>
                      </div>
                    }
                    type="warning"
                    showIcon={false}
                    style={{ marginBottom: 8 }}
                  />
                )}
                
                {/* Other Warnings */}
                {warnings.filter(w => 
                  !w.toLowerCase().includes('ssl certificate') && 
                  !w.toLowerCase().includes('unknown or invalid option') &&
                  !((w.toLowerCase().includes('servers without port') || w.toLowerCase().includes('have been excluded')) && w.includes('TCP mode')) &&
                  !w.toLowerCase().includes('capture directive') &&
                  !w.toLowerCase().includes('capture reference')
                ).length > 0 && (
                  <Alert
                    message={
                      <Space>
                        <span style={{ fontSize: '16px' }}>💡</span>
                        <Text strong>Configuration Recommendations</Text>
                      </Space>
                    }
                    description={
                      <div>
                        {warnings
                          .filter(w => 
                            !w.toLowerCase().includes('ssl certificate') && 
                            !w.toLowerCase().includes('unknown or invalid option') &&
                            !((w.toLowerCase().includes('servers without port') || w.toLowerCase().includes('have been excluded')) && w.includes('TCP mode')) &&
                            !w.toLowerCase().includes('capture directive') &&
                            !w.toLowerCase().includes('capture reference')
                          )
                          .map((warning, index) => (
                            <div key={index} style={{ marginBottom: 4 }}>
                              <Text style={{ fontSize: '13px', color: '#595959' }}>
                                • {warning}
                              </Text>
                            </div>
                          ))}
                      </div>
                    }
                    type="info"
                    showIcon={false}
                  />
                )}
              </Space>
            </Card>
          )}

          {/* Parse Results */}
          {parseResult && (
            <Card title="Step 2: Review Parsed Entities" size="small">
              <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                {/* Import Strategy Info */}
                {parseResult.summary.update_frontends > 0 || parseResult.summary.update_backends > 0 ? (
                  <Alert
                    type="info"
                    message="UPSERT Mode: Smart Merge Strategy"
                    description={
                      <div>
                        <p>This import uses intelligent change detection:</p>
                        <ul style={{ marginBottom: 0 }}>
                          <li><strong>New entities:</strong> Will be created</li>
                          <li><strong>Existing entities:</strong> Will be compared - only actual changes updated</li>
                          <li><strong>Preserved:</strong> SSL mappings, ACL rules, unchanged fields</li>
                          <li><strong>Servers:</strong> New servers added, existing servers preserved</li>
                          <li><strong>Note:</strong> "Existing" entities without changes will not be updated</li>
                        </ul>
                      </div>
                    }
                    showIcon
                  />
                ) : (
                  <Alert
                    type="success"
                    message="All entities are new - no conflicts"
                    description="All parsed entities will be created as new. No existing entities will be modified."
                    showIcon
                  />
                )}
                
                {/* Summary with New/Update Breakdown */}
                <Descriptions bordered size="small" column={3}>
                  <Descriptions.Item label="Frontends">
                    <Space size="small">
                      <Tag color="blue">{parseResult.summary.frontends_count} total</Tag>
                      {parseResult.summary.new_frontends > 0 && (
                        <Tag color="green">{parseResult.summary.new_frontends} new</Tag>
                      )}
                      {parseResult.summary.update_frontends > 0 && (
                        <Tag color="blue">{parseResult.summary.update_frontends} existing</Tag>
                      )}
                    </Space>
                  </Descriptions.Item>
                  <Descriptions.Item label="Backends">
                    <Space size="small">
                      <Tag color="blue">{parseResult.summary.backends_count} total</Tag>
                      {parseResult.summary.new_backends > 0 && (
                        <Tag color="green">{parseResult.summary.new_backends} new</Tag>
                      )}
                      {parseResult.summary.update_backends > 0 && (
                        <Tag color="blue">{parseResult.summary.update_backends} existing</Tag>
                      )}
                    </Space>
                  </Descriptions.Item>
                  <Descriptions.Item label="Total Servers">
                    <Space size="small">
                      <Tag color="purple">{parseResult.summary.total_servers_count} total</Tag>
                      {parseResult.summary.new_servers > 0 && (
                        <Tag color="green">{parseResult.summary.new_servers} new</Tag>
                      )}
                    </Space>
                  </Descriptions.Item>
                </Descriptions>

                <Divider />

                {/* Frontends */}
                {parseResult.frontends && parseResult.frontends.length > 0 && (
                  <Collapse defaultActiveKey={['frontends']}>
                    <Panel 
                      header={<Text strong>Frontends ({parseResult.frontends.length})</Text>} 
                      key="frontends"
                    >
                      <Table
                        dataSource={parseResult.frontends}
                        columns={frontendColumns}
                        rowKey="name"
                        pagination={false}
                        size="small"
                        expandable={{
                          expandedRowRender: (frontend) => {
                            const hasDetails = frontend.request_headers || frontend.response_headers || 
                                             frontend.options || frontend.tcp_request_rules || 
                                             (frontend.acl_rules && frontend.acl_rules.length > 0) ||
                                             (frontend.use_backend_rules && frontend.use_backend_rules.length > 0);
                            
                            if (!hasDetails) return null;
                            
                            return (
                              <div style={{ paddingLeft: 24 }}>
                                <Text strong>Frontend Configuration Details:</Text>
                                <Descriptions size="small" bordered column={1} style={{ marginTop: 8 }}>
                                  {frontend.options && (
                                    <Descriptions.Item label="Frontend Options">
                                      <Text code style={{ whiteSpace: 'pre-wrap', fontSize: '11px' }}>
                                        {frontend.options}
                                      </Text>
                                    </Descriptions.Item>
                                  )}
                                  {frontend.request_headers && (
                                    <Descriptions.Item label="Request Headers">
                                      <Text code style={{ whiteSpace: 'pre-wrap', fontSize: '11px' }}>
                                        {frontend.request_headers}
                                      </Text>
                                    </Descriptions.Item>
                                  )}
                                  {frontend.response_headers && (
                                    <Descriptions.Item label="Response Headers">
                                      <Text code style={{ whiteSpace: 'pre-wrap', fontSize: '11px' }}>
                                        {frontend.response_headers}
                                      </Text>
                                    </Descriptions.Item>
                                  )}
                                  {frontend.tcp_request_rules && (
                                    <Descriptions.Item label="TCP Request Rules">
                                      <Text code style={{ whiteSpace: 'pre-wrap', fontSize: '11px' }}>
                                        {frontend.tcp_request_rules}
                                      </Text>
                                    </Descriptions.Item>
                                  )}
                                  {frontend.acl_rules && frontend.acl_rules.length > 0 && (
                                    <Descriptions.Item label={`ACL Rules (${frontend.acl_rules.length})`}>
                                      {frontend.acl_rules.map((acl, idx) => (
                                        <div key={idx}>
                                          <Text code style={{ fontSize: '11px' }}>{acl}</Text>
                                        </div>
                                      ))}
                                    </Descriptions.Item>
                                  )}
                                  {frontend.use_backend_rules && frontend.use_backend_rules.length > 0 && (
                                    <Descriptions.Item label={`Backend Routing Rules (${frontend.use_backend_rules.length})`}>
                                      {frontend.use_backend_rules.map((rule, idx) => (
                                        <div key={idx}>
                                          <Text code style={{ fontSize: '11px' }}>{rule}</Text>
                                        </div>
                                      ))}
                                    </Descriptions.Item>
                                  )}
                                </Descriptions>
                              </div>
                            );
                          },
                          rowExpandable: (record) => 
                            record.request_headers || record.response_headers || 
                            record.tcp_request_rules || (record.acl_rules && record.acl_rules.length > 0) ||
                            (record.use_backend_rules && record.use_backend_rules.length > 0)
                        }}
                      />
                    </Panel>
                  </Collapse>
                )}

                {/* Backends with Servers */}
                {parseResult.backends && parseResult.backends.length > 0 && (
                  <Collapse defaultActiveKey={['backends']}>
                    <Panel 
                      header={<Text strong>Backends ({parseResult.backends.length})</Text>} 
                      key="backends"
                    >
                      <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                        <Table
                          dataSource={parseResult.backends}
                          columns={backendColumns}
                          rowKey="name"
                          pagination={false}
                          size="small"
                          expandable={{
                            expandedRowRender: (backend) => (
                              <div style={{ paddingLeft: 24 }}>
                                {/* Backend Details */}
                                {(backend.default_server_inter || backend.default_server_fall || backend.default_server_rise ||
                                  backend.request_headers || backend.response_headers || backend.options || backend.cookie_options) && (
                                  <div style={{ marginBottom: 16 }}>
                                    <Text strong>Backend Configuration Details:</Text>
                                    <Descriptions size="small" bordered column={2} style={{ marginTop: 8 }}>
                                      {backend.default_server_inter && (
                                        <Descriptions.Item label="Default Server Interval">
                                          {backend.default_server_inter}ms
                                        </Descriptions.Item>
                                      )}
                                      {backend.default_server_fall && (
                                        <Descriptions.Item label="Default Server Fall">
                                          {backend.default_server_fall}
                                        </Descriptions.Item>
                                      )}
                                      {backend.default_server_rise && (
                                        <Descriptions.Item label="Default Server Rise">
                                          {backend.default_server_rise}
                                        </Descriptions.Item>
                                      )}
                                      {backend.cookie_options && (
                                        <Descriptions.Item label="Cookie Options" span={2}>
                                          <Text code>{backend.cookie_options}</Text>
                                        </Descriptions.Item>
                                      )}
                                      {backend.options && (
                                        <Descriptions.Item label="Backend Options" span={2}>
                                          <Text code style={{ whiteSpace: 'pre-wrap', fontSize: '11px' }}>
                                            {backend.options}
                                          </Text>
                                        </Descriptions.Item>
                                      )}
                                      {backend.request_headers && (
                                        <Descriptions.Item label="Request Headers" span={2}>
                                          <Text code style={{ whiteSpace: 'pre-wrap', fontSize: '11px' }}>
                                            {backend.request_headers}
                                          </Text>
                                        </Descriptions.Item>
                                      )}
                                      {backend.response_headers && (
                                        <Descriptions.Item label="Response Headers" span={2}>
                                          <Text code style={{ whiteSpace: 'pre-wrap', fontSize: '11px' }}>
                                            {backend.response_headers}
                                          </Text>
                                        </Descriptions.Item>
                                      )}
                                    </Descriptions>
                                  </div>
                                )}
                                
                                {/* Servers Table */}
                                <Text strong>Servers in {backend.name}:</Text>
                                <Table
                                  dataSource={backend.servers}
                                  columns={serverColumns}
                                  rowKey="server_name"
                                  pagination={false}
                                  size="small"
                                  style={{ marginTop: 8 }}
                                />
                              </div>
                            )
                          }}
                        />
                      </Space>
                    </Panel>
                  </Collapse>
                )}

                <Divider />

                {/* Create Button */}
                <div style={{ textAlign: 'center' }}>
                  <Space>
                    <Button
                      onClick={() => {
                        setParseResult(null);
                        setErrors([]);
                        setWarnings([]);
                      }}
                    >
                      Cancel
                    </Button>
                    <Button
                      type="primary"
                      size="large"
                      icon={<CheckCircleOutlined />}
                      onClick={handleCreateEntities}
                      loading={creating}
                    >
                      Confirm & Create Entities
                    </Button>
                  </Space>
                </div>

                <Alert
                  message="Important"
                  description="After creating entities, they will be in PENDING status. You need to go to Apply Changes page to activate them."
                  type="warning"
                  showIcon
                  icon={<InfoCircleOutlined />}
                />
              </Space>
            </Card>
          )}
        </Space>
      </Card>

      {/* Example Config Modal */}
      <Modal
        title="Example HAProxy Configuration"
        visible={exampleModalVisible}
        onCancel={() => setExampleModalVisible(false)}
        footer={[
          <Button key="copy" onClick={() => {
            navigator.clipboard.writeText(exampleConfig);
            message.success('Example config copied to clipboard');
          }}>
            Copy to Clipboard
          </Button>,
          <Button key="close" type="primary" onClick={() => setExampleModalVisible(false)}>
            Close
          </Button>
        ]}
        width={700}
      >
        <Paragraph>
          This is an example HAProxy configuration that can be imported via bulk import:
        </Paragraph>
        <div style={{ 
          backgroundColor: '#f5f5f5', 
          padding: 16, 
          borderRadius: 4,
          fontFamily: 'monospace',
          whiteSpace: 'pre',
          overflow: 'auto'
        }}>
          {exampleConfig}
        </div>
        <Paragraph style={{ marginTop: 16 }}>
          <Text strong>Notes:</Text>
          <ul>
            <li>The example shows a TCP frontend and backend with multiple servers</li>
            <li>Each server has health check enabled</li>
            <li>You can modify this template for your own use case</li>
            <li>SSL and WAF configurations are not included in bulk import</li>
          </ul>
        </Paragraph>
      </Modal>
    </div>
  );
};

export default BulkConfigImport;

