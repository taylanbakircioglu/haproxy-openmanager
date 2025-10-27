import React, { useState, useEffect } from 'react';
import {
  Card, Table, Button, Modal, Form, Input, Select, Space, message, 
  Popconfirm, Tag, Tooltip, Row, Col, Typography, Divider, InputNumber,
  Switch, List, Badge, Tabs, Statistic, Alert, Spin
} from 'antd';
import { getAgentSyncColor, getConfigStatusColor, getEntityStatusColor } from '../utils/colors';
import EntitySyncStatus from './EntitySyncStatus';
import {
  PlusOutlined, EditOutlined, DeleteOutlined, ReloadOutlined,
  EyeOutlined, SettingOutlined,
  CheckCircleOutlined, ExclamationCircleOutlined,
  UserOutlined, GlobalOutlined, ClockCircleOutlined, FireOutlined,
  BugOutlined, SecurityScanOutlined, StopOutlined, HistoryOutlined,
  PlayCircleOutlined
} from '@ant-design/icons';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { useCluster } from '../contexts/ClusterContext';
import { VersionHistory } from './VersionHistory';

// Error Boundary Component
class WAFErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('WAF Management Error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <Alert
          message="WAF Management Error"
          description="There was an error loading WAF Management. Please refresh the page."
          type="error"
          showIcon
          action={
            <Button size="small" danger onClick={() => window.location.reload()}>
              Refresh Page
            </Button>
          }
        />
      );
    }

    return this.props.children;
  }
}

const { Title, Text } = Typography;
const { Option } = Select;
const { TextArea } = Input;
const { TabPane } = Tabs;

// HAProxy WAF Validation Utilities
const WAFValidationUtils = {
  // Validate IP addresses and CIDR blocks
  validateIPAddresses: (value) => {
    if (!value || !value.trim()) return { valid: true };
    
    const lines = value.split('\n').map(line => line.trim()).filter(line => line);
    const errors = [];
    
    lines.forEach((line, index) => {
      // Check for valid IP or CIDR format
      const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$/;
      if (!ipRegex.test(line)) {
        errors.push(`Line ${index + 1}: "${line}" is not a valid IP address or CIDR block`);
      }
    });
    
    return {
      valid: errors.length === 0,
      errors: errors
    };
  },

  // Validate HAProxy condition syntax
  validateHAProxyCondition: (value) => {
    if (!value || !value.trim()) return { valid: true };
    
    const condition = value.trim();
    const errors = [];
    
    // Allow complete HAProxy directives
    if (condition.startsWith('http-request') || condition.startsWith('http-response') || condition.startsWith('acl')) {
      return { valid: true };
    }
    
    // Check for HAProxy ACL expression patterns
    const hasValidKeywords = /\b(req\.|res\.|src|dst|hdr|method|path|body|url)\b/.test(condition);
    const hasValidOperators = /\b(-m|-f|-i|eq|ne|gt|lt|ge|le)\b/.test(condition);
    const hasBraces = condition.includes('{') && condition.includes('}');
    
    if (!hasValidKeywords && !hasBraces) {
      errors.push('Condition should contain HAProxy keywords like req., res., src, dst, hdr, method, path');
    }
    
    // Check for obviously invalid patterns
    if (condition.split(' ').length < 2 && !hasBraces) {
      errors.push('Condition appears too simple. Example: { req.hdr(user-agent) -m sub bot }');
    }
    
    // Check for dangerous characters that might break config
    if (/[;&|`$(){}[\]\\]/.test(condition) && !hasBraces) {
      errors.push('Condition contains potentially dangerous characters. Use proper HAProxy syntax.');
    }
    
    return {
      valid: errors.length === 0,
      errors: errors,
      examples: [
        '{ req.hdr(user-agent) -m sub bot }',
        '{ src -f /etc/haproxy/whitelist.lst }',
        '{ req.hdr(host) -m reg ^api\\. }',
        '{ path -m beg /admin/ }'
      ]
    };
  },

  // Validate regex patterns
  validateRegexPattern: (value) => {
    if (!value || !value.trim()) return { valid: true };
    
    try {
      new RegExp(value);
      return { valid: true };
    } catch (error) {
      return {
        valid: false,
        errors: [`Invalid regex pattern: ${error.message}`],
        examples: [
          '^/admin/',
          '.*(union|select).*',
          '\\.(php|asp|jsp)$'
        ]
      };
    }
  },

  // Validate country codes (ISO 3166-1)
  validateCountryCodes: (value) => {
    if (!value || !value.trim()) return { valid: true };
    
    const codes = value.split(',').map(code => code.trim().toUpperCase()).filter(code => code);
    const errors = [];
    const validCountryCodes = [
      'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AO', 'AQ', 'AR', 'AS', 'AT', 'AU', 'AW', 'AX', 'AZ',
      'BA', 'BB', 'BD', 'BE', 'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ', 'BR', 'BS',
      'BT', 'BV', 'BW', 'BY', 'BZ', 'CA', 'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN',
      'CO', 'CR', 'CU', 'CV', 'CW', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC', 'EE',
      'EG', 'EH', 'ER', 'ES', 'ET', 'FI', 'FJ', 'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF',
      'GG', 'GH', 'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK', 'HM',
      'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ', 'IR', 'IS', 'IT', 'JE', 'JM',
      'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC',
      'LI', 'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME', 'MF', 'MG', 'MH', 'MK',
      'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA',
      'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU', 'NZ', 'OM', 'PA', 'PE', 'PF', 'PG',
      'PH', 'PK', 'PL', 'PM', 'PN', 'PR', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS', 'RU', 'RW',
      'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'SS',
      'ST', 'SV', 'SX', 'SY', 'SZ', 'TC', 'TD', 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO',
      'TR', 'TT', 'TV', 'TW', 'TZ', 'UA', 'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG', 'VI',
      'VN', 'VU', 'WF', 'WS', 'YE', 'YT', 'ZA', 'ZM', 'ZW'
    ];
    
    codes.forEach(code => {
      if (code.length !== 2) {
        errors.push(`"${code}" should be 2 characters (ISO 3166-1 format)`);
      } else if (!validCountryCodes.includes(code)) {
        errors.push(`"${code}" is not a valid ISO 3166-1 country code`);
      }
    });
    
    return {
      valid: errors.length === 0,
      errors: errors,
      examples: ['CN,RU,KP', 'US,CA', 'DE,FR,IT']
    };
  },

  // Validate size values (bytes)
  validateSizeValue: (value, fieldName = 'Size') => {
    if (!value) return { valid: true };
    
    const numValue = parseInt(value);
    const errors = [];
    
    if (isNaN(numValue) || numValue <= 0) {
      errors.push(`${fieldName} must be a positive number`);
    } else if (numValue > 2147483647) { // 2GB limit for HAProxy
      errors.push(`${fieldName} cannot exceed 2GB (2147483647 bytes)`);
    } else if (numValue < 1024 && fieldName.includes('Size')) {
      errors.push(`${fieldName} should be at least 1024 bytes (1KB) for practical use`);
    }
    
    return {
      valid: errors.length === 0,
      errors: errors,
      examples: ['1048576 (1MB)', '10485760 (10MB)', '104857600 (100MB)']
    };
  },

  // Validate rate limit values
  validateRateLimit: (requests, window) => {
    const errors = [];
    
    if (requests && (isNaN(requests) || requests <= 0 || requests > 10000)) {
      errors.push('Max Requests should be between 1 and 10000');
    }
    
    if (window && (isNaN(window) || window < 1 || window > 3600)) {
      errors.push('Time Window should be between 1 and 3600 seconds');
    }
    
    if (requests && window && requests > window * 100) {
      errors.push('Max Requests seems too high for the time window (max ~100 req/sec)');
    }
    
    return {
      valid: errors.length === 0,
      errors: errors
    };
  }
};

const WAFManagement = () => {
  const { selectedCluster } = useCluster();
  const navigate = useNavigate();
  const [rules, setRules] = useState([]);
  const [stats, setStats] = useState({});

  const [loading, setLoading] = useState(false);
  const [applyLoading, setApplyLoading] = useState(false);
  const [pendingChanges, setPendingChanges] = useState(false);
  const [versionModalVisible, setVersionModalVisible] = useState(false);
  const [selectedEntityForVersion, setSelectedEntityForVersion] = useState(null);
  const [modalVisible, setModalVisible] = useState(false);
  const [statsModalVisible, setStatsModalVisible] = useState(false);
  const [editingRule, setEditingRule] = useState(null);
  const [selectedRuleType, setSelectedRuleType] = useState('rate_limit');
  const [form] = Form.useForm();
  const [searchText, setSearchText] = useState('');
  const [filteredRules, setFilteredRules] = useState([]);
  const [frontends, setFrontends] = useState([]);
  const [showPending, setShowPending] = useState(true);  // Default TRUE: users must see their changes
  const [showRejected, setShowRejected] = useState(true);  // Default TRUE: users must see rejected items
  const [refreshKey, setRefreshKey] = useState(0);


  // Persist toggle states across navigation
  useEffect(() => {
    const sp = localStorage.getItem('waf:showPending');
    const sr = localStorage.getItem('waf:showRejected');
    // Default to true for showPending if not set in localStorage
    if (sp !== null) setShowPending(sp === 'true');
    else setShowPending(true);  // Show PENDING by default
    if (sr !== null) setShowRejected(sr === 'true');
  }, []);
  const onToggleShowPending = (checked) => {
    setShowPending(checked);
    localStorage.setItem('waf:showPending', String(checked));
  };
  const onToggleShowRejected = (checked) => {
    setShowRejected(checked);
    localStorage.setItem('waf:showRejected', String(checked));
  };

  useEffect(() => {
    fetchRules();
    fetchStats();
    checkPendingChanges();
    fetchFrontends();
  }, [selectedCluster]);

  useEffect(() => {
    setFilteredRules(applyStatusFilters(rules));
  }, [rules, showPending, showRejected]);

  const handleSearch = (value) => {
    setSearchText(value);
    if (!value) {
      setFilteredRules(applyStatusFilters(rules));
    } else {
      const filtered = rules.filter(rule =>
        rule.name.toLowerCase().includes(value.toLowerCase()) ||
        rule.rule_type.toLowerCase().includes(value.toLowerCase()) ||
        rule.description?.toLowerCase().includes(value.toLowerCase()) ||
        rule.action.toLowerCase().includes(value.toLowerCase())
      );
      setFilteredRules(applyStatusFilters(filtered));
    }
  };

  const applyStatusFilters = (items) => {
    return (items || []).filter(item => {
      const isPending = !!item.has_pending_config;
      const status = item.config_status || (isPending ? 'PENDING' : 'APPLIED');
      if (!showPending && isPending) return false;
      if (!showRejected && status === 'REJECTED') return false;
      return true;
    });
  };

  const fetchRules = async () => {
    if (!selectedCluster) return;
    setLoading(true);
    try {
      const response = await axios.get(`/api/waf/rules?cluster_id=${selectedCluster.id}`);
      const fetchedRules = response.data.rules || [];
      setRules(fetchedRules);
      // Apply filters immediately to maintain consistency
      setFilteredRules(applyStatusFilters(fetchedRules));
    } catch (error) {
      message.error('Failed to fetch WAF rules: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const fetchFrontends = async () => {
    if (!selectedCluster) return;
    
    try {
      const response = await axios.get(`/api/frontends?cluster_id=${selectedCluster.id}`);
      setFrontends(response.data.frontends || []);
    } catch (error) {
      console.error('Failed to fetch frontends:', error);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await axios.get('/api/waf/stats');
      setStats(response.data);
    } catch (error) {
      console.error('Failed to fetch WAF stats:', error);
    }
  };

  const fetchEntityAgentSync = async (entityType, entityId) => {
    if (!selectedCluster) return null;
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`/api/clusters/${selectedCluster.id}/entity-sync/${entityType}/${entityId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      return response.data;
    } catch (error) {
      console.error(`Failed to fetch entity sync for ${entityType}/${entityId}:`, error);
      return null;
    }
  };

  // Check for pending configuration changes
  const checkPendingChanges = async () => {
    if (!selectedCluster) return;
    
    try {
      console.log('🎯 WAF APPLY DEBUG: Checking pending changes for cluster:', selectedCluster.id);
      const response = await axios.get(`/api/clusters/${selectedCluster.id}/config-versions`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      const versions = response.data.versions || [];
      const hasPending = versions.some(version => version.status === 'PENDING');
      console.log('🎯 WAF APPLY DEBUG: Has pending changes:', hasPending);
      setPendingChanges(hasPending);
    } catch (error) {
      console.error('🎯 WAF APPLY DEBUG: Failed to check pending changes:', error);
    }
  };

  // Apply pending configuration changes
  const handleApplyChanges = async () => {
    if (!selectedCluster) return;
    
    setApplyLoading(true);
    try {
      const token = localStorage.getItem('token');
      if (!token || token === 'null' || token.trim() === '') {
        message.error('Authentication required. Please login again.');
        return;
      }
      
      const response = await axios.post(
        `/api/clusters/${selectedCluster.id}/apply-changes`,
        {},
        {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        }
      );
      
      message.success(response.data.message);
      
      // Refresh pending changes status from server
      await checkPendingChanges();
      
      // Also refresh the WAF rules list to update Config Status column
      fetchRules();
      
      // Show sync results if available
      if (response.data.sync_results && response.data.sync_results.length > 0) {
        const agentResults = response.data.sync_results.filter(r => r.success);
        if (agentResults.length > 0) {
          message.info(`Configuration applied to ${agentResults.length} agent(s). HAProxy reloaded.`);
        }
      }
      
    } catch (error) {
      console.error('WAF Apply changes failed:', error);
      if (error.response?.status === 401) {
        message.error('Authentication failed. Please login again.');
      } else if (error.response?.data?.error === 'COMPREHENSIVE_VALIDATION_FAILED') {
        // Handle comprehensive validation errors from API
        const validationErrors = error.response.data.validation_errors || [];
        
        Modal.error({
          title: '🚫 Configuration Validation Failed',
          content: (
            <div>
              <p><strong>Multiple configuration issues detected!</strong></p>
              <p style={{ color: '#ff4d4f', marginBottom: 16 }}>{error.response.data.message}</p>
              
              {validationErrors.map((error, index) => (
                <div key={index} style={{ 
                  marginBottom: 16, 
                  padding: 12, 
                  border: '1px solid #ffccc7', 
                  borderRadius: 6,
                  backgroundColor: '#fff2f0'
                }}>
                  <h4 style={{ color: '#cf1322', margin: '0 0 8px 0' }}>
                    {error.type === 'BACKENDS_WITHOUT_SERVERS' && '🔸 Backends Missing Servers'}
                    {error.type === 'UNUSED_BACKENDS' && '🔸 Unused Backends'}
                    {error.type === 'FRONTENDS_WITH_MISSING_BACKENDS' && '🔸 Frontend → Backend Mismatch'}
                    {error.type === 'NO_FRONTENDS' && '🔸 No Frontends Defined'}
                  </h4>
                  <p style={{ margin: '0 0 8px 0' }}>{error.message}</p>
                  <p style={{ margin: '0 0 8px 0', fontWeight: 'bold' }}>Items:</p>
                  <ul style={{ margin: '0 0 8px 20px' }}>
                    {error.items.map((item, idx) => (
                      <li key={idx} style={{ color: '#d4380d' }}>{item}</li>
                    ))}
                  </ul>
                  <p style={{ margin: 0, color: '#389e0d' }}>
                    <strong>💡 Solution:</strong> {error.solution}
                  </p>
                </div>
              ))}
              
              <div style={{ 
                marginTop: 16, 
                padding: 12, 
                backgroundColor: '#f6ffed', 
                border: '1px solid #b7eb8f',
                borderRadius: 6 
              }}>
                <p style={{ margin: 0, color: '#389e0d' }}>
                  <strong>🎯 Quick Actions:</strong>
                </p>
                <div style={{ marginTop: 8 }}>
                  <Button 
                    type="primary" 
                    size="small"
                    onClick={() => window.location.href = '/frontend-management'}
                    style={{ marginRight: 8 }}
                  >
                    Manage Frontends
                  </Button>
                  <Button 
                    type="default" 
                    size="small"
                    onClick={() => window.location.href = '/backend-servers'}
                    style={{ marginRight: 8 }}
                  >
                    Manage Backends
                  </Button>
                  <Button 
                    type="default" 
                    size="small"
                    onClick={() => window.location.reload()}
                  >
                    Refresh Page
                  </Button>
                </div>
              </div>
            </div>
          ),
          width: 800,
          okText: 'I Understand',
          okType: 'primary'
        });
      } else if (error.response?.data?.error === 'BACKEND_VALIDATION_FAILED') {
        // Legacy: Handle old backend validation error from API
        const backendNames = error.response.data.details?.backends_without_servers || [];
        
        Modal.error({
          title: '🚫 Configuration Apply Failed',
          content: (
            <div>
              <p><strong>Backend validation failed!</strong></p>
              <p style={{ color: '#ff4d4f' }}>{error.response.data.message}</p>
              <br />
              <p><strong>Backends without servers:</strong></p>
              <ul style={{ marginTop: 10, marginBottom: 10 }}>
                {backendNames.map(name => (
                  <li key={name} style={{ color: '#ff4d4f' }}>
                    <strong>{name}</strong>
                  </li>
                ))}
              </ul>
              <p>✅ <strong>Solution:</strong> Go to Backend Management and add servers to these backends before applying WAF changes.</p>
              <br />
              <Button 
                type="primary" 
                onClick={() => window.location.href = '/backend-servers'}
                style={{ marginTop: 10 }}
              >
                Go to Backend Management
              </Button>
            </div>
          ),
          width: 600,
          okText: 'I Understand',
          okType: 'default'
        });
      } else {
        message.error(`Failed to apply changes: ${error.response?.data?.message || error.response?.data?.detail || error.message}`);
      }
    } finally {
      setApplyLoading(false);
    }
  };

  // Version history modal handlers
  const handleShowVersionHistory = (record) => {
    if (record && record.id) {
      setSelectedEntityForVersion({
        entityType: 'waf',
        entityId: record.id
      });
      setVersionModalVisible(true);
    } else {
      // For global version history button (if no record passed)
      if (selectedCluster) {
        setSelectedEntityForVersion({
          entityType: 'cluster',
          entityId: selectedCluster.id
        });
        setVersionModalVisible(true);
      } else {
        message.warning('Please select a cluster first');
      }
    }
  };

  const handleVersionModalCancel = () => {
    setVersionModalVisible(false);
    setSelectedEntityForVersion(null);
  };

  const handleRestoreSuccess = (restoreData) => {
    // Refresh pending changes status after successful restore
    checkPendingChanges();
    // Refresh WAF rules list to show updated data
    fetchRules();
    message.info(
      <div>
        <div><strong>Configuration restored as PENDING</strong></div>
        <div style={{ fontSize: '12px', marginTop: 4 }}>
          Use "Apply Changes" button to activate the restored configuration
        </div>
      </div>,
      4
    );
  };

  const handleAdd = () => {
    form.resetFields();
    setEditingRule(null);
    setSelectedRuleType('rate_limit');
    setModalVisible(true);
  };

  const handleEdit = (rule) => {
    // DEBUG: Log rule data to identify why form fields are empty
    console.log('WAF Edit Debug - Rule data:', rule);
    console.log('WAF Edit Debug - Rule config:', rule.config);
    console.log('WAF Edit Debug - Frontend IDs:', rule.frontend_ids);
    
    const formValues = {
      name: rule.name,
      rule_type: rule.rule_type,
      action: rule.action,
      priority: rule.priority,
      is_active: rule.is_active,
      description: rule.description,
      frontend_ids: rule.frontend_ids,
      ...rule.config,
    };
    
    console.log('WAF Edit Debug - Form values being set:', formValues);
    
    form.setFieldsValue(formValues);
    setEditingRule(rule);
    setSelectedRuleType(rule.rule_type);
    setModalVisible(true);
  };

  const handleDelete = async (ruleId) => {
    try {
      // Send delete action to backend
      await axios.post(`/api/waf/rules/${ruleId}/toggle`, null, {
        params: { action: 'delete', cluster_id: selectedCluster?.id }
      });
      message.success('WAF rule marked for deletion. Go to Apply Changes to remove it from agents.');
      fetchRules();
      checkPendingChanges();
    } catch (error) {
      message.error('Failed to delete rule: ' + (error.response?.data?.detail || error.message));
    }
  };

  const handleToggle = async (ruleId) => {
    try {
      await axios.post(`/api/waf/rules/${ruleId}/toggle`, null, {
        params: { cluster_id: selectedCluster?.id }
      });
      message.success('WAF rule status updated');
      fetchRules();
      checkPendingChanges();
    } catch (error) {
      message.error('Failed to toggle rule: ' + error.response?.data?.detail);
    }
  };

  const handleSubmit = async (values) => {
    try {
      // Consolidate all rule-specific fields into a single 'config' object
      const {
        name, rule_type, action, priority, is_active, description, frontend_ids,
        ...config
      } = values;

      // Clean up ip_addresses from textarea
      if (config.ip_addresses) {
        config.ip_addresses = config.ip_addresses.split('\n').map(ip => ip.trim()).filter(ip => ip);
      }
      // Clean up countries from input
      if (config.countries) {
        config.countries = config.countries.split(',').map(c => c.trim()).filter(c => c);
      }

      const ruleData = {
        name,
        rule_type,
        action,
        priority,
        is_active,
        description,
        frontend_ids,
        config,
      };

      if (editingRule) {
        await axios.put(`/api/waf/rules/${editingRule.id}`, ruleData, {
          params: { cluster_id: selectedCluster?.id }
        });
        message.success('WAF rule updated successfully. Go to Apply Changes to activate.');
      } else {
        await axios.post('/api/waf/rules', ruleData, {
          params: { cluster_id: selectedCluster?.id }
        });
        message.success('WAF rule created successfully. Go to Apply Changes to activate.');
      }
      
      setModalVisible(false);
      fetchRules();
      checkPendingChanges();
    } catch (error) {
      message.error('Failed to save rule: ' + (error.response?.data?.detail || error.message));
    }
  };

  const getRuleTypeIcon = (type) => {
    const icons = {
      'rate_limit': <ClockCircleOutlined style={{ color: '#1890ff' }} />,
      'ip_filter': <UserOutlined style={{ color: '#52c41a' }} />,
      'header_filter': <BugOutlined style={{ color: '#722ed1' }} />,
      'request_filter': <SecurityScanOutlined style={{ color: '#fa8c16' }} />,
      'geo_block': <GlobalOutlined style={{ color: '#faad14' }} />,
      'size_limit': <FireOutlined style={{ color: '#ff4d4f' }} />,
    };
    return icons[type] || <SecurityScanOutlined />;
  };

  const getActionColor = (action) => {
    const colors = {
      'block': 'red',
      'allow': 'green',
      'log': 'blue',
      'redirect': 'orange',
    };
    return colors[action] || 'default';
  };

  const renderRuleConfig = (rule) => {
    switch (rule.rule_type) {
      case 'rate_limit':
        return `${rule.config.rate_limit_requests} req/${rule.config.rate_limit_window}s`;
      case 'ip_filter':
        return `${rule.config.ip_action}: ${rule.config.ip_addresses?.length || 0} IPs`;
      case 'header_filter':
        return `${rule.config.header_name}: ${rule.config.header_condition}`;
      case 'request_filter':
        return `${rule.config.http_method} ${rule.config.path_pattern}`;
      case 'geo_block':
        return `${rule.config.geo_action}: ${rule.config.countries?.length || 0} countries`;
      case 'size_limit':
        return `Max: ${rule.config.max_request_size ? (rule.config.max_request_size / 1024 / 1024).toFixed(1) + 'MB' : 'N/A'}`;
      default:
        return '-';
    }
  };

  const columns = [
    {
      title: 'Rule',
      dataIndex: 'name',
      key: 'name',
      render: (text, record) => (
        <Space>
          {getRuleTypeIcon(record.rule_type)}
          <div>
            <strong>{text}</strong>
            <br />
            <Text type="secondary" style={{ fontSize: 12 }}>
              Priority: {record.priority}
            </Text>
          </div>
        </Space>
      ),
    },
    {
      title: 'Sync Status',
      key: 'sync_status',
      render: (_, record) => (
        <EntitySyncStatus
          key={`${record.id}-${refreshKey}`}
          entityType="waf_rules"
          entityId={record.id}
          entityUpdatedAt={record.updated_at}
          lastConfigStatus={record.last_config_status}
          clusterId={selectedCluster?.id}
          selectedCluster={selectedCluster}
        />
      ),
    },
    {
      title: 'Type',
      dataIndex: 'rule_type',
      key: 'rule_type',
      render: (type) => (
        <Tag color="blue">{type.replace('_', ' ').toUpperCase()}</Tag>
      ),
    },
    {
      title: 'Action',
      dataIndex: 'action',
      key: 'action',
      render: (action) => (
        <Tag color={getActionColor(action)}>{action.toUpperCase()}</Tag>
      ),
    },
    {
      title: 'Configuration',
      key: 'config',
      render: (_, record) => (
        <Text code style={{ fontSize: 12 }}>
          {renderRuleConfig(record)}
        </Text>
      ),
    },
    {
      title: 'Frontend Usage',
      dataIndex: 'frontend_count',
      key: 'frontend_count',
      render: (count) => (
        <Tag color={count > 0 ? 'green' : 'default'}>{count}</Tag>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'is_active',
      key: 'is_active',
      render: (isActive, record) => (
        <Switch
          checked={isActive}
          checkedChildren="ON"
          unCheckedChildren="OFF"
          onChange={() => handleToggle(record.id)}
        />
      ),
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date) => date ? new Date(date).toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      }) : '-',
    },
    {
      title: 'Last Update', 
      dataIndex: 'updated_at',
      key: 'updated_at',
      render: (date) => date ? new Date(date).toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      }) : '-',
    },
    {
      title: 'Config Status',
      key: 'config_status',
      render: (_, record) => {
        const status = record.last_config_status || (record.has_pending_config ? 'PENDING' : 'APPLIED');
        const color = getConfigStatusColor(status);
        return (
          <Tag color={color}>{status}</Tag>
        );
      },
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space size="small">
          {(record.has_pending_config || false) && (
            <Tooltip title="Apply pending configuration changes">
              <Button
                type="primary"
                size="small"
                icon={<PlayCircleOutlined />}
                onClick={() => window.location.href = '/apply-management'}
                style={{
                  backgroundColor: '#1890ff',
                  borderColor: '#1890ff',
                }}
              >
                Apply
              </Button>
            </Tooltip>
          )}

          <Tooltip title="Edit Rule">
            <Button
              size="small"
              icon={<EditOutlined />}
              onClick={() => handleEdit(record)}
            />
          </Tooltip>
          <Popconfirm
            title="Delete WAF Rule"
            description="Are you sure you want to delete this rule?"
            onConfirm={() => handleDelete(record.id)}
            okText="Yes"
            cancelText="No"
          >
            <Tooltip title="Delete Rule">
              <Button
                danger
                size="small"
                icon={<DeleteOutlined />}
              />
            </Tooltip>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const renderRuleTypeFields = () => {
    switch (selectedRuleType) {
      case 'rate_limit':
        return (
          <>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item
                  name="rate_limit_requests"
                  label="Max Requests"
                  rules={[
                    { required: true, message: 'Please enter max requests' },
                    {
                      validator: (_, value) => {
                        if (!value) return Promise.resolve();
                        const formValues = form.getFieldsValue();
                        const validation = WAFValidationUtils.validateRateLimit(value, formValues.rate_limit_window);
                        if (validation.valid) {
                          return Promise.resolve();
                        }
                        return Promise.reject(new Error(validation.errors.join('; ')));
                      }
                    }
                  ]}
                >
                  <InputNumber 
                    min={1} 
                    max={10000} 
                    placeholder="e.g., 100" 
                    style={{ width: '100%' }}
                    onChange={() => {
                      // Trigger validation for both fields when either changes
                      setTimeout(() => form.validateFields(['rate_limit_window']), 100);
                    }}
                  />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item
                  name="rate_limit_window"
                  label="Time Window (seconds)"
                  rules={[
                    { required: true, message: 'Please enter time window' },
                    {
                      validator: (_, value) => {
                        if (!value) return Promise.resolve();
                        const formValues = form.getFieldsValue();
                        const validation = WAFValidationUtils.validateRateLimit(formValues.rate_limit_requests, value);
                        if (validation.valid) {
                          return Promise.resolve();
                        }
                        return Promise.reject(new Error(validation.errors.join('; ')));
                      }
                    }
                  ]}
                >
                  <InputNumber 
                    min={1} 
                    max={3600} 
                    placeholder="e.g., 60" 
                    style={{ width: '100%' }}
                    onChange={() => {
                      // Trigger validation for both fields when either changes
                      setTimeout(() => form.validateFields(['rate_limit_requests']), 100);
                    }}
                  />
                </Form.Item>
              </Col>
            </Row>
          </>
        );
      case 'ip_filter':
        return (
          <>
            <Form.Item
              name="ip_addresses"
              label="IP Addresses/CIDR"
              rules={[
                { required: true, message: 'Please enter IP addresses' },
                {
                  validator: (_, value) => {
                    if (!value) return Promise.resolve();
                    
                    const validation = WAFValidationUtils.validateIPAddresses(value);
                    if (validation.valid) {
                      return Promise.resolve();
                    }
                    return Promise.reject(new Error(validation.errors.join('\n')));
                  }
                }
              ]}
            >
              <TextArea
                rows={4}
                placeholder="One IP or CIDR per line:&#10;192.168.1.0/24&#10;10.0.0.1&#10;203.0.113.0/24"
                onBlur={(e) => {
                  const value = e.target.value;
                  if (value) {
                    const validation = WAFValidationUtils.validateIPAddresses(value);
                    if (!validation.valid) {
                      message.warning(`IP Address Warning: ${validation.errors[0]}`);
                    }
                  }
                }}
              />
            </Form.Item>
            <Form.Item
              name="ip_action"
              label="Action Type"
              rules={[{ required: true, message: 'Please select action type' }]}
            >
              <Select placeholder="Select action">
                <Option value="whitelist">Whitelist (Allow only these IPs)</Option>
                <Option value="blacklist">Blacklist (Block these IPs)</Option>
              </Select>
            </Form.Item>
          </>
        );
      case 'header_filter':
        return (
          <>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item
                  name="header_name"
                  label="Header Name"
                  rules={[{ required: true, message: 'Please enter header name' }]}
                >
                  <Input placeholder="e.g., User-Agent, X-API-Key" />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item
                  name="header_condition"
                  label="Condition"
                  rules={[{ required: true, message: 'Please select condition' }]}
                >
                  <Select placeholder="Select condition">
                    <Option value="equals">Equals</Option>
                    <Option value="contains">Contains</Option>
                    <Option value="regex">Regex Match</Option>
                  </Select>
                </Form.Item>
              </Col>
            </Row>
            <Form.Item
              name="header_value"
              label="Header Value/Pattern"
              rules={[{ required: true, message: 'Please enter header value' }]}
            >
              <Input placeholder="e.g., malicious-bot, (bot|crawler|scanner)" />
            </Form.Item>
          </>
        );
      case 'request_filter':
        return (
          <>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item
                  name="http_method"
                  label="HTTP Method"
                >
                  <Select placeholder="Select method (optional)">
                    <Option value="">Any</Option>
                    <Option value="GET">GET</Option>
                    <Option value="POST">POST</Option>
                    <Option value="PUT">PUT</Option>
                    <Option value="DELETE">DELETE</Option>
                    <Option value="PATCH">PATCH</Option>
                  </Select>
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item
                  name="path_pattern"
                  label="Path Pattern (Regex)"
                  rules={[
                    { required: true, message: 'Please enter path pattern' },
                    {
                      validator: (_, value) => {
                        if (!value) return Promise.resolve();
                        
                        const validation = WAFValidationUtils.validateRegexPattern(value);
                        if (validation.valid) {
                          return Promise.resolve();
                        }
                        
                        const errorMsg = validation.errors.join('; ');
                        const exampleMsg = validation.examples ? `\n\nExamples:\n${validation.examples.join('\n')}` : '';
                        return Promise.reject(new Error(errorMsg + exampleMsg));
                      }
                    }
                  ]}
                >
                  <Input 
                    placeholder="e.g., ^/admin/, .*(union|select).*"
                    onBlur={(e) => {
                      const value = e.target.value;
                      if (value) {
                        const validation = WAFValidationUtils.validateRegexPattern(value);
                        if (!validation.valid) {
                          message.warning(`Regex Pattern Warning: ${validation.errors[0]}`);
                        }
                      }
                    }}
                  />
                </Form.Item>
              </Col>
            </Row>
          </>
        );
      case 'geo_block':
        return (
          <>
            <Form.Item
              name="countries"
              label="Country Codes (ISO 3166-1)"
              rules={[
                { required: true, message: 'Please enter country codes' },
                {
                  validator: (_, value) => {
                    if (!value) return Promise.resolve();
                    
                    const validation = WAFValidationUtils.validateCountryCodes(value);
                    if (validation.valid) {
                      return Promise.resolve();
                    }
                    
                    const errorMsg = validation.errors.join('\n');
                    const exampleMsg = validation.examples ? `\n\nExamples: ${validation.examples.join(', ')}` : '';
                    return Promise.reject(new Error(errorMsg + exampleMsg));
                  }
                }
              ]}
            >
              <Input 
                placeholder="e.g., CN,RU,KP (comma separated)"
                onBlur={(e) => {
                  const value = e.target.value;
                  if (value) {
                    const validation = WAFValidationUtils.validateCountryCodes(value);
                    if (!validation.valid) {
                      message.warning(`Country Code Warning: ${validation.errors[0]}`);
                    }
                  }
                }}
              />
            </Form.Item>
            <Form.Item
              name="geo_action"
              label="Geo Action"
              rules={[{ required: true, message: 'Please select geo action' }]}
            >
              <Select placeholder="Select action">
                <Option value="block">Block from these countries</Option>
                <Option value="allow">Allow only these countries</Option>
              </Select>
            </Form.Item>
          </>
        );
      case 'size_limit':
        return (
          <>
            <Row gutter={16}>
              <Col span={12}>
                <Form.Item
                  name="max_request_size"
                  label="Max Request Size (bytes)"
                  rules={[
                    {
                      validator: (_, value) => {
                        if (!value) return Promise.resolve();
                        
                        const validation = WAFValidationUtils.validateSizeValue(value, 'Max Request Size');
                        if (validation.valid) {
                          return Promise.resolve();
                        }
                        
                        const errorMsg = validation.errors.join('; ');
                        const exampleMsg = validation.examples ? `\n\nExamples: ${validation.examples.join(', ')}` : '';
                        return Promise.reject(new Error(errorMsg + exampleMsg));
                      }
                    }
                  ]}
                >
                  <InputNumber 
                    min={1024} 
                    max={2147483647}
                    placeholder="e.g., 10485760 (10MB)" 
                    style={{ width: '100%' }}
                    formatter={value => `${value}`.replace(/\B(?=(\d{3})+(?!\d))/g, ',')}
                    parser={value => value.replace(/\$\s?|(,*)/g, '')}
                  />
                </Form.Item>
              </Col>
              <Col span={12}>
                <Form.Item
                  name="max_header_size"
                  label="Max Header Size (bytes)"
                  rules={[
                    {
                      validator: (_, value) => {
                        if (!value) return Promise.resolve();
                        
                        const validation = WAFValidationUtils.validateSizeValue(value, 'Max Header Size');
                        if (validation.valid) {
                          return Promise.resolve();
                        }
                        
                        const errorMsg = validation.errors.join('; ');
                        const exampleMsg = validation.examples ? `\n\nExamples: ${validation.examples.join(', ')}` : '';
                        return Promise.reject(new Error(errorMsg + exampleMsg));
                      }
                    }
                  ]}
                >
                  <InputNumber 
                    min={1024} 
                    max={2147483647}
                    placeholder="e.g., 8192 (8KB)" 
                    style={{ width: '100%' }}
                    formatter={value => `${value}`.replace(/\B(?=(\d{3})+(?!\d))/g, ',')}
                    parser={value => value.replace(/\$\s?|(,*)/g, '')}
                  />
                </Form.Item>
              </Col>
            </Row>
          </>
        );
      default:
        return null;
    }
  };

  return (
    <div>
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={24} sm={24} md={12} lg={12} xl={12}>
          <Title level={2} style={{ margin: 0 }}>
            <SecurityScanOutlined style={{ marginRight: 8, color: '#ff4d4f' }} />
            WAF Management
          </Title>
        </Col>
        <Col xs={24} sm={24} md={12} lg={12} xl={12} style={{ textAlign: 'right' }}>
          {/* Ana butonlar - her zaman üstte */}
          <div style={{ marginBottom: 8 }}>
            <Space>
              <Button
                type="primary"
                icon={<PlusOutlined />}
                onClick={handleAdd}
              >
                Add WAF Rule
              </Button>
              {pendingChanges && (
                <Button
                  type="primary"
                  icon={<PlayCircleOutlined />}
                  onClick={() => window.location.href = '/apply-management'}
                  style={{
                    backgroundColor: '#1890ff',
                    borderColor: '#1890ff',
                    animation: 'pulse 1.5s infinite'
                  }}
                >
                  Go to Apply Management
                </Button>
              )}
            </Space>
          </div>
          
          {/* Filtreler ve diğer butonlar - responsive wrap */}
          <Space wrap size={[8, 8]}>
            <Space>
              <span style={{ fontSize: 12 }}>Pending</span>
              <Switch
                checked={showPending}
                onChange={onToggleShowPending}
                size="small"
              />
            </Space>
            <Space>
              <span style={{ fontSize: 12 }}>Rejected</span>
              <Switch
                checked={showRejected}
                onChange={onToggleShowRejected}
                size="small"
              />
            </Space>
            <div style={{ 
              position: 'relative', 
              display: 'inline-block',
              width: 200
            }}>
              <input
                type="text"
                placeholder="Search WAF rules..."
                value={searchText}
                onChange={(e) => handleSearch(e.target.value)}
                style={{
                  width: '100%',
                  height: 32,
                  paddingLeft: 8,
                  paddingRight: 8,
                  border: '1px solid #d9d9d9',
                  borderRadius: 6,
                  fontSize: 14,
                  outline: 'none',
                  boxShadow: 'none',
                  backgroundColor: '#fff',
                  transition: 'border-color 0.3s ease'
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = '#1890ff';
                  e.target.style.outline = 'none';
                  e.target.style.boxShadow = 'none';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = '#d9d9d9';
                }}
                onMouseOver={(e) => {
                  if (e.target !== document.activeElement) {
                    e.target.style.borderColor = '#40a9ff';
                  }
                }}
                onMouseOut={(e) => {
                  if (e.target !== document.activeElement) {
                    e.target.style.borderColor = '#d9d9d9';
                  }
                }}
              />
            </div>
            <Button
              icon={<ReloadOutlined />}
              onClick={() => {
                fetchRules();
                setRefreshKey(prev => prev + 1); // Force EntitySyncStatus refresh
              }}
              loading={loading}
            >
              Refresh
            </Button>
            <Button
              icon={<EyeOutlined />}
              onClick={() => setStatsModalVisible(true)}
            >
              Statistics
            </Button>
          </Space>
        </Col>
      </Row>

      {/* Quick Stats */}
      <Row gutter={16} style={{ marginBottom: 16 }}>
        <Col span={6}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 'bold', color: '#1890ff' }}>
              {rules?.length || 0}
            </div>
            <div>Total Rules</div>
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 'bold', color: '#52c41a' }}>
              {rules?.filter(r => r.is_active)?.length || 0}
            </div>
            <div>Active Rules</div>
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 'bold', color: '#faad14' }}>
              {stats.summary?.blocked_requests || 0}
            </div>
            <div>Blocked (24h)</div>
          </Card>
        </Col>
        <Col span={6}>
          <Card size="small" style={{ textAlign: 'center' }}>
            <div style={{ fontSize: 20, fontWeight: 'bold', color: '#ff4d4f' }}>
              {stats.summary?.block_rate?.toFixed(1) || 0}%
            </div>
            <div>Block Rate</div>
          </Card>
        </Col>
      </Row>

      <Card>
        <Table
          columns={columns}
          dataSource={filteredRules}
          rowKey="id"
          loading={loading}
          pagination={{
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) =>
              `${range[0]}-${range[1]} of ${total} rules`,
          }}
        />
      </Card>

      {/* Add/Edit Rule Modal */}
      <Modal
        title={editingRule ? "Edit WAF Rule" : "Add WAF Rule"}
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        footer={null}
        width={800}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleSubmit}
          initialValues={{
            action: 'block',
            priority: 100,
            is_active: true,
          }}
        >
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="name"
                label="Rule Name"
                rules={[
                  { required: true, message: 'Please enter rule name' },
                  { pattern: /^[a-zA-Z0-9_-]+$/, message: 'Only alphanumeric, underscore and dash allowed' }
                ]}
              >
                <Input placeholder="e.g., api_rate_limit" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="rule_type"
                label="Rule Type"
                rules={[{ required: true, message: 'Please select rule type' }]}
              >
                <Select 
                  placeholder="Select rule type"
                  onChange={setSelectedRuleType}
                >
                  <Option value="rate_limit">Rate Limiting</Option>
                  <Option value="ip_filter">IP Filtering</Option>
                  <Option value="header_filter">Header Filtering</Option>
                  <Option value="request_filter">Request Filtering</Option>
                  <Option value="geo_block">Geo Blocking</Option>
                  <Option value="size_limit">Size Limiting</Option>
                </Select>
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col span={24}>
              <Form.Item
                name="frontend_ids"
                label="Target Frontends"
                tooltip="WAF rule will be applied to selected frontends. This can be left empty for a globally available WAF rule."
              >
                <Select 
                  mode="multiple"
                  placeholder="Select frontends to apply this WAF rule"
                  disabled={!selectedCluster}
                  maxTagCount="responsive"
                >
                  {frontends.map(frontend => (
                    <Option key={frontend.id} value={frontend.id}>
                      {frontend.name} ({frontend.bind_address}:{frontend.bind_port})
                    </Option>
                  ))}
                </Select>
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col span={8}>
              <Form.Item
                name="action"
                label="Action"
                rules={[{ required: true, message: 'Please select action' }]}
              >
                <Select>
                  <Option value="block">Block</Option>
                  <Option value="allow">Allow</Option>
                  <Option value="log">Log Only</Option>
                  <Option value="redirect">Redirect</Option>
                </Select>
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item
                name="priority"
                label="Priority"
                rules={[{ required: true, message: 'Please enter priority' }]}
              >
                <InputNumber min={1} max={1000} style={{ width: '100%' }} />
              </Form.Item>
            </Col>
            <Col span={8}>
              <Form.Item name="is_active" label="Status" valuePropName="checked">
                <Switch checkedChildren="Active" unCheckedChildren="Inactive" />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item
            name="description"
            label="Description"
          >
            <TextArea rows={2} placeholder="Optional description..." />
          </Form.Item>

          <Divider orientation="left">Rule Configuration</Divider>
          
          {renderRuleTypeFields()}

          <Divider orientation="left">Advanced Options</Divider>

          <Form.Item
            noStyle
            shouldUpdate={(prevValues, currentValues) =>
              prevValues.action !== currentValues.action
            }
          >
            {({ getFieldValue }) =>
              getFieldValue('action') === 'redirect' ? (
                <Form.Item
                  name="redirect_url"
                  label="Redirect URL"
                  rules={[{ required: true, message: 'Please enter redirect URL' }]}
                >
                  <Input placeholder="https://example.com/blocked" />
                </Form.Item>
              ) : null
            }
          </Form.Item>

          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="log_message"
                label="Custom Log Message"
                rules={[
                  {
                    validator: (_, value) => {
                      if (!value || value.length <= 200) {
                        return Promise.resolve();
                      }
                      return Promise.reject(new Error('Log message should not exceed 200 characters'));
                    }
                  }
                ]}
              >
                <Input 
                  placeholder="Custom message for logs" 
                  maxLength={200}
                  showCount
                />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="custom_condition"
                label="Custom HAProxy Condition"
                rules={[
                  {
                    validator: (_, value) => {
                      if (!value) return Promise.resolve();
                      
                      const validation = WAFValidationUtils.validateHAProxyCondition(value);
                      if (validation.valid) {
                        return Promise.resolve();
                      }
                      
                      const errorMsg = validation.errors.join('; ');
                      const exampleMsg = validation.examples ? `\n\nExamples:\n${validation.examples.join('\n')}` : '';
                      return Promise.reject(new Error(errorMsg + exampleMsg));
                    }
                  }
                ]}
              >
                <Input 
                  placeholder="{ req.hdr(user-agent) -m sub bot }"
                  onBlur={(e) => {
                    const value = e.target.value;
                    if (value) {
                      const validation = WAFValidationUtils.validateHAProxyCondition(value);
                      if (!validation.valid) {
                        message.warning(`HAProxy Condition Warning: ${validation.errors[0]}`);
                      }
                    }
                  }}
                />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item style={{ marginBottom: 0, textAlign: 'right' }}>
            <Space>
              <Button onClick={() => setModalVisible(false)}>
                Cancel
              </Button>
              <Button type="primary" htmlType="submit">
                {editingRule ? 'Update' : 'Create'} Rule
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Statistics Modal */}
      <Modal
        title="WAF Statistics & Activity"
        open={statsModalVisible}
        onCancel={() => setStatsModalVisible(false)}
        footer={[
          <Button key="close" onClick={() => setStatsModalVisible(false)}>
            Close
          </Button>
        ]}
        width={900}
      >
        <Tabs defaultActiveKey="1">
          <TabPane tab="Overview" key="1">
            <Row gutter={16} style={{ marginBottom: 16 }}>
              <Col span={6}>
                <Statistic
                  title="Total Requests (24h)"
                  value={stats.summary?.total_requests || 0}
                  prefix={<CheckCircleOutlined />}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="Blocked Requests"
                  value={stats.summary?.blocked_requests || 0}
                  prefix={<StopOutlined />}
                  valueStyle={{ color: '#ff4d4f' }}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="Unique IPs"
                  value={stats.summary?.unique_ips || 0}
                  prefix={<UserOutlined />}
                />
              </Col>
              <Col span={6}>
                <Statistic
                  title="Block Rate"
                  value={stats.summary?.block_rate || 0}
                  precision={1}
                  suffix="%"
                  prefix={<ExclamationCircleOutlined />}
                />
              </Col>
            </Row>
          </TabPane>
          <TabPane tab="Rule Activity" key="2">
            <List
              dataSource={stats.rule_activity || []}
              renderItem={item => (
                <List.Item>
                  <List.Item.Meta
                    avatar={getRuleTypeIcon(item.rule_type)}
                    title={item.rule_name}
                    description={`Type: ${item.rule_type}`}
                  />
                  <div>
                    <Space direction="vertical" style={{ textAlign: 'right' }}>
                      <Text>Triggers: <strong>{item.trigger_count}</strong></Text>
                      <Text>Blocks: <strong style={{ color: '#ff4d4f' }}>{item.block_count}</strong></Text>
                    </Space>
                  </div>
                </List.Item>
              )}
            />
          </TabPane>
          <TabPane tab="Recent Activity" key="3">
            <List
              dataSource={stats.recent_activity || []}
              renderItem={item => (
                <List.Item>
                  <List.Item.Meta
                    title={
                      <Space>
                        <Tag color={item.blocked ? 'red' : 'blue'}>{item.action_taken}</Tag>
                        <Text>{item.client_ip}</Text>
                        <Text code>{item.method} {item.path}</Text>
                      </Space>
                    }
                    description={
                      <Space>
                        <Text type="secondary">Rule: {item.rule_name}</Text>
                        <Text type="secondary">
                          {new Date(item.timestamp).toLocaleString()}
                        </Text>
                      </Space>
                    }
                  />
                </List.Item>
              )}
            />
          </TabPane>
        </Tabs>
      </Modal>

      {/* Version History Modal */}
      <VersionHistory
        visible={versionModalVisible}
        onCancel={handleVersionModalCancel}
        entityType={selectedEntityForVersion?.entityType}
        entityId={selectedEntityForVersion?.entityId}
        onRestoreSuccess={handleRestoreSuccess}
      />
    </div>
  );
};

function WAFManagementWithErrorBoundary() {
  return (
    <WAFErrorBoundary>
      <WAFManagement />
    </WAFErrorBoundary>
  );
}

export { WAFManagementWithErrorBoundary as WAFManagement };
export default WAFManagementWithErrorBoundary; 