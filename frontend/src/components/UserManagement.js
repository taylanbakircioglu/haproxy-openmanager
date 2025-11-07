import React, { useState, useEffect } from 'react';
import {
  Card,
  Table,
  Button,
  Modal,
  Form,
  Input,
  Select,
  Switch,
  Space,
  message,
  Tabs,
  Tag,
  Popconfirm,
  Tooltip,
  Row,
  Col,
  Badge,
  Tree,
  Typography,
  Divider
} from 'antd';
import {
  UserOutlined,
  TeamOutlined,
  SecurityScanOutlined,
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  HistoryOutlined,
  UserAddOutlined,
  KeyOutlined,
  DownloadOutlined
} from '@ant-design/icons';
import axios from 'axios';
import { useAuth } from '../contexts/AuthContext';

const { TabPane } = Tabs;
const { Option } = Select;
const { Text, Title } = Typography;
const { TextArea } = Input;

// Comprehensive Permission tree data structure - Enterprise RBAC
const PERMISSION_TREE = [
  {
    title: '📊 Dashboard',
    key: 'dashboard',
    children: [
      { title: 'View Dashboard', key: 'dashboard.read' },
      { title: 'View Statistics', key: 'dashboard.statistics' },
      { title: 'View Performance Metrics', key: 'dashboard.metrics' }
    ]
  },
  {
    title: '🌐 Frontend Management',
    key: 'frontends',
    children: [
      { title: 'View Frontends', key: 'frontends.read' },
      { title: 'Create Frontend', key: 'frontends.create' },
      { title: 'Edit Frontend', key: 'frontends.update' },
      { title: 'Delete Frontend', key: 'frontends.delete' },
      { title: 'Toggle Frontend', key: 'frontends.toggle' },
      { title: 'View Frontend History', key: 'frontends.history' }
    ]
  },
  {
    title: '🔧 Backend Management',
    key: 'backends',
    children: [
      { title: 'View Backends', key: 'backends.read' },
      { title: 'Create Backend', key: 'backends.create' },
      { title: 'Edit Backend', key: 'backends.update' },
      { title: 'Delete Backend', key: 'backends.delete' },
      { title: 'Toggle Backend', key: 'backends.toggle' },
      { title: 'Manage Servers', key: 'backends.servers' },
      { title: 'View Backend History', key: 'backends.history' }
    ]
  },
  {
    title: '🛡️ WAF Management',
    key: 'waf',
    children: [
      { title: 'View WAF Rules', key: 'waf.read' },
      { title: 'Create WAF Rule', key: 'waf.create' },
      { title: 'Edit WAF Rule', key: 'waf.update' },
      { title: 'Delete WAF Rule', key: 'waf.delete' },
      { title: 'Toggle WAF Rule', key: 'waf.toggle' },
      { title: 'View WAF History', key: 'waf.history' }
    ]
  },
  {
    title: '🔐 SSL Management',
    key: 'ssl',
    children: [
      { title: 'View SSL Certificates', key: 'ssl.read' },
      { title: 'Upload SSL Certificate', key: 'ssl.create' },
      { title: 'Edit SSL Certificate', key: 'ssl.update' },
      { title: 'Delete SSL Certificate', key: 'ssl.delete' },
      { title: 'Download SSL Certificate', key: 'ssl.download' },
      { title: 'View SSL History', key: 'ssl.history' }
    ]
  },
  {
    title: '🚀 Apply Management',
    key: 'apply',
    children: [
      { title: 'View Pending Changes', key: 'apply.read' },
      { title: 'Apply Changes', key: 'apply.execute' },
      { title: 'Reject Changes', key: 'apply.reject' },
      { title: 'View Apply History', key: 'apply.history' },
      { title: 'Bulk Apply', key: 'apply.bulk' },
      { title: 'Emergency Apply', key: 'apply.emergency' }
    ]
  },
  {
    title: '🤖 Agent Management',
    key: 'agents',
    children: [
      { title: 'View Agents', key: 'agents.read' },
      { title: 'Create Agent', key: 'agents.create' },
      { title: 'Edit Agent', key: 'agents.update' },
      { title: 'Delete Agent', key: 'agents.delete' },
      { title: 'Generate Agent Script', key: 'agents.script' },
      { title: 'Toggle Agent', key: 'agents.toggle' },
      { title: 'Upgrade Agent', key: 'agents.upgrade' },
      { title: 'View Agent Version Info', key: 'agents.version' },
      { title: 'View Agent Logs', key: 'agents.logs' }
    ]
  },
  {
    title: '🏢 Cluster Management',
    key: 'clusters',
    children: [
      { title: 'View Clusters', key: 'clusters.read' },
      { title: 'Create Cluster', key: 'clusters.create' },
      { title: 'Edit Cluster', key: 'clusters.update' },
      { title: 'Delete Cluster', key: 'clusters.delete' },
      { title: 'Switch Cluster', key: 'clusters.switch' },
      { title: 'View Cluster Config', key: 'clusters.config' }
    ]
  },
  {
    title: '📝 Configuration',
    key: 'config',
    children: [
      { title: 'View Configuration', key: 'config.read' },
      { title: 'Edit Configuration', key: 'config.update' },
      { title: 'Download Config', key: 'config.download' },
      { title: 'Upload Config', key: 'config.upload' },
      { title: 'Backup Config', key: 'config.backup' },
      { title: 'Restore Config', key: 'config.restore' },
      { title: 'View Config History', key: 'config.history' },
      { title: 'Bulk Import Configurations', key: 'config.bulk_import' },
      { title: 'View Config Request', key: 'config.view_request' },
      { title: 'Download Config Request', key: 'config.download_request' }
    ]
  },
  {
    title: '👥 User Management',
    key: 'users',
    children: [
      { title: 'View Users', key: 'users.read' },
      { title: 'Create User', key: 'users.create' },
      { title: 'Edit User', key: 'users.update' },
      { title: 'Delete User', key: 'users.delete' },
      { title: 'Change Password', key: 'users.password' },
      { title: 'Assign Roles', key: 'users.roles' }
    ]
  },
  {
    title: '🎭 Role Management',
    key: 'roles',
    children: [
      { title: 'View Roles', key: 'roles.read' },
      { title: 'Create Role', key: 'roles.create' },
      { title: 'Edit Role', key: 'roles.update' },
      { title: 'Delete Role', key: 'roles.delete' },
      { title: 'Manage Permissions', key: 'roles.permissions' }
    ]
  },
  {
    title: '📈 Statistics & Monitoring',
    key: 'statistics',
    children: [
      { title: 'View Statistics', key: 'statistics.read' },
      { title: 'View Performance Metrics', key: 'statistics.performance' },
      { title: 'View Agent Status', key: 'statistics.agents' },
      { title: 'View System Health', key: 'statistics.health' },
      { title: 'Export Statistics', key: 'statistics.export' }
    ]
  },
  {
    title: '📋 Activity Logs',
    key: 'activity',
    children: [
      { title: 'View Activity Logs', key: 'activity.read' },
      { title: 'View All User Activities', key: 'activity.all' },
      { title: 'Export Activity Logs', key: 'activity.export' }
    ]
  },
  {
    title: '⚙️ Settings',
    key: 'settings',
    children: [
      { title: 'View Settings', key: 'settings.read' },
      { title: 'Update Settings', key: 'settings.update' },
      { title: 'System Settings', key: 'settings.system' },
      { title: 'Security Settings', key: 'settings.security' }
    ]
  },
  {
    title: '🔧 System Administration',
    key: 'system',
    children: [
      { title: 'System Restart', key: 'system.restart' },
      { title: 'View System Logs', key: 'system.logs' },
      { title: 'Database Management', key: 'system.database' },
      { title: 'Service Management', key: 'system.services' },
      { title: 'Emergency Mode', key: 'system.emergency' }
    ]
  }
];

const UserManagement = () => {
  const { isAdmin } = useAuth(); // Get admin status from auth context
  const [activeTab, setActiveTab] = useState('users');
  
  // Users state
  const [users, setUsers] = useState([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [userModalVisible, setUserModalVisible] = useState(false);
  const [userForm] = Form.useForm();
  const [editingUser, setEditingUser] = useState(null);
  const [passwordModalVisible, setPasswordModalVisible] = useState(false);
  const [passwordForm] = Form.useForm();
  
  // Roles state
  const [roles, setRoles] = useState([]);
  const [rolesLoading, setRolesLoading] = useState(false);
  const [roleModalVisible, setRoleModalVisible] = useState(false);
  const [roleForm] = Form.useForm();
  const [editingRole, setEditingRole] = useState(null);
  const [checkedPermissions, setCheckedPermissions] = useState([]);
  
  // Role assignment state
  const [roleAssignmentModalVisible, setRoleAssignmentModalVisible] = useState(false);
  const [assignmentForm] = Form.useForm();
  const [selectedUser, setSelectedUser] = useState(null);
  
  // Activity logs state
  const [activities, setActivities] = useState([]);
  const [activitiesLoading, setActivitiesLoading] = useState(false);
  
  // Cluster state for role assignment
  const [clusters, setClusters] = useState([]);
  const [selectedClusters, setSelectedClusters] = useState([]);
  
  // Search states
  const [userSearchText, setUserSearchText] = useState('');
  const [filteredUsers, setFilteredUsers] = useState([]);
  const [roleSearchText, setRoleSearchText] = useState('');
  const [filteredRoles, setFilteredRoles] = useState([]);
  const [activitySearchText, setActivitySearchText] = useState('');
  const [filteredActivities, setFilteredActivities] = useState([]);

  // Fetch data on component mount
  useEffect(() => {
    fetchUsers();
    fetchRoles();
    fetchUserActivity();
    fetchClusters();
  }, []);

  // Update filtered data when original data changes
  useEffect(() => {
    setFilteredUsers(users);
  }, [users]);

  useEffect(() => {
    setFilteredRoles(roles);
  }, [roles]);

  useEffect(() => {
    setFilteredActivities(activities);
  }, [activities]);

  // Search handlers
  const handleUserSearch = (value) => {
    setUserSearchText(value);
    if (!value) {
      setFilteredUsers(users);
    } else {
      const filtered = users.filter(user =>
        user.username.toLowerCase().includes(value.toLowerCase()) ||
        user.email.toLowerCase().includes(value.toLowerCase()) ||
        user.full_name?.toLowerCase().includes(value.toLowerCase())
      );
      setFilteredUsers(filtered);
    }
  };

  const handleRoleSearch = (value) => {
    setRoleSearchText(value);
    if (!value) {
      setFilteredRoles(roles);
    } else {
      const filtered = roles.filter(role =>
        role.name.toLowerCase().includes(value.toLowerCase()) ||
        role.description?.toLowerCase().includes(value.toLowerCase())
      );
      setFilteredRoles(filtered);
    }
  };

  const handleActivitySearch = (value) => {
    setActivitySearchText(value);
    if (!value) {
      setFilteredActivities(activities);
    } else {
      const filtered = activities.filter(activity => {
        const searchLower = value.toLowerCase();
        
        // Search in all text fields
        const actionMatch = activity.action?.toLowerCase().includes(searchLower);
        const usernameMatch = activity.username?.toLowerCase().includes(searchLower);
        const resourceMatch = activity.resource?.toLowerCase().includes(searchLower);
        const resourceTypeMatch = activity.resource_type?.toLowerCase().includes(searchLower);
        const ipMatch = activity.ip_address?.toLowerCase().includes(searchLower);
        
        // Search in timestamp (formatted date)
        let timestampMatch = false;
        const dateValue = activity.timestamp || activity.created_at;
        if (dateValue) {
          try {
            let parsedDate;
            if (typeof dateValue === 'string') {
              parsedDate = new Date(dateValue.includes('T') && !dateValue.endsWith('Z') ? dateValue + 'Z' : dateValue);
            } else {
              parsedDate = new Date(dateValue);
            }
            if (!isNaN(parsedDate.getTime())) {
              timestampMatch = parsedDate.toLocaleString().toLowerCase().includes(searchLower);
            }
          } catch (e) {
            // Ignore date parsing errors for search
          }
        }
        
        // Search in details JSON
        let detailsMatch = false;
        if (activity.details) {
          try {
            const detailsString = typeof activity.details === 'string' 
              ? activity.details 
              : JSON.stringify(activity.details);
            detailsMatch = detailsString.toLowerCase().includes(searchLower);
          } catch (e) {
            // Ignore JSON parsing errors for search
          }
        }
        
        return actionMatch || usernameMatch || resourceMatch || resourceTypeMatch || 
               ipMatch || timestampMatch || detailsMatch;
      });
      setFilteredActivities(filtered);
    }
  };

  // Export activities to CSV
  const exportActivitiesToCSV = () => {
    try {
      // Prepare CSV headers
      const headers = ['User', 'Email', 'Action', 'Resource Type', 'Resource ID', 'IP Address', 'Time', 'Details'];
      
      // Prepare CSV rows
      const rows = filteredActivities.map(activity => {
        const dateValue = activity.timestamp || activity.created_at;
        let formattedDate = 'N/A';
        
        if (dateValue) {
          try {
            let parsedDate;
            if (typeof dateValue === 'string') {
              parsedDate = new Date(dateValue.includes('T') && !dateValue.endsWith('Z') ? dateValue + 'Z' : dateValue);
            } else {
              parsedDate = new Date(dateValue);
            }
            if (!isNaN(parsedDate.getTime())) {
              formattedDate = parsedDate.toLocaleString();
            }
          } catch (e) {
            // Keep default N/A
          }
        }
        
        // Format details as readable string
        let detailsString = '';
        if (activity.details) {
          try {
            const details = typeof activity.details === 'string' 
              ? JSON.parse(activity.details) 
              : activity.details;
            detailsString = Object.entries(details)
              .map(([key, value]) => `${key}: ${value}`)
              .join('; ');
          } catch (e) {
            detailsString = String(activity.details);
          }
        }
        
        return [
          activity.username || 'N/A',
          activity.email || 'N/A',
          activity.action || 'N/A',
          activity.resource_type || 'N/A',
          activity.resource_id || 'N/A',
          activity.ip_address || 'N/A',
          formattedDate,
          detailsString
        ];
      });
      
      // Create CSV content
      const csvContent = [
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      ].join('\n');
      
      // Create download link
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `user_activities_${new Date().toISOString().split('T')[0]}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      message.success(`Exported ${filteredActivities.length} activities to CSV`);
    } catch (error) {
      console.error('Error exporting activities:', error);
      message.error('Failed to export activities to CSV');
    }
  };

  // ==== CLUSTERS MANAGEMENT ====
  
  const fetchClusters = async () => {
    try {
      const response = await axios.get('/api/clusters');
      setClusters(response.data.clusters || []);
    } catch (error) {
      console.error('Failed to fetch clusters:', error);
      // Don't show error message for clusters as it's not critical
    }
  };

  // ==== USERS MANAGEMENT ====
  
  const fetchUsers = async () => {
    setUsersLoading(true);
    try {
      const response = await axios.get('/api/users', {
        headers: {
          'Cache-Control': 'no-cache, no-store, must-revalidate',
          'Pragma': 'no-cache'
        }
      });
      setUsers(response.data.users);
    } catch (error) {
      message.error('Failed to fetch users: ' + error.message);
    } finally {
      setUsersLoading(false);
    }
  };

  const handleCreateUser = () => {
    setEditingUser(null);
    userForm.resetFields();
    setUserModalVisible(true);
  };

  const handleEditUser = (user) => {
    setEditingUser(user);
    userForm.setFieldsValue({
      username: user.username,
      email: user.email,
      full_name: user.full_name,
      phone: user.phone,
      is_active: user.is_active,
      is_verified: user.is_verified,
      role_ids: user.roles ? user.roles.map(role => role.id) : []
    });
    setUserModalVisible(true);
  };

  const handleUserSubmit = async (values) => {
    try {
      if (editingUser) {
        await axios.put(`/api/users/${editingUser.id}`, values);
        message.success('User updated successfully');
      } else {
        await axios.post('/api/users', values);
        message.success('User created successfully');
      }
      setUserModalVisible(false);
      fetchUsers();
    } catch (error) {
      message.error(error.response?.data?.detail || 'Operation failed');
    }
  };

  const handleDeleteUser = async (user) => {
    try {
      await axios.delete(`/api/users/${user.id}`);
      message.success(`User '${user.username}' deleted successfully`);
      fetchUsers();
    } catch (error) {
      message.error(error.response?.data?.detail || 'Failed to delete user');
    }
  };

  const handleChangePassword = (user) => {
    setSelectedUser(user);
    passwordForm.resetFields();
    setPasswordModalVisible(true);
  };

  const handlePasswordSubmit = async (values) => {
    try {
      await axios.put(`/api/users/${selectedUser.id}/password`, values);
      message.success('Password changed successfully');
      setPasswordModalVisible(false);
    } catch (error) {
      message.error(error.response?.data?.detail || 'Failed to change password');
    }
  };

  const handleAssignRoles = (user) => {
    setSelectedUser(user);
    assignmentForm.setFieldsValue({
      role_ids: user.roles.map(role => role.id)
    });
    setRoleAssignmentModalVisible(true);
  };

  const handleRoleAssignmentSubmit = async (values) => {
    try {
      await axios.post('/api/user-roles', {
        user_id: selectedUser.id,
        role_ids: values.role_ids || []
      });
      message.success('Roles assigned successfully');
      setRoleAssignmentModalVisible(false);
      fetchUsers();
    } catch (error) {
      message.error(error.response?.data?.detail || 'Failed to assign roles');
    }
  };

  // ==== ROLES MANAGEMENT ====
  
  const fetchRoles = async () => {
    setRolesLoading(true);
    try {
      const response = await axios.get('/api/roles');
      // Parse JSON strings for permissions and cluster_ids
      const parsedRoles = response.data.roles.map(role => ({
        ...role,
        permissions: typeof role.permissions === 'string' ? JSON.parse(role.permissions) : (role.permissions || []),
        cluster_ids: typeof role.cluster_ids === 'string' ? JSON.parse(role.cluster_ids) : (role.cluster_ids || null)
      }));
      setRoles(parsedRoles);
    } catch (error) {
      message.error('Failed to fetch roles: ' + error.message);
    } finally {
      setRolesLoading(false);
    }
  };

  const handleCreateRole = () => {
    setEditingRole(null);
    roleForm.resetFields();
    setCheckedPermissions([]);
    setRoleModalVisible(true);
  };

  const handleEditRole = (role) => {
    setEditingRole(role);
    roleForm.setFieldsValue({
      name: role.name,
      display_name: role.display_name,
      description: role.description,
      is_active: role.is_active,
      cluster_ids: role.cluster_ids || []
    });
    
    // Convert permissions array to checked keys array
    const permissions = role.permissions || [];
    setCheckedPermissions(Array.isArray(permissions) ? permissions : []);
    setRoleModalVisible(true);
  };

  const handleRoleSubmit = async (values) => {
    // Use checked permissions as array (new format)
    const roleData = { 
      ...values, 
      permissions: checkedPermissions,
      cluster_ids: values.cluster_ids || null
    };

    try {
      if (editingRole) {
        await axios.put(`/api/roles/${editingRole.id}`, roleData);
        message.success('Role updated successfully');
      } else {
        await axios.post('/api/roles', roleData);
        message.success('Role created successfully');
      }
      setRoleModalVisible(false);
      roleForm.resetFields();
      setCheckedPermissions([]);
      fetchRoles();
    } catch (error) {
      message.error(error.response?.data?.detail || 'Operation failed');
    }
  };

  const handleDeleteRole = async (role) => {
    try {
      await axios.delete(`/api/roles/${role.id}`);
      message.success(`Role '${role.display_name}' deleted successfully`);
      fetchRoles();
    } catch (error) {
      message.error(error.response?.data?.detail || 'Failed to delete role');
    }
  };

  // ==== ACTIVITY LOGS ====
  
  const fetchUserActivity = async () => {
    setActivitiesLoading(true);
    try {
      const token = localStorage.getItem('token');
      console.log('UserManagement token check:', token ? `Token exists (${token.length} chars)` : 'Token is null/empty');
      
      // Check for null, empty, or 'null' string
      if (!token || token === 'null' || token === 'undefined' || token.trim() === '') {
        console.error('No valid authentication token found for UserManagement');
        message.error('Authentication required. Please login again.');
        window.location.href = '/login';
        return;
      }
      
      // Fetch user activity from backend
      console.log('🔍 ACTIVITY DEBUG: Fetching user activities with token:', token ? 'Token exists' : 'No token');
      
      const response = await axios.get('/api/user-activity', {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      console.log('🔍 ACTIVITY DEBUG: API Response:', response.data);
      console.log('🔍 ACTIVITY DEBUG: Activities count:', response.data.activities?.length || 0);
      console.log('🔍 ACTIVITY DEBUG: Total from API:', response.data.total || 0);
      
      setActivities(response.data.activities || []);
    } catch (error) {
      console.error('🔍 ACTIVITY DEBUG: Error in fetchUserActivity:', error);
      console.error('🔍 ACTIVITY DEBUG: Error response:', error.response?.data);
      console.error('🔍 ACTIVITY DEBUG: Error status:', error.response?.status);
      setActivities([]);
    } finally {
      setActivitiesLoading(false);
    }
  };

  // Table columns definitions
  const userColumns = [
    {
      title: 'Username',
      dataIndex: 'username',
      key: 'username',
      render: (text, record) => (
        <Space>
          <UserOutlined />
          <Text strong={record.is_active}>{text}</Text>
          {!record.is_active && <Tag color="red">Inactive</Tag>}
          {record.is_verified && <Tag color="green">Verified</Tag>}
        </Space>
      )
    },
    {
      title: 'Full Name',
      dataIndex: 'full_name',
      key: 'full_name'
    },
    {
      title: 'Email',
      dataIndex: 'email',
      key: 'email'
    },
    {
      title: 'Roles',
      dataIndex: 'roles',
      key: 'roles',
      render: (roles) => (
        <Space wrap>
          {roles?.map(role => (
            <Tag key={role.id} color="blue">{role.display_name}</Tag>
          )) || []}
          {(!roles || roles.length === 0) && <Text type="secondary">No roles assigned</Text>}
        </Space>
      )
    },
    {
      title: 'Last Login',
      dataIndex: 'last_login_at',
      key: 'last_login_at',
      render: (date) => date ? new Date(date).toLocaleString() : 'Never'
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          {isAdmin() && (
            <>
              <Tooltip title="Edit User">
                <Button 
                  icon={<EditOutlined />} 
                  size="small" 
                  onClick={() => handleEditUser(record)}
                />
              </Tooltip>
              <Tooltip title="Assign Roles">
                <Button 
                  icon={<TeamOutlined />} 
                  size="small" 
                  onClick={() => handleAssignRoles(record)}
                />
              </Tooltip>
              <Tooltip title="Change Password">
                <Button 
                  icon={<KeyOutlined />} 
                  size="small" 
                  onClick={() => handleChangePassword(record)}
                />
              </Tooltip>
              <Popconfirm
                title="Are you sure you want to delete this user?"
                onConfirm={() => handleDeleteUser(record)}
                okText="Yes"
                cancelText="No"
              >
                <Tooltip title="Delete User">
                  <Button 
                    icon={<DeleteOutlined />} 
                    danger 
                    size="small"
                  />
                </Tooltip>
              </Popconfirm>
            </>
          )}
          {!isAdmin() && (
            <Text type="secondary">View Only</Text>
          )}
        </Space>
      )
    }
  ];

  const roleColumns = [
    {
      title: 'Role Name',
      dataIndex: 'display_name',
      key: 'display_name',
      render: (text, record) => (
        <Space>
          <SecurityScanOutlined />
          <Text strong>{text}</Text>
          {record.is_system && <Tag color="orange">System</Tag>}
          {!record.is_active && <Tag color="red">Inactive</Tag>}
        </Space>
      )
    },
    {
      title: 'Description',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true
    },
    {
      title: 'Users',
      dataIndex: 'user_count',
      key: 'user_count',
      render: (count) => <Badge count={count} color="blue" />
    },
    {
      title: 'Permissions',
      dataIndex: 'permissions',
      key: 'permissions',
      render: (permissions) => {
        const count = Array.isArray(permissions) ? permissions.length : Object.keys(permissions || {}).length;
        return <Badge count={count} color="green" />;
      }
    },
    {
      title: 'Cluster Access',
      dataIndex: 'cluster_ids',
      key: 'cluster_ids',
      render: (cluster_ids, record) => {
        if (!cluster_ids || cluster_ids.length === 0) {
          return <Tag color="blue">🌐 All Clusters</Tag>;
        }
        
        const clusterNames = cluster_ids.map(clusterId => {
          const cluster = clusters.find(c => c.id === clusterId);
          return cluster ? `${cluster.name}${cluster.environment ? ` (${cluster.environment})` : ''}` : `Cluster ${clusterId}`;
        });
        
        return (
          <Space wrap>
            {clusterNames.map((name, index) => (
              <Tag key={index} color="cyan">🏢 {name}</Tag>
            ))}
          </Space>
        );
      }
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          {isAdmin() && (
            <>
              <Tooltip title="Edit Role">
                <Button 
                  icon={<EditOutlined />} 
                  size="small" 
                  onClick={() => handleEditRole(record)}
                  disabled={record.is_system}
                />
              </Tooltip>
              <Popconfirm
                title="Are you sure you want to delete this role?"
                onConfirm={() => handleDeleteRole(record)}
                okText="Yes"
                cancelText="No"
              >
                <Tooltip title="Delete Role">
                  <Button 
                    icon={<DeleteOutlined />} 
                danger 
                size="small"
                disabled={record.is_system || record.user_count > 0}
              />
            </Tooltip>
          </Popconfirm>
            </>
          )}
          {!isAdmin() && (
            <Text type="secondary">View Only</Text>
          )}
        </Space>
      )
    }
  ];

  const activityColumns = [
    {
      title: 'User',
      dataIndex: 'username',
      key: 'username',
      render: (username, record) => (
        <Space>
          <UserOutlined />
          <Text>{record.full_name || username}</Text>
        </Space>
      )
    },
    {
      title: 'Action',
      dataIndex: 'action',
      key: 'action',
      render: (action) => <Tag color="blue">{action}</Tag>
    },
    {
      title: 'Resource',
      dataIndex: 'resource_type',
      key: 'resource_type',
      render: (resourceType) => (
        <Tag color="green">{resourceType || 'N/A'}</Tag>
      )
    },
    {
      title: 'Details',
      dataIndex: 'details',
      key: 'details',
      width: 250,
      render: (details, record) => {
        if (!details) return <Text type="secondary">-</Text>;
        
        try {
          const detailsObj = typeof details === 'string' ? JSON.parse(details) : details;
          
          // Extract meaningful information from details
          const importantKeys = ['entity_name', 'path', 'method', 'entity_type', 'cluster_id', 'status_code'];
          const displayDetails = [];
          
          // Show important keys first
          importantKeys.forEach(key => {
            if (detailsObj[key] !== undefined) {
              displayDetails.push(`${key}: ${detailsObj[key]}`);
            }
          });
          
          // If no important keys found, show first few keys
          if (displayDetails.length === 0) {
            const keys = Object.keys(detailsObj).slice(0, 3);
            keys.forEach(key => {
              displayDetails.push(`${key}: ${detailsObj[key]}`);
            });
          }
          
          const displayText = displayDetails.join(', ');
          const fullDetails = JSON.stringify(detailsObj, null, 2);
          
          return (
            <Tooltip title={<pre style={{ margin: 0, maxHeight: 300, overflow: 'auto' }}>{fullDetails}</pre>}>
              <Text ellipsis style={{ maxWidth: 230, display: 'inline-block' }}>
                {displayText || '-'}
              </Text>
            </Tooltip>
          );
        } catch (error) {
          return <Text type="secondary">Invalid JSON</Text>;
        }
      }
    },
    {
      title: 'Time',
      dataIndex: 'timestamp',
      key: 'timestamp',
      render: (date, record) => {
        // Try both timestamp and created_at fields
        const dateValue = date || record.created_at;
        
        if (!dateValue) return <Text type="secondary">No date</Text>;
        
        try {
          // Try multiple date formats for compatibility
          let parsedDate;
          
          if (typeof dateValue === 'string') {
            // Handle different timestamp formats
            if (dateValue.includes('T') && !dateValue.endsWith('Z')) {
              parsedDate = new Date(dateValue + 'Z'); // Add Z for UTC
            } else {
              parsedDate = new Date(dateValue);
            }
          } else {
            parsedDate = new Date(dateValue);
          }
          
          // Check if date is valid
          if (isNaN(parsedDate.getTime())) {
            console.warn('Invalid date in activity logs:', dateValue);
            return <Text type="secondary">Invalid date</Text>;
          }
          
          return (
            <Tooltip title={`Raw: ${dateValue} | Parsed: ${parsedDate.toISOString()}`}>
              <Text>{parsedDate.toLocaleString()}</Text>
            </Tooltip>
          );
        } catch (error) {
          console.error('Date parsing error in activity logs:', error, dateValue);
          return <Text type="secondary">Date error</Text>;
        }
      }
    },
    {
      title: 'IP Address',
      dataIndex: 'ip_address',
      key: 'ip_address'
    }
  ];

  return (
    <div style={{ padding: '24px' }}>
      <Title level={2}>
        <UserOutlined /> User & Role Management
      </Title>
      
      <Tabs activeKey={activeTab} onChange={setActiveTab}>
        {/* Users Tab */}
        <TabPane 
          tab={
            <span>
              <UserOutlined />
              Users ({users.length})
            </span>
          } 
          key="users"
        >
          <Card 
            title="User Management"
            extra={
              <Space>
                                 <div style={{ 
                   position: 'relative', 
                   display: 'inline-block',
                   width: 200
                 }}>
                   <input
                     type="text"
                     placeholder="Search users..."
                     value={userSearchText}
                     onChange={(e) => handleUserSearch(e.target.value)}
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
                {isAdmin() && (
                  <Button 
                    type="primary" 
                    icon={<UserAddOutlined />}
                    onClick={handleCreateUser}
                  >
                    Add User
                  </Button>
                )}
              </Space>
            }
          >
            <Table
              columns={userColumns}
              dataSource={filteredUsers}
              rowKey="id"
              loading={usersLoading}
              pagination={{ pageSize: 10 }}
            />
          </Card>
        </TabPane>

        {/* Roles Tab */}
        <TabPane 
          tab={
            <span>
              <SecurityScanOutlined />
              Roles ({roles.length})
            </span>
          } 
          key="roles"
        >
          <Card 
            title="Role Management"
            extra={
              <Space>
                                 <div style={{ 
                   position: 'relative', 
                   display: 'inline-block',
                   width: 200
                 }}>
                   <input
                     type="text"
                     placeholder="Search roles..."
                     value={roleSearchText}
                     onChange={(e) => handleRoleSearch(e.target.value)}
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
                {isAdmin() && (
                  <Button 
                    type="primary" 
                    icon={<PlusOutlined />}
                    onClick={handleCreateRole}
                  >
                    Add Role
                  </Button>
                )}
              </Space>
            }
          >
            <Table
              columns={roleColumns}
              dataSource={filteredRoles}
              rowKey="id"
              loading={rolesLoading}
              pagination={{ pageSize: 10 }}
            />
          </Card>
        </TabPane>

        {/* Activity Logs Tab */}
        <TabPane 
          tab={
            <span>
              <HistoryOutlined />
              Activity Logs
            </span>
          } 
          key="activity"
        >
          <Card 
            title="User Activity Logs"
            extra={
              <Space>
                <Input
                  placeholder="Search activities..."
                  value={activitySearchText}
                  onChange={(e) => handleActivitySearch(e.target.value)}
                  style={{ 
                    width: 300,
                    display: 'flex',
                    alignItems: 'center'
                  }}
                  allowClear
                />
                <Button
                  type="primary"
                  icon={<DownloadOutlined />}
                  onClick={exportActivitiesToCSV}
                  disabled={filteredActivities.length === 0}
                >
                  Export CSV
                </Button>
              </Space>
            }
          >
            <Table
              columns={activityColumns}
              dataSource={filteredActivities}
              rowKey="timestamp"
              loading={activitiesLoading}
              pagination={{ 
                pageSize: 20,
                showSizeChanger: true,
                showTotal: (total) => `Total ${total} activities`,
                pageSizeOptions: ['10', '20', '50', '100']
              }}
              scroll={{ x: 1200 }}
              size="small"
            />
          </Card>
        </TabPane>
      </Tabs>

      {/* User Modal */}
      <Modal
        title={editingUser ? 'Edit User' : 'Create User'}
        open={userModalVisible}
        onCancel={() => setUserModalVisible(false)}
        footer={null}
        width={600}
      >
        <Form
          form={userForm}
          layout="vertical"
          onFinish={handleUserSubmit}
        >
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="username"
                label="Username"
                rules={[{ required: true, message: 'Please enter username' }]}
              >
                <Input prefix={<UserOutlined />} />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="email"
                label="Email"
                rules={[
                  { required: true, message: 'Please enter email' },
                  { type: 'email', message: 'Invalid email format' }
                ]}
              >
                <Input />
              </Form.Item>
            </Col>
          </Row>

          {!editingUser && (
            <Form.Item
              name="password"
              label="Password"
              rules={[
                { required: true, message: 'Please enter password' },
                { min: 6, message: 'Password must be at least 6 characters' }
              ]}
            >
              <Input.Password />
            </Form.Item>
          )}

          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="full_name" label="Full Name">
                <Input />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="phone" label="Phone">
                <Input />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={16}>
            <Col span={12}>
              <Form.Item name="is_active" label="Active" valuePropName="checked">
                <Switch />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item name="is_verified" label="Verified" valuePropName="checked">
                <Switch />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item name="role_ids" label="Assign Roles">
            <Select
              mode="multiple"
              placeholder="Select roles for this user"
              allowClear
              showSearch
              filterOption={(input, option) =>
                option.children.toLowerCase().indexOf(input.toLowerCase()) >= 0
              }
            >
              {roles.map(role => (
                <Option key={role.id} value={role.id}>
                  {role.display_name} - {role.description}
                </Option>
              ))}
            </Select>
          </Form.Item>

          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit">
                {editingUser ? 'Update' : 'Create'}
              </Button>
              <Button onClick={() => setUserModalVisible(false)}>
                Cancel
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Role Modal */}
      <Modal
        title={editingRole ? 'Edit Role' : 'Create Role'}
        open={roleModalVisible}
        onCancel={() => setRoleModalVisible(false)}
        footer={null}
        width={800}
      >
        <Form
          form={roleForm}
          layout="vertical"
          onFinish={handleRoleSubmit}
        >
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="name"
                label="Role Name (System ID)"
                rules={[{ required: true, message: 'Please enter role name' }]}
              >
                <Input />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="display_name"
                label="Display Name"
                rules={[{ required: true, message: 'Please enter display name' }]}
              >
                <Input />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item name="description" label="Description">
            <TextArea rows={3} />
          </Form.Item>

          <Form.Item name="is_active" label="Active" valuePropName="checked">
            <Switch />
          </Form.Item>

          <Divider>Cluster Access</Divider>
          
          <Form.Item 
            name="cluster_ids" 
            label="Cluster Access"
            extra="Leave empty to grant access to all clusters"
          >
            <Select
              mode="multiple"
              placeholder="Select specific clusters (optional)"
              allowClear
            >
              {clusters.map(cluster => (
                <Option key={cluster.id} value={cluster.id}>
                  🏢 {cluster.name}{cluster.environment ? ` (${cluster.environment})` : ''}
                </Option>
              ))}
            </Select>
          </Form.Item>

          <Divider>Permissions</Divider>
          
          <Tree
            checkable
            checkedKeys={checkedPermissions}
            onCheck={setCheckedPermissions}
            treeData={PERMISSION_TREE}
            height={300}
          />

          <Form.Item style={{ marginTop: 24 }}>
            <Space>
              <Button type="primary" htmlType="submit">
                {editingRole ? 'Update' : 'Create'}
              </Button>
              <Button onClick={() => setRoleModalVisible(false)}>
                Cancel
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Password Change Modal */}
      <Modal
        title={`Change Password - ${selectedUser?.username}`}
        open={passwordModalVisible}
        onCancel={() => setPasswordModalVisible(false)}
        footer={null}
      >
        <Form
          form={passwordForm}
          layout="vertical"
          onFinish={handlePasswordSubmit}
        >
          <Form.Item
            name="current_password"
            label="Current Password"
            rules={[{ required: true, message: 'Please enter current password' }]}
          >
            <Input.Password />
          </Form.Item>

          <Form.Item
            name="new_password"
            label="New Password"
            rules={[
              { required: true, message: 'Please enter new password' },
              { min: 6, message: 'Password must be at least 6 characters' }
            ]}
          >
            <Input.Password />
          </Form.Item>

          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit">
                Change Password
              </Button>
              <Button onClick={() => setPasswordModalVisible(false)}>
                Cancel
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      {/* Role Assignment Modal */}
      <Modal
        title={`Assign Roles - ${selectedUser?.username}`}
        open={roleAssignmentModalVisible}
        onCancel={() => setRoleAssignmentModalVisible(false)}
        footer={null}
      >
        <Form
          form={assignmentForm}
          layout="vertical"
          onFinish={handleRoleAssignmentSubmit}
        >
          <Form.Item
            name="role_ids"
            label="Select Roles"
          >
            <Select
              mode="multiple"
              placeholder="Select roles for this user"
              style={{ width: '100%' }}
            >
              {roles.filter(role => role.is_active).map(role => (
                <Option key={role.id} value={role.id}>
                  <Space>
                    <SecurityScanOutlined />
                    {role.display_name}
                    {role.is_system && <Tag size="small" color="orange">System</Tag>}
                  </Space>
                </Option>
              ))}
            </Select>
          </Form.Item>

          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit">
                Assign Roles
              </Button>
              <Button onClick={() => setRoleAssignmentModalVisible(false)}>
                Cancel
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default UserManagement; 