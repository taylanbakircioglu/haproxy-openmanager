import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useNavigate, useLocation } from 'react-router-dom';
import { Layout, Menu, theme, Spin, Button, Dropdown, Avatar, Typography, ConfigProvider } from 'antd';
import {
  DashboardOutlined,
  SettingOutlined,
  CloudServerOutlined,
  BarChartOutlined,
  FileTextOutlined,
  GlobalOutlined,
  SafetyCertificateOutlined,
  SecurityScanOutlined,
  UserOutlined,
  LogoutOutlined,
  DownOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  PlayCircleOutlined,
  CloudUploadOutlined,
  ApiOutlined
} from '@ant-design/icons';

import Dashboard from './components/DashboardV2';
import BackendServers from './components/BackendServers';
import { FrontendManagement } from './components/FrontendManagement';
// Statistics component removed - will be redesigned later
import { Settings } from './components/Settings';
import { SSLManagement } from './components/SSLManagement';
import { WAFManagement } from './components/WAFManagement';
import ApplyManagement from './components/ApplyManagement';
import BulkVersionHistory from './components/BulkVersionHistory';
import BulkConfigImport from './components/BulkConfigImport';
import UserManagement from './components/UserManagement';
import Security from './components/Security';
import AgentManagement from './components/AgentManagement';
import PoolManagement from './components/PoolManagement';
import Login from './components/Login';
import ClusterSelector from './components/ClusterSelector';
import ClusterManagement from './components/ClusterManagement';
import Configuration from './components/Configuration';
import APIDocumentation from './components/APIDocumentation';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { ClusterProvider } from './contexts/ClusterContext';
import { ThemeProvider, useTheme } from './contexts/ThemeContext';
import { ProgressProvider } from './contexts/ProgressContext';
import GlobalProgress from './components/GlobalProgress';

import './App.css';

const { Header, Sider, Content } = Layout;
const { Text } = Typography;

// Force rebuild: 2024-10-21 - Added APIs menu item

  const menuItems = [
    {
      key: '/',
      icon: <DashboardOutlined />,
      label: <Link to="/">Dashboard</Link>,
    },
    // Statistics temporarily removed - will be redesigned
    {
      key: '/frontends',
      icon: <GlobalOutlined />,
      label: <Link to="/frontends">Frontend Management</Link>,
    },
    {
      key: '/backends',
      icon: <CloudServerOutlined />,
      label: <Link to="/backends">Backend Servers</Link>,
    },
    {
      key: '/ssl-certificates',
      icon: <SafetyCertificateOutlined />,
      label: <Link to="/ssl-certificates">SSL Certificate</Link>,
    },
    {
      key: '/waf',
      icon: <SecurityScanOutlined />,
      label: <Link to="/waf">WAF Management</Link>,
    },
    {
      key: '/bulk-config-import',
      icon: <CloudUploadOutlined />,
      label: <Link to="/bulk-config-import">Bulk Config Import</Link>,
    },
    {
      key: '/apply-management',
      icon: <PlayCircleOutlined />,
      label: <Link to="/apply-management">Apply Changes</Link>,
    },
    {
      key: '/agents',
      icon: <CloudServerOutlined />,
      label: <Link to="/agents">Agent Management</Link>,
    },
    {
      key: '/configuration',
      icon: <FileTextOutlined />,
      label: <Link to="/configuration">Configuration Management</Link>,
    },
    {
      key: '/clusters',
      icon: <CloudServerOutlined />,
      label: <Link to="/clusters">Cluster Management</Link>,
    },
    {
      key: '/pools',
      icon: <GlobalOutlined />,
      label: <Link to="/pools">Agent Pool Management</Link>,
    },
    {
      key: '/users',
      icon: <UserOutlined />,
      label: <Link to="/users">User Management</Link>,
    },
    {
      key: '/security',
      icon: <SecurityScanOutlined />,
      label: <Link to="/security">Security</Link>,
    },
    {
      key: '/settings',
      icon: <SettingOutlined />,
      label: <Link to="/settings">Settings</Link>,
    },
    {
      key: '/api-docs',
      icon: <ApiOutlined />,
      label: <Link to="/api-docs">APIs</Link>,
    },
  ];

function AppContent() {
  const {
    token: { colorBgContainer },
  } = theme.useToken();
  
  const navigate = useNavigate();
  const location = useLocation();
  const [selectedKey, setSelectedKey] = React.useState(location.pathname);
  const [collapsed, setCollapsed] = React.useState(false);
  const { user, logout, isAuthenticated, loading, getUserRoleNames } = useAuth();
  const { isDarkMode } = useTheme();

  React.useEffect(() => {
    setSelectedKey(location.pathname);
  }, [location.pathname]);

  const handleLogout = async () => {
    await logout();
  };

  const userMenuItems = [
    {
      key: 'profile',
      label: (
        <div style={{ padding: '8px 0' }}>
          <div style={{ fontWeight: 500 }}>{user?.username}</div>
          <div style={{ fontSize: '12px', color: '#666' }}>{getUserRoleNames()}</div>
        </div>
      ),
      disabled: true,
    },
    {
      type: 'divider',
    },
    {
      key: 'logout',
      label: 'Logout',
      icon: <LogoutOutlined />,
      onClick: handleLogout,
    },
  ];

  if (loading) {
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh',
        flexDirection: 'column',
        gap: '16px'
      }}>
        <Spin size="large" />
        <Text type="secondary">Loading...</Text>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Login />;
  }

  return (
    <ConfigProvider
      theme={{
        algorithm: isDarkMode ? theme.darkAlgorithm : theme.defaultAlgorithm,
      }}
    >
      <Layout style={{ minHeight: '100vh' }}>
        <Sider
          trigger={null}
          collapsible
          collapsed={collapsed}
          breakpoint="lg"
          collapsedWidth="0"
          onBreakpoint={(broken) => {
            console.log(broken);
          }}
        >
          <div style={{ 
            height: 64, 
            margin: 16,
            marginBottom: 24, 
            background: 'rgba(255, 255, 255, 0.15)',
            borderRadius: 8,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'white',
            fontWeight: 'bold',
            fontSize: collapsed ? '14px' : '16px',
            transition: 'all 0.2s',
            overflow: 'hidden'
          }}>
            {collapsed ? (
              <div style={{ 
                fontSize: '20px',
                color: '#1890ff',
                textShadow: '0 0 10px rgba(24, 144, 255, 0.5)'
              }}>
                H
              </div>
            ) : (
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: '8px',
                fontSize: '16px'
              }}>
                <div style={{ 
                  fontSize: '24px', 
                  color: '#1890ff',
                  textShadow: '0 0 10px rgba(24, 144, 255, 0.5)'
                }}>
                  ⚡
                </div>
                <span>HAProxy Management</span>
              </div>
            )}
          </div>
          <Menu
            theme="dark"
            mode="inline"
            selectedKeys={[selectedKey]}
            items={menuItems}
          />
        </Sider>
        <Layout>
          <Header
            style={{
              padding: 0,
              background: colorBgContainer,
              boxShadow: '0 1px 4px rgba(0,21,41,.08)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <Button
                type="text"
                icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
                onClick={() => setCollapsed(!collapsed)}
                style={{
                  fontSize: '16px',
                  width: 64,
                  height: 64,
                }}
              />
              <div style={{ 
                fontSize: '18px', 
                fontWeight: 'bold',
                color: '#1890ff',
                marginLeft: '8px'
              }}>
                HAProxy Load Balancer Management
              </div>
            </div>
            <div style={{ flex: 1, display: 'flex', justifyContent: 'center', padding: '0 24px' }}>
              <ClusterSelector />
            </div>
            <div style={{ padding: '0 24px' }}>
              <Dropdown
                menu={{ items: userMenuItems }}
                trigger={['click']}
                placement="bottomRight"
              >
                <Button 
                  type="text" 
                  style={{ 
                    height: '40px', 
                    display: 'flex', 
                    alignItems: 'center', 
                    gap: '8px',
                    fontWeight: 500
                  }}
                >
                  <Avatar size="small" icon={<UserOutlined />} />
                  <span>{user?.username}</span>
                  <DownOutlined style={{ fontSize: '10px' }} />
                </Button>
              </Dropdown>
            </div>
          </Header>
          <Content
            style={{
              margin: '24px 16px',
              padding: 24,
              minHeight: 280,
              background: colorBgContainer,
            }}
          >
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/frontends" element={<FrontendManagement />} />
              <Route path="/backends" element={<BackendServers />} />
              <Route path="/ssl-certificates" element={<SSLManagement />} />
              <Route path="/waf" element={<WAFManagement />} />
              <Route path="/bulk-config-import" element={<BulkConfigImport />} />
              <Route path="/apply-management" element={<ApplyManagement />} />
              <Route path="/version-history" element={<BulkVersionHistory />} />
              {/* Statistics route temporarily removed - will be redesigned */}
              <Route path="/users" element={<UserManagement />} />
              <Route path="/security" element={<Security />} />
              <Route path="/agents" element={<AgentManagement />} />
              <Route path="/configuration" element={<Configuration />} />
              <Route path="/api-docs" element={<APIDocumentation />} />
              <Route path="/pools" element={<PoolManagement />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="/clusters" element={<ClusterManagement />} />
            </Routes>
          </Content>
                </Layout>
      </Layout>
    </ConfigProvider>
  );
}

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <ClusterProvider>
          <ProgressProvider>
            <Router>
              <AppContent />
              <GlobalProgress />
            </Router>
          </ProgressProvider>
        </ClusterProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;