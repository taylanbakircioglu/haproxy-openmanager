import React, { useState } from 'react';
import { 
  Card, 
  Form, 
  Input, 
  Button, 
  message, 
  Typography, 
  Row, 
  Col,
  Alert,
  Spin
} from 'antd';
import { 
  UserOutlined, 
  LockOutlined, 
  SecurityScanOutlined 
} from '@ant-design/icons';
import axios from 'axios';
import { useAuth } from '../contexts/AuthContext';
import './Login.css';

const { Title, Text } = Typography;

const Login = () => {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();

  const handleSubmit = async (values) => {
    setLoading(true);
    setError('');
    
    try {
      const response = await axios.post('/api/auth/login', {
        username: values.username,
        password: values.password
      });

      // Store authentication data - API returns access_token, not session_token!
      localStorage.setItem('token', response.data.access_token);
      localStorage.setItem('authToken', response.data.access_token);
      localStorage.setItem('userData', JSON.stringify(response.data.user));
      localStorage.setItem('userRoles', JSON.stringify([])); // API doesn't return roles directly
      localStorage.setItem('userPermissions', JSON.stringify({})); // API doesn't return permissions directly
      
      // Calculate expiry from expires_in (seconds)
      const expiryDate = new Date();
      expiryDate.setSeconds(expiryDate.getSeconds() + response.data.expires_in);
      localStorage.setItem('tokenExpiry', expiryDate.toISOString());

      // Update authentication context
      const loginSuccess = login(response.data);
      
      if (loginSuccess) {
        message.success(`Welcome back, ${response.data.user.username}!`);
        // The authentication context will automatically trigger a re-render
        // and the user will be redirected to the main dashboard
      } else {
        throw new Error('Failed to update authentication state');
      }
      
    } catch (error) {
      const errorMessage = error.response?.data?.detail || 'Login failed. Please try again.';
      setError(errorMessage);
      message.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <Row 
        justify="center" 
        align="middle" 
        style={{ 
          minHeight: '100vh',
          minHeight: '100dvh',
          width: '100%',
          margin: 0
        }}
      >
        <Col 
          xs={24} 
          sm={20} 
          md={16} 
          lg={12} 
          xl={10} 
          xxl={8}
          style={{ 
            display: 'flex',
            justifyContent: 'center',
            padding: '0 8px'
          }}
        >
          <Card className="login-card">
            <div className="login-header">
              <SecurityScanOutlined className="login-icon" />
              <Title level={2} className="login-title">
                HAProxy Management
              </Title>
              <Text type="secondary" className="login-subtitle">
                Sign in to your account
              </Text>
            </div>

            {error && (
              <Alert
                message={error}
                type="error"
                showIcon
                style={{ marginBottom: 24 }}
                closable
                onClose={() => setError('')}
              />
            )}

            <Form
              form={form}
              name="login"
              onFinish={handleSubmit}
              layout="vertical"
              autoComplete="off"
            >
              <Form.Item
                name="username"
                rules={[
                  { required: true, message: 'Please enter your username!' },
                  { min: 3, message: 'Username must be at least 3 characters!' }
                ]}
              >
                <Input
                  prefix={<UserOutlined />}
                  placeholder="Username"
                  autoComplete="username"
                />
              </Form.Item>

              <Form.Item
                name="password"
                rules={[
                  { required: true, message: 'Please enter your password!' },
                  { min: 6, message: 'Password must be at least 6 characters!' }
                ]}
              >
                <Input.Password
                  prefix={<LockOutlined />}
                  placeholder="Password"
                  autoComplete="current-password"
                />
              </Form.Item>

              <Form.Item style={{ marginBottom: 0 }}>
                <Button
                  type="primary"
                  htmlType="submit"
                  loading={loading}
                  block
                  className="login-button"
                >
                  {loading ? 'Signing in...' : 'Sign In'}
                </Button>
              </Form.Item>
            </Form>

            <div className="login-footer">
              <div className="demo-accounts">
                <Title level={5} style={{ color: '#666', marginBottom: 8 }}>
                  Demo Accounts:
                </Title>
                <div className="demo-account-list">
                  <div className="demo-account">
                    <Text strong>admin</Text> - Super Administrator
                  </div>
                  <div className="demo-account">
                    <Text strong>operator1</Text> - Daily Operations
                  </div>
                  <div className="demo-account">
                    <Text strong>security1</Text> - Security Management
                  </div>
                  <div className="demo-account">
                    <Text strong>viewer1</Text> - Read-only Access
                  </div>
                </div>
              </div>
            </div>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Login; 