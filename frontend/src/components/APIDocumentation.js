import React from 'react';
import { Card, Typography, Alert } from 'antd';
import { ApiOutlined, BookOutlined, CodeOutlined } from '@ant-design/icons';

const { Title, Paragraph, Text, Link } = Typography;

const APIDocumentation = () => {
  // Get base URL from current location
  const baseUrl = window.location.origin;
  const apiDocsUrl = `${baseUrl}/api/docs`;
  const redocUrl = `${baseUrl}/api/redoc`;
  const openApiUrl = `${baseUrl}/api/openapi.json`;

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto' }}>
      <Title level={2}>
        <ApiOutlined /> API Documentation
      </Title>
      
      <Alert
        message="Interactive API Documentation Available"
        description="HAProxy Open Manager provides comprehensive, interactive API documentation via Swagger UI and ReDoc. You can test API endpoints directly from the documentation interface."
        type="info"
        showIcon
        style={{ marginBottom: 24 }}
      />

      <Card 
        title={<><CodeOutlined /> Swagger UI - Interactive API Explorer</>}
        style={{ marginBottom: 24 }}
        extra={
          <Link href={apiDocsUrl} target="_blank" rel="noopener noreferrer">
            Open Swagger UI →
          </Link>
        }
      >
        <Paragraph>
          <Text strong>Swagger UI</Text> provides an interactive interface where you can:
        </Paragraph>
        <ul>
          <li>Browse all available API endpoints</li>
          <li>View detailed request/response schemas</li>
          <li>Execute API calls directly from the browser</li>
          <li>Test authentication and authorization</li>
          <li>See real-time examples and responses</li>
        </ul>
        
        <div style={{ 
          background: '#f5f5f5', 
          padding: '16px', 
          borderRadius: '4px',
          marginTop: '16px'
        }}>
          <Text code>{apiDocsUrl}</Text>
        </div>

        <Paragraph style={{ marginTop: 16 }}>
          <Text type="secondary">
            Click "Authorize" button in Swagger UI and enter your JWT token to test authenticated endpoints.
          </Text>
        </Paragraph>
      </Card>

      <Card 
        title={<><BookOutlined /> ReDoc - Clean API Reference</>}
        style={{ marginBottom: 24 }}
        extra={
          <Link href={redocUrl} target="_blank" rel="noopener noreferrer">
            Open ReDoc →
          </Link>
        }
      >
        <Paragraph>
          <Text strong>ReDoc</Text> provides a clean, three-panel API reference with:
        </Paragraph>
        <ul>
          <li>Beautiful, easy-to-read documentation</li>
          <li>Comprehensive endpoint descriptions</li>
          <li>Request/response examples</li>
          <li>Schema definitions</li>
          <li>Searchable interface</li>
        </ul>
        
        <div style={{ 
          background: '#f5f5f5', 
          padding: '16px', 
          borderRadius: '4px',
          marginTop: '16px'
        }}>
          <Text code>{redocUrl}</Text>
        </div>
      </Card>

      <Card 
        title="OpenAPI Specification (JSON)"
        style={{ marginBottom: 24 }}
        extra={
          <Link href={openApiUrl} target="_blank" rel="noopener noreferrer">
            Download OpenAPI JSON →
          </Link>
        }
      >
        <Paragraph>
          Download the raw OpenAPI 3.0 specification in JSON format for:
        </Paragraph>
        <ul>
          <li>API client code generation (Postman, Insomnia, etc.)</li>
          <li>Custom documentation generation</li>
          <li>CI/CD integration and testing</li>
          <li>Third-party tool integration</li>
        </ul>
        
        <div style={{ 
          background: '#f5f5f5', 
          padding: '16px', 
          borderRadius: '4px',
          marginTop: '16px'
        }}>
          <Text code>{openApiUrl}</Text>
        </div>
      </Card>

      <Card title="Quick Start Guide">
        <Title level={4}>1. Authentication</Title>
        <Paragraph>
          All API endpoints (except <Text code>/api/auth/login</Text>) require JWT authentication.
        </Paragraph>
        
        <div style={{ 
          background: '#1f1f1f', 
          padding: '16px', 
          borderRadius: '4px',
          marginBottom: '16px',
          overflow: 'auto'
        }}>
          <pre style={{ margin: 0, color: '#fff' }}>
{`# Login to get access token
curl -X POST "${baseUrl}/api/auth/login" \\
  -H "Content-Type: application/json" \\
  -d '{
    "username": "admin",
    "password": "admin123"
  }'

# Response
{
  "access_token": "eyJhbGciOiJIUz...",
  "token_type": "bearer",
  "expires_in": 86400
}`}
          </pre>
        </div>

        <Title level={4}>2. Using the Token</Title>
        <Paragraph>
          Include the access token in the <Text code>Authorization</Text> header:
        </Paragraph>
        
        <div style={{ 
          background: '#1f1f1f', 
          padding: '16px', 
          borderRadius: '4px',
          marginBottom: '16px',
          overflow: 'auto'
        }}>
          <pre style={{ margin: 0, color: '#fff' }}>
{`# Example: Get all clusters
curl -X GET "${baseUrl}/api/clusters" \\
  -H "Authorization: Bearer eyJhbGciOiJIUz..."

# Example: Create a new backend
curl -X POST "${baseUrl}/api/backends" \\
  -H "Authorization: Bearer eyJhbGciOiJIUz..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "my-backend",
    "cluster_id": 1,
    "balance_algorithm": "roundrobin"
  }'`}
          </pre>
        </div>

        <Title level={4}>3. API Categories</Title>
        <Paragraph>
          The API is organized into the following categories:
        </Paragraph>
        <ul>
          <li><Text strong>Authentication</Text> - Login, logout, token management</li>
          <li><Text strong>Clusters</Text> - HAProxy cluster management</li>
          <li><Text strong>Pools</Text> - Agent pool management</li>
          <li><Text strong>Agents</Text> - Agent installation and monitoring</li>
          <li><Text strong>Frontends</Text> - Frontend configuration (listeners)</li>
          <li><Text strong>Backends</Text> - Backend and server management</li>
          <li><Text strong>WAF</Text> - Web Application Firewall rules</li>
          <li><Text strong>SSL</Text> - SSL/TLS certificate management</li>
          <li><Text strong>Configuration</Text> - Bulk import and version history</li>
          <li><Text strong>Dashboard</Text> - Statistics and monitoring</li>
          <li><Text strong>Users</Text> - User management and RBAC</li>
          <li><Text strong>Security</Text> - Audit logs and security settings</li>
        </ul>
      </Card>

      <Card 
        title="Architecture Overview" 
        style={{ marginTop: 24 }}
      >
        <Title level={4}>Agent-Pull Architecture</Title>
        <Paragraph>
          HAProxy Open Manager uses an <Text strong>agent-pull architecture</Text>:
        </Paragraph>
        <ol>
          <li>
            <Text strong>Backend API</Text> - Central management system (this API)
          </li>
          <li>
            <Text strong>Agent Service</Text> - Installed on each HAProxy server
            <ul>
              <li>Polls backend every 10-30 seconds for tasks</li>
              <li>Applies configuration changes locally</li>
              <li>Reloads HAProxy service as needed</li>
              <li>Reports status and metrics back to backend</li>
            </ul>
          </li>
          <li>
            <Text strong>Configuration Flow</Text>
            <ol type="a">
              <li>User creates/updates configuration via UI or API</li>
              <li>Changes stored in backend database</li>
              <li>Agent polls backend and retrieves pending tasks</li>
              <li>Agent applies changes to local haproxy.cfg</li>
              <li>Agent reloads HAProxy service</li>
              <li>Agent reports success/failure to backend</li>
            </ol>
          </li>
        </ol>

        <Alert
          message="Important"
          description="Changes are NOT pushed to agents. Agents actively pull tasks from the backend. This design ensures better security and reliability in distributed environments."
          type="warning"
          showIcon
          style={{ marginTop: 16 }}
        />
      </Card>
    </div>
  );
};

export default APIDocumentation;

