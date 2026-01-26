/**
 * ValidationErrorModal Component
 * 
 * Displays detailed HAProxy validation error information with:
 * - Parsed error summary
 * - Quick fix suggestions
 * - Manual troubleshooting guide (when parse fails)
 * - Raw error output
 * - Entity navigation
 */

import React from 'react';
import {
  Modal, Card, Space, Tag, Button, Alert, Divider,
  Typography, Descriptions, Steps, Collapse, message
} from 'antd';
import {
  ExclamationCircleOutlined, CodeOutlined, CopyOutlined,
  EditOutlined, CheckCircleOutlined, WarningOutlined,
  RightOutlined, QuestionCircleOutlined, BugOutlined
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';

const { Text, Paragraph, Title } = Typography;
const { Step } = Steps;
const { Panel } = Collapse;

// Error type display names
const ERROR_TYPE_LABELS = {
  unknown_backend: 'Unknown Backend',
  unknown_frontend: 'Unknown Frontend',
  duplicate_name: 'Duplicate Name',
  mode_mismatch: 'Mode Mismatch',
  invalid_keyword: 'Invalid Keyword',
  syntax_error: 'Syntax Error',
  missing_server: 'Missing Server',
  acl_error: 'ACL Error',
  bind_error: 'Bind/Port Error',
  unknown: 'Unknown Error'
};

const ValidationErrorModal = ({ 
  visible, 
  onClose, 
  validationError,
  validationErrorReportedAt,
  parsedError 
}) => {
  const navigate = useNavigate();

  // Copy raw error to clipboard
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    message.success('Error message copied to clipboard');
  };

  // Navigate to entity
  const navigateToEntity = () => {
    if (parsedError?.quick_fix_url) {
      navigate(parsedError.quick_fix_url);
      onClose();
    } else if (parsedError?.entity_type) {
      const path = parsedError.entity_type === 'frontend' ? '/frontends' : '/backends';
      navigate(path);
      onClose();
    }
  };

  // Determine confidence level for display
  const getConfidenceLevel = () => {
    const confidence = parsedError?.parse_confidence || 0;
    if (confidence >= 70) return { level: 'high', color: 'success', text: 'High Confidence' };
    if (confidence >= 30) return { level: 'medium', color: 'warning', text: 'Partial Match' };
    return { level: 'low', color: 'error', text: 'Could Not Parse' };
  };

  const confidenceInfo = getConfidenceLevel();
  const hasGoodParse = parsedError?.parse_success && parsedError?.parse_confidence >= 30;

  return (
    <Modal
      title={
        <Space>
          <ExclamationCircleOutlined style={{ color: '#ff4d4f' }} />
          <span>HAProxy Validation Error</span>
        </Space>
      }
      open={visible}
      onCancel={onClose}
      width={800}
      footer={[
        <Button key="close" onClick={onClose}>
          Close
        </Button>,
        parsedError?.entity_name && (
          <Button 
            key="navigate" 
            type="primary"
            icon={<EditOutlined />}
            onClick={navigateToEntity}
          >
            {parsedError?.quick_fix_available 
              ? `Fix: ${parsedError.entity_name}` 
              : `Go to ${parsedError.entity_type === 'frontend' ? 'Frontends' : 'Backends'}`
            }
          </Button>
        )
      ].filter(Boolean)}
    >
      {/* Status Badge */}
      <div style={{ marginBottom: 16, display: 'flex', alignItems: 'center', gap: 12 }}>
        <Tag color="error" style={{ fontSize: 14, padding: '4px 12px' }}>
          Configuration Rejected
        </Tag>
        <Tag color={confidenceInfo.color}>
          {confidenceInfo.text}
        </Tag>
        {validationErrorReportedAt && (
          <Text type="secondary" style={{ fontSize: 12 }}>
            Reported: {new Date(validationErrorReportedAt).toLocaleString()}
          </Text>
        )}
      </div>

      {/* Parsed Error Summary - Only shown if parse was successful enough */}
      {hasGoodParse && (
        <Card 
          size="small" 
          style={{ 
            marginBottom: 16, 
            background: 'linear-gradient(135deg, #fff2f0 0%, #ffebe6 100%)',
            border: '1px solid #ffccc7'
          }}
        >
          <Descriptions column={2} size="small">
            {parsedError?.line_number && (
              <Descriptions.Item label="Error Location">
                <Tag color="red">Line {parsedError.line_number}</Tag>
              </Descriptions.Item>
            )}
            {parsedError?.error_type && (
              <Descriptions.Item label="Error Type">
                <Text strong>{ERROR_TYPE_LABELS[parsedError.error_type] || parsedError.error_type}</Text>
              </Descriptions.Item>
            )}
            {parsedError?.entity_type && (
              <Descriptions.Item label="Entity Type">
                <Tag color="blue">{parsedError.entity_type}</Tag>
              </Descriptions.Item>
            )}
            {parsedError?.entity_name && (
              <Descriptions.Item label="Entity Name">
                <Text code>{parsedError.entity_name}</Text>
              </Descriptions.Item>
            )}
            {parsedError?.related_entity && (
              <Descriptions.Item label="Related Entity">
                <Text code>{parsedError.related_entity}</Text>
              </Descriptions.Item>
            )}
            {parsedError?.field_hint && (
              <Descriptions.Item label="Problem Field">
                <Text mark>{parsedError.field_hint}</Text>
              </Descriptions.Item>
            )}
          </Descriptions>
        </Card>
      )}

      {/* Quick Fix Suggestion */}
      {parsedError?.suggestion && parsedError?.suggestion_type !== 'none' && (
        <Card 
          title={
            <Space>
              <CheckCircleOutlined style={{ color: '#52c41a' }} />
              <span>Recommended Action</span>
            </Space>
          }
          size="small" 
          style={{ marginBottom: 16 }}
        >
          <Paragraph style={{ margin: 0 }}>
            {parsedError.suggestion}
          </Paragraph>
          {parsedError?.quick_fix_available && parsedError?.quick_fix_url && (
            <Button 
              type="primary" 
              icon={<EditOutlined />}
              style={{ marginTop: 12 }}
              onClick={navigateToEntity}
            >
              Edit {parsedError.entity_name} → {parsedError.field_hint || 'configuration'}
            </Button>
          )}
        </Card>
      )}

      {/* Manual Troubleshooting Guide - Shown when parse failed or low confidence */}
      {(!parsedError?.parse_success || parsedError?.parse_confidence < 30) && (
        <Card 
          title={
            <Space>
              <QuestionCircleOutlined style={{ color: '#faad14' }} />
              <span>Manual Troubleshooting</span>
            </Space>
          }
          size="small" 
          style={{ marginBottom: 16, background: '#fffbe6', border: '1px solid #ffe58f' }}
        >
          <Paragraph type="secondary" style={{ marginBottom: 16 }}>
            The error message could not be automatically analyzed. Follow these steps to identify and fix the issue:
          </Paragraph>
          <Steps direction="vertical" size="small" current={-1}>
            <Step 
              title="Find the Line Number" 
              description={
                <span>
                  Look for <Text code>:XX]</Text> pattern in the error (e.g., <Text code>:45]</Text> means line 45)
                </span>
              }
            />
            <Step 
              title="Check Failed Config" 
              description={
                <span>
                  On the agent server, run: <Text code>cat /tmp/haproxy-failed-*.cfg</Text>
                </span>
              }
            />
            <Step 
              title="Validate Manually" 
              description={
                <span>
                  Run: <Text code>haproxy -c -f /tmp/haproxy-failed-*.cfg</Text> for detailed output
                </span>
              }
            />
            <Step 
              title="Identify the Entity" 
              description="Determine if the error is in a frontend, backend, or server configuration"
            />
          </Steps>
          <Divider style={{ margin: '16px 0' }} />
          <Space wrap>
            <Button onClick={() => { navigate('/frontends'); onClose(); }}>
              Go to Frontends
            </Button>
            <Button onClick={() => { navigate('/backends'); onClose(); }}>
              Go to Backends
            </Button>
            <Button onClick={() => { navigate('/waf'); onClose(); }}>
              Go to WAF Rules
            </Button>
          </Space>
        </Card>
      )}

      {/* Raw Error Output - Always Shown */}
      <Card 
        title={
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Space>
              <CodeOutlined />
              <span>Raw HAProxy Output</span>
            </Space>
            <Button 
              size="small" 
              icon={<CopyOutlined />}
              onClick={() => copyToClipboard(validationError)}
            >
              Copy
            </Button>
          </div>
        }
        size="small"
        bodyStyle={{ padding: 0 }}
      >
        <pre style={{ 
          background: '#1f1f1f', 
          color: '#ff6b6b',
          padding: 16, 
          borderRadius: '0 0 8px 8px',
          margin: 0,
          overflow: 'auto',
          maxHeight: 250,
          fontSize: 12,
          lineHeight: 1.6,
          fontFamily: 'Monaco, Menlo, "Ubuntu Mono", monospace'
        }}>
          {validationError || 'No error message available'}
        </pre>
      </Card>

      {/* Help Tip */}
      <Alert
        type="info"
        showIcon
        icon={<BugOutlined />}
        message="Debug Tip"
        description={
          <span>
            If the error persists, check the agent logs on the HAProxy server. 
            Failed configurations are saved at <Text code>/tmp/haproxy-failed-*.cfg</Text> for inspection.
          </span>
        }
        style={{ marginTop: 16 }}
      />

      {/* Multiple Errors Warning */}
      {parsedError?.has_multiple_errors && (
        <Alert
          type="warning"
          showIcon
          message={`${parsedError.additional_errors_count} Additional Error(s)`}
          description="There are more errors in the configuration. Fix the first error and re-apply to see subsequent errors."
          style={{ marginTop: 16 }}
        />
      )}
    </Modal>
  );
};

export default ValidationErrorModal;
