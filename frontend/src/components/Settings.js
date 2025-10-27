import React, { useEffect } from 'react';
import { Card, Form, Switch, Button, InputNumber, message } from 'antd';

const Settings = () => {
  const [form] = Form.useForm();

  const onFinish = (values) => {
    console.log('Settings:', values);
    
    // Save settings to localStorage
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

  // Load saved settings on component mount  
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

  return (
    <div>
      <Card title="General Settings">
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
          <Form.Item
            name="autoRefresh"
            label="Auto Refresh Dashboard"
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>

          <Form.Item
            name="refreshInterval"
            label="Refresh Interval (seconds)"
          >
            <InputNumber min={1} max={60} />
          </Form.Item>

          <Form.Item
            name="notifications"
            label="Enable Notifications"
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>



          <Form.Item>
            <Button type="primary" htmlType="submit">
              Save Settings
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  );
};

export { Settings };