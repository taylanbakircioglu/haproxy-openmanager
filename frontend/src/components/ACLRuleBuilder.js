import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Card, Row, Col, Input, Select, Button, Space, Tag, Tooltip,
  Typography, Divider, Empty, Alert
} from 'antd';
import {
  PlusOutlined, DeleteOutlined, CodeOutlined,
  FormOutlined, ArrowRightOutlined, FilterOutlined, LinkOutlined
} from '@ant-design/icons';

const { Text } = Typography;
const { Option } = Select;
const { TextArea } = Input;

// ═══════════════════════════════════════════════════════
// Match Type Definitions
// ═══════════════════════════════════════════════════════
const MATCH_TYPES = [
  { value: 'path_beg', label: 'Path begins with', category: 'Path', placeholder: '/api, /admin' },
  { value: 'path_end', label: 'Path ends with', category: 'Path', placeholder: '.css .js .png' },
  { value: 'path', label: 'Path equals', category: 'Path', placeholder: '/login' },
  { value: 'path_reg', label: 'Path matches regex', category: 'Path', placeholder: '^/api/v[0-9]+/' },
  { value: 'path_dir', label: 'Path contains dir', category: 'Path', placeholder: '/images' },
  { value: 'path_sub', label: 'Path contains', category: 'Path', placeholder: 'api' },
  { value: 'url_beg', label: 'URL begins with', category: 'URL', placeholder: '/search?q=' },
  { value: 'url_end', label: 'URL ends with', category: 'URL', placeholder: '.html' },
  { value: 'url_reg', label: 'URL matches regex', category: 'URL', placeholder: '^/api/.*' },
  { value: 'hdr(host)', label: 'Host header equals', category: 'Header', placeholder: 'example.com' },
  { value: 'hdr_beg(host)', label: 'Host begins with', category: 'Header', placeholder: 'api.' },
  { value: 'hdr_end(host)', label: 'Host ends with', category: 'Header', placeholder: '.example.com' },
  { value: 'hdr_reg(host)', label: 'Host matches regex', category: 'Header', placeholder: '^(www\\.)?example\\.com$' },
  { value: 'hdr(User-Agent)', label: 'User-Agent contains', category: 'Header', placeholder: 'Mozilla' },
  { value: 'hdr(Referer)', label: 'Referer header', category: 'Header', placeholder: 'https://google.com' },
  { value: 'hdr(X-Forwarded-For)', label: 'X-Forwarded-For', category: 'Header', placeholder: '10.0.0.0/8' },
  { value: 'src', label: 'Source IP', category: 'Network', placeholder: '192.168.1.0/24' },
  { value: 'src_port', label: 'Source port', category: 'Network', placeholder: '1024-65535' },
  { value: 'dst', label: 'Destination IP', category: 'Network', placeholder: '10.0.0.1' },
  { value: 'dst_port', label: 'Destination port', category: 'Network', placeholder: '443' },
  { value: 'method', label: 'HTTP Method', category: 'Method', placeholder: 'GET POST' },
  { value: 'ssl_fc', label: 'SSL connection', category: 'SSL', placeholder: '' },
  { value: 'ssl_fc_sni', label: 'SSL SNI', category: 'SSL', placeholder: 'example.com' },
  { value: 'req.hdr_cnt(host)', label: 'Host header count', category: 'Advanced', placeholder: '0' },
  { value: 'custom', label: 'Custom expression', category: 'Advanced', placeholder: 'nbsrv(backend_name) lt 1' },
];

const MATCH_TYPE_GROUPS = [
  { label: 'Path', options: MATCH_TYPES.filter(m => m.category === 'Path') },
  { label: 'URL', options: MATCH_TYPES.filter(m => m.category === 'URL') },
  { label: 'Header', options: MATCH_TYPES.filter(m => m.category === 'Header') },
  { label: 'Network', options: MATCH_TYPES.filter(m => m.category === 'Network') },
  { label: 'Method', options: MATCH_TYPES.filter(m => m.category === 'Method') },
  { label: 'SSL', options: MATCH_TYPES.filter(m => m.category === 'SSL') },
  { label: 'Advanced', options: MATCH_TYPES.filter(m => m.category === 'Advanced') },
];

const FLAGS = [
  { value: '-i', label: '-i  (case insensitive)' },
  { value: '-f', label: '-f  (from file)' },
  { value: '-m beg', label: '-m beg  (begins with)' },
  { value: '-m end', label: '-m end  (ends with)' },
  { value: '-m sub', label: '-m sub  (contains)' },
  { value: '-m reg', label: '-m reg  (regex)' },
  { value: '-m str', label: '-m str  (exact string)' },
  { value: '-m len', label: '-m len  (length)' },
  { value: '-m found', label: '-m found  (exists)' },
];

const FLAG_HINTS = {
  Path: '-i, -f ...',
  URL: '-i, -f ...',
  Header: '-i ...',
  Method: '-i ...',
  Network: '-f ...',
  SSL: 'Optional',
  Advanced: 'Optional',
};

const REDIRECT_TYPES = [
  { value: 'scheme', label: 'Scheme', description: 'Change protocol (HTTP→HTTPS)' },
  { value: 'prefix', label: 'Prefix', description: 'Change URL prefix' },
  { value: 'location', label: 'Location', description: 'Redirect to specific URL' },
];

const REDIRECT_CODES = [
  { value: '301', label: '301 - Permanent' },
  { value: '302', label: '302 - Temporary (default)' },
  { value: '303', label: '303 - See Other' },
  { value: '307', label: '307 - Temporary (preserve method)' },
  { value: '308', label: '308 - Permanent (preserve method)' },
];


// ═══════════════════════════════════════════════════════
// Parse / Serialize Helpers
// ═══════════════════════════════════════════════════════

/**
 * Parse a raw ACL rule string like "is_api path_beg -i /api"
 * into a structured object { name, matchType, flags, value }
 */
function parseAclRule(ruleStr) {
  if (!ruleStr || typeof ruleStr !== 'string') return null;
  let str = ruleStr.trim();
  // Remove leading "acl " if present
  if (str.toLowerCase().startsWith('acl ')) {
    str = str.substring(4).trim();
  }
  if (!str) return null;

  // Split into tokens
  const tokens = str.split(/\s+/);
  if (tokens.length < 2) {
    // Not enough tokens to be a structured rule
    return { raw: ruleStr.trim() };
  }

  const name = tokens[0];
  let matchType = tokens[1];
  let flags = [];
  let valueTokens = [];

  // Check if matchType is known
  const knownMatch = MATCH_TYPES.find(m => m.value === matchType);
  if (!knownMatch && matchType !== 'custom') {
    return { raw: ruleStr.trim() };
  }

  // Parse remaining tokens for flags and values
  let i = 2;
  while (i < tokens.length) {
    if (tokens[i] === '-i' || tokens[i] === '-f') {
      flags.push(tokens[i]);
      i++;
    } else if (tokens[i] === '-m' && i + 1 < tokens.length) {
      flags.push(`-m ${tokens[i + 1]}`);
      i += 2;
    } else {
      break;
    }
  }

  // Remaining tokens are the value
  valueTokens = tokens.slice(i);

  return {
    name,
    matchType,
    flags,
    value: valueTokens.join(' '),
  };
}

/**
 * Serialize a structured ACL rule object back to string
 */
function serializeAclRule(rule) {
  if (rule.raw !== undefined) return rule.raw;
  if (!rule.name || !rule.name.trim() || !rule.matchType) return '';
  const parts = [`${rule.name.trim()} ${rule.matchType}`];
  if (rule.flags && rule.flags.length > 0) {
    const sorted = [...rule.flags].sort((a, b) => {
      if (a === '-i') return -1;
      if (b === '-i') return 1;
      if (a === '-f') return 1;
      if (b === '-f') return -1;
      return 0;
    });
    parts.push(sorted.join(' '));
  }
  if (rule.value) {
    parts.push(rule.value);
  }
  return parts.join(' ');
}

/**
 * Parse use_backend rule string like "use_backend api_servers if is_api"
 */
function parseUseBackendRule(ruleStr) {
  if (!ruleStr || typeof ruleStr !== 'string') return null;
  let str = ruleStr.trim();
  if (str.toLowerCase().startsWith('use_backend ')) {
    str = str.substring(12).trim();
  }
  if (!str) return null;

  // Pattern: "backend_name if|unless condition(s)"
  const ifMatch = str.match(/^(\S+)\s+(if|unless)\s+(.+)$/i);
  if (ifMatch) {
    return {
      backend: ifMatch[1],
      operator: ifMatch[2].toLowerCase(),
      condition: ifMatch[3].trim(),
    };
  }
  // Fallback for raw/complex rules
  return { raw: ruleStr.trim() };
}

function serializeUseBackendRule(rule) {
  if (rule.raw !== undefined) return rule.raw;
  if (!rule.backend || !rule.backend.trim()) return '';
  const backend = rule.backend.trim();
  if (!rule.condition || !rule.condition.trim()) return backend;
  return `${backend} ${rule.operator || 'if'} ${rule.condition.trim()}`;
}

/**
 * Parse redirect rule string like "scheme https if !{ ssl_fc }"
 */
function parseRedirectRule(ruleStr) {
  if (!ruleStr || typeof ruleStr !== 'string') return null;
  let str = ruleStr.trim();
  if (str.toLowerCase().startsWith('redirect ')) {
    str = str.substring(9).trim();
  }
  if (!str) return null;

  // Pattern: "type target [code NNN] [if|unless condition]"
  const typeMatch = str.match(/^(scheme|prefix|location)\s+/i);
  if (!typeMatch) return { raw: ruleStr.trim() };

  const type = typeMatch[1].toLowerCase();
  let rest = str.substring(typeMatch[0].length).trim();

  // Extract code if present
  let code = '';
  const codeMatch = rest.match(/\bcode\s+(\d{3})\b/i);
  if (codeMatch) {
    code = codeMatch[1];
    rest = rest.replace(codeMatch[0], '').trim();
  }

  // Extract condition
  let condition = '';
  const condMatch = rest.match(/\s+(if|unless)\s+(.+)$/i);
  if (condMatch) {
    condition = `${condMatch[1]} ${condMatch[2]}`.trim();
    rest = rest.substring(0, rest.length - condMatch[0].length).trim();
  }

  return {
    type,
    target: rest,
    code,
    condition,
  };
}

function serializeRedirectRule(rule) {
  if (rule.raw !== undefined) return rule.raw;
  if (!rule.type || !rule.target || !rule.target.trim()) return '';
  let str = `${rule.type} ${rule.target.trim()}`;
  if (rule.code && rule.code !== '302') {
    str += ` code ${rule.code}`;
  }
  if (rule.condition) {
    str += ` ${rule.condition}`;
  }
  return str;
}

// ═══════════════════════════════════════════════════════
// Sub-components
// ═══════════════════════════════════════════════════════

const ruleCardStyle = {
  marginBottom: 8,
  borderRadius: 8,
  border: '1px solid #f0f0f0',
};

const deleteButtonStyle = {
  color: '#ff4d4f',
};

function ACLDefinitionCard({ rule, index, onChange, onDelete }) {
  const isRaw = rule.raw !== undefined;

  if (isRaw) {
    return (
      <Card size="small" style={ruleCardStyle}>
        <Row gutter={8} align="middle">
          <Col flex="auto">
            <Input
              value={rule.raw}
              onChange={(e) => onChange(index, { raw: e.target.value })}
              placeholder="Raw ACL rule (e.g. my_acl path_beg /api)"
              prefix={<Tag color="default" style={{ marginRight: 4 }}>RAW</Tag>}
            />
          </Col>
          <Col>
            <Tooltip title="Delete rule">
              <Button
                type="text"
                icon={<DeleteOutlined />}
                style={deleteButtonStyle}
                onClick={() => onDelete(index)}
                size="small"
              />
            </Tooltip>
          </Col>
        </Row>
      </Card>
    );
  }

  const matchDef = MATCH_TYPES.find(m => m.value === rule.matchType);

  return (
    <Card size="small" style={ruleCardStyle}>
      <Row gutter={8} align="middle" wrap={false}>
        <Col flex="140px">
          <Input
            value={rule.name}
            onChange={(e) => onChange(index, { ...rule, name: e.target.value.replace(/[^a-zA-Z0-9_-]/g, '') })}
            placeholder="acl_name"
            size="small"
            addonBefore={<FilterOutlined style={{ fontSize: 11 }} />}
          />
        </Col>
        <Col flex="160px">
          <Select
            value={rule.matchType}
            onChange={(val) => onChange(index, { ...rule, matchType: val })}
            placeholder="Match type"
            size="small"
            style={{ width: '100%' }}
            showSearch
            optionFilterProp="label"
            popupMatchSelectWidth={false}
          >
            {MATCH_TYPE_GROUPS.map(group => (
              <Select.OptGroup key={group.label} label={group.label}>
                {group.options.map(opt => (
                  <Option key={opt.value} value={opt.value} label={`${opt.label} (${opt.value})`}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                      <span>{opt.label}</span>
                      <Text type="secondary" style={{ fontSize: 11 }}>{opt.value}</Text>
                    </div>
                  </Option>
                ))}
              </Select.OptGroup>
            ))}
          </Select>
        </Col>
        <Col flex="100px">
          <Select
            mode="multiple"
            value={rule.flags || []}
            onChange={(val) => {
              const mFlags = val.filter(f => f.startsWith('-m'));
              if (mFlags.length > 1) {
                const otherFlags = val.filter(f => !f.startsWith('-m'));
                onChange(index, { ...rule, flags: [...otherFlags, mFlags[mFlags.length - 1]] });
              } else {
                onChange(index, { ...rule, flags: val });
              }
            }}
            placeholder={FLAG_HINTS[matchDef?.category] || 'Flags'}
            size="small"
            style={{ width: '100%' }}
            maxTagCount={2}
            maxTagTextLength={8}
            popupMatchSelectWidth={false}
            allowClear
          >
            {FLAGS.map(f => (
              <Option key={f.value} value={f.value}>{f.label}</Option>
            ))}
          </Select>
        </Col>
        <Col flex="auto">
          {(() => {
            const hasFileFlag = (rule.flags || []).includes('-f');
            const badFilePath = hasFileFlag && rule.value && !rule.value.startsWith('/');
            if (rule.matchType === 'ssl_fc') {
              return <Text type="secondary" style={{ fontSize: 12 }}>(no value needed)</Text>;
            }
            if (rule.matchType === 'custom') {
              return (
                <Input
                  value={rule.value}
                  onChange={(e) => onChange(index, { ...rule, value: e.target.value })}
                  placeholder="Custom expression..."
                  size="small"
                />
              );
            }
            return (
              <Tooltip title={badFilePath ? 'Flag -f requires an absolute file path (e.g. /etc/haproxy/patterns.txt)' : ''} open={badFilePath ? undefined : false}>
                <Input
                  value={rule.value}
                  onChange={(e) => onChange(index, { ...rule, value: e.target.value })}
                  placeholder={hasFileFlag ? '/path/to/patterns.txt' : (matchDef?.placeholder || 'Value')}
                  size="small"
                  status={badFilePath ? 'error' : undefined}
                />
              </Tooltip>
            );
          })()}
        </Col>
        <Col flex="none">
          <Tooltip title="Delete rule">
            <Button
              type="text"
              icon={<DeleteOutlined />}
              style={deleteButtonStyle}
              onClick={() => onDelete(index)}
              size="small"
            />
          </Tooltip>
        </Col>
      </Row>
    </Card>
  );
}

function BackendRoutingCard({ rule, index, onChange, onDelete, backends, aclNames }) {
  const isRaw = rule.raw !== undefined;

  if (isRaw) {
    return (
      <Card size="small" style={ruleCardStyle}>
        <Row gutter={8} align="middle">
          <Col flex="auto">
            <Input
              value={rule.raw}
              onChange={(e) => onChange(index, { raw: e.target.value })}
              placeholder="Raw rule (e.g. use_backend api_servers if is_api)"
              prefix={<Tag color="default" style={{ marginRight: 4 }}>RAW</Tag>}
            />
          </Col>
          <Col>
            <Tooltip title="Delete rule">
              <Button type="text" icon={<DeleteOutlined />} style={deleteButtonStyle} onClick={() => onDelete(index)} size="small" />
            </Tooltip>
          </Col>
        </Row>
      </Card>
    );
  }

  return (
    <Card size="small" style={ruleCardStyle}>
      <Row gutter={8} align="middle" wrap={false}>
        <Col flex="180px">
          <Select
            value={rule.backend}
            onChange={(val) => onChange(index, { ...rule, backend: val })}
            placeholder="Select backend"
            size="small"
            style={{ width: '100%' }}
            showSearch
            optionFilterProp="children"
          >
            {backends.map(b => (
              <Option key={b.name || b} value={b.name || b}>{b.name || b}</Option>
            ))}
          </Select>
        </Col>
        <Col flex="80px">
          <Select
            value={rule.operator || 'if'}
            onChange={(val) => onChange(index, { ...rule, operator: val })}
            size="small"
            style={{ width: '100%' }}
          >
            <Option value="if">if</Option>
            <Option value="unless">unless</Option>
          </Select>
        </Col>
        <Col flex="auto">
          {aclNames.length > 0 ? (
            <Select
              mode="tags"
              value={rule.condition ? rule.condition.split(/\s+/).filter(t => t && t !== 'if' && t !== 'unless') : []}
              onChange={(vals) => onChange(index, { ...rule, condition: vals.join(' ') })}
              placeholder="Select ACL conditions or type custom"
              size="small"
              style={{ width: '100%' }}
              tokenSeparators={[' ']}
            >
              {aclNames.map(name => (
                <Option key={name} value={name}>{name}</Option>
              ))}
              {aclNames.map(name => (
                <Option key={`!${name}`} value={`!${name}`}>!{name} (negated)</Option>
              ))}
            </Select>
          ) : (
            <Input
              value={rule.condition}
              onChange={(e) => onChange(index, { ...rule, condition: e.target.value })}
              placeholder="ACL condition (e.g. is_api)"
              size="small"
            />
          )}
        </Col>
        <Col flex="none">
          <Tooltip title="Delete rule">
            <Button type="text" icon={<DeleteOutlined />} style={deleteButtonStyle} onClick={() => onDelete(index)} size="small" />
          </Tooltip>
        </Col>
      </Row>
    </Card>
  );
}

function RedirectRuleCard({ rule, index, onChange, onDelete }) {
  const isRaw = rule.raw !== undefined;

  if (isRaw) {
    return (
      <Card size="small" style={ruleCardStyle}>
        <Row gutter={8} align="middle">
          <Col flex="auto">
            <Input
              value={rule.raw}
              onChange={(e) => onChange(index, { raw: e.target.value })}
              placeholder="Raw redirect rule (e.g. scheme https if !{ ssl_fc })"
              prefix={<Tag color="default" style={{ marginRight: 4 }}>RAW</Tag>}
            />
          </Col>
          <Col>
            <Tooltip title="Delete rule">
              <Button type="text" icon={<DeleteOutlined />} style={deleteButtonStyle} onClick={() => onDelete(index)} size="small" />
            </Tooltip>
          </Col>
        </Row>
      </Card>
    );
  }

  return (
    <Card size="small" style={ruleCardStyle}>
      <Row gutter={8} align="middle" wrap={false}>
        <Col flex="100px">
          <Select
            value={rule.type}
            onChange={(val) => onChange(index, { ...rule, type: val })}
            placeholder="Type"
            size="small"
            style={{ width: '100%' }}
          >
            {REDIRECT_TYPES.map(t => (
              <Option key={t.value} value={t.value}>
                <Tooltip title={t.description}>{t.label}</Tooltip>
              </Option>
            ))}
          </Select>
        </Col>
        <Col flex="auto">
          {rule.type === 'scheme' ? (
            <Select
              value={rule.target === 'http' || rule.target === 'https' ? rule.target : undefined}
              onChange={(val) => onChange(index, { ...rule, target: val })}
              placeholder="Select scheme"
              size="small"
              style={{ width: '100%' }}
            >
              <Option value="https">https</Option>
              <Option value="http">http</Option>
            </Select>
          ) : (
            <Input
              value={rule.target}
              onChange={(e) => onChange(index, { ...rule, target: e.target.value })}
              placeholder="https://example.com"
              size="small"
            />
          )}
        </Col>
        <Col flex="120px">
          <Select
            value={rule.code || undefined}
            onChange={(val) => onChange(index, { ...rule, code: val })}
            placeholder="Code"
            size="small"
            style={{ width: '100%' }}
            allowClear
            popupMatchSelectWidth={false}
          >
            {REDIRECT_CODES.map(c => (
              <Option key={c.value} value={c.value}>{c.label}</Option>
            ))}
          </Select>
        </Col>
        <Col flex="150px">
          <Input
            value={rule.condition}
            onChange={(e) => onChange(index, { ...rule, condition: e.target.value })}
            placeholder="if !{ ssl_fc }"
            size="small"
          />
        </Col>
        <Col flex="none">
          <Tooltip title="Delete rule">
            <Button type="text" icon={<DeleteOutlined />} style={deleteButtonStyle} onClick={() => onDelete(index)} size="small" />
          </Tooltip>
        </Col>
      </Row>
    </Card>
  );
}


// ═══════════════════════════════════════════════════════
// Main ACLRuleBuilder Component
// ═══════════════════════════════════════════════════════

/**
 * Props:
 *   aclRules: string[] (array of ACL rule strings from backend)
 *   useBackendRules: string[] (array of use_backend rule strings)
 *   redirectRules: string[] (array of redirect rule strings)
 *   backends: { name: string }[] (available backends)
 *   onChange({ aclRules, useBackendRules, redirectRules }) 
 */
export default function ACLRuleBuilder({ aclRules = [], useBackendRules = [], redirectRules = [], backends = [], onChange }) {
  // ─── State ──────────────────────────────────────
  const [aclDefs, setAclDefs] = useState([]);
  const [routingRules, setRoutingRules] = useState([]);
  const [redirRules, setRedirRules] = useState([]);

  const [rawModeAcl, setRawModeAcl] = useState(false);
  const [rawModeRouting, setRawModeRouting] = useState(false);
  const [rawModeRedirect, setRawModeRedirect] = useState(false);

  const [rawTextAcl, setRawTextAcl] = useState('');
  const [rawTextRouting, setRawTextRouting] = useState('');
  const [rawTextRedirect, setRawTextRedirect] = useState('');

  // ─── Initialize from props ─────────────────────
  useEffect(() => {
    const parsedAcls = (Array.isArray(aclRules) ? aclRules : [])
      .map(r => parseAclRule(r))
      .filter(Boolean);
    setAclDefs(parsedAcls);
    setRawTextAcl((Array.isArray(aclRules) ? aclRules : []).join('\n'));

    const parsedRouting = (Array.isArray(useBackendRules) ? useBackendRules : [])
      .map(r => parseUseBackendRule(r))
      .filter(Boolean);
    setRoutingRules(parsedRouting);
    setRawTextRouting((Array.isArray(useBackendRules) ? useBackendRules : []).join('\n'));

    const parsedRedirects = (Array.isArray(redirectRules) ? redirectRules : [])
      .map(r => parseRedirectRule(r))
      .filter(Boolean);
    setRedirRules(parsedRedirects);
    setRawTextRedirect((Array.isArray(redirectRules) ? redirectRules : []).join('\n'));
  }, []); // Only on mount — parent should remount on frontend change

  // ─── Derived: collected ACL names ──────────────
  const aclNames = useMemo(() => {
    return aclDefs
      .filter(d => d.name && d.raw === undefined)
      .map(d => d.name);
  }, [aclDefs]);

  // ─── Emit changes ─────────────────────────────
  const emitChange = useCallback((newAcls, newRouting, newRedirects) => {
    if (!onChange) return;
    const serializedAcl = newAcls.map(serializeAclRule).filter(Boolean);
    const serializedRouting = newRouting.map(serializeUseBackendRule).filter(Boolean);
    const serializedRedirects = newRedirects.map(serializeRedirectRule).filter(Boolean);
    onChange({
      aclRules: serializedAcl,
      useBackendRules: serializedRouting,
      redirectRules: serializedRedirects,
    });
  }, [onChange]);

  // ─── ACL Definitions Handlers ──────────────────
  const handleAclChange = useCallback((idx, newRule) => {
    const updated = [...aclDefs];
    updated[idx] = newRule;
    setAclDefs(updated);
    setRawTextAcl(updated.map(serializeAclRule).filter(Boolean).join('\n'));
    emitChange(updated, routingRules, redirRules);
  }, [aclDefs, routingRules, redirRules, emitChange]);

  const handleAclDelete = useCallback((idx) => {
    const updated = aclDefs.filter((_, i) => i !== idx);
    setAclDefs(updated);
    setRawTextAcl(updated.map(serializeAclRule).filter(Boolean).join('\n'));
    emitChange(updated, routingRules, redirRules);
  }, [aclDefs, routingRules, redirRules, emitChange]);

  const handleAclAdd = useCallback(() => {
    const newRule = { name: '', matchType: 'path_beg', flags: ['-i'], value: '' };
    const updated = [...aclDefs, newRule];
    setAclDefs(updated);
    emitChange(updated, routingRules, redirRules);
  }, [aclDefs, routingRules, redirRules, emitChange]);

  // ─── Backend Routing Handlers ──────────────────
  const handleRoutingChange = useCallback((idx, newRule) => {
    const updated = [...routingRules];
    updated[idx] = newRule;
    setRoutingRules(updated);
    setRawTextRouting(updated.map(serializeUseBackendRule).filter(Boolean).join('\n'));
    emitChange(aclDefs, updated, redirRules);
  }, [aclDefs, routingRules, redirRules, emitChange]);

  const handleRoutingDelete = useCallback((idx) => {
    const updated = routingRules.filter((_, i) => i !== idx);
    setRoutingRules(updated);
    setRawTextRouting(updated.map(serializeUseBackendRule).filter(Boolean).join('\n'));
    emitChange(aclDefs, updated, redirRules);
  }, [aclDefs, routingRules, redirRules, emitChange]);

  const handleRoutingAdd = useCallback(() => {
    const newRule = { backend: '', operator: 'if', condition: '' };
    const updated = [...routingRules, newRule];
    setRoutingRules(updated);
    emitChange(aclDefs, updated, redirRules);
  }, [aclDefs, routingRules, redirRules, emitChange]);

  // ─── Redirect Handlers ────────────────────────
  const handleRedirectChange = useCallback((idx, newRule) => {
    const updated = [...redirRules];
    updated[idx] = newRule;
    setRedirRules(updated);
    setRawTextRedirect(updated.map(serializeRedirectRule).filter(Boolean).join('\n'));
    emitChange(aclDefs, routingRules, updated);
  }, [aclDefs, routingRules, redirRules, emitChange]);

  const handleRedirectDelete = useCallback((idx) => {
    const updated = redirRules.filter((_, i) => i !== idx);
    setRedirRules(updated);
    setRawTextRedirect(updated.map(serializeRedirectRule).filter(Boolean).join('\n'));
    emitChange(aclDefs, routingRules, updated);
  }, [aclDefs, routingRules, redirRules, emitChange]);

  const handleRedirectAdd = useCallback(() => {
    const newRule = { type: 'scheme', target: 'https', code: '', condition: 'if !{ ssl_fc }' };
    const updated = [...redirRules, newRule];
    setRedirRules(updated);
    emitChange(aclDefs, routingRules, updated);
  }, [aclDefs, routingRules, redirRules, emitChange]);

  // ─── Raw Mode Toggle Handlers ─────────────────
  const toggleRawModeAcl = useCallback(() => {
    if (rawModeAcl) {
      const lines = rawTextAcl.split('\n').filter(l => l.trim());
      const parsed = lines.map(l => parseAclRule(l)).filter(Boolean);
      setAclDefs(parsed);
      emitChange(parsed, routingRules, redirRules);
    } else {
      setRawTextAcl(aclDefs.map(serializeAclRule).filter(Boolean).join('\n'));
    }
    setRawModeAcl(!rawModeAcl);
  }, [rawModeAcl, rawTextAcl, aclDefs, routingRules, redirRules, emitChange]);

  const toggleRawModeRouting = useCallback(() => {
    if (rawModeRouting) {
      const lines = rawTextRouting.split('\n').filter(l => l.trim());
      const parsed = lines.map(l => parseUseBackendRule(l)).filter(Boolean);
      setRoutingRules(parsed);
      emitChange(aclDefs, parsed, redirRules);
    } else {
      setRawTextRouting(routingRules.map(serializeUseBackendRule).filter(Boolean).join('\n'));
    }
    setRawModeRouting(!rawModeRouting);
  }, [rawModeRouting, rawTextRouting, aclDefs, routingRules, redirRules, emitChange]);

  const toggleRawModeRedirect = useCallback(() => {
    if (rawModeRedirect) {
      const lines = rawTextRedirect.split('\n').filter(l => l.trim());
      const parsed = lines.map(l => parseRedirectRule(l)).filter(Boolean);
      setRedirRules(parsed);
      emitChange(aclDefs, routingRules, parsed);
    } else {
      setRawTextRedirect(redirRules.map(serializeRedirectRule).filter(Boolean).join('\n'));
    }
    setRawModeRedirect(!rawModeRedirect);
  }, [rawModeRedirect, rawTextRedirect, aclDefs, routingRules, redirRules, emitChange]);

  // Raw text change handlers — emit on change
  const handleRawAclChange = useCallback((text) => {
    setRawTextAcl(text);
    const lines = text.split('\n').filter(l => l.trim());
    const serialized = lines.map(l => {
      let s = l.trim();
      if (s.toLowerCase().startsWith('acl ')) s = s.substring(4).trim();
      return s;
    }).filter(Boolean);
    if (onChange) {
      onChange({
        aclRules: serialized,
        useBackendRules: routingRules.map(serializeUseBackendRule).filter(Boolean),
        redirectRules: redirRules.map(serializeRedirectRule).filter(Boolean),
      });
    }
  }, [onChange, routingRules, redirRules]);

  const handleRawRoutingChange = useCallback((text) => {
    setRawTextRouting(text);
    const lines = text.split('\n').filter(l => l.trim());
    const serialized = lines.map(l => {
      let s = l.trim();
      if (s.toLowerCase().startsWith('use_backend ')) s = s.substring(12).trim();
      return s;
    }).filter(Boolean);
    if (onChange) {
      onChange({
        aclRules: aclDefs.map(serializeAclRule).filter(Boolean),
        useBackendRules: serialized,
        redirectRules: redirRules.map(serializeRedirectRule).filter(Boolean),
      });
    }
  }, [onChange, aclDefs, redirRules]);

  const handleRawRedirectChange = useCallback((text) => {
    setRawTextRedirect(text);
    const lines = text.split('\n').filter(l => l.trim());
    const serialized = lines.map(l => {
      let s = l.trim();
      if (s.toLowerCase().startsWith('redirect ')) s = s.substring(9).trim();
      return s;
    }).filter(Boolean);
    if (onChange) {
      onChange({
        aclRules: aclDefs.map(serializeAclRule).filter(Boolean),
        useBackendRules: routingRules.map(serializeUseBackendRule).filter(Boolean),
        redirectRules: serialized,
      });
    }
  }, [onChange, aclDefs, routingRules]);

  // ─── Section Header with Raw Toggle ─────────────
  const SectionHeader = ({ title, icon, color, count, rawMode, onToggle }) => (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
      <Space>
        {icon}
        <Text strong style={{ fontSize: 14 }}>{title}</Text>
        {count > 0 && <Tag color={color}>{count} rule{count !== 1 ? 's' : ''}</Tag>}
      </Space>
      <Tooltip title={rawMode ? 'Switch to Visual Builder' : 'Switch to Raw Editor'}>
        <Button
          type="text"
          size="small"
          icon={rawMode ? <FormOutlined /> : <CodeOutlined />}
          onClick={onToggle}
        >
          {rawMode ? 'Visual' : 'Raw'}
        </Button>
      </Tooltip>
    </div>
  );

  // ═══════════════════════════════════════════════════
  // Render
  // ═══════════════════════════════════════════════════
  return (
    <div>
      {/* ─── ACL Definitions ─────────────────── */}
      <div style={{ marginBottom: 20 }}>
        <SectionHeader
          title="ACL Definitions"
          icon={<FilterOutlined style={{ color: '#1890ff' }} />}
          color="blue"
          count={rawModeAcl ? rawTextAcl.split('\n').filter(l => l.trim()).length : aclDefs.length}
          rawMode={rawModeAcl}
          onToggle={toggleRawModeAcl}
        />
        <Text type="secondary" style={{ display: 'block', marginBottom: 8, fontSize: 12 }}>
          Define named conditions to match incoming requests by path, header, source IP, and more.
        </Text>

        {rawModeAcl ? (
          <TextArea
            value={rawTextAcl}
            onChange={(e) => handleRawAclChange(e.target.value)}
            rows={6}
            placeholder={`One rule per line. Format: acl_name match_type [flags] value\n\nExamples:\nacl is_api path_beg /api\nacl is_static path_end .css .js .png .jpg\nacl is_admin src 192.168.1.0/24\nacl host_example hdr(host) -i example.com`}
            style={{ fontFamily: 'monospace', fontSize: 13 }}
          />
        ) : (
          <>
            {aclDefs.length === 0 ? (
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description="No ACL rules defined"
                style={{ margin: '12px 0' }}
              />
            ) : (
              aclDefs.map((rule, idx) => (
                <ACLDefinitionCard
                  key={idx}
                  rule={rule}
                  index={idx}
                  onChange={handleAclChange}
                  onDelete={handleAclDelete}
                />
              ))
            )}
            <Button
              type="dashed"
              onClick={handleAclAdd}
              block
              icon={<PlusOutlined />}
              style={{ marginTop: 4 }}
            >
              Add ACL Rule
            </Button>
          </>
        )}
      </div>

      <Divider style={{ margin: '12px 0' }} />

      {/* ─── Backend Routing ─────────────────── */}
      <div style={{ marginBottom: 20 }}>
        <SectionHeader
          title="Backend Routing Rules"
          icon={<ArrowRightOutlined style={{ color: '#52c41a' }} />}
          color="green"
          count={rawModeRouting ? rawTextRouting.split('\n').filter(l => l.trim()).length : routingRules.length}
          rawMode={rawModeRouting}
          onToggle={toggleRawModeRouting}
        />
        <Text type="secondary" style={{ display: 'block', marginBottom: 8, fontSize: 12 }}>
          Route requests to specific backends based on ACL conditions defined above.
        </Text>

        {rawModeRouting ? (
          <TextArea
            value={rawTextRouting}
            onChange={(e) => handleRawRoutingChange(e.target.value)}
            rows={4}
            placeholder={`One rule per line. Format: backend_name if|unless condition\n\nExamples:\nuse_backend api_servers if is_api\nuse_backend static_servers if is_static`}
            style={{ fontFamily: 'monospace', fontSize: 13 }}
          />
        ) : (
          <>
            {routingRules.length === 0 ? (
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description="No routing rules defined"
                style={{ margin: '12px 0' }}
              />
            ) : (
              routingRules.map((rule, idx) => (
                <BackendRoutingCard
                  key={idx}
                  rule={rule}
                  index={idx}
                  onChange={handleRoutingChange}
                  onDelete={handleRoutingDelete}
                  backends={backends}
                  aclNames={aclNames}
                />
              ))
            )}
            <Button
              type="dashed"
              onClick={handleRoutingAdd}
              block
              icon={<PlusOutlined />}
              style={{ marginTop: 4 }}
            >
              Add Routing Rule
            </Button>
          </>
        )}
      </div>

      <Divider style={{ margin: '12px 0' }} />

      {/* ─── Redirect Rules ─────────────────── */}
      <div>
        <SectionHeader
          title="HTTP Redirect Rules"
          icon={<LinkOutlined style={{ color: '#fa8c16' }} />}
          color="orange"
          count={rawModeRedirect ? rawTextRedirect.split('\n').filter(l => l.trim()).length : redirRules.length}
          rawMode={rawModeRedirect}
          onToggle={toggleRawModeRedirect}
        />
        <Text type="secondary" style={{ display: 'block', marginBottom: 8, fontSize: 12 }}>
          Define HTTP redirect rules (HTTP to HTTPS, domain redirects, etc.). Applied before backend routing.
        </Text>

        {rawModeRedirect ? (
          <TextArea
            value={rawTextRedirect}
            onChange={(e) => handleRawRedirectChange(e.target.value)}
            rows={4}
            placeholder={`One rule per line. Format: type target [code NNN] [if condition]\n\nExamples:\nredirect scheme https if !{ ssl_fc }\nredirect prefix https://www.example.com code 301 if { hdr(host) -i example.com }\nredirect location https://newsite.com code 302`}
            style={{ fontFamily: 'monospace', fontSize: 13 }}
          />
        ) : (
          <>
            {redirRules.length === 0 ? (
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description="No redirect rules defined"
                style={{ margin: '12px 0' }}
              />
            ) : (
              redirRules.map((rule, idx) => (
                <RedirectRuleCard
                  key={idx}
                  rule={rule}
                  index={idx}
                  onChange={handleRedirectChange}
                  onDelete={handleRedirectDelete}
                />
              ))
            )}
            <Button
              type="dashed"
              onClick={handleRedirectAdd}
              block
              icon={<PlusOutlined />}
              style={{ marginTop: 4 }}
            >
              Add Redirect Rule
            </Button>
          </>
        )}
      </div>

      {/* ─── Summary Preview ──────────────────── */}
      {(aclDefs.length > 0 || routingRules.length > 0 || redirRules.length > 0) && (
        <>
          <Divider style={{ margin: '16px 0 8px' }} />
          <Alert
            type="info"
            showIcon
            message="Generated HAProxy Configuration Preview"
            description={
              <pre style={{ margin: 0, fontSize: 12, fontFamily: 'monospace', whiteSpace: 'pre-wrap', maxHeight: 200, overflow: 'auto' }}>
                {[
                  ...aclDefs.map(r => serializeAclRule(r)).filter(Boolean).map(s => `    acl ${s}`),
                  ...(aclDefs.some(r => serializeAclRule(r)) && (routingRules.length > 0 || redirRules.length > 0) ? [''] : []),
                  ...redirRules.map(r => serializeRedirectRule(r)).filter(Boolean).map(s => `    redirect ${s}`),
                  ...routingRules.map(r => serializeUseBackendRule(r)).filter(Boolean).map(s => `    use_backend ${s}`),
                ].join('\n')}
              </pre>
            }
          />
        </>
      )}
    </div>
  );
}
