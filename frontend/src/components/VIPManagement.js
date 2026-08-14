import React, { useState, useEffect, useCallback } from 'react';
import {
  Table, Button, Space, Modal, Form, Input, InputNumber, Select, Tag, message,
  Switch, Typography, Card, Alert, Tooltip, Spin, Checkbox
} from 'antd';
import {
  PlusOutlined, EditOutlined, DeleteOutlined, ReloadOutlined, WarningOutlined,
  PlayCircleOutlined, SyncOutlined, CrownOutlined, ClockCircleOutlined, FileSearchOutlined,
  InfoCircleOutlined
} from '@ant-design/icons';
import { useCluster } from '../contexts/ClusterContext';
import { extractApiError } from '../utils/apiError';

const { Option } = Select;
const { Title, Text } = Typography;

// Interfaces that are never sensible VIP carriers — hidden from the dropdown.
const IFACE_HIDE = /^(lo|docker|veth|br-|cni|flannel|kube|virbr)/i;

const authHeaders = () => ({
  'Content-Type': 'application/json',
  'Authorization': `Bearer ${localStorage.getItem('authToken') || ''}`,
});

// Convergence-aware status (issue #27 follow-up): like other entities, a VIP only reads
// "live" once its member agents have actually deployed & acked — never the instant Apply
// is clicked. Backend returns deploy_status; we fall back to last_config_status.
const DEPLOY_STATUS = {
  PENDING:   { color: 'orange',     label: 'PENDING',  tip: 'Staged change — review and Apply (or Reject) it from the Apply Management page.' },
  PENDING_DELETE: { color: 'volcano', label: 'PENDING DELETE', tip: 'Deletion staged for approval — the VIP keeps running untouched until you APPROVE it in Apply Management. Reject to keep it. The node is not changed until approval.' },
  DELETING:  { color: 'processing', label: 'DELETING', tip: 'Deletion approved — member node(s) are stopping keepalived and releasing the VIP. Disappears once every node has torn down.' },
  DELETED:   { color: 'default',    label: 'DELETED',  tip: 'All member nodes have torn keepalived down.' },
  SYNCING:   { color: 'processing', label: 'SYNCING',  tip: 'Applied — an online member node is installing/configuring keepalived and will acknowledge on its next poll (~2–3 min).' },
  AWAITING:  { color: 'gold',       label: 'AWAITING AGENT', tip: 'Applied, but the member node(s) that still need it are OFFLINE, so nothing can deploy yet. Bring the node\'s agent online — it converges on its next poll. (Not a hang.)' },
  ACTIVE:    { color: 'green',      label: 'ACTIVE',   tip: 'Applied and every member node has deployed keepalived and acknowledged the current config.' },
  ERROR:     { color: 'red',        label: 'ERROR',    tip: 'A member node failed to deploy keepalived — see Members / Live state for the node, then check that agent.' },
  ATTENTION: { color: 'gold',       label: 'ATTENTION',tip: 'A member already runs a hand-managed keepalived; the agent left it untouched (externally managed). Resolve it on that node or remove it from the VIP.' },
  APPLIED:   { color: 'green',      label: 'APPLIED',  tip: 'Applied.' },
};

// agents.capabilities / network_interfaces come from the API as JSONB → a JSON string
// (asyncpg has no jsonb codec). Mirror AgentManagement.js and JSON.parse when needed.
const parseArr = (v) => {
  if (Array.isArray(v)) return v;
  if (typeof v === 'string') { try { const p = JSON.parse(v); return Array.isArray(p) ? p : []; } catch { return []; } }
  return [];
};

// v1.10.4 — adoption blockers come back as prose from the parser. Two classes are resolvable by
// the operator and the rest are not, so the modal has to tell them apart:
//   * `loss`   — "our renderer cannot reproduce this, so adopting would delete it". A deliberate
//                choice, waivable with an explicit tick.
//   * `prefix` — the address has no explicit prefix length. Supplying it resolves the blocker;
//                we never guess a netmask for a live VIP.
//   * `hard`   — an unknown VRID, a fractional advert_int, an unsupported auth_type. Not losses
//                but impossibilities; nothing in the UI may override them.
const splitBlockers = (blockers) => {
  const list = blockers || [];
  return {
    loss: list.filter((b) => b.includes('would delete it')),
    prefix: list.filter((b) => b.includes('no explicit prefix length')),
    hard: list.filter((b) => !b.includes('would delete it') && !b.includes('no explicit prefix length')),
  };
};

// v1.10.10 — every node of an instance reports the SAME problems about the SAME shared config,
// so merging their blocker lists repeats each one per member. The line numbers differ between
// the files, so exact-string dedup does not collapse them; key on the text WITHOUT the leading
// "line N:" and keep the first occurrence. Four issues on a pair used to read as eight.
const mergeBlockers = (lists) => {
  const seen = new Map();
  lists.flat().forEach((b) => {
    const key = String(b).replace(/^line \d+:\s*/, '');
    if (!seen.has(key)) seen.set(key, b);
  });
  return Array.from(seen.values());
};

// This component uses raw fetch(), but extractApiError expects an axios-shaped error
// (err.response.data). Read the fetch Response body and reuse the envelope-aware extractor
// so backend messages — e.g. the 409 "node already in VIP X" — actually reach the user.
const fetchApiError = async (res, fallback) => {
  try { const data = await res.json(); return extractApiError({ response: { data } }, fallback); }
  catch { return fallback; }
};

const VIPManagement = () => {
  const { clusters, selectedCluster } = useCluster();
  const [vips, setVips] = useState([]);
  const [loading, setLoading] = useState(false);
  const [modalVisible, setModalVisible] = useState(false);
  const [editing, setEditing] = useState(null);
  const [selectedPoolId, setSelectedPoolId] = useState(null);
  // One row per agent in the selected pool — the user toggles which participate.
  const [memberRows, setMemberRows] = useState([]);
  const [form] = Form.useForm();
  // Delete confirmation (with opt-in package uninstall) + diagnostics modal state.
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [showL2Note, setShowL2Note] = useState(false);
  // v1.10.4 — VIP adoption from what the agents found on their nodes.
  const [discoveries, setDiscoveries] = useState([]);
  const [adoptTarget, setAdoptTarget] = useState(null);   // { discovery, candidate }
  const [adoptAcceptLoss, setAdoptAcceptLoss] = useState(false);
  const [adopting, setAdopting] = useState(false);
  const [adoptForm] = Form.useForm();
  const [diagVip, setDiagVip] = useState(null);
  const [diagData, setDiagData] = useState(null);
  const [diagLoading, setDiagLoading] = useState(false);

  // Distinct pools derived from the cluster list (cluster -> pool_id).
  const pools = React.useMemo(() => {
    const seen = new Map();
    (clusters || []).forEach((c) => {
      if (c.pool_id && !seen.has(c.pool_id)) seen.set(c.pool_id, c.name || `pool ${c.pool_id}`);
    });
    return Array.from(seen, ([id, name]) => ({ id, name }));
  }, [clusters]);

  // v1.10.6 — both lists follow the cluster picked in the header, like every other page. The
  // selector was always there but this page ignored it, so a fleet with several clusters saw
  // one undifferentiated list. Falls back to fleet-wide while the context is still resolving.
  const scopeQuery = selectedCluster?.id ? `?cluster_id=${selectedCluster.id}` : '';

  const fetchVips = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/vip${scopeQuery}`, { headers: authHeaders() });
      if (res.ok) {
        const data = await res.json();
        setVips(data.vips || []);
      } else if (res.status === 403) {
        message.warning('You do not have permission to view VIPs (vip.read).');
        setVips([]);
      }
    } catch (e) {
      console.error('fetchVips failed', e);
    } finally {
      setLoading(false);
    }
  }, [scopeQuery]);

  // v1.10.4 — keepalived configs the agents found on their nodes but do NOT manage. This is why
  // the page could be empty on a fleet that already runs keepalived: the flow was one-way, so
  // nothing ever read what was already there.
  const fetchDiscoveries = useCallback(async () => {
    try {
      const res = await fetch(`/api/vip/discoveries${scopeQuery}`, { headers: authHeaders() });
      if (!res.ok) { setDiscoveries([]); return; }
      const data = await res.json();
      // v1.10.8 — hide a node only while its adoption still STANDS. Filtering on adopted_vip_id
      // alone hid it forever after a reject: nothing clears that column, the VIP is only ever
      // soft-deleted, and the agent does not re-report an unchanged file.
      setDiscoveries((data.discoveries || [])
        .filter((d) => !d.is_managed && !d.adopted_vip_active));
    } catch (e) {
      console.error('fetchDiscoveries failed', e);
    }
  }, [scopeQuery]);

  useEffect(() => {
    fetchVips();
    fetchDiscoveries();
    const t = setInterval(() => { fetchVips(); fetchDiscoveries(); }, 30000); // live MASTER/BACKUP via existing detection pipeline
    return () => clearInterval(t);
  }, [fetchVips, fetchDiscoveries]);

  // v1.10.8 — one row per VRRP INSTANCE, not per node. Adoption now takes the whole instance
  // (every node in the pool reporting the same VRID + address), so listing the nodes as separate
  // adoptable rows invited exactly the half-adoption the backend refuses: adopting the BACKUP
  // alone cannot be applied, and on a unicast pair adopting one side drops the peer list and
  // drops both nodes into a split brain. Identity is (VRID, address), same as keepalived's.
  const discoveryGroups = React.useMemo(() => {
    const groups = new Map();
    (discoveries || []).forEach((d) => {
      const cands = d.analysis?.candidates || [];
      if (cands.length === 0) {
        const key = `solo:${d.agent_id}`;
        groups.set(key, { key, instance_name: '—', vip: null, members: [{ discovery: d, candidate: null }] });
        return;
      }
      cands.forEach((c) => {
        const vrid = c.vip?.virtual_router_id;
        const addr = c.vip?.virtual_ip;
        const key = (vrid != null && addr) ? `${vrid}|${addr}` : `solo:${d.agent_id}:${c.instance_name}`;
        if (!groups.has(key)) {
          groups.set(key, { key, instance_name: c.instance_name, vip: c.vip, members: [] });
        }
        groups.get(key).members.push({ discovery: d, candidate: c });
      });
    });
    return Array.from(groups.values());
  }, [discoveries]);

  // What stops a whole instance from being adopted. Mirrors the backend's checks so the button
  // state and the 422 it would return cannot drift apart.
  const groupState = (g) => {
    const parseFailed = g.members.filter((m) => m.discovery.parse_error);
    const noCandidate = g.members.filter((m) => !m.candidate);
    const blockers = mergeBlockers(g.members.map((m) => m.candidate?.blockers || []));
    const { hard, loss, prefix } = splitBlockers(blockers);
    const masters = g.members.filter((m) => m.candidate?.member?.role === 'MASTER').length;
    // Any reported config that mentions this address but is NOT one of this group's nodes would
    // be left behind when the others are taken over — unparseable, agent disabled, different
    // pool. The endpoint refuses on exactly that question, so ask it here too rather than letting
    // the operator click into a 422. This list is cluster-scoped, so a peer in another pool is
    // invisible from here; the endpoint still catches it.
    const inGroup = new Set(g.members.map((m) => m.discovery.agent_id));
    const strandedPeers = g.vip?.virtual_ip
      ? discoveries.filter((d) => !inGroup.has(d.agent_id)
          && (d.config_preview || '').includes(g.vip.virtual_ip))
      : [];
    let reason = null;
    if (parseFailed.length) reason = `${parseFailed.map((m) => m.discovery.agent_name).join(', ')}: config could not be parsed`;
    else if (noCandidate.length) reason = 'no vrrp_instance in the report';
    else if (strandedPeers.length) {
      reason = `${strandedPeers.map((d) => d.agent_name).join(', ')} reference ${g.vip.virtual_ip} `
        + 'but their config could not be parsed — fix those nodes first, or they would be left '
        + 'running an unmanaged config';
    } else if (hard.length) reason = hard.join(' · ');
    else if (masters !== 1) {
      reason = masters === 0
        ? 'no node in this instance declares state MASTER — enable the missing node\'s agent so it reports its config'
        : `${masters} nodes declare MASTER; exactly one must`;
    }
    return { parseFailed, noCandidate, hard, loss, prefix, masters, blockers, reason };
  };

  const openAdopt = (group) => {
    // Any member can carry the request: the backend resolves the whole instance from it. Prefer
    // the MASTER so the suggested name and the preview show the authoritative node.
    const primary = group.members.find((m) => m.candidate?.member?.role === 'MASTER') || group.members[0];
    setAdoptTarget({ group, primary, discovery: primary.discovery, candidate: primary.candidate });
    setAdoptAcceptLoss(false);
    adoptForm.setFieldsValue({
      name: `${group.vip?.virtual_ip || primary.discovery.agent_name}-vip`,
      prefix_length: group.vip?.prefix_length ?? undefined,
    });
  };

  const submitAdopt = async () => {
    if (!adoptTarget) return;
    let values;
    try { values = await adoptForm.validateFields(); } catch { return; }
    setAdopting(true);
    try {
      const res = await fetch('/api/vip/adopt', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          agent_id: adoptTarget.discovery.agent_id,
          instance_name: adoptTarget.candidate.instance_name,
          name: values.name,
          description: values.description || undefined,
          prefix_length: values.prefix_length ?? undefined,
          accept_data_loss: adoptAcceptLoss || undefined,
        }),
      });
      if (!res.ok) {
        message.error(await fetchApiError(res, 'Adoption failed'), 8);
        return;
      }
      const data = await res.json();
      message.success(data.message || 'VIP adopted', 8);
      setAdoptTarget(null);
      fetchVips();
      fetchDiscoveries();
    } catch (e) {
      message.error('Adoption failed');
    } finally {
      setAdopting(false);
    }
  };

  // Build the participating-nodes table from the pool's EXISTING agents (installed via the
  // standard Agent Management process). On edit, pre-select the VIP's current members.
  const buildMemberRows = (agents, existing) => {
    const ex = {};
    (existing || []).forEach((m) => { ex[m.agent_id] = m; });
    return (agents || [])
      .filter((a) => !String(a.name).startsWith('token_'))
      .map((a) => {
        const interfaces = parseArr(a.network_interfaces).filter((n) => !IFACE_HIDE.test(n));
        const e = ex[a.id];
        return {
          agent_id: a.id,
          agent_name: a.name,
          ip_address: a.ip_address,
          capable: parseArr(a.capabilities).includes('keepalived_management'),
          interfaces,
          participate: !!e,
          role: e ? e.role : 'BACKUP',
          priority: e ? e.priority : 100,
          network_interface: e ? e.network_interface : (interfaces[0] || ''),
        };
      });
  };

  const loadPoolMembers = useCallback(async (poolId, existing) => {
    if (!poolId) { setMemberRows([]); return; }
    try {
      const res = await fetch(`/api/agents?pool_id=${poolId}`, { headers: authHeaders() });
      const data = res.ok ? await res.json() : { agents: [] };
      setMemberRows(buildMemberRows(data.agents || [], existing));
    } catch (e) {
      console.error('loadPoolMembers failed', e);
      setMemberRows([]);
    }
  }, []);

  const setRow = (agentId, patch) =>
    setMemberRows((rows) => rows.map((r) => (r.agent_id === agentId ? { ...r, ...patch } : r)));

  // Toggling a node into the VIP: if no other participating node is MASTER yet, make this
  // one the MASTER. This makes the single-node case work without the operator having to flip
  // the role by hand (a one-node VIP's only node IS the master), and gives a sensible default
  // for multi-node (first picked = master, the rest backup). Editing keeps stored roles.
  const toggleParticipate = (agentId, on) =>
    setMemberRows((rows) => {
      const otherMaster = rows.some((r) => r.agent_id !== agentId && r.participate && r.role === 'MASTER');
      return rows.map((r) => {
        if (r.agent_id !== agentId) return r;
        if (on && !otherMaster) return { ...r, participate: true, role: 'MASTER', priority: 150 };
        return { ...r, participate: on };
      });
    });

  const openCreate = () => {
    setEditing(null);
    setSelectedPoolId(null);
    setMemberRows([]);
    form.resetFields();
    form.setFieldsValue({ prefix_length: 24, advert_int: 1, use_unicast: true, track_haproxy: true });
    setModalVisible(true);
  };

  const openEdit = (vip) => {
    setEditing(vip);
    setSelectedPoolId(vip.pool_id);
    loadPoolMembers(vip.pool_id, vip.members);
    form.resetFields();
    form.setFieldsValue({
      name: vip.name, description: vip.description, pool_id: vip.pool_id,
      virtual_ip: vip.virtual_ip, prefix_length: vip.prefix_length,
      virtual_router_id: vip.virtual_router_id, advert_int: vip.advert_int,
      use_unicast: vip.use_unicast, track_haproxy: vip.track_haproxy,
    });
    setModalVisible(true);
  };

  const submit = async () => {
    let values;
    try { values = await form.validateFields(); }
    catch { return; }

    const chosen = memberRows.filter((r) => r.participate);
    if (chosen.length < 1) { message.error('Select at least 1 participating node.'); return; }
    const masters = chosen.filter((r) => r.role === 'MASTER');
    if (masters.length !== 1) { message.error('Exactly one participating node must be MASTER.'); return; }
    if (chosen.some((r) => !r.network_interface)) { message.error('Pick a network interface for every participating node.'); return; }
    const maxBackup = Math.max(...chosen.filter((r) => r.role === 'BACKUP').map((r) => r.priority));
    if (masters[0].priority <= maxBackup) { message.error('The MASTER must have a higher priority than every BACKUP.'); return; }

    const body = {
      ...values,
      members: chosen.map((r) => ({
        agent_id: r.agent_id, network_interface: r.network_interface, role: r.role, priority: r.priority,
      })),
    };
    if (!body.auth_pass) delete body.auth_pass; // omit to keep existing on edit
    try {
      const url = editing ? `/api/vip/${editing.id}` : '/api/vip';
      const res = await fetch(url, { method: editing ? 'PUT' : 'POST', headers: authHeaders(), body: JSON.stringify(body) });
      if (res.ok) {
        message.success(editing
          ? 'VIP updated (PENDING) — apply it from the Apply Management page'
          : 'VIP created (PENDING) — apply it from the Apply Management page');
        setModalVisible(false);
        fetchVips();
      } else {
        message.error(await fetchApiError(res, 'Failed to save VIP'));
      }
    } catch (e) {
      message.error('Failed to save VIP: ' + e.message);
    }
  };

  const deleteVip = async (vip, purge) => {
    try {
      const res = await fetch(`/api/vip/${vip.id}${purge ? '?purge_package=true' : ''}`,
        { method: 'DELETE', headers: authHeaders() });
      if (res.ok) {
        let body = {};
        try { body = await res.json(); } catch (_) { /* ignore */ }
        // Backend returns staged=true (approval required, VIP still running) or staged=false
        // (never-applied VIP removed at once). Surface its exact message either way.
        (body.staged ? message.info : message.success)(
          body.message || 'Deletion requested.');
        setDeleteTarget(null); fetchVips();
      } else message.error(await fetchApiError(res, 'Delete failed'));
    } catch (e) { message.error('Delete failed: ' + e.message); }
  };

  // Diagnostics: per-member deploy state/ack from GET /api/vip/{id}/status — the live view
  // of what each node reported (installing/applied/error/externally-managed), most useful
  // while a freshly-applied VIP is SYNCING (keepalived install can take ~30s).
  const openDiagnostics = async (vip) => {
    setDiagVip(vip); setDiagData(null); setDiagLoading(true);
    try {
      const res = await fetch(`/api/vip/${vip.id}/status`, { headers: authHeaders() });
      if (res.ok) setDiagData(await res.json());
      else message.error(await fetchApiError(res, 'Failed to load diagnostics'));
    } catch (e) { message.error('Diagnostics failed: ' + e.message); }
    finally { setDiagLoading(false); }
  };

  // Colorful, IP-Inventory/Agent-consistent state: live VRRP MASTER (green, crowned) /
  // BACKUP (orange) / FAULT (red); when the agent hasn't reported a live state yet, show
  // the configured role as a dashed outline tag (same color) so it's clearly "intended,
  // not yet observed". A node whose agent is too old gets an "awaiting agent" flag.
  const renderMembers = (_, vip) => (
    <Space direction="vertical" size={4}>
      {(vip.members || []).map((m) => {
        const live = m.keepalive_state && m.keepalive_state !== 'NONE' ? m.keepalive_state : null;
        const roleColor = m.role === 'MASTER' ? 'green' : 'orange';
        const awaiting = !live && !m.keepalived_capable;
        return (
          <Space key={m.agent_id} size={6}>
            <Text style={{ fontSize: 12 }}>{m.agent_name || `agent ${m.agent_id}`}</Text>
            {live ? (
              <Tooltip title={`Live VRRP state: ${live}`}>
                <Tag
                  color={live === 'MASTER' ? 'green' : live === 'BACKUP' ? 'orange' : 'red'}
                  icon={live === 'MASTER' ? <CrownOutlined /> : undefined}
                  style={{ marginInlineEnd: 0, fontWeight: 600 }}
                >
                  {live}
                </Tag>
              </Tooltip>
            ) : (
              <Tooltip title="Configured role — live VRRP state not observed yet (agent offline or still converging).">
                <Tag color={roleColor} style={{ marginInlineEnd: 0, borderStyle: 'dashed', opacity: 0.85 }}>
                  {m.role}
                </Tag>
              </Tooltip>
            )}
            {awaiting && (
              <Tooltip title="This node's agent does not advertise keepalived_management — upgrade the agent.">
                <Tag color="gold" icon={<WarningOutlined />} style={{ marginInlineEnd: 0 }}>awaiting agent</Tag>
              </Tooltip>
            )}
          </Space>
        );
      })}
    </Space>
  );

  const columns = [
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Virtual IP', key: 'vip', render: (_, v) => <Text code>{v.virtual_ip}/{v.prefix_length}</Text> },
    { title: 'Pool', dataIndex: 'pool_name', key: 'pool' },
    { title: 'VRID', dataIndex: 'virtual_router_id', key: 'vrid' },
    { title: 'Members / Live state', key: 'members', render: renderMembers },
    {
      title: 'Status', key: 'status', render: (_, v) => {
        const s = v.deploy_status || v.last_config_status;
        const d = DEPLOY_STATUS[s] || { color: 'default', label: s, tip: '' };
        const count = (s === 'SYNCING' || s === 'AWAITING' || s === 'ACTIVE' || s === 'DELETING' || s === 'DELETED') && v.deploy_total
          ? ` (${v.deploy_synced}/${v.deploy_total})` : '';
        return (
          <Tooltip title={d.tip}>
            <Tag color={d.color} icon={(s === 'SYNCING' || s === 'DELETING') ? <SyncOutlined spin /> : s === 'AWAITING' ? <ClockCircleOutlined /> : undefined}>
              {(d.label || s)}{count}
            </Tag>
          </Tooltip>
        );
      },
    },
    {
      title: 'Actions', key: 'actions', render: (_, v) => (
        <Space>
          {v.last_config_status === 'PENDING' && (
            <Tooltip title="Apply pending configuration changes">
              <Button type="primary" size="small" icon={<PlayCircleOutlined />}
                onClick={() => { window.location.href = '/apply-management'; }}
                style={{ backgroundColor: '#1890ff', borderColor: '#1890ff' }}>
                Apply
              </Button>
            </Tooltip>
          )}
          <Tooltip title="Edit VIP (changes become PENDING; apply from Apply Management)">
            <Button size="small" icon={<EditOutlined />} onClick={() => openEdit(v)} />
          </Tooltip>
          <Tooltip title="Diagnostics — per-node keepalived deploy status & logs">
            <Button size="small" icon={<FileSearchOutlined />} onClick={() => openDiagnostics(v)} />
          </Tooltip>
          <Tooltip title="Delete VIP">
            <Button size="small" danger icon={<DeleteOutlined />}
              onClick={() => setDeleteTarget(v)} />
          </Tooltip>
        </Space>
      ),
    },
  ];

  // Member-selection table inside the modal — the pool's installed agents (nodes).
  const memberColumns = [
    {
      title: 'Node (agent)', key: 'node', render: (_, r) => (
        <span>
          <Text strong>{r.agent_name}</Text>{' '}
          <Text type="secondary" style={{ fontSize: 12 }}>{r.ip_address ? `(${r.ip_address})` : '(no IP yet)'}</Text>
          {!r.capable && (
            <Tooltip title="This agent doesn't advertise keepalived_management — upgrade it or this node won't deploy.">
              {' '}<Tag color="gold" icon={<WarningOutlined />}>agent too old</Tag>
            </Tooltip>
          )}
        </span>
      ),
    },
    {
      title: 'Participate', key: 'participate', width: 100, render: (_, r) => (
        <Switch checked={r.participate} onChange={(c) => toggleParticipate(r.agent_id, c)} />
      ),
    },
    {
      title: 'Role', key: 'role', width: 130, render: (_, r) => (
        <Select size="small" style={{ width: 110 }} value={r.role} disabled={!r.participate}
          onChange={(val) => setRow(r.agent_id, { role: val, priority: val === 'MASTER' ? 150 : 100 })}>
          <Option value="MASTER">MASTER</Option>
          <Option value="BACKUP">BACKUP</Option>
        </Select>
      ),
    },
    {
      title: 'Priority', key: 'priority', width: 110, render: (_, r) => (
        <InputNumber size="small" min={1} max={254} value={r.priority} disabled={!r.participate}
          onChange={(val) => setRow(r.agent_id, { priority: val })} />
      ),
    },
    {
      title: 'Interface', key: 'iface', width: 160, render: (_, r) => (
        <Select size="small" style={{ width: 140 }} value={r.network_interface || undefined}
          placeholder="interface" disabled={!r.participate} showSearch
          onChange={(val) => setRow(r.agent_id, { network_interface: val })}
          notFoundContent="no interfaces reported"
          options={(r.interfaces || []).map((n) => ({ label: n, value: n }))}
          {...((r.interfaces || []).length === 0 ? { mode: 'tags' } : {})} />
      ),
    },
  ];

  return (
    <div>
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <Title level={2} style={{ margin: 0 }}>HA / VIP (Keepalived)</Title>
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetchVips}>Refresh</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>Create VIP</Button>
          </Space>
        </div>
        {/* The cloud caveat is rarely relevant for the on-prem target audience, so it's a
            subtle, collapsed-by-default info note (not a prominent yellow warning). */}
        <div style={{ marginBottom: 12 }}>
          <Button type="link" size="small" icon={<InfoCircleOutlined />} style={{ paddingLeft: 0 }}
            onClick={() => setShowL2Note((v) => !v)}>
            Network requirements (on-prem / L2)
          </Button>
          {showL2Note && (
            <Alert
              type="info" showIcon style={{ marginTop: 4 }}
              message="On-prem / L2 networks"
              description="VRRP-based VIP failover targets bare-metal / VMware / on-prem L2 segments. On AWS/Azure/GCP, cloud fabrics don't honor VRRP/gratuitous-ARP, so VIPs won't move. Ensure VRRP (IP protocol 112) is permitted by host firewalls."
            />
          )}
        </div>
        <Table rowKey="id" columns={columns} dataSource={vips} loading={loading} pagination={{ pageSize: 10 }} />
      </Card>

      {/* v1.10.4 — keepalived that already exists on a node. Shown separately from managed VIPs
          because OpenManager is NOT managing these: the agent found them, reported them, and
          deliberately left them untouched. */}
      {discoveries.length > 0 && (
        <Card style={{ marginTop: 16 }} title={
          <Space>
            <FileSearchOutlined />
            <span>Unmanaged keepalived detected on {discoveries.length} node(s)</span>
          </Space>
        }>
          <Alert
            type="info" showIcon style={{ marginBottom: 12 }}
            message="These nodes already run keepalived, configured outside OpenManager"
            description={
              <span>
                The agent read each <Text code>keepalived.conf</Text> and left it untouched — nothing
                on these nodes has been changed. Adopting one creates a managed VIP from the values
                in that file, and the node's config is only handed over when you apply it from
                Apply Management. Adoption replaces the file with OpenManager's render, so anything
                it cannot reproduce is listed as a blocker rather than silently dropped.
              </span>
            }
          />
          <Table
            rowKey={(r) => r.key}
            size="small"
            pagination={false}
            dataSource={discoveryGroups}
            columns={[
              { title: 'Nodes', key: 'agents',
                render: (_v, r) => (
                  <Space direction="vertical" size={0}>
                    {r.members.map((m) => (
                      <Text strong key={m.discovery.agent_id}>{m.discovery.agent_name}</Text>
                    ))}
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      {r.members[0]?.discovery.pool_name || 'no pool'}
                    </Text>
                  </Space>
                ) },
              { title: 'Instance', dataIndex: 'instance_name', key: 'instance' },
              { title: 'Virtual IP', key: 'vip',
                render: (_v, r) => (r.vip?.virtual_ip
                  ? <Text code>{r.vip.virtual_ip}
                      {r.vip.prefix_length != null ? `/${r.vip.prefix_length}` : ''}</Text>
                  : <Text type="secondary">—</Text>) },
              { title: 'VRID', key: 'vrid',
                render: (_v, r) => (r.vip?.virtual_router_id ?? <Text type="secondary">—</Text>) },
              { title: 'Members', key: 'member',
                render: (_v, r) => (
                  <Space direction="vertical" size={0}>
                    {r.members.map((m) => (
                      <Space size={4} key={m.discovery.agent_id}>
                        {m.candidate ? (
                          <>
                            <Tag color={m.candidate.member.role === 'MASTER' ? 'green' : 'default'}>
                              {m.candidate.member.role}
                            </Tag>
                            <Text type="secondary" style={{ fontSize: 12 }}>
                              prio {m.candidate.member.priority} · {m.candidate.member.network_interface}
                            </Text>
                          </>
                        ) : <Text type="secondary">—</Text>}
                      </Space>
                    ))}
                  </Space>
                ) },
              { title: 'Adoptable', key: 'adoptable',
                render: (_v, r) => {
                  const st = groupState(r);
                  if (st.parseFailed.length) {
                    return (
                      <Tooltip title={st.parseFailed.map((m) => `${m.discovery.agent_name}: ${m.discovery.parse_error}`).join(' · ')}>
                        <Tag color="red">unparseable</Tag>
                      </Tooltip>
                    );
                  }
                  if (st.noCandidate.length) return <Tag>no vrrp_instance</Tag>;
                  if (st.hard.length || st.masters !== 1) {
                    return <Tooltip title={st.reason}><Tag color="red">
                      {st.hard.length ? `${st.hard.length} blocker(s)` : 'MASTER missing'}
                    </Tag></Tooltip>;
                  }
                  if (!st.blockers.length) return <Tag color="green">yes</Tag>;
                  return (
                    <Tooltip title={st.blockers.join(' · ')}><Tag color="gold">needs review</Tag></Tooltip>
                  );
                } },
              { title: 'Actions', key: 'actions',
                render: (_v, r) => {
                  const st = groupState(r);
                  const btn = (
                    <Button size="small" type="primary" ghost
                      disabled={!!st.reason} onClick={() => openAdopt(r)}>
                      Adopt
                    </Button>
                  );
                  // A disabled antd Button swallows mouse events, so the tooltip needs a live
                  // wrapper or the operator never learns WHY adoption is unavailable.
                  return st.reason
                    ? <Tooltip title={st.reason}><span style={{ display: 'inline-block' }}>{btn}</span></Tooltip>
                    : btn;
                } },
            ]}
          />
        </Card>
      )}

      {/* Adopt modal — shows what will be taken over, what was assumed, and what would be lost. */}
      <Modal
        title={adoptTarget
          ? `Adopt ${adoptTarget.group.instance_name} — ${adoptTarget.group.members.length} node(s)`
          : 'Adopt VIP'}
        open={!!adoptTarget}
        onCancel={() => setAdoptTarget(null)}
        onOk={submitAdopt}
        confirmLoading={adopting}
        okText="Adopt as PENDING"
        width={720}
        okButtonProps={{
          disabled: !!adoptTarget && (() => {
            const { loss, hard } = splitBlockers(
              mergeBlockers(adoptTarget.group.members.map((m) => m.candidate?.blockers || [])));
            return hard.length > 0 || (loss.length > 0 && !adoptAcceptLoss);
          })(),
        }}
      >
        {adoptTarget && (() => {
          const cand = adoptTarget.candidate;
          // Blockers are aggregated across EVERY node of the instance, because adoption
          // overwrites every one of their files — the backend refuses on the same combined set.
          const { loss, prefix, hard } = splitBlockers(
            mergeBlockers(adoptTarget.group.members.map((m) => m.candidate?.blockers || [])));
          return (
            <>
              <Alert type="info" showIcon style={{ marginBottom: 12 }}
                message={`These ${adoptTarget.group.members.length} node(s) will be taken over together`}
                description={
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {adoptTarget.group.members.map((m) => (
                      <li key={m.discovery.agent_id}>
                        <Text strong>{m.discovery.agent_name}</Text>
                        {' — '}{m.candidate?.member?.role} · prio {m.candidate?.member?.priority}
                        {' · '}{m.candidate?.member?.network_interface}
                        {' · '}<Text code>{m.discovery.config_path}</Text>
                      </li>
                    ))}
                  </ul>
                } />
              {hard.length > 0 && (
                <Alert type="error" showIcon style={{ marginBottom: 12 }}
                  message="This config cannot be adopted"
                  description={<ul style={{ margin: 0, paddingLeft: 18 }}>
                    {hard.map((b, i) => <li key={i}>{b}</li>)}
                  </ul>} />
              )}
              {loss.length > 0 && (
                <Alert type="warning" showIcon style={{ marginBottom: 12 }}
                  message="Adopting would delete these directives from the node's config"
                  description={
                    <>
                      <ul style={{ margin: '0 0 8px', paddingLeft: 18 }}>
                        {loss.map((b, i) => <li key={i}>{b}</li>)}
                      </ul>
                      <Checkbox checked={adoptAcceptLoss} onChange={(e) => setAdoptAcceptLoss(e.target.checked)}>
                        I understand these will be lost when the config is handed over
                      </Checkbox>
                    </>
                  } />
              )}
              {(cand.defaulted || []).length > 0 && (
                <Alert type="info" showIcon style={{ marginBottom: 12 }}
                  message={`Assumed from keepalived's defaults (absent from the file): ${cand.defaulted.join(', ')}`} />
              )}
              <Form form={adoptForm} layout="vertical">
                <Form.Item name="name" label="VIP name"
                  rules={[{ required: true, message: 'Give the managed VIP a name' }]}>
                  <Input placeholder="e.g. dmz-web-vip" />
                </Form.Item>
                {prefix.length > 0 && (
                  <Form.Item name="prefix_length" label="Prefix length"
                    extra="The file has no explicit prefix, and guessing one would change this VIP's netmask on takeover. State it here."
                    rules={[{ required: true, message: 'Required — the file does not state one' }]}>
                    <InputNumber min={1} max={32} style={{ width: 160 }} />
                  </Form.Item>
                )}
                <Form.Item name="description" label="Description (optional)">
                  <Input placeholder={`Adopted from ${adoptTarget.discovery.agent_name}`} />
                </Form.Item>
              </Form>
              <Text type="secondary" style={{ fontSize: 12 }}>
                Config found at <Text code>{adoptTarget.discovery.config_path}</Text> — the VRRP
                password is masked below and is carried over encrypted.
              </Text>
              <pre style={{ marginTop: 8, maxHeight: 220, overflow: 'auto', fontSize: 12,
                            background: 'rgba(127,127,127,0.08)', padding: 8, borderRadius: 4 }}>
                {adoptTarget.discovery.config_preview || '(not available)'}
              </pre>
            </>
          );
        })()}
      </Modal>

      <Modal
        title={editing ? `Edit VIP — ${editing.name}` : 'Create VIP'}
        open={modalVisible}
        onCancel={() => setModalVisible(false)}
        onOk={submit}
        okText={editing ? 'Save (PENDING)' : 'Create (PENDING)'}
        width={880}
        destroyOnClose
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label="Name" rules={[{ required: true }]}>
            <Input placeholder="web-vip" disabled={!!editing} />
          </Form.Item>
          <Form.Item name="description" label="Description">
            <Input placeholder="optional" />
          </Form.Item>
          {!editing && (
            <Form.Item name="pool_id" label="Pool" rules={[{ required: true }]}
              tooltip="The VIP's nodes are the HAProxy servers (agents) already enrolled in this pool.">
              <Select placeholder="Select a pool" onChange={(pid) => { setSelectedPoolId(pid); loadPoolMembers(pid); }}>
                {pools.map((p) => <Option key={p.id} value={p.id}>{p.name}</Option>)}
              </Select>
            </Form.Item>
          )}
          <Space size="large" style={{ display: 'flex' }}>
            <Form.Item name="virtual_ip" label="Virtual IP (IPv4)" rules={[{ required: true }]}>
              <Input placeholder="10.0.0.100" />
            </Form.Item>
            <Form.Item name="prefix_length" label="Prefix" rules={[{ required: true }]}>
              <InputNumber min={1} max={32} />
            </Form.Item>
            <Form.Item name="virtual_router_id" label="VRID (blank = auto)">
              <InputNumber min={1} max={255} placeholder="auto" />
            </Form.Item>
            <Form.Item name="advert_int" label="Advert int (s)">
              <InputNumber min={1} max={255} />
            </Form.Item>
          </Space>
          <Space size="large">
            <Form.Item name="use_unicast" label="Unicast VRRP" valuePropName="checked" tooltip="Recommended; works where multicast is blocked.">
              <Switch />
            </Form.Item>
            <Form.Item name="track_haproxy" label="Fail over when HAProxy drops" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Form.Item name="auth_pass" label="VRRP secret (≤8 chars)">
              <Input.Password placeholder={editing ? '•••• (unchanged)' : 'optional'} maxLength={8} />
            </Form.Item>
          </Space>

          <Text strong>Participating nodes</Text>
          <div style={{ color: '#888', fontSize: 12, marginBottom: 8 }}>
            These are the HAProxy servers (agents) already enrolled in this pool — toggle which join the VIP.
            Pick <b>exactly one MASTER</b> (highest priority); the rest are BACKUP. A <b>single node</b> is allowed
            (a keepalived-managed VIP <i>without</i> failover) — add a second node for real HA. Add new servers from
            the standard Agent Management install flow.
          </div>
          <Alert
            type="info" showIcon style={{ marginBottom: 8 }}
            message="keepalived is installed automatically on Apply"
            description={<>On Apply, any participating node that doesn’t already run keepalived will <b>install it from the node’s OS package repositories</b> (apt/dnf/yum/zypper/apk) — make sure the node can reach its repos (internet or an internal mirror). A node already running a <b>hand-managed</b> keepalived is left untouched (reported as “externally managed”).</>}
          />
          <Table
            rowKey="agent_id"
            size="small"
            columns={memberColumns}
            dataSource={memberRows}
            pagination={false}
            locale={{ emptyText: selectedPoolId ? 'No agents in this pool — install agents from Agent Management first.' : 'Select a pool to list its nodes.' }}
          />
        </Form>
      </Modal>

      {/* Delete confirmation with opt-in package uninstall. Enterprise-safe DEFAULT keeps the
          package (just stop/disable + remove our config + release the VIP). */}
      <Modal
        title="Delete VIP — requires approval"
        open={!!deleteTarget}
        onCancel={() => setDeleteTarget(null)}
        onOk={() => deleteVip(deleteTarget, false)}
        okText="Stage deletion for approval"
        okButtonProps={{ danger: true }}
      >
        {deleteTarget && (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Alert
              type="warning"
              showIcon
              message="This does NOT delete the VIP immediately"
              description={<>It stages the deletion for approval. The VIP <b>keeps running, untouched</b>, on its
                member node(s) until you <b>Approve</b> it on the <b>Apply Management</b> page — and you can
                <b> Reject</b> it there to keep it. The node is changed <b>only after approval</b>, so an
                accidental click can't tear down a production VIP.</>}
            />
            <Text>
              Stage deletion of <Text strong>{deleteTarget.name}</Text> ({deleteTarget.virtual_ip}/{deleteTarget.prefix_length})?
              When approved, the member node(s) <b>stop &amp; disable keepalived, remove the config we manage, and release the VIP</b>. The keepalived package itself is left installed, so re-adding a VIP later is instant.
            </Text>
          </Space>
        )}
      </Modal>

      {/* Per-node keepalived deploy diagnostics + node-side log commands (esp. during SYNCING). */}
      <Modal
        title={diagVip ? `Diagnostics — ${diagVip.name}` : 'Diagnostics'}
        open={!!diagVip}
        onCancel={() => { setDiagVip(null); setDiagData(null); }}
        width={780}
        footer={[
          <Button key="refresh" icon={<ReloadOutlined />} onClick={() => diagVip && openDiagnostics(diagVip)}>Refresh</Button>,
          <Button key="close" type="primary" onClick={() => { setDiagVip(null); setDiagData(null); }}>Close</Button>,
        ]}
      >
        {diagLoading && <div style={{ textAlign: 'center', padding: 24 }}><Spin /></div>}
        {!diagLoading && diagData && (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Text type="secondary">
              Staging <Tag>{diagData.last_config_status}</Tag> — each node reports its deploy state after every poll; a fresh keepalived install can take ~30s.
            </Text>
            <Table
              size="small" rowKey={(m) => m.agent_name} pagination={false}
              dataSource={diagData.members || []}
              columns={[
                { title: 'Node', key: 'node', render: (_, m) => (
                  <Space size={4}>
                    <Text style={{ fontSize: 12 }}>{m.agent_name}</Text>
                    {m.role === 'MASTER'
                      ? <Tag color="green" icon={<CrownOutlined />} style={{ marginInlineEnd: 0 }}>MASTER</Tag>
                      : <Tag color="orange" style={{ marginInlineEnd: 0 }}>BACKUP</Tag>}
                  </Space>) },
                { title: 'Agent', dataIndex: 'agent_status', key: 'agent',
                  render: (s) => <Tag color={s === 'online' ? 'green' : 'red'}>{s || 'offline'}</Tag> },
                { title: 'Live VRRP', dataIndex: 'keepalive_state', key: 'live',
                  render: (s) => (s && s !== 'NONE')
                    ? <Tag color={s === 'MASTER' ? 'green' : s === 'BACKUP' ? 'orange' : 'red'}>{s}</Tag>
                    : <Text type="secondary">—</Text> },
                { title: 'Deploy', key: 'deploy', render: (_, m) => {
                    const st = m.deploy_state;
                    const color = st === 'enabled' ? 'green' : st === 'error' ? 'red'
                      : st === 'externally_managed' ? 'gold' : 'blue';
                    return <Tooltip title={m.deploy_message || ''}><Tag color={color}>{m.convergence || st || 'pending'}</Tag></Tooltip>;
                  } },
                { title: 'Last ack', dataIndex: 'deploy_at', key: 'ack',
                  render: (t) => t ? <Text style={{ fontSize: 11 }}>{new Date(t).toLocaleString()}</Text> : <Text type="secondary">—</Text> },
              ]}
            />
            {(diagData.members || []).some((m) => m.deploy_message) && (
              <Card size="small" title="Latest node messages" bodyStyle={{ padding: 8 }}>
                {(diagData.members || []).filter((m) => m.deploy_message).map((m) => (
                  <div key={m.agent_name} style={{ fontSize: 12 }}><Text strong>{m.agent_name}:</Text> {m.deploy_message}</div>
                ))}
              </Card>
            )}
            <Alert
              type="info" showIcon
              message="See the live install / VRRP logs on the node"
              description={
                <pre style={{ margin: 0, fontSize: 11, whiteSpace: 'pre-wrap' }}>{`systemctl status keepalived --no-pager
journalctl -u keepalived --no-pager -n 50
tail -n 100 /var/log/haproxy-agent/agent.log | grep -i keepalived`}</pre>
              }
            />
          </Space>
        )}
        {!diagLoading && !diagData && <Text type="secondary">No diagnostics available.</Text>}
      </Modal>
    </div>
  );
};

export default VIPManagement;
