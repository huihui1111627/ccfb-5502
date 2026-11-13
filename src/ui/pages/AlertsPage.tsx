import { useEffect, useState } from 'react';
import { useApp } from '../state';
import { useSession, AttachFileBanner } from '../session';
import { alertsToCsv } from '../../core/exporter';
import type { Alert } from '../../core/types';
import { ALERT_META, downloadText, fmtTime } from '../utils';
import { RawPacketViewer } from '../components/RawPacketViewer';

const PAGE_SIZE = 100;

export function AlertsPage() {
  const { state, dispatch } = useApp();
  const { store } = useSession();
  const [rows, setRows] = useState<Alert[]>([]);
  const [offset, setOffset] = useState(0);
  const [focus, setFocus] = useState<number | null>(null);
  const [counts, setCounts] = useState({ all: 0, open: 0, ack: 0, ignore: 0 });
  const f = state.filter;

  const refresh = () => {
    void store.queryAlerts(f, PAGE_SIZE, offset).then(setRows);
    void Promise.all([
      store.countAlerts('all'),
      store.countAlerts('open'),
      store.countAlerts('ack'),
      store.countAlerts('ignore'),
    ]).then(([all, open, ack, ignore]) => setCounts({ all, open, ack, ignore }));
  };

  useEffect(() => {
    setOffset(0);
  }, [f.type, f.status, f.connId, f.q]);

  useEffect(refresh, [store, f, offset]);

  const setStatus = async (id: number, status: Alert['status']) => {
    await store.updateAlertStatus(id, status);
    refresh();
  };

  return (
    <div className="page">
      <AttachFileBanner />
      <div className="toolbar">
        <select
          className="input narrow"
          value={f.type ?? ''}
          onChange={(e) => dispatch({ type: 'filter', patch: { type: e.target.value as Alert['type'] | undefined } })}
        >
          <option value="">全部类型</option>
          {Object.entries(ALERT_META).map(([k, v]) => (
            <option key={k} value={k}>{v.label}</option>
          ))}
        </select>
        <select
          className="input narrow"
          value={f.status ?? 'all'}
          onChange={(e) => dispatch({ type: 'filter', patch: { status: e.target.value as Alert['status'] | 'all' } })}
        >
          <option value="all">全部状态 ({counts.all})</option>
          <option value="open">待处理 ({counts.open})</option>
          <option value="ack">已确认 ({counts.ack})</option>
          <option value="ignore">已忽略 ({counts.ignore})</option>
        </select>
        <input
          className="input"
          placeholder="搜索告警内容…"
          value={f.q ?? ''}
          onChange={(e) => dispatch({ type: 'filter', patch: { q: e.target.value } })}
        />
        <div className="spacer" />
        <button className="btn" onClick={() => void store.queryAlerts({ ...f, status: 'all' }, 100000, 0).then((all) => downloadText('alerts.csv', alertsToCsv(all)))}>
          导出 CSV
        </button>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>时间</th>
              <th>类型</th>
              <th>严重度</th>
              <th>标题 / 详情</th>
              <th>连接</th>
              <th>状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const meta = ALERT_META[a.type];
              return (
                <tr key={a.id} className={a.status === 'ignore' ? 'ignored' : ''}>
                  <td>{fmtTime(a.tsMs)}</td>
                  <td>
                    <span className="badge" style={{ background: meta?.color }}>{meta?.label ?? a.type}</span>
                    {a.inBaselineWindow && <small className="muted"> 学习期</small>}
                  </td>
                  <td>
                    <span className={`sev sev-${a.severity}`}>{a.severity}</span>
                  </td>
                  <td>
                    <div><strong>{a.title}</strong></div>
                    <small className="muted">{a.detail}</small>
                  </td>
                  <td><small>{a.connId}</small></td>
                  <td><span className={`badge ${a.status === 'open' ? 'red' : a.status === 'ack' ? 'blue' : 'gray'}`}>{a.status}</span></td>
                  <td className="actions">
                    <button className="btn small ghost" onClick={() => setFocus(a.packetIndex)}>原始报文</button>
                    {a.status !== 'ack' && (
                      <button className="btn small" onClick={() => void setStatus(a.id, 'ack')}>确认</button>
                    )}
                    {a.status !== 'ignore' && (
                      <button className="btn small ghost" onClick={() => void setStatus(a.id, 'ignore')}>忽略</button>
                    )}
                  </td>
                </tr>
              );
            })}
            {rows.length === 0 && <tr><td colSpan={7} className="empty">没有匹配的告警</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="pager">
        <button className="btn small" disabled={offset === 0} onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}>上一页</button>
        <span className="muted">{offset + 1}–{Math.min(offset + PAGE_SIZE, counts.all)}</span>
        <button className="btn small" disabled={offset + PAGE_SIZE >= counts.all} onClick={() => setOffset((o) => o + PAGE_SIZE)}>下一页</button>
      </div>

      {focus != null && <RawPacketViewer packetIndex={focus} onClose={() => setFocus(null)} />}
    </div>
  );
}
