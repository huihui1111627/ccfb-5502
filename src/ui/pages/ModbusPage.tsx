import { useEffect, useState } from 'react';
import { useApp } from '../state';
import { useSession, AttachFileBanner } from '../session';
import { modbusToCsv } from '../../core/exporter';
import type { ModbusFrame } from '../../core/types';
import { downloadText, FC_NAMES, fmtTime } from '../utils';
import { RawPacketViewer } from '../components/RawPacketViewer';

const PAGE_SIZE = 100;

export function ModbusPage() {
  const { state, dispatch } = useApp();
  const { store } = useSession();
  const [rows, setRows] = useState<ModbusFrame[]>([]);
  const [offset, setOffset] = useState(0);
  const [total] = useState(state.session?.modbusCount ?? 0);
  const [focus, setFocus] = useState<number | null>(null);

  const f = state.filter;

  useEffect(() => {
    setOffset(0);
  }, [f.connId, f.fc, f.unitId, f.q]);

  useEffect(() => {
    void store.queryModbus(state.filter, PAGE_SIZE, offset).then(setRows);
  }, [store, state.filter, offset]);

  return (
    <div className="page">
      <AttachFileBanner />
      <div className="toolbar">
        <input
          className="input"
          placeholder="搜索 IP / 连接 / 地址…"
          value={f.q ?? ''}
          onChange={(e) => dispatch({ type: 'filter', patch: { q: e.target.value } })}
        />
        <select
          className="input narrow"
          value={f.fc ?? ''}
          onChange={(e) => dispatch({ type: 'filter', patch: { fc: e.target.value ? Number(e.target.value) : undefined } })}
        >
          <option value="">全部功能码</option>
          {Object.entries(FC_NAMES).map(([code, name]) => (
            <option key={code} value={code}>FC{code} {name}</option>
          ))}
        </select>
        <input
          className="input narrow"
          placeholder="单元 ID"
          type="number"
          value={f.unitId ?? ''}
          onChange={(e) =>
            dispatch({ type: 'filter', patch: { unitId: e.target.value ? Number(e.target.value) : undefined } })
          }
        />
        {f.connId && (
          <span className="badge blue">
            {f.connId}
            <button className="x" onClick={() => dispatch({ type: 'filter', patch: { connId: undefined } })}>×</button>
          </span>
        )}
        <div className="spacer" />
        <button className="btn" onClick={() => void store.queryModbus(state.filter, 100000, 0).then((all) => downloadText('modbus.csv', modbusToCsv(all)))}>
          导出 CSV
        </button>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>时间</th>
              <th>连接 / 方向</th>
              <th>事务</th>
              <th>单元</th>
              <th>功能码</th>
              <th>类型</th>
              <th>地址</th>
              <th>数量</th>
              <th>值</th>
              <th>原始报文</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td>{r.id}</td>
                <td>{fmtTime(r.tsMs)}</td>
                <td>
                  <div>{r.connId}</div>
                  <small className="muted">{r.dir}</small>
                </td>
                <td>{r.transId}</td>
                <td>{r.unitId}</td>
                <td>
                  FC{r.fc} <small className="muted">{FC_NAMES[r.fc] ?? '未知'}</small>
                </td>
                <td>
                  <span className={`badge ${r.kind === 'request' ? 'blue' : r.kind === 'exception' ? 'red' : 'green'}`}>
                    {r.kind}
                  </span>
                </td>
                <td>{r.address ?? '—'}</td>
                <td>{r.quantity ?? '—'}</td>
                <td className="vals" title={r.values?.join(', ')}>
                  {r.values ? r.values.slice(0, 8).join(', ') + (r.values.length > 8 ? '…' : '') : r.value ?? '—'}
                </td>
                <td>
                  <button className="btn small ghost" onClick={() => setFocus(r.packetIndex)}>
                    查看
                  </button>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr><td colSpan={11} className="empty">没有匹配的 Modbus 帧</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="pager">
        <button className="btn small" disabled={offset === 0} onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}>
          上一页
        </button>
        <span className="muted">
          {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} / {total.toLocaleString()}
        </span>
        <button className="btn small" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset((o) => o + PAGE_SIZE)}>
          下一页
        </button>
      </div>

      {focus != null && <RawPacketViewer packetIndex={focus} onClose={() => setFocus(null)} />}
    </div>
  );
}
