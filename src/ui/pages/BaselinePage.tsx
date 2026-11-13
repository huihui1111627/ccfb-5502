import { useEffect, useState } from 'react';
import { useSession, AttachFileBanner } from '../session';
import type { Baseline } from '../../core/types';
import { fmtTime } from '../utils';

export function BaselinePage() {
  const { store } = useSession();
  const [baseline, setBaseline] = useState<Baseline | null>(null);
  const [openConn, setOpenConn] = useState<string | null>(null);

  useEffect(() => {
    void store.getBaseline().then((b) => setBaseline(b ?? null));
  }, [store]);

  if (!baseline) {
    return (
      <div className="page">
        <AttachFileBanner />
        <div className="empty-card">本次导入没有学到基线（可能没有 Modbus 流量）</div>
      </div>
    );
  }

  return (
    <div className="page">
      <AttachFileBanner />
      <div className="baseline-head">
        <h2>正常时段基线</h2>
        <p className="muted">
          学习窗口 {fmtTime(baseline.windowStartMs)} — {fmtTime(baseline.windowEndMs)}（
          {((baseline.windowEndMs - baseline.windowStartMs) / 1000).toFixed(1)} 秒），覆盖 {baseline.conns.length} 条连接
        </p>
      </div>

      {baseline.conns.map((c) => (
        <section key={c.connId} className="conn-card">
          <div className="conn-head" onClick={() => setOpenConn(openConn === c.connId ? null : c.connId)}>
            <div>
              <strong>{c.connId}</strong>
              <small className="muted">
                {' '}单元 {c.unitId} · {c.requestCount} 次请求 · 功能码 [{c.fcs.map((x) => `FC${x}`).join(', ')}] · 地址范围 [{c.addrMin}, {c.addrMax}]
              </small>
            </div>
            <div className="conn-stats">
              <span>轮询周期 p50 <strong>{c.periodMs.p50}ms</strong></span>
              <span>p95 <strong>{c.periodMs.p95}ms</strong></span>
              <span>范围 {c.periodMs.min}–{c.periodMs.max}ms</span>
              <span className="caret">{openConn === c.connId ? '▾' : '▸'} {c.addrs.length} 个地址</span>
            </div>
          </div>

          {openConn === c.connId && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>功能码</th>
                    <th>地址</th>
                    <th>数量</th>
                    <th>出现次数</th>
                    <th>周期 p50/p95 (ms)</th>
                    <th>值范围</th>
                    <th>均值</th>
                  </tr>
                </thead>
                <tbody>
                  {c.addrs.map((a) => (
                    <tr key={a.key}>
                      <td>FC{a.fc}</td>
                      <td>{a.address}</td>
                      <td>{a.quantity}</td>
                      <td>{a.count}</td>
                      <td>{a.periodMs.p50} / {a.periodMs.p95}</td>
                      <td>
                        {a.valueMin} — {a.valueMax}
                      </td>
                      <td>{a.valueMean.toFixed(1)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      ))}
    </div>
  );
}
