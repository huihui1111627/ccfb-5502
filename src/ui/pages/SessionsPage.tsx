import { useEffect, useMemo, useState } from 'react';
import { useApp } from '../state';
import { useSession, AttachFileBanner } from '../session';
import { connsToCsv, exportPcapToBlob } from '../../core/exporter';
import type { RawPacket, TcpConnStats } from '../../core/types';
import { downloadBlob, downloadText, fmtBytes, fmtTime } from '../utils';

export function SessionsPage() {
  const { state, dispatch } = useApp();
  const { store, source } = useSession();
  const [conns, setConns] = useState<TcpConnStats[]>([]);
  const [q, setQ] = useState('');
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    void store.getAllConns().then(setConns);
  }, [store]);

  const filtered = useMemo(() => {
    if (!q.trim()) return conns;
    return conns.filter((c) => c.connId.includes(q.trim()));
  }, [conns, q]);

  const exportCsv = () => {
    downloadText(`${state.session!.fileName}-会话.csv`, connsToCsv(filtered));
  };

  /** 按当前会话筛选结果导出新 pcap：用连接的起止时间圈定帧范围，流式回读重打包 */
  const exportPcap = async () => {
    if (!source) {
      alert('请先在顶部挂载原始 pcap/pcapng 文件');
      return;
    }
    setExporting(true);
    try {
      const startMs = Math.min(...filtered.map((c) => c.startMs));
      const endMs = Math.max(...filtered.map((c) => c.lastMs));
      const meta = state.session!;
      // 按块流式扫描时间范围内的帧（每块 256 帧，内存恒定），边扫边交给导出器重打包
      const frames: RawPacket[] = [];
      await store.scanPacketRange(startMs, endMs, meta.packetCount, (p) => frames.push(p));
      const blob = await exportPcapToBlob(source, frames, meta.linkType);
      downloadBlob(`${meta.fileName}-筛选导出.pcap`, blob);
    } finally {
      setExporting(false);
    }
  };

  const totalPackets = conns.reduce((s, c) => s + c.packets, 0);

  return (
    <div className="page">
      <AttachFileBanner />
      <div className="toolbar">
        <input className="input" placeholder="按连接四元组筛选…" value={q} onChange={(e) => setQ(e.target.value)} />
        <div className="spacer" />
        <span className="muted">
          {filtered.length} 条 TCP 连接 · 共 {totalPackets.toLocaleString()} 报文
        </span>
        <button className="btn" onClick={exportCsv}>导出 CSV</button>
        <button className="btn primary" disabled={exporting || !source} onClick={exportPcap}>
          {exporting ? '导出中…' : '导出筛选 pcap'}
        </button>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>连接</th>
              <th>客户端</th>
              <th>服务端</th>
              <th>开始时间</th>
              <th>持续</th>
              <th>报文</th>
              <th>乱序</th>
              <th>重传</th>
              <th>Modbus 帧</th>
              <th>状态</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((c) => (
              <tr key={c.connId}>
                <td title={c.connId}>{c.connId}</td>
                <td>{c.clientIp}:{c.clientPort}</td>
                <td>{c.serverIp}:{c.serverPort}</td>
                <td>{fmtTime(c.startMs)}</td>
                <td>{((c.lastMs - c.startMs) / 1000).toFixed(1)}s</td>
                <td>{c.packets.toLocaleString()}</td>
                <td className={c.outOfOrder > 0 ? 'warn' : ''}>{c.outOfOrder}</td>
                <td className={c.retransmits > 0 ? 'warn' : ''}>{c.retransmits}</td>
                <td>{c.modbusFrames}</td>
                <td>
                  <span className={`badge ${c.closed ? 'gray' : 'green'}`}>{c.closed ? '已关闭' : '活跃'}</span>
                </td>
                <td>
                  <button
                    className="btn small ghost"
                    onClick={() => {
                      dispatch({ type: 'filter', patch: { connId: c.connId } });
                      dispatch({ type: 'page', page: 'modbus' });
                    }}
                  >
                    看 Modbus
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="hint">
        会话页展示 TCP 重组统计：乱序与重传计数由重组器逐段判定；文件大小 {fmtBytes(state.session!.fileSize)}，
        全程流式读取，峰值内存只含一个 4MiB 读取窗口与结构化结果。
      </p>
    </div>
  );
}
