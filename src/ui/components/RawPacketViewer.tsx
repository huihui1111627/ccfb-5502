import { useEffect, useState } from 'react';
import { useSession } from '../session';
import { hex } from '../../core/bytes';
import { decodeEthernet } from '../../core/decode';
import type { RawPacket } from '../../core/types';
import { fmtTime } from '../utils';

/** 原始报文查看器：按帧定位信息回读字节，逐层解码展示（不依赖全量包缓存） */
export function RawPacketViewer({ packetIndex, onClose }: { packetIndex: number; onClose: () => void }) {
  const { readFrame, source } = useSession();
  const [data, setData] = useState<Uint8Array | null>(null);
  const [tsMs, setTsMs] = useState(0);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setData(null);
    setErr(null);
    readFrame(packetIndex)
      .then((r) => {
        if (!alive) return;
        setData(r.data);
        setTsMs(r.tsMs);
      })
      .catch((e) => alive && setErr(e instanceof Error ? e.message : String(e)));
    return () => {
      alive = false;
    };
  }, [packetIndex, readFrame]);

  if (!source) {
    return (
      <div className="modal-mask" onClick={onClose}>
        <div className="modal" onClick={(e) => e.stopPropagation()}>
          <h3>无法查看原始报文</h3>
          <p>历史会话只保留结构化结果与帧定位索引，请先在页面顶部重新挂载原始 pcap/pcapng 文件。</p>
          <button className="btn primary" onClick={onClose}>知道了</button>
        </div>
      </div>
    );
  }

  const pkt: RawPacket = {
    index: packetIndex,
    tsMs,
    fileOffset: 0,
    fileRecordLen: 0,
    capLen: data?.length ?? 0,
    origLen: data?.length ?? 0,
    l2: 'other',
  };
  if (data) decodeEthernet(data, pkt, 1);

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal wide" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h3>原始报文 · 帧 #{packetIndex}</h3>
          <button className="x" onClick={onClose}>×</button>
        </div>
        {err && <div className="error-banner">{err}</div>}
        {!data && !err && <div className="muted">回读中…</div>}
        {data && (
          <>
            <div className="pkt-meta">
              <span>{fmtTime(tsMs)}</span>
              <span>{pkt.srcMac} → {pkt.dstMac}</span>
              <span>{pkt.srcIp}:{pkt.srcPort} → {pkt.dstIp}:{pkt.dstPort}</span>
              <span>TCP flags=0x{(pkt.tcpFlags ?? 0).toString(16)} seq={pkt.seq} ack={pkt.ack}</span>
              <span>{data.length} 字节</span>
            </div>
            <pre className="hexdump">{toHexDump(data)}</pre>
            <details open>
              <summary>TCP 载荷（{pkt.payloadLength ?? 0} 字节）</summary>
              {pkt.payloadLength ? (
                <>
                  <pre className="hexdump small">{toHexDump(data.subarray(pkt.payloadOffset!, pkt.payloadOffset! + pkt.payloadLength!))}</pre>
                  <pre className="muted">{hex(data.subarray(pkt.payloadOffset!, pkt.payloadOffset! + pkt.payloadLength!))}</pre>
                </>
              ) : (
                <p className="muted">无载荷（纯控制报文）</p>
              )}
            </details>
          </>
        )}
      </div>
    </div>
  );
}

function toHexDump(b: Uint8Array): string {
  const lines: string[] = [];
  for (let o = 0; o < b.length; o += 16) {
    const chunk = b.subarray(o, o + 16);
    const hexPart = [...chunk].map((x) => x.toString(16).padStart(2, '0')).join(' ').padEnd(48);
    const ascii = [...chunk].map((x) => (x >= 32 && x < 127 ? String.fromCharCode(x) : '.')).join('');
    lines.push(`${o.toString(16).padStart(4, '0')}  ${hexPart}  ${ascii}`);
  }
  return lines.join('\n');
}
