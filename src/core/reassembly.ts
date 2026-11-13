/**
 * TCP 流重组。
 * - 序列号按 RFC793 无符号 32 位回绕处理
 * - 乱序段进入 pending 表，缺口补齐后按序上交
 * - 完全重复段计为重传；部分重叠段去重后只上交新字节
 * - 零拷贝：按序直达的段直接转发帧视图；需要缓存的乱序段才复制
 */
import type { RawPacket, StreamSegment, TcpConnStats } from './types';
import { TCP_SYN, TCP_FIN, TCP_RST, TCP_ACK } from './types';

const MOD32 = 0x100000000;

function seqAdd(a: number, n: number): number {
  return (a + n) % MOD32;
}

interface PendingSeg {
  relStart: number;
  relEnd: number;
  data: Uint8Array; // 副本
  packetIndex: number;
  tsMs: number;
}

interface DirState {
  isn: number | null;
  /** 期望的下一个字节的相对序列号 */
  relNext: number;
  pending: Map<number, PendingSeg>;
  finSeen: boolean;
}

function newDir(): DirState {
  return { isn: null, relNext: 0, pending: new Map(), finSeen: false };
}

interface Conn {
  stats: TcpConnStats;
  c2s: DirState;
  s2r: DirState;
  /** 尚未确定方向时缓存的首个五元组判定 */
  clientKey: string | null;
}

export interface ReasmHandlers {
  onSegment: (seg: StreamSegment) => void;
  onConn?: (stats: TcpConnStats) => void;
}

export class TcpReassembler {
  private conns = new Map<string, Conn>();
  /** 反向索引：任一四元组 -> connId，免得到处拼 key */
  private tupleIndex = new Map<string, string>();

  constructor(private handlers: ReasmHandlers) {}

  get connCount(): number {
    return this.conns.size;
  }

  getConns(): TcpConnStats[] {
    return [...this.conns.values()].map((c) => c.stats);
  }

  handle(pkt: RawPacket, frame: Uint8Array): void {
    if (pkt.ipProto !== 6 || !pkt.srcIp || !pkt.dstIp || pkt.srcPort == null || pkt.dstPort == null) {
      return;
    }
    const flags = pkt.tcpFlags ?? 0;
    const isSyn = !!(flags & TCP_SYN);
    const isRst = !!(flags & TCP_RST);
    const isFin = !!(flags & TCP_FIN);

    const tuple = `${pkt.srcIp}:${pkt.srcPort}>${pkt.dstIp}:${pkt.dstPort}`;
    let connId = this.tupleIndex.get(tuple);
    let conn: Conn | undefined;
    if (connId) conn = this.conns.get(connId);

    if (!conn) {
      // 新连接：SYN 包的发起方是 client；无 SYN（抓包中途开始）用端口启发式
      const srcIsClient = isSyn ? true : pkt.srcPort > pkt.dstPort;
      const clientIp = srcIsClient ? pkt.srcIp : pkt.dstIp;
      const clientPort = srcIsClient ? pkt.srcPort : pkt.dstPort;
      const serverIp = srcIsClient ? pkt.dstIp : pkt.srcIp;
      const serverPort = srcIsClient ? pkt.dstPort : pkt.srcPort;
      connId = `${clientIp}:${clientPort}->${serverIp}:${serverPort}`;
      conn = this.conns.get(connId);
      if (!conn) {
        const stats: TcpConnStats = {
          connId,
          clientIp,
          clientPort,
          serverIp,
          serverPort,
          startMs: pkt.tsMs,
          lastMs: pkt.tsMs,
          packets: 0,
          outOfOrder: 0,
          retransmits: 0,
          modbusFrames: 0,
          established: false,
          closed: false,
        };
        conn = { stats, c2s: newDir(), s2r: newDir(), clientKey: null };
        this.conns.set(connId, conn);
        this.tupleIndex.set(`${clientIp}:${clientPort}>${serverIp}:${serverPort}`, connId);
        this.tupleIndex.set(`${serverIp}:${serverPort}>${clientIp}:${clientPort}`, connId);
      }
    }

    const c = conn;
    const dir: DirState = pkt.srcIp === c.stats.clientIp && pkt.srcPort === c.stats.clientPort ? c.c2s : c.s2r;
    const dirName = dir === c.c2s ? 'C2S' : 'S2R';
    c.stats.packets++;
    c.stats.lastMs = pkt.tsMs;

    if (isSyn && !(flags & TCP_ACK)) {
      // 初始 SYN：ISN 占用一个序号
      dir.isn = pkt.seq!;
      dir.relNext = 1;
      c.stats.established = true;
    } else if (isSyn && flags & TCP_ACK) {
      // SYN/ACK
      dir.isn = pkt.seq!;
      dir.relNext = 1;
    }

    if (isRst) {
      c.stats.closed = true;
      this.closeConn(c);
      return;
    }

    const payloadLen = pkt.payloadLength ?? 0;
    if (payloadLen > 0 && pkt.payloadOffset != null) {
      if (dir.isn == null) {
        // 抓包中途切入、没看到 SYN：把首见数据 seq 视作 ISN（与 SYN 占用一个序号的语义对齐），
        // 这样首包若本身就是乱序段（relStart>1）会正确进入 pending 而不是被误交付
        dir.isn = (pkt.seq! - 1) >>> 0;
        dir.relNext = 1;
      }
      const data = frame.subarray(pkt.payloadOffset, pkt.payloadOffset + payloadLen);
      this.ingestData(c, dir, dirName, pkt, data);
    }

    if (isFin) {
      dir.finSeen = true;
      if (c.c2s.finSeen && c.s2r.finSeen) {
        c.stats.closed = true;
        this.closeConn(c);
      }
    }
  }

  private ingestData(
    c: Conn,
    dir: DirState,
    dirName: 'C2S' | 'S2R',
    pkt: RawPacket,
    data: Uint8Array,
  ): void {
    const absSeq = pkt.seq!;
    let relStart = (absSeq - (dir.isn ?? 0)) >>> 0;
    let relEnd = seqAdd(relStart, data.length);
    let bytes = data;
    let startTrim = 0;

    // 完全落在已交付区间 = 纯重传
    if (relEnd <= dir.relNext) {
      c.stats.retransmits++;
      return;
    }
    // 部分重叠已交付区：重叠部分计重传，只保留新字节
    if (relStart < dir.relNext) {
      startTrim = dir.relNext - relStart;
      c.stats.retransmits++;
      bytes = bytes.subarray(startTrim);
      relStart = dir.relNext;
    }

    if (relStart > dir.relNext) {
      // 乱序：缓存副本（帧视图回调后失效，必须 copy），先与已有 pending 做裁剪去重
      c.stats.outOfOrder++;
      const merged = this.trimIntoPending(dir, {
        relStart,
        relEnd,
        data: bytes.slice(),
        packetIndex: pkt.index,
        tsMs: pkt.tsMs,
      });
      if (merged) dir.pending.set(merged.relStart, merged);
      return;
    }

    // 按序到达，直接上交（零拷贝视图）
    this.emit(c, dirName, absSeq, bytes, pkt.index, pkt.tsMs);
    dir.relNext = relEnd;
    this.drainPending(c, dir, dirName);
  }

  /**
   * 新乱序段入表前与已有段做重叠裁剪：
   * - 完全被覆盖 -> 返回 null（丢弃）
   * - 覆盖旧段 -> 删除旧段
   * - 部分重叠 -> 切掉自身重叠部分
   * 保持 pending 表内各段互不重叠，drain 时按 relNext 顺序取即可。
   */
  private trimIntoPending(dir: DirState, seg: PendingSeg): PendingSeg | null {
    let { relStart, relEnd, data } = seg;
    for (const [key, old] of [...dir.pending]) {
      if (old.relStart <= relStart && old.relEnd >= relEnd) return null; // 完全被包含
      if (relStart <= old.relStart && relEnd >= old.relEnd) {
        dir.pending.delete(key); // 新段完全覆盖旧段
        continue;
      }
      if (old.relStart < relEnd && old.relEnd > relStart) {
        if (old.relStart <= relStart) {
          // 旧段盖住新段头部
          const cut = old.relEnd - relStart;
          relStart += cut;
          data = data.subarray(cut);
        } else {
          // 旧段盖住新段尾部
          relEnd = old.relStart;
          data = data.subarray(0, relEnd - seg.relStart);
        }
      }
    }
    if (relEnd <= relStart) return null;
    return { ...seg, relStart, relEnd, data };
  }

  private drainPending(c: Conn, dir: DirState, dirName: 'C2S' | 'S2R'): void {
    while (true) {
      const seg = dir.pending.get(dir.relNext);
      if (!seg) {
        // 清理已被覆盖的残留重复段
        for (const [k, v] of dir.pending) {
          if (v.relEnd <= dir.relNext) dir.pending.delete(k);
        }
        return;
      }
      dir.pending.delete(dir.relNext);
      const absSeq = seqAdd(dir.isn ?? 0, seg.relStart);
      this.emit(c, dirName, absSeq, seg.data, seg.packetIndex, seg.tsMs);
      dir.relNext = seg.relEnd;
    }
  }

  private emit(
    c: Conn,
    dirName: 'C2S' | 'S2R',
    absSeq: number,
    data: Uint8Array,
    packetIndex: number,
    tsMs: number,
  ): void {
    const s = c.stats;
    const src = dirName === 'C2S'
      ? { ip: s.clientIp, port: s.clientPort }
      : { ip: s.serverIp, port: s.serverPort };
    const dst = dirName === 'C2S'
      ? { ip: s.serverIp, port: s.serverPort }
      : { ip: s.clientIp, port: s.clientPort };
    this.handlers.onSegment({
      connId: s.connId,
      dir: dirName,
      srcIp: src.ip,
      srcPort: src.port,
      dstIp: dst.ip,
      dstPort: dst.port,
      seq: absSeq,
      data,
      packetIndex,
      tsMs,
    });
  }

  private closeConn(c: Conn): void {
    c.c2s.pending.clear();
    c.s2r.pending.clear();
    this.handlers.onConn?.(c.stats);
  }

  /** 抓包结束时调用：上交统计，丢弃无法补齐的缺口缓存 */
  flush(): TcpConnStats[] {
    for (const c of this.conns.values()) {
      c.c2s.pending.clear();
      c.s2r.pending.clear();
    }
    return this.getConns();
  }
}
