/**
 * 基线学习：从正常时段的 Modbus 流量中学习
 * - 每条连接的轮询周期（请求间隔分布 p50/p95/min/max）
 * - 每个 (fc, 地址) 的取值范围（min/max/mean）
 * 纯数据计算，不碰存储；输入帧序列按时间有序。
 */
import type { AddressBaseline, Baseline, ConnBaseline, ModbusFrame } from './types';

interface AddrAcc {
  fc: number;
  address: number;
  quantity: number;
  count: number;
  intervals: number[];
  lastTs: number;
  vMin: number;
  vMax: number;
  vSum: number;
  vCount: number;
}

interface ConnAcc {
  connId: string;
  clientIp: string;
  clientPort: number;
  serverIp: string;
  serverPort: number;
  unitIds: Set<number>;
  fcs: Set<number>;
  intervals: number[];
  lastReqTs: number;
  requestCount: number;
  addrMin: number;
  addrMax: number;
  addrs: Map<string, AddrAcc>;
}

export class BaselineLearner {
  private conns = new Map<string, ConnAcc>();
  private windowStart = Infinity;
  private windowEnd = 0;

  /** 学习窗口内逐帧喂入 */
  learn(f: ModbusFrame): void {
    let c = this.conns.get(f.connId);
    if (!c) {
      c = {
        connId: f.connId,
        clientIp: f.srcIp,
        clientPort: f.srcPort,
        serverIp: f.dstIp,
        serverPort: f.dstPort,
        unitIds: new Set(),
        fcs: new Set(),
        intervals: [],
        lastReqTs: 0,
        requestCount: 0,
        addrMin: 0xffff,
        addrMax: 0,
        addrs: new Map(),
      };
      this.conns.set(f.connId, c);
    }
    this.windowStart = Math.min(this.windowStart, f.tsMs);
    this.windowEnd = Math.max(this.windowEnd, f.tsMs);
    c.unitIds.add(f.unitId);
    if (f.kind !== 'request') return;

    c.fcs.add(f.fc);
    c.requestCount++;
    if (c.lastReqTs > 0) c.intervals.push(f.tsMs - c.lastReqTs);
    c.lastReqTs = f.tsMs;

    if (f.address != null) {
      c.addrMin = Math.min(c.addrMin, f.address);
      c.addrMax = Math.max(c.addrMax, f.address + (f.quantity ?? 1) - 1);
      const key = `${f.fc}:${f.address}`;
      let a = c.addrs.get(key);
      if (!a) {
        a = {
          fc: f.fc,
          address: f.address,
          quantity: f.quantity ?? 1,
          count: 0,
          intervals: [],
          lastTs: 0,
          vMin: Infinity,
          vMax: -Infinity,
          vSum: 0,
          vCount: 0,
        };
        c.addrs.set(key, a);
      }
      a.count++;
      if (a.lastTs > 0) a.intervals.push(f.tsMs - a.lastTs);
      a.lastTs = f.tsMs;
      // 取值范围：写请求带 values/value；读响应在检测阶段另由响应帧补充（learn 只收请求也可，
      // 但值范围主要来自响应，所以 learner 同时接受响应帧，见下方响应处理）
      for (const v of f.values ?? []) {
        a.vMin = Math.min(a.vMin, v);
        a.vMax = Math.max(a.vMax, v);
        a.vSum += v;
        a.vCount++;
      }
      if (f.value != null && (f.fc === 5 || f.fc === 6)) {
        a.vMin = Math.min(a.vMin, f.value);
        a.vMax = Math.max(a.vMax, f.value);
        a.vSum += f.value;
        a.vCount++;
      }
    }
  }

  /** 响应帧里的值并入对应 (fc, address) 基线（读响应本身没地址，按最近同 transId 请求配对） */
  learnResponse(f: ModbusFrame, reqAddress: number | undefined): void {
    if (f.kind !== 'response' || reqAddress == null || !f.values?.length) return;
    const c = this.conns.get(f.connId);
    if (!c) return;
    const key = `${f.fc}:${reqAddress}`;
    let a = c.addrs.get(key);
    if (!a) {
      a = {
        fc: f.fc,
        address: reqAddress,
        quantity: f.quantity ?? f.values.length,
        count: 0,
        intervals: [],
        lastTs: 0,
        vMin: Infinity,
        vMax: -Infinity,
        vSum: 0,
        vCount: 0,
      };
      c.addrs.set(key, a);
    }
    for (const v of f.values) {
      a.vMin = Math.min(a.vMin, v);
      a.vMax = Math.max(a.vMax, v);
      a.vSum += v;
      a.vCount++;
    }
  }

  build(learnedAtMs: number): Baseline {
    const out: ConnBaseline[] = [];
    for (const c of this.conns.values()) {
      const unitId = c.unitIds.values().next().value ?? 1;
      const addrs: AddressBaseline[] = [];
      for (const a of c.addrs.values()) {
        addrs.push({
          key: `${a.fc}:${a.address}`,
          fc: a.fc,
          address: a.address,
          quantity: a.quantity,
          count: a.count,
          periodMs: percentileStats(a.intervals),
          valueMin: a.vCount ? a.vMin : 0,
          valueMax: a.vCount ? a.vMax : 0,
          valueMean: a.vCount ? a.vSum / a.vCount : 0,
          lastSeenMs: a.lastTs,
        });
      }
      addrs.sort((x, y) => x.address - y.address);
      out.push({
        connId: c.connId,
        clientIp: c.clientIp,
        clientPort: c.clientPort,
        serverIp: c.serverIp,
        serverPort: c.serverPort,
        unitId,
        periodMs: percentileStats(c.intervals),
        requestCount: c.requestCount,
        fcs: [...c.fcs].sort((x, y) => x - y),
        addrMin: c.addrMin === 0xffff ? 0 : c.addrMin,
        addrMax: c.addrMax,
        addrs,
      });
    }
    out.sort((a, b) => a.connId.localeCompare(b.connId));
    return {
      learnedAtMs,
      windowStartMs: this.windowStart === Infinity ? 0 : this.windowStart,
      windowEndMs: this.windowEnd,
      conns: out,
    };
  }
}

function percentileStats(samples: number[]): { p50: number; p95: number; min: number; max: number } {
  if (!samples.length) return { p50: 0, p95: 0, min: 0, max: 0 };
  const s = [...samples].sort((a, b) => a - b);
  const pick = (q: number) => s[Math.min(s.length - 1, Math.floor(q * s.length))];
  return { p50: pick(0.5), p95: pick(0.95), min: s[0], max: s[s.length - 1] };
}
