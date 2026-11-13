/**
 * 攻击/异常检测。
 * 规则（水厂工控语义）：
 *  1. write-coil / write-register：任何 FC5/15、FC6/16/23 写操作（基线通常只有轮询读）
 *  2. out-of-range：访问地址超出基线地址并集，或读响应值超出基线值范围
 *  3. scan：滑动窗口内同一源对同一设备发起大量不同地址/功能码的探测请求
 *  4. replay：相同 (unitId,fc,address,quantity,values) 的请求在非轮询周期内重复出现，
 *     且间隔明显偏离基线周期（重放工具的典型特征：原样重发历史写请求）
 *  5. modbus-exception：设备返回异常码（辅助告警）
 */
import type { Alert, Baseline, ConnBaseline, ModbusFrame } from './types';
import { FC } from './types';

interface ScanState {
  keys: Set<string>;
  windowStart: number;
  packets: number;
}

interface ReplayState {
  signature: string;
  lastTs: number;
  count: number;
}

const SCAN_WINDOW_MS = 5000;
const SCAN_UNIQUE_THRESHOLD = 20; // 5s 内 20 个不同 (fc,addr) 判定扫描
const REPLAY_RATIO = 0.35; // 实际间隔 < 基线 p50 的 35%，视为非周期性重发

export class Detector {
  private alertId = 0;
  private scans = new Map<string, ScanState>();
  private replays = new Map<string, ReplayState>();
  /** transId -> 最近请求（响应配对用） */
  private pendingReq = new Map<string, ModbusFrame>();

  constructor(
    private baseline: Baseline | null,
    private baselineWindowMs: number,
  ) {}

  detect(f: ModbusFrame, nowMs: number): Alert[] {
    const inWindow = nowMs <= this.baselineWindowMs;
    const out: Alert[] = [];
    const connBase = this.baseline?.conns.find((c) => c.connId === f.connId) ?? null;

    if (f.kind === 'request') {
      this.pendingReq.set(this.reqKey(f), f);

      // 规则 1：写操作
      if (f.fc === FC.WRITE_SINGLE_COIL || f.fc === FC.WRITE_MULTI_COIL) {
        out.push(this.mk(f, 'write-coil', 'high',
          `写线圈操作 FC${f.fc} 地址=${f.address} 数量=${f.quantity ?? 1}`,
          `源 ${f.srcIp}:${f.srcPort} 向单元 ${f.unitId} 写入线圈，正常轮询基线中无写操作`, inWindow));
      }
      if (f.fc === FC.WRITE_SINGLE_REG || f.fc === FC.WRITE_MULTI_REG || f.fc === FC.READ_WRITE_MULTI) {
        out.push(this.mk(f, 'write-register', 'high',
          `写寄存器操作 FC${f.fc} 地址=${f.address} 数量=${f.quantity ?? 1}`,
          `源 ${f.srcIp}:${f.srcPort} 向单元 ${f.unitId} 写入保持寄存器`, inWindow));
      }

      // 规则 2：越界地址
      if (connBase && f.address != null && !this.addressKnown(connBase, f)) {
        out.push(this.mk(f, 'out-of-range', 'medium',
          `越界地址访问 FC${f.fc} 地址=${f.address}`,
          `基线地址范围 [${connBase.addrMin}, ${connBase.addrMax}]，功能码基线 [${connBase.fcs.join(',')}]`,
          inWindow));
      }

      // 规则 3：扫描
      const scanAlert = this.detectScan(f, inWindow);
      if (scanAlert) out.push(scanAlert);

      // 规则 4：重放
      const replayAlert = this.detectReplay(f, connBase, inWindow);
      if (replayAlert) out.push(replayAlert);
    }

    if (f.kind === 'exception') {
      out.push(this.mk(f, 'modbus-exception', 'low',
        `Modbus 异常响应 FC${f.fc} 异常码=${f.exceptionCode}`,
        `设备 ${f.srcIp}:${f.srcPort} 拒绝请求（异常码 ${f.exceptionCode}）`, inWindow));
    }

    if (f.kind === 'response' && connBase && f.values?.length) {
      // 规则 2b：响应值越界
      const req = this.pendingReq.get(this.respKey(f));
      const addr = req?.address;
      if (addr != null) {
        const ab = connBase.addrs.find((a) => a.fc === f.fc && a.address === addr);
        if (ab && ab.count > 0) {
          for (const v of f.values) {
            if (v < ab.valueMin || v > ab.valueMax) {
              out.push(this.mk(f, 'out-of-range', 'medium',
                `响应值越界 FC${f.fc} 地址=${addr} 值=${v}`,
                `基线值范围 [${ab.valueMin}, ${ab.valueMax}]，均值 ${ab.valueMean.toFixed(1)}`, inWindow));
              break;
            }
          }
        }
      }
    }

    return out;
  }

  private addressKnown(c: ConnBaseline, f: ModbusFrame): boolean {
    if (!c.fcs.includes(f.fc)) return false;
    if (f.address == null) return true;
    const end = f.address + (f.quantity ?? 1) - 1;
    return f.address >= c.addrMin && end <= c.addrMax;
  }

  private detectScan(f: ModbusFrame, inWindow: boolean): Alert | null {
    const key = `${f.connId}:${f.unitId}`;
    let st = this.scans.get(key);
    if (!st || f.tsMs - st.windowStart > SCAN_WINDOW_MS) {
      st = { keys: new Set(), windowStart: f.tsMs, packets: 0 };
      this.scans.set(key, st);
    }
    st.packets++;
    if (f.address != null) st.keys.add(`${f.fc}:${f.address}`);
    if (st.keys.size === SCAN_UNIQUE_THRESHOLD) {
      // 刚跨过阈值时告警一次，避免每个包都报
      return this.mk(f, 'scan', 'high',
        `Modbus 地址扫描：${SCAN_WINDOW_MS / 1000}s 内 ${st.keys.size} 个不同目标`,
        `源 ${f.srcIp}:${f.srcPort} 对单元 ${f.unitId} 遍历 ${st.keys.size} 个 (功能码,地址)，疑似探测/指纹识别`,
        inWindow);
    }
    return null;
  }

  private detectReplay(f: ModbusFrame, connBase: ConnBaseline | null, inWindow: boolean): Alert | null {
    // 只对写请求和带固定载荷的请求做签名；纯轮询读的周期性由基线周期解释
    const isWrite = f.fc === FC.WRITE_SINGLE_COIL || f.fc === FC.WRITE_SINGLE_REG ||
      f.fc === FC.WRITE_MULTI_COIL || f.fc === FC.WRITE_MULTI_REG;
    if (!isWrite || f.address == null) return null;

    const sig = `${f.connId}|${f.unitId}|${f.fc}|${f.address}|${f.quantity ?? 1}|${(f.values ?? [f.value ?? 0]).join(',')}`;
    const prev = this.replays.get(sig);
    if (!prev) {
      this.replays.set(sig, { signature: sig, lastTs: f.tsMs, count: 1 });
      return null;
    }
    const gap = f.tsMs - prev.lastTs;
    prev.lastTs = f.tsMs;
    prev.count++;

    // 周期明显偏离基线 => 重放
    const p50 = connBase?.periodMs.p50 ?? 0;
    const periodic = p50 > 0 && gap >= p50 * (1 - REPLAY_RATIO) && gap <= p50 * 2.5;
    if (!periodic) {
      return this.mk(f, 'replay', 'high',
        `疑似重放攻击：相同写请求第 ${prev.count} 次出现`,
        `签名 FC${f.fc} 地址=${f.address} 值=[${(f.values ?? [f.value]).join(',')}]，距上次 ${gap}ms（基线周期 p50=${p50}ms）`,
        inWindow);
    }
    return null;
  }

  private reqKey(f: ModbusFrame): string {
    return `${f.connId}|${f.unitId}|${f.transId}`;
  }
  private respKey(f: ModbusFrame): string {
    return `${f.connId}|${f.unitId}|${f.transId}`;
  }

  private mk(
    f: ModbusFrame,
    type: Alert['type'],
    severity: Alert['severity'],
    title: string,
    detail: string,
    inWindow: boolean,
  ): Alert {
    return {
      id: this.alertId++,
      type,
      severity,
      tsMs: f.tsMs,
      connId: f.connId,
      modbusId: f.id,
      packetIndex: f.packetIndex,
      title,
      detail,
      status: 'open',
      inBaselineWindow: inWindow,
    };
  }
}
