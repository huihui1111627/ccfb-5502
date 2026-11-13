/**
 * 分析引擎：编排整条解析管线，与运行环境（Worker / Node）无关。
 *
 * 内存策略（满足 2GB 不全量读入）：
 *  - 文件按 4MiB 窗口流式读取，原始帧不驻留内存
 *  - 结构化结果通过 Sink 接口上交：默认数组 sink 仅适合中小文件；
 *    大文件可注入有界/落盘 sink（如分块写 IndexedDB），引擎内部不长期持有结果
 *  - 引擎自身的常驻状态只与「连接数 / 学习窗口 / 待配对事务」有关，与总帧数解耦
 * 单遍扫描：先在窗口内学基线，窗口结束立刻 build，后续帧直接用基线检测。
 */
import { readCapture, type CaptureHeader } from './pcap';
import type { ChunkSource } from './chunk';
import { TcpReassembler } from './reassembly';
import { ModbusParser } from './modbus';
import { BaselineLearner } from './baseline';
import { Detector } from './detect';
import type {
  Alert,
  Baseline,
  ModbusFrame,
  ProgressEvent,
  RawPacket,
  TcpConnStats,
} from './types';

/** 结果下沉接口：引擎每产生一条结果就调用，实现方决定存内存还是落盘 */
export interface AnalysisSink {
  onPacket?(p: RawPacket): void;
  onModbus?(f: ModbusFrame): void;
  onAlert?(a: Alert): void;
}

export interface EngineOptions {
  /** 基线学习窗口（毫秒，相对抓包起点）；默认前 60s 的流量为正常时段 */
  baselineWindowMs?: number;
  onProgress?: (p: ProgressEvent) => void;
  /** 每 N 帧上报一次进度，避免 Worker 消息洪泛 */
  progressInterval?: number;
  /** 结果下沉；不传则用数组收集并随 EngineResult 返回（适合中小文件与测试） */
  sink?: AnalysisSink;
}

export interface EngineResult {
  header: CaptureHeader;
  /** 仅在未注入 sink 时填充；注入 sink 后为空数组，结果已流式上交 */
  packets: RawPacket[];
  modbus: ModbusFrame[];
  alerts: Alert[];
  counts: { packets: number; modbus: number; alerts: number };
  conns: TcpConnStats[];
  baseline: Baseline | null;
  startMs: number;
  endMs: number;
}

/**
 * 待配对事务/去重签名的有界缓存上限。
 * 工控轮询的请求-响应配对都在毫秒~秒级完成，1 万条足以覆盖任何真实乱序/重传窗口；
 * 超限按最旧淘汰。设上界是为了让引擎常驻内存与总帧数解耦（2GB 文件也不膨胀）。
 */
export const TXN_CACHE_MAX = 10_000;

export async function runAnalysis(src: ChunkSource, opts: EngineOptions = {}): Promise<EngineResult> {
  const windowMs = opts.baselineWindowMs ?? 60_000;
  const progressInterval = opts.progressInterval ?? 4096;
  const sink = opts.sink;

  // 无 sink 时才用数组兜底；注入 sink 后结果流式上交、不在引擎内累积（大文件内存关键）
  const collecting = !sink;
  const packets: RawPacket[] = [];
  const modbus: ModbusFrame[] = [];
  const alerts: Alert[] = [];
  const counts = { packets: 0, modbus: 0, alerts: 0 };

  const learner = new BaselineLearner();
  let detector = new Detector(null, Infinity);
  let baseline: Baseline | null = null;
  let baselineBuilt = false;
  let startMs = Infinity;
  let endMs = 0;
  let readBytes = 0;

  /** transId 配对：响应帧没有地址，需要找对应请求。Map 有上界，避免内存随帧数线性增长 */
  const txnMap = new Map<string, ModbusFrame>();
  /** 请求去重：同一 (连接,单元,事务ID,方向,功能码,地址) 只认第一次（TCP 重传会再次产出同帧） */
  const seenFrames = new Set<string>();

  const rememberTxn = (key: string, f: ModbusFrame) => {
    if (txnMap.size >= TXN_CACHE_MAX) {
      const oldest = txnMap.keys().next().value;
      if (oldest != null) txnMap.delete(oldest);
    }
    txnMap.set(key, f);
  };

  const reassembler = new TcpReassembler({
    onSegment: (seg) => {
      parser.feed(seg);
    },
  });
  const parser = new ModbusParser((f) => {
    const dedupKey = `${f.connId}|${f.unitId}|${f.transId}|${f.dir}|${f.fc}|${f.address ?? ''}`;
    if (seenFrames.has(dedupKey)) return; // 重传导致的重复 ADU，丢弃
    seenFrames.add(dedupKey);
    // 去重表同样设上界：仅保留近期签名，旧的不可能再被重传
    if (seenFrames.size > TXN_CACHE_MAX) {
      const oldest = seenFrames.values().next().value;
      if (oldest != null) seenFrames.delete(oldest);
    }

    counts.modbus++;
    if (collecting) modbus.push(f);
    sink?.onModbus?.(f);
    const conn = reassembler.getConns().find((c) => c.connId === f.connId);
    if (conn) conn.modbusFrames++;

    if (f.kind === 'request') {
      rememberTxn(`${f.connId}|${f.unitId}|${f.transId}`, f);
      if (!baselineBuilt) learner.learn(f);
    } else if (f.kind === 'response') {
      const req = txnMap.get(`${f.connId}|${f.unitId}|${f.transId}`);
      if (!baselineBuilt) learner.learnResponse(f, req?.address);
    }

    // 学习窗口结束：固化基线，后续帧进入正式检测
    if (!baselineBuilt && startMs !== Infinity && f.tsMs - startMs >= windowMs) {
      baseline = learner.build(f.tsMs);
      detector = new Detector(baseline, startMs + windowMs);
      baselineBuilt = true;
    }

    const found = detector.detect(f, f.tsMs);
    for (const a of found) {
      counts.alerts++;
      if (collecting) alerts.push(a);
      sink?.onAlert?.(a);
    }
  });

  const header = await readCapture(
    src,
    ({ packet, frame }) => {
      counts.packets++;
      if (collecting) packets.push(packet);
      sink?.onPacket?.(packet);
      startMs = Math.min(startMs, packet.tsMs);
      endMs = Math.max(endMs, packet.tsMs);
      reassembler.handle(packet, frame);

      if ((packet.index & (progressInterval - 1)) === 0) {
        opts.onProgress?.({
          phase: 'read',
          packets: counts.packets,
          totalBytes: src.size,
          readBytes,
          modbusFrames: counts.modbus,
          alerts: counts.alerts,
        });
      }
    },
    (b) => {
      readBytes = b;
    },
  );

  const conns = reassembler.flush();

  // 窗口内一直没出现写操作、且流量短于窗口：用全部数据建基线
  if (!baselineBuilt) {
    baseline = learner.build(endMs);
  }

  opts.onProgress?.({
    phase: 'done',
    packets: counts.packets,
    totalBytes: src.size,
    readBytes: src.size,
    modbusFrames: counts.modbus,
    alerts: counts.alerts,
  });

  return {
    header,
    packets,
    modbus,
    alerts,
    counts,
    conns,
    baseline,
    startMs: startMs === Infinity ? 0 : startMs,
    endMs,
  };
}
