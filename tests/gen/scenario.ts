/**
 * 测试场景生成。
 *
 * 时间线（默认）：
 *   0–90s   正常轮询（基线学习窗口取前 60s）
 *   ~20s    TCP 拆段 / 乱序 / 重传（验证重组正确性，不产生攻击告警）
 *   95s     写线圈攻击 FC5
 *   100s    写多寄存器攻击 FC16
 *   105s    越界地址访问（基线外地址）
 *   110s    地址扫描（5s 内 25 个不同地址）
 *   120s    重放攻击（原样重发历史写请求，间隔偏离周期）
 *
 * ground truth 与 pcap 一并落盘，测试按时间戳比对，要求检出误差 ≤1s。
 */
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { PcapWriter, PcapngWriter } from './pcap-writer';
import {
  ACK,
  FIN,
  PSH,
  SYN,
  ackData,
  buildTcpPacket,
  mbEchoResponse,
  mbException,
  mbReadResponse,
  mbRequest,
  newTcpCtx,
  type Endpoint,
} from './builders';

export interface GroundTruthEvent {
  type: 'write-coil' | 'write-register' | 'out-of-range' | 'scan' | 'replay' | 'modbus-exception';
  /** 攻击注入的精确时间（毫秒） */
  tsMs: number;
  description: string;
}

export interface GroundTruth {
  file: string;
  format: 'pcap' | 'pcapng';
  baselineWindowMs: number;
  normalStartMs: number;
  normalEndMs: number;
  events: GroundTruthEvent[];
  /** 正常轮询的周期，供基线测试断言 */
  expectedPollPeriodMs: number;
  /** 正常寄存器值的范围 */
  expectedValueRange: { min: number; max: number };
  /** 乱序/重传/拆段注入位置 */
  tcpQuirks: { splitAtMs: number; outOfOrderAtMs: number; retransmitAtMs: number };
}

const SCADA: Endpoint = { ip: '10.10.0.20', port: 49201, mac: '02:00:00:00:00:20' };
const PLC: Endpoint = { ip: '10.10.0.10', port: 502, mac: '02:00:00:00:00:10' };
const UNIT = 1;
const POLL_MS = 1000;
const NORMAL_SEC = 90;

export interface GenOptions {
  outDir: string;
  formats?: Array<'pcap' | 'pcapng'>;
}

export async function generateScenario(opts: GenOptions): Promise<GroundTruth[]> {
  await mkdir(opts.outDir, { recursive: true });
  const formats = opts.formats ?? ['pcap', 'pcapng'];
  const results: GroundTruth[] = [];

  for (const format of formats) {
    const writer = format === 'pcap' ? new PcapWriter(1) : new PcapngWriter(1);
    const events: GroundTruthEvent[] = [];
    const cCtx = newTcpCtx();
    const sCtx = newTcpCtx();
    let transId = 1;
    // 用固定 epoch 基准（2026-01-01T00:00:00Z），避免相对时间戳在 Date/基线窗口计算中语义模糊
    const BASE_MS = Date.UTC(2026, 0, 1);
    const at = (ms: number) => (BASE_MS + ms) * 1000;

    const emitC2s = (payload: Uint8Array, ms: number, flags = PSH | ACK, advance = true) => {
      const frame = buildTcpPacket({ src: SCADA, dst: PLC, ctx: cCtx, flags, payload, advanceSeq: advance });
      writer.packet(frame, at(ms));
      if (advance) ackData(sCtx, payload.length);
      return frame;
    };
    const emitS2r = (payload: Uint8Array, ms: number, flags = PSH | ACK) => {
      const frame = buildTcpPacket({ src: PLC, dst: SCADA, ctx: sCtx, flags, payload });
      writer.packet(frame, at(ms));
      ackData(cCtx, payload.length);
    };
    const pureAck = (ms: number) => {
      writer.packet(buildTcpPacket({ src: SCADA, dst: PLC, ctx: cCtx, flags: ACK }), at(ms));
    };
    /** ground truth 时间戳与 pcap 帧使用同一绝对时间基准 */
    const mark = (type: GroundTruthEvent['type'], relMs: number, description: string) => {
      events.push({ type, tsMs: BASE_MS + relMs, description });
    };

    // ---- 三次握手 ----
    writer.packet(buildTcpPacket({ src: SCADA, dst: PLC, ctx: cCtx, flags: SYN }), at(0));
    writer.packet(buildTcpPacket({ src: PLC, dst: SCADA, ctx: sCtx, flags: SYN | ACK }), at(1));
    writer.packet(buildTcpPacket({ src: SCADA, dst: PLC, ctx: cCtx, flags: ACK }), at(1));
    sCtx.ack = cCtx.seq;
    cCtx.ack = sCtx.seq;

    // ---- 正常轮询 0..90s：FC3 读保持寄存器 地址0 数量10，值在 40..60 内周期波动 ----
    const baseRegs = [42, 51, 47, 55, 44, 58, 49, 53, 46, 50];
    for (let ms = 10; ms <= NORMAL_SEC * 1000; ms += POLL_MS) {
      const tick = Math.floor(ms / POLL_MS);
      const values = baseRegs.map((v, i) => clamp(v + ((tick + i) % 5) - 2, 40, 60));
      const req = mbRequest(transId, UNIT, 3, 0, 10);
      emitC2s(req, ms);
      emitS2r(mbReadResponse(transId, UNIT, 3, values), ms + 20);
      transId++;
    }

    // ---- TCP 重组考验（约 20s 处插入，夹在正常轮询之间）----
    const quirksMs = 20500;
    // 1) 拆段：一个 Modbus 请求拆成两个 TCP 段
    {
      const req = mbRequest(transId, UNIT, 3, 100, 4);
      const half = Math.ceil(req.length / 2);
      // 第一段：只推进 half，剩余 half 由第二段推进
      const f1 = buildTcpPacket({ src: SCADA, dst: PLC, ctx: cCtx, flags: PSH | ACK, payload: req.subarray(0, half) });
      writer.packet(f1, at(quirksMs));
      const f2 = buildTcpPacket({ src: SCADA, dst: PLC, ctx: cCtx, flags: PSH | ACK, payload: req.subarray(half) });
      writer.packet(f2, at(quirksMs + 2));
      ackData(sCtx, req.length);
      emitS2r(mbReadResponse(transId, UNIT, 3, [10, 11, 12, 13]), quirksMs + 25);
      transId++;
    }
    // 2) 乱序：先发高 seq 段，再补发低 seq 段（用独立 seq 控制，不污染共享 ctx 的连续推进）
    {
      const reqA = mbRequest(transId, UNIT, 3, 200, 2);
      const reqB = mbRequest(transId + 1, UNIT, 3, 202, 2);
      const seqA = cCtx.seq;
      const seqB = (seqA + reqA.length) >>> 0;
      const seqAfter = (seqB + reqB.length) >>> 0;
      // 先到 B（乱序），advanceSeq=false 防止内部推进
      writer.packet(
        buildTcpPacket({ src: SCADA, dst: PLC, ctx: { ...cCtx, seq: seqB }, flags: PSH | ACK, payload: reqB, advanceSeq: false }),
        at(21000),
      );
      // 再到 A 补齐缺口
      writer.packet(
        buildTcpPacket({ src: SCADA, dst: PLC, ctx: { ...cCtx, seq: seqA }, flags: PSH | ACK, payload: reqA, advanceSeq: false }),
        at(21050),
      );
      // 共享 ctx 一次性推进到两段之后，保持后续序列号连续
      cCtx.seq = seqAfter;
      ackData(sCtx, reqA.length + reqB.length);
      emitS2r(mbReadResponse(transId, UNIT, 3, [20, 21]), 21100);
      emitS2r(mbReadResponse(transId + 1, UNIT, 3, [22, 23]), 21120);
      transId += 2;
    }
    // 3) 重传：同一 seq 原样再发一次（必须显式回退 seq，模拟真实 TCP 重传语义）
    {
      const req = mbRequest(transId, UNIT, 3, 300, 2);
      emitC2s(req, 22000);
      const retransSeq = (cCtx.seq - req.length) >>> 0; // 回到该载荷原始起始 seq
      writer.packet(
        buildTcpPacket({
          src: SCADA,
          dst: PLC,
          ctx: { ...cCtx, seq: retransSeq },
          flags: PSH | ACK,
          payload: req,
          advanceSeq: false,
        }),
        at(22300),
      );
      emitS2r(mbReadResponse(transId, UNIT, 3, [30, 31]), 22050);
      transId++;
    }

    // ---- 攻击 1：写单个线圈 FC5（95s）----
    {
      const ms = 95000;
      const req = mbRequest(transId, UNIT, 5, 8192, 1, [1]);
      emitC2s(req, ms);
      emitS2r(mbEchoResponse(transId, UNIT, 5, 8192, 1), ms + 20);
      mark('write-coil', ms, 'FC5 写线圈 地址8192=ON');
      transId++;
    }

    // ---- 攻击 2：写多寄存器 FC16（100s）----
    {
      const ms = 100000;
      const req = mbRequest(transId, UNIT, 16, 4000, 4, [1, 2, 3, 4]);
      emitC2s(req, ms);
      emitS2r(mbEchoResponse(transId, UNIT, 16, 4000, 4), ms + 20);
      mark('write-register', ms, 'FC16 写寄存器 地址4000 数量4');
      transId++;
    }

    // ---- 攻击 3：越界地址（105s，基线地址范围只有 0..9 / 100..等正常区，47000 明显越界）----
    {
      const ms = 105000;
      const req = mbRequest(transId, UNIT, 3, 47000, 8);
      emitC2s(req, ms);
      emitS2r(mbException(transId, UNIT, 3, 2), ms + 15); // 非法地址异常
      mark('out-of-range', ms, 'FC3 访问基线外地址 47000');
      mark('modbus-exception', ms + 15, '设备返回异常码 2');
      transId++;
    }

    // ---- 攻击 4：地址扫描（110s 起，1s 内 25 个不同地址）----
    {
      const startMs = 110000;
      for (let i = 0; i < 25; i++) {
        const ms = startMs + i * 40;
        const req = mbRequest(transId, UNIT, 3, 20000 + i, 1);
        emitC2s(req, ms);
        emitS2r(mbException(transId, UNIT, 3, 2), ms + 10);
        transId++;
      }
      mark('scan', startMs, '5s 窗口内扫描 25 个不同地址（阈值20）');
    }

    // ---- 攻击 5：重放（120s，原样重发 95s 的写线圈请求，间隔远偏离 1s 轮询周期）----
    {
      const ms = 120000;
      const replayReq = mbRequest(transId, UNIT, 5, 8192, 1, [1]);
      emitC2s(replayReq, ms);
      emitS2r(mbEchoResponse(transId, UNIT, 5, 8192, 1), ms + 20);
      mark('replay', ms, '重放 FC5 写线圈（同签名，间隔25s，偏离周期）');
      transId++;
      // 再来一次，保证重放签名命中
      const ms2 = 120500;
      const replayReq2 = mbRequest(transId, UNIT, 5, 8192, 1, [1]);
      emitC2s(replayReq2, ms2);
      emitS2r(mbEchoResponse(transId, UNIT, 5, 8192, 1), ms2 + 20);
      mark('replay', ms2, '重放 FC5 写线圈（第二次）');
      transId++;
    }

    // ---- 挥手 ----
    pureAck(125000);
    writer.packet(buildTcpPacket({ src: SCADA, dst: PLC, ctx: cCtx, flags: FIN | ACK }), at(125100));
    writer.packet(buildTcpPacket({ src: PLC, dst: SCADA, ctx: sCtx, flags: FIN | ACK }), at(125200));
    writer.packet(buildTcpPacket({ src: SCADA, dst: PLC, ctx: cCtx, flags: ACK }), at(125300));

    const file = `synthetic.${format}`;
    await writer.save(join(opts.outDir, file));
    const gt: GroundTruth = {
      file,
      format,
      baselineWindowMs: 60_000,
      normalStartMs: BASE_MS,
      normalEndMs: BASE_MS + NORMAL_SEC * 1000,
      events,
      expectedPollPeriodMs: POLL_MS,
      expectedValueRange: { min: 40, max: 60 },
      tcpQuirks: { splitAtMs: quirksMs, outOfOrderAtMs: 21000, retransmitAtMs: 22000 },
    };
    results.push(gt);
  }
  return results;
}

function clamp(v: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, v));
}
