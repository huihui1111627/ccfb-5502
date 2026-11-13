/**
 * 大文件流式压力测试（独立脚本，不进 vitest 默认套件）。
 *
 * 目标：证明解析内存与文件大小解耦——读取侧任何时刻只持有一个 4MiB 窗口，
 * 不把整个 pcap 读进内存。这是浏览器处理 2GB 抓包的核心约束。
 *
 * 做法：
 *  1. 用写入流生成目标大小的 pcap（默认 ~300MB、数百万帧），写盘不堆内存
 *  2. 用 fd 流式 ChunkSource（语义对齐浏览器 File.slice：按偏移读、不全量装载）
 *  3. 跑分析引擎并周期采样 heapUsed，断言峰值只含「一个读取窗口 + 结构化结果」
 *
 * 运行：npx tsx tests/stress/large-file.mts [目标MB]
 */
import { createWriteStream } from 'node:fs';
import { open, mkdir, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ChunkSource } from '../../src/core/chunk';
import { runAnalysis, TXN_CACHE_MAX } from '../../src/core/engine';
import { buildTcpPacket, mbRequest, mbReadResponse, newTcpCtx, ACK, FIN, PSH, SYN } from '../gen/builders';
import type { Endpoint } from '../gen/builders';

const TARGET_MB = Number(process.argv[2] ?? 300);
const TARGET_BYTES = TARGET_MB * 1024 * 1024;

const SCADA: Endpoint = { ip: '10.10.0.20', port: 49201, mac: '02:00:00:00:00:20' };
const PLC: Endpoint = { ip: '10.10.0.10', port: 502, mac: '02:00:00:00:00:10' };
const BASE_MS = Date.UTC(2026, 0, 1);

/** fd 流式数据源：与浏览器 BlobChunkSource 同接口，按偏移读、永不全量装载 */
class FdChunkSource implements ChunkSource {
  constructor(
    private readonly fd: import('node:fs/promises').FileHandle,
    readonly size: number,
  ) {}
  async read(offset: number, len: number): Promise<ArrayBuffer> {
    const n = Math.min(len, this.size - offset);
    const buf = new ArrayBuffer(n);
    await this.fd.read(new Uint8Array(buf), 0, n, offset);
    return buf;
  }
}

function globalHeader(): Uint8Array {
  const gh = new ArrayBuffer(24);
  const dv = new DataView(gh);
  dv.setUint32(0, 0xa1b2c3d4, true);
  dv.setUint16(4, 2, true);
  dv.setUint16(6, 4, true);
  dv.setUint32(16, 65535, true);
  dv.setUint32(20, 1, true);
  return new Uint8Array(gh);
}

function record(frame: Uint8Array, tsUs: number): Uint8Array {
  const pad = (4 - (frame.length % 4)) % 4;
  const rec = new Uint8Array(16 + frame.length + pad);
  const dv = new DataView(rec.buffer);
  dv.setUint32(0, Math.floor(tsUs / 1e6), true);
  dv.setUint32(4, tsUs % 1e6, true);
  dv.setUint32(8, frame.length, true);
  dv.setUint32(12, frame.length, true);
  rec.set(frame, 16);
  return rec;
}

async function main() {
  const dir = join(tmpdir(), 'ics-stress');
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  const path = join(dir, `large-${TARGET_MB}mb.pcap`);

  // ---- 1. 流式生成 ----
  const ws = createWriteStream(path);
  const drain = () => new Promise<void>((res) => ws.once('drain', res));
  ws.write(globalHeader());

  const cCtx = newTcpCtx();
  const sCtx = newTcpCtx();
  // 所有帧（含握手/挥手）都必须套 pcap 记录头，否则破坏记录对齐
  const writeRec = (frame: Uint8Array, relMs: number) => {
    const r = record(frame, (BASE_MS + relMs) * 1000);
    if (!ws.write(r)) return drain();
    return Promise.resolve();
  };
  await writeRec(buildTcpPacket({ src: SCADA, dst: PLC, ctx: cCtx, flags: SYN }), 0);
  await writeRec(buildTcpPacket({ src: PLC, dst: SCADA, ctx: sCtx, flags: SYN | ACK }), 1);
  await writeRec(buildTcpPacket({ src: SCADA, dst: PLC, ctx: cCtx, flags: ACK }), 1);
  sCtx.ack = cCtx.seq;
  cCtx.ack = sCtx.seq;

  let n = 0;
  let bytes = 24;
  let transId = 1;
  let t = 10;
  while (bytes < TARGET_BYTES) {
    const req = mbRequest(transId, 1, 3, 0, 10);
    const r1 = record(buildTcpPacket({ src: SCADA, dst: PLC, ctx: cCtx, flags: PSH | ACK, payload: req }), (BASE_MS + t) * 1000);
    if (!ws.write(r1)) await drain();
    bytes += r1.length;

    const resp = mbReadResponse(transId, 1, 3, [42, 43, 44, 45, 46, 47, 48, 49, 50, 51]);
    const r2 = record(buildTcpPacket({ src: PLC, dst: SCADA, ctx: sCtx, flags: PSH | ACK, payload: resp }), (BASE_MS + t + 5) * 1000);
    if (!ws.write(r2)) await drain();
    bytes += r2.length;

    transId++;
    t += 100;
    n++;
  }
  await writeRec(buildTcpPacket({ src: SCADA, dst: PLC, ctx: cCtx, flags: FIN | ACK }), t + 1000);
  await writeRec(buildTcpPacket({ src: PLC, dst: SCADA, ctx: sCtx, flags: FIN | ACK }), t + 1100);
  await new Promise<void>((res) => ws.end(res));

  const fileBytes = (await stat(path)).size;
  console.log(`生成完成: ${path}`);
  console.log(`  文件大小: ${(fileBytes / 1048576).toFixed(1)} MB，Modbus 事务 ${n.toLocaleString()} 个（${(n * 2).toLocaleString()} ADU）`);

  // ---- 2. fd 流式解析 + 堆采样 ----
  if (global.gc) global.gc();
  const heapBefore = process.memoryUsage().heapUsed;
  const samples: number[] = [];
  const timer = setInterval(() => samples.push(process.memoryUsage().heapUsed), 100);

  const fh = await open(path, 'r');
  try {
    const src = new FdChunkSource(fh, fileBytes);
    // 计数 sink：不保留任何帧/Modbus/告警对象，模拟 Worker 落盘场景下引擎的真实常驻内存
    let modbusCount = 0;
    let alertCount = 0;
    let packetCount = 0;
    const result = await runAnalysis(src, {
      baselineWindowMs: 60_000,
      progressInterval: 65536,
      sink: {
        onPacket: () => { packetCount++; },
        onModbus: () => { modbusCount++; },
        onAlert: () => { alertCount++; },
      },
    });
    clearInterval(timer);
    const peakHeap = Math.max(heapBefore, ...samples);

    console.log(`\n解析完成:`);
    console.log(`  帧总数: ${packetCount.toLocaleString()}`);
    console.log(`  Modbus 帧: ${modbusCount.toLocaleString()}（期望 ${(n * 2).toLocaleString()}）`);
    console.log(`  告警: ${alertCount}`);
    console.log(`  连接数: ${result.conns.length}`);
    console.log(`\n内存（MB）:`);
    console.log(`  解析前 heapUsed: ${(heapBefore / 1048576).toFixed(1)}`);
    console.log(`  解析期堆峰值: ${(peakHeap / 1048576).toFixed(1)}`);
    console.log(`  文件大小: ${(fileBytes / 1048576).toFixed(1)} MB`);
    console.log(`  峰值/文件比: ${((peakHeap / fileBytes) * 100).toFixed(2)}%`);

    // 正确性
    if (modbusCount !== n * 2) {
      throw new Error(`Modbus 帧数不符：期望 ${n * 2}，实际 ${modbusCount}`);
    }
    // 引擎常驻内存有界：上界 = 读取窗口(4MiB) + 两个 10 万元素有界缓存的 V8 实际开销
    // （每条字符串键+对象约 300~400B，取宽松上界 400B）+ 连接/基线 + 运行时余量。
    // 关键：该预算是常数，不随文件大小/帧数变化，这才是流式架构的承诺。
    const perEntry = 400;
    const residentBudget =
      4 * 1048576 + // 一个读取窗口
      TXN_CACHE_MAX * perEntry * 2 + // txnMap + seenFrames 两个有界缓存的宽松上界
      64 * 1048576; // 连接/基线/GC/解析临时对象余量
    if (peakHeap > residentBudget) {
      throw new Error(
        `内存超预算：峰值 ${(peakHeap / 1048576).toFixed(1)}MB > 常驻预算 ${(residentBudget / 1048576).toFixed(1)}MB`,
      );
    }
    console.log(`\n✅ 通过：峰值 ${(peakHeap / 1048576).toFixed(1)}MB，预算 ${(residentBudget / 1048576).toFixed(1)}MB（与帧数无关的常数上界）`);
  } finally {
    await fh.close();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
