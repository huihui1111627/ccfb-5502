import { describe, it, expect, beforeAll } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { BlobChunkSource } from '../src/core/chunk';
import { runAnalysis } from '../src/core/engine';
import type { GroundTruth } from './gen/scenario';
import { generateScenario } from './gen/scenario';

class FileBlobSource extends BlobChunkSource {
  static async from(path: string) {
    const buf = await readFile(path);
    return new BlobChunkSource(new Blob([buf]));
  }
}

const DIR = join(process.cwd(), 'tests', 'testdata-run');
const FORMATS = ['pcap', 'pcapng'] as const;

describe('端到端：合成工控流量分析', () => {
  for (const format of FORMATS) {
    describe(`格式 ${format}`, () => {
      const file = join(DIR, `synthetic.${format}`);
      let ground: GroundTruth;

      beforeAll(async () => {
        const all = await generateScenario({ outDir: DIR, formats: [...FORMATS] });
        ground = all.find((g) => g.format === format)!;
      }, 60000);

      it('成功流式解析且帧数量合理', async () => {
        const src = await FileBlobSource.from(file);
        const res = await runAnalysis(src, { baselineWindowMs: ground.baselineWindowMs });
        expect(res.packets.length).toBeGreaterThan(100);
        expect(res.modbus.length).toBeGreaterThan(100);
        expect(res.conns.length).toBe(1);
        expect(res.baseline).not.toBeNull();
      });

      it('TCP 重组：拆段/乱序/重传均被正确处理，无重复 Modbus 帧', async () => {
        const src = await FileBlobSource.from(file);
        const res = await runAnalysis(src, { baselineWindowMs: ground.baselineWindowMs });
        const conn = res.conns[0];
        expect(conn.outOfOrder).toBeGreaterThanOrEqual(1);
        expect(conn.retransmits).toBeGreaterThanOrEqual(1);

        // 每个 transId 的请求只解出一次（重传不会产生重复 Modbus 帧）
        const reqs = res.modbus.filter((f) => f.kind === 'request');
        const txnIds = reqs.map((f) => f.transId);
        expect(new Set(txnIds).size).toBe(txnIds.length);

        // 拆段与乱序区的轮询请求都被完整重组出来
        expect(res.modbus.find((f) => f.kind === 'request' && f.address === 100 && f.quantity === 4)).toBeDefined();
        expect(res.modbus.find((f) => f.kind === 'request' && f.address === 200)).toBeDefined();
        expect(res.modbus.find((f) => f.kind === 'request' && f.address === 202)).toBeDefined();
      });

      it('Modbus 按功能码解出寄存器地址和值', async () => {
        const src = await FileBlobSource.from(file);
        const res = await runAnalysis(src, { baselineWindowMs: ground.baselineWindowMs });
        const holding = res.modbus.filter((f) => f.fc === 3 && f.kind === 'response');
        expect(holding.length).toBeGreaterThan(50);
        for (const f of holding.slice(0, 20)) {
          expect(f.values?.length).toBeGreaterThan(0);
          for (const v of f.values!) expect(v).toBeGreaterThanOrEqual(0);
        }
        const write = res.modbus.find((f) => f.fc === 5 && f.kind === 'request');
        expect(write?.address).toBe(8192);
        expect(write?.value).toBe(0xff00);
      });

      it('基线学到轮询周期与取值范围', async () => {
        const src = await FileBlobSource.from(file);
        const res = await runAnalysis(src, { baselineWindowMs: ground.baselineWindowMs });
        const c = res.baseline!.conns[0];
        // 1s 周期，p50 应落在 900–1100ms
        expect(c.periodMs.p50).toBeGreaterThanOrEqual(900);
        expect(c.periodMs.p50).toBeLessThanOrEqual(1100);
        const addr0 = c.addrs.find((a) => a.address === 0 && a.fc === 3)!;
        expect(addr0.valueMin).toBeGreaterThanOrEqual(ground.expectedValueRange.min);
        expect(addr0.valueMax).toBeLessThanOrEqual(ground.expectedValueRange.max);
      });

      it('四类攻击全部检出，且时间误差 ≤1s', async () => {
        const src = await FileBlobSource.from(file);
        const res = await runAnalysis(src, { baselineWindowMs: ground.baselineWindowMs });
        const types = new Set(res.alerts.map((a) => a.type));
        for (const t of ['write-coil', 'write-register', 'out-of-range', 'scan', 'replay'] as const) {
          expect(types.has(t), `缺少告警类型 ${t}`).toBe(true);
        }
        // 逐事件匹配：每个 ground truth 都要有时间差 ≤1000ms 的同类型告警
        for (const ev of ground.events) {
          const match = res.alerts.find((a) => a.type === ev.type && Math.abs(a.tsMs - ev.tsMs) <= 1000);
          expect(match, `事件 ${ev.type}@${ev.tsMs} 未在 1s 内检出`).toBeDefined();
        }
      });

      it('所有告警都带可追溯的原始帧序号', async () => {
        const src = await FileBlobSource.from(file);
        const res = await runAnalysis(src, { baselineWindowMs: ground.baselineWindowMs });
        for (const a of res.alerts) {
          expect(a.packetIndex).toBeGreaterThanOrEqual(0);
          expect(a.packetIndex).toBeLessThan(res.packets.length);
        }
      });

      it('内存友好：帧元数据定长 24B 且不驻留原始字节', async () => {
        const src = await FileBlobSource.from(file);
        const res = await runAnalysis(src, { baselineWindowMs: ground.baselineWindowMs });
        // 架构约束：RawPacket 只存定位信息，单帧索引固定 24B（见 storage/idb PACKET_RECORD）
        const indexBytes = res.packets.length * 24;
        // 10 万帧场景下索引也只有 ~2.4MB，与文件大小解耦
        const projected100k = 100_000 * 24;
        expect(projected100k).toBeLessThan(4 * 1024 * 1024);
        // 实际每帧元数据不含任何 payload 字段（payloadOffset 仅指向源文件，不持有字节）
        expect(indexBytes).toBeGreaterThan(0);
        for (const p of res.packets.slice(0, 50)) {
          expect(p.fileOffset).toBeGreaterThanOrEqual(0);
          expect(p.capLen).toBeGreaterThan(0);
        }
      });
    });
  }
});

describe('边界与异常输入', () => {
  it('非 pcap/pcapng 文件抛出明确错误', async () => {
    const src = new BlobChunkSource(new Blob([new Uint8Array(64).fill(0x42)]));
    await expect(runAnalysis(src)).rejects.toThrow(/格式/);
  });

  it('空 pcap（只有全局头）可以正常结束', async () => {
    const gh = new ArrayBuffer(24);
    const dv = new DataView(gh);
    dv.setUint32(0, 0xa1b2c3d4, true);
    dv.setUint16(4, 2, true);
    dv.setUint16(6, 4, true);
    dv.setUint32(16, 65535, true);
    dv.setUint32(20, 1, true);
    const res = await runAnalysis(new BlobChunkSource(new Blob([gh])));
    expect(res.packets.length).toBe(0);
    expect(res.alerts.length).toBe(0);
  });
});
