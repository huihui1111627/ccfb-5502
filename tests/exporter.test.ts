import { describe, it, expect, beforeAll } from 'vitest';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { BlobChunkSource } from '../src/core/chunk';
import { runAnalysis } from '../src/core/engine';
import { exportPcap } from '../src/core/exporter';
import { readCapture } from '../src/core/pcap';
import { alertsToCsv, modbusToCsv } from '../src/core/exporter';
import { generateScenario } from './gen/scenario';
import type { RawPacket } from '../src/core/types';

const DIR = join(process.cwd(), 'tests', 'testdata-export');

describe('导出', () => {
  let packets: RawPacket[];
  let linkType: number;
  let src: BlobChunkSource;
  let file: string;

  beforeAll(async () => {
    const gt = await generateScenario({ outDir: DIR, formats: ['pcap'] });
    file = join(DIR, gt[0].file);
    const blob = new Blob([await readFile(file)]);
    src = new BlobChunkSource(blob);
    const res = await runAnalysis(src, { baselineWindowMs: 60000 });
    packets = res.packets;
    linkType = res.header.linkType;
  }, 60000);

  it('导出的 pcap 可被读取器重新解析，帧内容一致', async () => {
    const keep = packets.filter((_, i) => i % 10 === 0);
    const chunks: Uint8Array[] = [];
    const n = await exportPcap(src, keep, { linkType }, (c) => chunks.push(c));
    expect(n).toBe(keep.length);

    const exported = new Blob(chunks as BlobPart[]);
    const reSrc = new BlobChunkSource(exported);
    let count = 0;
    const hdr = await readCapture(
      reSrc,
      ({ packet, frame }) => {
        const orig = keep[count];
        expect(packet.tsMs).toBeCloseTo(orig.tsMs, 0);
        expect(frame.length).toBe(orig.capLen);
        count++;
      },
    );
    expect(count).toBe(keep.length);
    expect(hdr.format).toBe('pcap');
    expect(hdr.linkType).toBe(linkType);
  });

  it('CSV 导出包含表头且正确转义', () => {
    const csv = alertsToCsv([
      {
        id: 1, tsMs: 1_700_000_000_000, type: 'scan', severity: 'high', packetIndex: 3,
        title: '扫描,测试', detail: '含"引号"', status: 'open', inBaselineWindow: false,
      },
    ]);
    expect(csv).toContain('类型');
    expect(csv).toContain('"扫描,测试"');
    expect(csv).toContain('含""引号""');
  });

  it('Modbus CSV 行字段完整', () => {
    const csv = modbusToCsv([
      {
        id: 9, connId: 'c', packetIndex: 1, packetIndices: [1], tsMs: 1, kind: 'request',
        transId: 2, protoId: 0, unitId: 1, fc: 3, address: 0, quantity: 2, values: [10, 20],
        srcIp: '1.1.1.1', srcPort: 1, dstIp: '2.2.2.2', dstPort: 502, dir: 'C2S', aduLen: 12,
      },
    ]);
    expect(csv).toContain('功能码');
    expect(csv).toContain('10 20');
  });
});
