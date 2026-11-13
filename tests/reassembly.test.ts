import { describe, it, expect } from 'vitest';
import { TcpReassembler } from '../src/core/reassembly';
import { ModbusParser } from '../src/core/modbus';
import { mbRequest, mbReadResponse } from './gen/builders';
import type { RawPacket, StreamSegment, ModbusFrame } from '../src/core/types';

function pkt(seq: number, payloadLen: number, index: number, tsMs = index): RawPacket {
  return {
    index,
    tsMs,
    fileOffset: 0,
    fileRecordLen: 0,
    capLen: 54 + payloadLen,
    origLen: 54 + payloadLen,
    l2: 'ethernet',
    srcIp: '1.1.1.1',
    dstIp: '2.2.2.2',
    ipProto: 6,
    srcPort: 12345,
    dstPort: 502,
    seq,
    ack: 1,
    tcpFlags: 0x18,
    payloadOffset: 54,
    payloadLength: payloadLen,
  };
}

function frameFor(payload: Uint8Array): Uint8Array {
  const f = new Uint8Array(54 + payload.length);
  f.set(payload, 54);
  return f;
}

describe('TCP 重组器', () => {
  it('序列号回绕正确处理', () => {
    const segs: StreamSegment[] = [];
    const r = new TcpReassembler({ onSegment: (s) => segs.push(s) });
    const isn = 0xfffffffa;
    // 三段跨过 32 位回绕点
    const p1 = new Uint8Array(10).fill(1);
    const p2 = new Uint8Array(10).fill(2);
    const p3 = new Uint8Array(10).fill(3);
    r.handle({ ...pkt(isn + 1, 10, 0), seq: isn + 1 }, frameFor(p1)); // rel 1..11
    r.handle({ ...pkt((isn + 11) >>> 0, 10, 1), seq: (isn + 11) >>> 0 }, frameFor(p2));
    r.handle({ ...pkt((isn + 21) >>> 0, 10, 2), seq: (isn + 21) >>> 0 }, frameFor(p3));
    expect(segs.length).toBe(3);
    const all = new Uint8Array([...segs[0].data, ...segs[1].data, ...segs[2].data]);
    expect(all.slice(0, 10).every((b) => b === 1)).toBe(true);
    expect(all.slice(10, 20).every((b) => b === 2)).toBe(true);
    expect(all.slice(20, 30).every((b) => b === 3)).toBe(true);
  });

  it('乱序到达后按序上交，重传被丢弃', () => {
    const segs: StreamSegment[] = [];
    const r = new TcpReassembler({ onSegment: (s) => segs.push(s) });
    const isn = 1000;
    // 先过 SYN 握手，建立 ISN（真实抓包语义）
    const synPkt: RawPacket = {
      ...pkt(isn, 0, -1, 0),
      tcpFlags: 0x02,
      payloadLength: undefined,
      payloadOffset: undefined,
    };
    r.handle(synPkt, new Uint8Array(54));

    const a = new Uint8Array([1, 2, 3, 4]);
    const b = new Uint8Array([5, 6, 7, 8]);
    // 先到 B（乱序）
    r.handle({ ...pkt(isn + 5, 4, 0), seq: isn + 5 }, frameFor(b));
    expect(segs.length).toBe(0);
    const stats0 = r.getConns()[0];
    expect(stats0.outOfOrder).toBe(1);
    // 再到 A，触发 A、B 连续上交
    r.handle({ ...pkt(isn + 1, 4, 1), seq: isn + 1 }, frameFor(a));
    expect(segs.length).toBe(2);
    expect([...segs[0].data]).toEqual([1, 2, 3, 4]);
    expect([...segs[1].data]).toEqual([5, 6, 7, 8]);
    // A 重传一次
    r.handle({ ...pkt(isn + 1, 4, 2), seq: isn + 1 }, frameFor(a));
    expect(segs.length).toBe(2);
    expect(r.getConns()[0].retransmits).toBe(1);
  });

  it('部分重叠段去重后只上交新字节', () => {
    const segs: StreamSegment[] = [];
    const r = new TcpReassembler({ onSegment: (s) => segs.push(s) });
    const isn = 5000;
    r.handle({ ...pkt(isn + 1, 8, 0), seq: isn + 1 }, frameFor(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])));
    // 起点回退 4 字节的重传+新数据
    r.handle({ ...pkt(isn + 5, 8, 1), seq: isn + 5 }, frameFor(new Uint8Array([5, 6, 7, 8, 9, 10, 11, 12])));
    expect(segs.length).toBe(2);
    expect([...segs[1].data]).toEqual([9, 10, 11, 12]);
  });
});

describe('Modbus 解析器', () => {
  it('跨 TCP 段的 ADU 被完整重组，粘包一次解出多帧', () => {
    const frames: ModbusFrame[] = [];
    const parser = new ModbusParser((f) => frames.push(f));
    const base = {
      connId: 'c',
      srcIp: '1.1.1.1',
      srcPort: 12345,
      dstIp: '2.2.2.2',
      dstPort: 502,
      seq: 1,
      packetIndex: 0,
      tsMs: 0,
    };

    const req1 = mbRequest(1, 1, 3, 0, 10);
    const req2 = mbRequest(2, 1, 3, 10, 2);
    const glue = new Uint8Array(req1.length + req2.length);
    glue.set(req1, 0);
    glue.set(req2, req1.length);

    // 拆成 3 段喂入
    const cut1 = 5;
    const cut2 = req1.length + 3;
    parser.feed({ ...base, dir: 'C2S', data: glue.subarray(0, cut1), packetIndex: 0 });
    parser.feed({ ...base, dir: 'C2S', data: glue.subarray(cut1, cut2), packetIndex: 1 });
    parser.feed({ ...base, dir: 'C2S', data: glue.subarray(cut2), packetIndex: 2 });

    expect(frames.length).toBe(2);
    expect(frames[0].transId).toBe(1);
    expect(frames[0].address).toBe(0);
    expect(frames[0].quantity).toBe(10);
    expect(frames[1].transId).toBe(2);
    expect(frames[1].address).toBe(10);
  });

  it('功能码解析：读响应解出寄存器值，写请求解出地址与值', () => {
    const frames: import('../src/core/types').ModbusFrame[] = [];
    const parser = new ModbusParser((f) => frames.push(f));
    const base = {
      connId: 'c',
      srcIp: '2.2.2.2',
      srcPort: 502,
      dstIp: '1.1.1.1',
      dstPort: 12345,
      seq: 1,
      packetIndex: 0,
      tsMs: 0,
    };
    parser.feed({ ...base, dir: 'S2R', data: mbReadResponse(7, 1, 3, [100, 200, 65535]) });
    const reqBase = { ...base, srcIp: '1.1.1.1', srcPort: 12345, dstIp: '2.2.2.2', dstPort: 502, dir: 'C2S' as const };
    parser.feed({ ...reqBase, data: mbRequest(8, 1, 16, 4000, 3, [1, 2, 3]) });

    expect(frames[0].values).toEqual([100, 200, 65535]);
    expect(frames[1].fc).toBe(16);
    expect(frames[1].address).toBe(4000);
    expect(frames[1].values).toEqual([1, 2, 3]);
  });
});
