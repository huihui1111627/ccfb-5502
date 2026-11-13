/**
 * Modbus/TCP (MBAP) 流解析器。
 * 输入是 TcpReassembler 上交的按序字节流，负责跨 TCP 段粘包/拆包：
 * 一个 ADU 可能横跨多个段，多个 ADU 也可能挤在同一个段里。
 * 参考 GB/T 32400 / Modbus Messaging on TCP/IP v1.0b3。
 *
 * 缓冲模型：每个 (连接,方向) 维护一个连续字节缓冲，只在 ADU 跨界时残留，
 * 每解出一个完整 ADU 就把它从缓冲头部移除。
 */
import { u16be } from './bytes';
import type { ModbusFrame, StreamSegment } from './types';
import { FC } from './types';

const MBAP_LEN = 7;

interface ConnBuf {
  bytes: Uint8Array;
  /** 缓冲首字节所在的承载帧序号（跨段时为参与帧的并集） */
  packetIndices: number[];
  /** 缓冲首字节时间戳 */
  firstTs: number;
}

export class ModbusParser {
  private bufs = new Map<string, ConnBuf>();
  private idSeq = 0;
  constructor(private onFrame: (f: ModbusFrame) => void) {}

  feed(seg: StreamSegment): void {
    const key = `${seg.connId}:${seg.dir}`;
    let buf = this.bufs.get(key);
    if (!buf) {
      buf = { bytes: new Uint8Array(0), packetIndices: [], firstTs: seg.tsMs };
      this.bufs.set(key, buf);
    }

    const wasEmpty = buf.bytes.length === 0;
    // 追加新段
    const merged = new Uint8Array(buf.bytes.length + seg.data.length);
    merged.set(buf.bytes, 0);
    merged.set(seg.data, buf.bytes.length);
    buf.bytes = merged;
    if (wasEmpty) {
      buf.packetIndices = [seg.packetIndex];
      buf.firstTs = seg.tsMs;
    } else if (!buf.packetIndices.includes(seg.packetIndex)) {
      buf.packetIndices.push(seg.packetIndex);
    }

    let off = 0;
    while (true) {
      if (buf.bytes.length - off < MBAP_LEN) break;
      const transId = u16be(buf.bytes, off);
      const protoId = u16be(buf.bytes, off + 2);
      const len = u16be(buf.bytes, off + 4);
      if (protoId !== 0) {
        // 流错位：跳过一个字节尝试再同步（正常 Modbus 流不会走到这里）
        off++;
        continue;
      }
      if (len < 2 || len > 260) {
        off++;
        continue;
      }
      const aduLen = MBAP_LEN - 1 + len; // length 字段 = unitId(1)+PDU
      if (buf.bytes.length - off < aduLen) break; // 等下一个段补齐

      const adu = buf.bytes.subarray(off, off + aduLen);
      const unitId = adu[6];
      const fcRaw = adu[7];
      const fc = fcRaw & 0x7f;
      const isException = fcRaw & 0x80;

      const frame: ModbusFrame = {
        id: this.idSeq++,
        connId: seg.connId,
        packetIndex: buf.packetIndices[0] ?? seg.packetIndex,
        packetIndices: [...buf.packetIndices],
        tsMs: buf.firstTs,
        kind: 'malformed',
        transId,
        protoId,
        unitId,
        fc,
        srcIp: seg.srcIp,
        srcPort: seg.srcPort,
        dstIp: seg.dstIp,
        dstPort: seg.dstPort,
        dir: seg.dir,
        aduLen,
      };

      if (isException) {
        frame.kind = 'exception';
        frame.exceptionCode = adu[8];
      } else {
        try {
          this.parsePdu(adu, fc, seg.dir, frame);
        } catch {
          frame.kind = 'malformed';
          frame.address = undefined;
        }
      }
      this.onFrame(frame);
      off += aduLen;
    }

    // 移除已消费字节，保留残留等待下一段；同时校正残留对应的帧归属
    if (off > 0) {
      if (off >= buf.bytes.length) {
        buf.bytes = new Uint8Array(0);
        buf.packetIndices = [seg.packetIndex];
        buf.firstTs = seg.tsMs;
      } else {
        buf.bytes = buf.bytes.slice(off);
        // 残留字节属于当前段（已完整消费的旧帧不再相关）
        buf.packetIndices = [seg.packetIndex];
        buf.firstTs = seg.tsMs;
      }
    }
  }

  /** PDU 从 adu[7] 开始（fc），adu[8..] 为参数 */
  private parsePdu(adu: Uint8Array, fc: number, dir: 'C2S' | 'S2R', frame: ModbusFrame): void {
    const p = (o: number) => u16be(adu, o); // 相对 adu 的 u16be

    if (dir === 'C2S') {
      switch (fc) {
        case FC.READ_COILS:
        case FC.READ_DISCRETE:
        case FC.READ_HOLDING:
        case FC.READ_INPUT:
          frame.kind = 'request';
          frame.address = p(8);
          frame.quantity = p(10);
          return;
        case FC.WRITE_SINGLE_COIL:
        case FC.WRITE_SINGLE_REG:
          frame.kind = 'request';
          frame.address = p(8);
          frame.value = p(10);
          frame.quantity = 1;
          return;
        case FC.WRITE_MULTI_COIL: {
          frame.kind = 'request';
          frame.address = p(8);
          frame.quantity = p(10);
          const byteCount = adu[12];
          frame.values = unpackBits(adu.subarray(13, 13 + byteCount), frame.quantity);
          return;
        }
        case FC.WRITE_MULTI_REG: {
          frame.kind = 'request';
          frame.address = p(8);
          frame.quantity = p(10);
          const byteCount = adu[12];
          frame.values = unpackRegs(adu.subarray(13, 13 + byteCount));
          return;
        }
        case FC.READ_WRITE_MULTI: {
          frame.kind = 'request';
          frame.address = p(8);
          frame.quantity = p(10);
          frame.value = p(12); // 写地址借存在 value 字段
          const writeQty = p(14);
          const byteCount = adu[16];
          frame.values = unpackRegs(adu.subarray(17, 17 + byteCount));
          frame.quantity = writeQty;
          return;
        }
        default:
          frame.kind = 'malformed';
          return;
      }
    }

    // 服务端响应
    switch (fc) {
      case FC.READ_COILS:
      case FC.READ_DISCRETE: {
        frame.kind = 'response';
        const byteCount = adu[8];
        frame.quantity = byteCount * 8;
        frame.values = unpackBits(adu.subarray(9, 9 + byteCount), byteCount * 8);
        return;
      }
      case FC.READ_HOLDING:
      case FC.READ_INPUT: {
        frame.kind = 'response';
        const byteCount = adu[8];
        frame.quantity = byteCount / 2;
        frame.values = unpackRegs(adu.subarray(9, 9 + byteCount));
        return;
      }
      case FC.WRITE_SINGLE_COIL:
      case FC.WRITE_SINGLE_REG:
      case FC.WRITE_MULTI_COIL:
      case FC.WRITE_MULTI_REG:
      case FC.READ_WRITE_MULTI:
        frame.kind = 'response';
        frame.address = p(8);
        frame.quantity = fc === FC.WRITE_SINGLE_COIL || fc === FC.WRITE_SINGLE_REG ? 1 : p(10);
        return;
      default:
        frame.kind = 'malformed';
    }
  }
}

function unpackRegs(b: Uint8Array): number[] {
  const out: number[] = [];
  for (let i = 0; i + 1 < b.length; i += 2) out.push(u16be(b, i));
  return out;
}

function unpackBits(b: Uint8Array, qty: number): number[] {
  const out: number[] = [];
  for (let i = 0; i < qty; i++) {
    const byte = b[i >> 3];
    if (byte == null) break;
    out.push((byte >> (i & 7)) & 1);
  }
  return out;
}
