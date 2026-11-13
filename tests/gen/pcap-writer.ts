/**
 * 合成 pcap / pcapng 写出器（纯 Node，无第三方依赖）。
 * 时间戳统一用微秒 tick；pcapng 按默认 if_tsresol=1e-6 写出。
 */
import { writeFile } from 'node:fs/promises';

export interface PcapIf {
  linkType?: number;
  snapLen?: number;
}

export class PcapWriter {
  private chunks: Uint8Array[] = [];
  private length = 0;

  constructor(linkType = 1) {
    const gh = new ArrayBuffer(24);
    const dv = new DataView(gh);
    dv.setUint32(0, 0xa1b2c3d4, true); // 经典微秒魔数，小端
    dv.setUint16(4, 2, true);
    dv.setUint16(6, 4, true);
    dv.setUint32(16, 65535, true);
    dv.setUint32(20, linkType, true);
    this.push(new Uint8Array(gh));
  }

  /** frame: 完整链路帧；tsUs: 微秒时间戳 */
  packet(frame: Uint8Array, tsUs: number): void {
    const hdr = new ArrayBuffer(16);
    const dv = new DataView(hdr);
    dv.setUint32(0, Math.floor(tsUs / 1e6), true);
    dv.setUint32(4, tsUs % 1e6, true);
    dv.setUint32(8, frame.length, true);
    dv.setUint32(12, frame.length, true);
    this.push(new Uint8Array(hdr));
    this.push(frame);
    // 4 字节对齐
    const pad = (4 - (frame.length % 4)) % 4;
    if (pad) this.push(new Uint8Array(pad));
  }

  private push(b: Uint8Array): void {
    this.chunks.push(b);
    this.length += b.length;
  }

  async save(path: string): Promise<void> {
    const out = new Uint8Array(this.length);
    let o = 0;
    for (const c of this.chunks) {
      out.set(c, o);
      o += c.length;
    }
    await writeFile(path, out);
  }
}

export class PcapngWriter {
  private chunks: Uint8Array[] = [];
  private length = 0;

  constructor(linkType = 1) {
    this.writeShb();
    this.writeIdb(linkType);
  }

  private block(type: number, body: Uint8Array): void {
    // pcapng 块整体按 32bit 对齐，body 不足 4 字节倍数时补零
    const pad = (4 - (body.length % 4)) % 4;
    const paddedBody = pad ? (() => {
      const b = new Uint8Array(body.length + pad);
      b.set(body, 0);
      return b;
    })() : body;
    const total = 12 + paddedBody.length; // 8 块头 + body + 4 尾长度
    const hdr = new ArrayBuffer(8);
    const dv = new DataView(hdr);
    dv.setUint32(0, type, true);
    dv.setUint32(4, total, true);
    const tail = new ArrayBuffer(4);
    new DataView(tail).setUint32(0, total, true);
    this.push(new Uint8Array(hdr));
    this.push(paddedBody);
    this.push(new Uint8Array(tail));
  }

  private writeShb(): void {
    // byte-order magic + version(2) + section length(-1, 8B)
    const body = new ArrayBuffer(16);
    const dv = new DataView(body);
    dv.setUint32(0, 0x1a2b3c4d, true);
    dv.setUint16(4, 1, true);
    dv.setUint16(6, 0, true);
    dv.setBigInt64(8, -1n);
    this.block(0x0a0d0d0a, new Uint8Array(body));
  }

  private writeIdb(linkType: number): void {
    const body = new ArrayBuffer(8);
    const dv = new DataView(body);
    dv.setUint16(0, linkType, true);
    dv.setUint16(2, 0, true);
    dv.setUint32(4, 65535, true);
    this.block(0x00000001, new Uint8Array(body));
  }

  packet(frame: Uint8Array, tsUs: number): void {
    const body = new ArrayBuffer(20 + frame.length);
    const dv = new DataView(body);
    dv.setUint32(0, 0, true); // interface id
    dv.setUint32(4, Math.floor(tsUs / 0x100000000), true); // ts high
    dv.setUint32(8, tsUs % 0x100000000, true); // ts low
    dv.setUint32(12, frame.length, true); // cap len
    dv.setUint32(16, frame.length, true); // orig len
    new Uint8Array(body, 20).set(frame);
    this.block(0x00000006, new Uint8Array(body));
  }

  private push(b: Uint8Array): void {
    this.chunks.push(b);
    this.length += b.length;
  }

  async save(path: string): Promise<void> {
    const out = new Uint8Array(this.length);
    let o = 0;
    for (const c of this.chunks) {
      out.set(c, o);
      o += c.length;
    }
    await writeFile(path, out);
  }
}
