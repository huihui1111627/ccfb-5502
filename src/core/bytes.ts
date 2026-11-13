/** 大端/小端读取工具，全部基于 DataView，零拷贝 */

export class ByteReader {
  readonly view: DataView;
  offset = 0;

  constructor(buf: ArrayBuffer, offset = 0, length?: number) {
    this.view = new DataView(buf, offset, length);
  }

  get remaining(): number {
    return this.view.byteLength - this.offset;
  }

  u8(le = false): number {
    const v = this.view.getUint8(this.offset);
    this.offset += 1;
    return le ? v : v;
  }

  u16(le = false): number {
    const v = this.view.getUint16(this.offset, le);
    this.offset += 2;
    return v;
  }

  u32(le = false): number {
    const v = this.view.getUint32(this.offset, le);
    this.offset += 4;
    return v;
  }

  i32(le = false): number {
    const v = this.view.getInt32(this.offset, le);
    this.offset += 4;
    return v;
  }

  bytes(n: number): Uint8Array {
    const start = this.view.byteOffset + this.offset;
    const out = new Uint8Array(this.view.buffer, start, n);
    this.offset += n;
    return out;
  }

  /** 跳过，返回跳过前的偏移（相对底层 buffer） */
  skip(n: number): number {
    const at = this.view.byteOffset + this.offset;
    this.offset += n;
    return at;
  }
}

export function u16be(b: Uint8Array, o: number): number {
  return (b[o] << 8) | b[o + 1];
}

export function u32be(b: Uint8Array, o: number): number {
  return (b[o] * 0x1000000) + ((b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);
}

export function u16le(b: Uint8Array, o: number): number {
  return b[o] | (b[o + 1] << 8);
}

export function u32le(b: Uint8Array, o: number): number {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}

export function hex(b: Uint8Array, max = 64): string {
  const n = Math.min(b.length, max);
  const parts: string[] = [];
  for (let i = 0; i < n; i++) parts.push(b[i].toString(16).padStart(2, '0'));
  return parts.join(' ') + (b.length > max ? ` …(+${b.length - max}B)` : '');
}

export function macStr(b: Uint8Array, o: number): string {
  return `${b[o].toString(16).padStart(2, '0')}:${b[o + 1].toString(16).padStart(2, '0')}:${b[o + 2]
    .toString(16)
    .padStart(2, '0')}:${b[o + 3].toString(16).padStart(2, '0')}:${b[o + 4]
    .toString(16)
    .padStart(2, '0')}:${b[o + 5].toString(16).padStart(2, '0')}`;
}

export function ipStr(b: Uint8Array, o: number): string {
  return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
}
