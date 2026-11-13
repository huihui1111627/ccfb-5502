/**
 * 合成 Ethernet/IPv4/TCP/Modbus 报文构造器。
 * 校验和按 RFC1071 真实计算，保证产出的 pcap 可被 Wireshark 正常解码。
 */

export interface Endpoint {
  ip: string;
  port: number;
  mac: string;
}

export interface TcpContext {
  seq: number;
  ack: number;
}

export function newTcpCtx(): TcpContext {
  // 固定 ISN 基准，生成结果可复现（不使用随机源）
  return { seq: 1000, ack: 1000 };
}

function ipToBytes(ip: string): Uint8Array {
  return Uint8Array.from(ip.split('.').map(Number));
}
function macToBytes(mac: string): Uint8Array {
  return Uint8Array.from(mac.split(':').map((h) => parseInt(h, 16)));
}

export function checksum(data: Uint8Array): number {
  let sum = 0;
  for (let i = 0; i + 1 < data.length; i += 2) {
    sum += (data[i] << 8) | data[i + 1];
  }
  if (data.length % 2) sum += data[data.length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

function ipChecksum(ip: Uint8Array): number {
  return checksum(ip.subarray(0, 20));
}

function tcpChecksum(src: Uint8Array, dst: Uint8Array, tcp: Uint8Array): number {
  const pseudo = new Uint8Array(12 + tcp.length);
  pseudo.set(src, 0);
  pseudo.set(dst, 4);
  pseudo[8] = 0;
  pseudo[9] = 6;
  pseudo[10] = (tcp.length >> 8) & 0xff;
  pseudo[11] = tcp.length & 0xff;
  pseudo.set(tcp, 12);
  return checksum(pseudo);
}

export interface BuildOpts {
  src: Endpoint;
  dst: Endpoint;
  ctx: TcpContext;
  flags: number;
  payload?: Uint8Array;
  /** 构造时是否推进本端 seq（重传场景需要 false） */
  advanceSeq?: boolean;
}

export const FIN = 0x01;
export const SYN = 0x02;
export const RST = 0x04;
export const PSH = 0x08;
export const ACK = 0x10;

export function buildTcpPacket(opts: BuildOpts): Uint8Array {
  const { src, dst, ctx, flags, payload = new Uint8Array(0), advanceSeq = true } = opts;
  const tcpLen = 20 + payload.length;
  const ipLen = 20 + tcpLen;
  const frameLen = 14 + ipLen;
  const frame = new Uint8Array(frameLen);

  // Ethernet
  frame.set(macToBytes(dst.mac), 0);
  frame.set(macToBytes(src.mac), 6);
  frame[12] = 0x08;
  frame[13] = 0x00;

  // IPv4
  const ip = frame.subarray(14, 34);
  ip[0] = 0x45;
  ip[1] = 0;
  new DataView(ip.buffer, ip.byteOffset).setUint16(2, ipLen);
  ip[9] = 6;
  ip[10] = 64; // TTL
  ip.set(ipToBytes(src.ip), 12);
  ip.set(ipToBytes(dst.ip), 16);
  new DataView(ip.buffer, ip.byteOffset).setUint16(10, ipChecksum(ip));

  // TCP
  const tcp = frame.subarray(34, 34 + tcpLen);
  const dv = new DataView(tcp.buffer, tcp.byteOffset);
  dv.setUint16(0, src.port);
  dv.setUint16(2, dst.port);
  dv.setUint32(4, ctx.seq >>> 0);
  dv.setUint32(8, ctx.ack >>> 0);
  tcp[12] = 5 << 4; // data offset 5
  tcp[13] = flags;
  dv.setUint16(14, 65535); // window
  tcp.set(payload, 20);
  dv.setUint16(16, tcpChecksum(ipToBytes(src.ip), ipToBytes(dst.ip), tcp));

  if (advanceSeq) {
    let consumed = payload.length;
    if (flags & SYN) consumed += 1;
    if (flags & FIN) consumed += 1;
    ctx.seq = (ctx.seq + consumed) >>> 0;
  }
  return frame;
}

/** 对端收到数据后推进 ack */
export function ackData(receiver: TcpContext, payloadLen: number): void {
  receiver.ack = (receiver.ack + payloadLen) >>> 0;
}

// ---------------- Modbus MBAP / PDU ----------------

export function mbap(transId: number, unitId: number, pdu: Uint8Array): Uint8Array {
  const out = new Uint8Array(7 + pdu.length);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, transId);
  dv.setUint16(2, 0); // Modbus proto
  dv.setUint16(4, pdu.length + 1);
  out[6] = unitId;
  out.set(pdu, 7);
  return out;
}

export function mbRequest(
  transId: number,
  unitId: number,
  fc: number,
  address: number,
  quantity: number,
  values?: number[],
): Uint8Array {
  let pdu: Uint8Array;
  const dv = new DataView(new ArrayBuffer(5));
  dv.setUint8(0, fc);
  dv.setUint16(1, address);
  dv.setUint16(3, quantity);
  switch (fc) {
    case 1: case 2: case 3: case 4:
      pdu = new Uint8Array(dv.buffer);
      break;
    case 5: {
      const b = new Uint8Array(5);
      new DataView(b.buffer).setUint8(0, fc);
      new DataView(b.buffer).setUint16(1, address);
      new DataView(b.buffer).setUint16(3, values?.[0] ? 0xff00 : 0x0000);
      pdu = b;
      break;
    }
    case 6: {
      const b = new Uint8Array(5);
      new DataView(b.buffer).setUint8(0, fc);
      new DataView(b.buffer).setUint16(1, address);
      new DataView(b.buffer).setUint16(3, values?.[0] ?? 0);
      pdu = b;
      break;
    }
    case 15: {
      const qtyBytes = Math.ceil(quantity / 8);
      const b = new Uint8Array(6 + qtyBytes);
      const v = new DataView(b.buffer);
      v.setUint8(0, fc);
      v.setUint16(1, address);
      v.setUint16(3, quantity);
      v.setUint8(5, qtyBytes);
      (values ?? []).forEach((val, i) => {
        if (val) b[6 + (i >> 3)] |= 1 << (i & 7);
      });
      pdu = b;
      break;
    }
    case 16: {
      const b = new Uint8Array(6 + quantity * 2);
      const v = new DataView(b.buffer);
      v.setUint8(0, fc);
      v.setUint16(1, address);
      v.setUint16(3, quantity);
      v.setUint8(5, quantity * 2);
      (values ?? []).forEach((val, i) => v.setUint16(6 + i * 2, val));
      pdu = b;
      break;
    }
    default:
      throw new Error(`生成器不支持 FC${fc}`);
  }
  return mbap(transId, unitId, pdu);
}

export function mbReadResponse(transId: number, unitId: number, fc: number, values: number[]): Uint8Array {
  const isBits = fc === 1 || fc === 2;
  const payloadBytes = isBits ? Math.ceil(values.length / 8) : values.length * 2;
  const pdu = new Uint8Array(2 + payloadBytes);
  const dv = new DataView(pdu.buffer);
  dv.setUint8(0, fc);
  dv.setUint8(1, payloadBytes);
  if (isBits) {
    values.forEach((val, i) => {
      if (val) pdu[2 + (i >> 3)] |= 1 << (i & 7);
    });
  } else {
    values.forEach((val, i) => dv.setUint16(2 + i * 2, val));
  }
  return mbap(transId, unitId, pdu);
}

export function mbEchoResponse(transId: number, unitId: number, fc: number, address: number, quantity: number): Uint8Array {
  const len = fc === 5 || fc === 6 ? 5 : 5;
  const pdu = new Uint8Array(len);
  const dv = new DataView(pdu.buffer);
  dv.setUint8(0, fc);
  dv.setUint16(1, address);
  dv.setUint16(3, fc === 5 ? (quantity ? 0xff00 : 0) : quantity);
  return mbap(transId, unitId, pdu);
}

export function mbException(transId: number, unitId: number, fc: number, code: number): Uint8Array {
  const pdu = Uint8Array.from([fc | 0x80, code]);
  return mbap(transId, unitId, pdu);
}
