/**
 * pcap / pcapng 流式读取器。
 * 逐块滑动窗口解析，回调逐帧返回，内存占用与文件大小无关（2GB 文件同样只持有一个窗口块）。
 */
import { ChunkPuller, type ChunkSource } from './chunk';
import { u16le, u32le, u16be, u32be } from './bytes';
import type { RawPacket } from './types';
import { decodeEthernet } from './decode';

export interface CaptureHeader {
  format: 'pcap' | 'pcapng';
  /** LINKTYPE_* */
  linkType: number;
  snapLen: number;
  /** pcap: 全局时间戳精度；pcapng: 每接口独立，这里给默认值 */
  tsResolution: number; // 每 tick 的秒数（小数）
}

export interface FrameEvent {
  packet: RawPacket;
  /** 帧字节视图（caplen），仅在本次回调期间有效 */
  frame: Uint8Array;
}

const PCAP_MAGIC_MICRO_LE = 0xa1b2c3d4;
const PCAP_MAGIC_NANO_LE = 0xa1b23c4d;
const PCAPNG_SHB = 0x0a0d0d0a;

/** 嗅探前 4 字节判断格式 */
export async function detectFormat(src: ChunkSource): Promise<'pcap' | 'pcapng'> {
  const head = new Uint8Array(await src.read(0, 4));
  const le = u32le(head, 0);
  if (le === PCAP_MAGIC_MICRO_LE || le === PCAP_MAGIC_NANO_LE) return 'pcap';
  const be = u32be(head, 0);
  if (be === PCAPNG_SHB) return 'pcapng';
  throw new Error('无法识别的文件格式（既不是 pcap 也不是 pcapng）');
}

export async function readCapture(
  src: ChunkSource,
  onFrame: (ev: FrameEvent) => void,
  onProgress?: (readBytes: number) => void,
): Promise<CaptureHeader & { packetCount: number }> {
  const fmt = await detectFormat(src);
  const puller = new ChunkPuller(src);
  if (fmt === 'pcap') return readPcap(puller, onFrame, onProgress);
  return readPcapng(puller, onFrame, onProgress);
}

// ---------------- pcap ----------------

interface PcapGlobal {
  le: boolean;
  nano: boolean;
  linkType: number;
  snapLen: number;
}

async function readPcap(
  p: ChunkPuller,
  onFrame: (ev: FrameEvent) => void,
  onProgress?: (readBytes: number) => void,
): Promise<CaptureHeader & { packetCount: number }> {
  const gh = (await p.take(24))!;
  const magicLe = u32le(gh, 0);
  const le = magicLe === PCAP_MAGIC_MICRO_LE || magicLe === PCAP_MAGIC_NANO_LE;
  const nano = (le ? magicLe : u32be(gh, 0)) === PCAP_MAGIC_NANO_LE;
  const r16 = (o: number) => (le ? u16le(gh, o) : u16be(gh, o));
  const r32 = (o: number) => (le ? u32le(gh, o) : u32be(gh, o));
  const g: PcapGlobal = { le, nano, snapLen: r32(16), linkType: r16(20) };

  let index = 0;
  const header: CaptureHeader = {
    format: 'pcap',
    linkType: g.linkType,
    snapLen: g.snapLen,
    tsResolution: nano ? 1e-9 : 1e-6,
  };

  while (true) {
    const recHdr = await p.peek(16);
    if (!recHdr) break;
    const recOffset = p.fileOffset;
    const r32p = (o: number) => (g.le ? u32le(recHdr, o) : u32be(recHdr, o));
    const tsSec = r32p(0);
    const tsFrac = r32p(4);
    const capLen = r32p(8);
    const origLen = r32p(12);
    p.consume(16);

    const frame = await p.take(capLen);
    if (!frame) throw new Error(`pcap 记录 #${index} 截断（期望 ${capLen}B）`);
    // 对齐到 4 字节（pcap 记录按 32bit 对齐）
    const pad = (4 - (capLen % 4)) % 4;
    if (pad) {
      const padBytes = await p.take(pad);
      if (!padBytes) throw new Error('pcap 对齐字节截断');
    }

    const tsMs = g.nano ? tsSec * 1000 + tsFrac / 1e6 : tsSec * 1000 + tsFrac / 1000;
    const packet: RawPacket = {
      index,
      tsMs,
      fileOffset: recOffset,
      fileRecordLen: 16 + capLen + pad,
      capLen,
      origLen,
      l2: 'other',
    };
    decodeEthernet(frame, packet, g.linkType);
    onFrame({ packet, frame });
    index++;
    if ((index & 0xfff) === 0) onProgress?.(p.fetched);
  }
  onProgress?.(p.fetched);
  return { ...header, packetCount: index };
}

// ---------------- pcapng ----------------

interface PcapngIface {
  linkType: number;
  snapLen: number;
  /** 每 tick 秒数，默认 1e-6 */
  tsResolSec: number;
}

async function readPcapng(
  p: ChunkPuller,
  onFrame: (ev: FrameEvent) => void,
  onProgress?: (readBytes: number) => void,
): Promise<CaptureHeader & { packetCount: number }> {
  const ifaces: PcapngIface[] = [];
  let index = 0;
  let header: CaptureHeader | null = null;
  let le = true;

  while (true) {
    const blockHead = await p.peek(8);
    if (!blockHead) break;
    const blockOffset = p.fileOffset;
    const bTypeLe = u32le(blockHead, 0);
    const bTypeBe = u32be(blockHead, 0);
    // SHB 决定字节序；其它块沿用
    const blockLe: boolean = bTypeLe === PCAPNG_SHB ? true : bTypeBe === PCAPNG_SHB ? false : le;
    le = blockLe;
    const blockType = blockLe ? bTypeLe : bTypeBe;
    const blockLen = blockLe ? u32le(blockHead, 4) : u32be(blockHead, 4);
    p.consume(8);

    if (blockLen < 12) throw new Error(`pcapng 块长度非法: ${blockLen} @${blockOffset}`);
    // 总长度 = 8 块头 + body + 4 尾长度；头已消费，这里取剩余全部（body + 尾 4B）
    const body = await p.take(blockLen - 8);
    if (!body) throw new Error('pcapng 块截断');
    const r16 = (o: number) => (le ? u16le(body, o) : u16be(body, o));
    const r32 = (o: number) => (le ? u32le(body, o) : u32be(body, o));

    switch (blockType) {
      case 0x0a0d0d0a: {
        // Section Header Block: body[0..4] byte-order magic
        const magic = r32(0);
        if (magic !== 0x1a2b3c4d) throw new Error('pcapng SHB 字节序魔数错误');
        break;
      }
      case 0x00000001: {
        // Interface Description Block
        const linkType = r16(0);
        const snapLen = r32(4);
        const tsResolSec = parseTsResol(body, 8, body.length, le);
        ifaces.push({ linkType, snapLen, tsResolSec });
        if (!header) {
          header = { format: 'pcapng', linkType, snapLen, tsResolution: tsResolSec };
        }
        break;
      }
      case 0x00000006: {
        // Enhanced Packet Block
        const ifId = r32(0);
        const tsHigh = r32(4);
        const tsLow = r32(8);
        const capLen = r32(12);
        const origLen = r32(16);
        const iface = ifaces[ifId] ?? { linkType: 1, snapLen: 0, tsResolSec: 1e-6 };
        const frame = body.subarray(20, 20 + capLen);
        const tsTicks = tsHigh * 0x100000000 + tsLow;
        const tsMs = (tsTicks * iface.tsResolSec) * 1000;
        const packet: RawPacket = {
          index,
          tsMs,
          fileOffset: blockOffset,
          fileRecordLen: blockLen,
          capLen,
          origLen,
          l2: 'other',
        };
        decodeEthernet(frame, packet, iface.linkType);
        onFrame({ packet, frame: frame.slice() }); // body 是 take 的副本，subarray 仍有效，但显式 copy 语义清晰
        index++;
        break;
      }
      case 0x00000003: {
        // Simple Packet Block
        const origLen = r32(0);
        const frame = body.subarray(4, 4 + origLen);
        const iface = ifaces[0] ?? { linkType: 1, snapLen: 0, tsResolSec: 1e-6 };
        const packet: RawPacket = {
          index,
          tsMs: 0,
          fileOffset: blockOffset,
          fileRecordLen: blockLen,
          capLen: Math.min(origLen, frame.length),
          origLen,
          l2: 'other',
        };
        decodeEthernet(frame, packet, iface.linkType);
        onFrame({ packet, frame: frame.slice() });
        index++;
        break;
      }
      default:
        // NRB/ISB/自定义块等跳过
        break;
    }

    if ((index & 0xfff) === 0 && index > 0) onProgress?.(p.fetched);
  }
  onProgress?.(p.fetched);
  if (!header) {
    // 只有 SPB 没有 IDB 的极端情况，给个 Ethernet 默认
    header = { format: 'pcapng', linkType: 1, snapLen: 65535, tsResolution: 1e-6 };
  }
  return { ...header, packetCount: index };
}

/** 解析 IDB 的 if_tsresol 选项（option code 9） */
function parseTsResol(body: Uint8Array, optsStart: number, bodyLen: number, le: boolean): number {
  let o = optsStart;
  const end = bodyLen - 4; // 尾部重复 block length
  const r16o = (off: number) => (le ? u16le(body, off) : u16be(body, off));
  while (o + 4 <= end) {
    const code = r16o(o);
    const len = r16o(o + 2);
    o += 4;
    if (code === 0) break; // opt_endofopt
    if (code === 9 && len >= 1) {
      const b = body[o];
      const base = b & 0x80 ? 10 : 2;
      const val = b & 0x7f;
      return base === 10 ? 10 ** -val : 2 ** -val;
    }
    o += (len + 3) & ~3;
  }
  return 1e-6;
}
