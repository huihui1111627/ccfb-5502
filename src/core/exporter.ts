/**
 * 结果导出：
 *  - CSV：会话 / Modbus 帧 / 告警（纯字符串拼接，前端直接下载）
 *  - pcap：按筛选条件回读原始帧，重写为标准 pcap（微秒精度、经典魔数），流式分块产出
 */
import type { Alert, ModbusFrame, RawPacket, TcpConnStats } from './types';
import type { ChunkSource } from './chunk';

// ---------------- CSV ----------------

function csvCell(v: unknown): string {
  const s = v == null ? '' : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function toCsv(headers: string[], rows: (string | number | undefined)[][]): string {
  const lines = [headers.join(',')];
  for (const r of rows) lines.push(r.map(csvCell).join(','));
  // 加 UTF-8 BOM，Excel 打开中文不乱码
  return '﻿' + lines.join('\r\n') + '\r\n';
}

export function alertsToCsv(alerts: Alert[]): string {
  return toCsv(
    ['id', '时间(ms)', '类型', '严重度', '状态', '连接', '帧序号', '标题', '详情', '基线窗口内'],
    alerts.map((a) => [
      a.id,
      new Date(a.tsMs).toISOString(),
      a.type,
      a.severity,
      a.status,
      a.connId,
      a.packetIndex,
      a.title,
      a.detail,
      a.inBaselineWindow ? '是' : '否',
    ]),
  );
}

export function modbusToCsv(frames: ModbusFrame[]): string {
  return toCsv(
    ['id', '时间(ms)', '连接', '方向', '事务ID', '单元ID', '功能码', '类型', '地址', '数量', '值', '原始帧序号'],
    frames.map((f) => [
      f.id,
      new Date(f.tsMs).toISOString(),
      f.connId,
      f.dir,
      f.transId,
      f.unitId,
      f.fc,
      f.kind,
      f.address,
      f.quantity,
      f.values?.join(' ') ?? (f.value ?? ''),
      f.packetIndex,
    ]),
  );
}

export function connsToCsv(conns: TcpConnStats[]): string {
  return toCsv(
    ['连接', '客户端', '服务端', '开始(ms)', '结束(ms)', '报文数', '乱序', '重传', 'Modbus帧', '已关闭'],
    conns.map((c) => [
      c.connId,
      `${c.clientIp}:${c.clientPort}`,
      `${c.serverIp}:${c.serverPort}`,
      new Date(c.startMs).toISOString(),
      new Date(c.lastMs).toISOString(),
      c.packets,
      c.outOfOrder,
      c.retransmits,
      c.modbusFrames,
      c.closed ? '是' : '否',
    ]),
  );
}

// ---------------- pcap 导出 ----------------

const PCAP_GLOBAL = 24;
const PCAP_REC = 16;

export interface PcapExportOptions {
  linkType: number;
  /** 每个产出块的目标大小 */
  chunkSize?: number;
}

/**
 * 从原文件回读筛选后的帧并重打包为 pcap。
 * 调用方提供要导出的帧（已按 index 排序），本函数逐帧 seek 读取，内存只持有一帧+一个输出块。
 */
export async function exportPcap(
  src: ChunkSource,
  frames: RawPacket[],
  opts: PcapExportOptions,
  onChunk: (chunk: Uint8Array) => void,
): Promise<number> {
  const chunkSize = opts.chunkSize ?? 1024 * 1024;
  let out = new Uint8Array(chunkSize);
  let pos = 0;
  let count = 0;

  const flush = () => {
    if (pos > 0) {
      // copy 成独立 buffer：回调方可能直接拼 Blob，带 byteOffset 的视图会被 Blob 构造器错误处理
      onChunk(out.slice(0, pos));
      out = new Uint8Array(chunkSize);
      pos = 0;
    }
  };
  const ensure = (n: number) => {
    if (pos + n > out.length) flush();
  };
  const write = (b: Uint8Array) => {
    ensure(b.length);
    out.set(b, pos);
    pos += b.length;
  };

  // 全局头（小端、微秒、LINKTYPE）
  const gh = new ArrayBuffer(PCAP_GLOBAL);
  const dv = new DataView(gh);
  dv.setUint32(0, 0xa1b2c3d4, true);
  dv.setUint16(4, 2, true); // version major
  dv.setUint16(6, 4, true); // version minor
  dv.setInt32(8, 0, true); // thiszone
  dv.setUint32(12, 0, true); // sigfigs
  dv.setUint32(16, 65535, true); // snaplen
  dv.setUint32(20, opts.linkType, true);
  write(new Uint8Array(gh));

  for (const pkt of frames) {
    // 回读原始记录：pcap 记录头 + 帧；pcapng 是整块，需要拆出 EPB 里的帧数据
    const raw = new Uint8Array(await src.read(pkt.fileOffset, pkt.fileRecordLen));
    let frameBytes: Uint8Array;
    let tsSec: number;
    let tsUsec: number;

    if (raw.length >= 28 && u32leAt(raw, 0) === 0x00000006) {
      // pcapng Enhanced Packet Block：跳过块头(8)+接口/时间戳/caplen/origlen(20)
      const tsHigh = u32leAt(raw, 12);
      const tsLow = u32leAt(raw, 16);
      const capLen = u32leAt(raw, 24);
      frameBytes = raw.subarray(28, 28 + Math.min(capLen, pkt.capLen));
      // pcapng 默认微秒 tick（生成器/常见抓包均如此）
      const ticks = tsHigh * 0x100000000 + tsLow;
      tsSec = Math.floor(ticks / 1e6);
      tsUsec = ticks % 1e6;
    } else {
      // 经典 pcap：记录头 16B
      tsSec = u32leAt(raw, 0);
      tsUsec = u32leAt(raw, 4);
      frameBytes = raw.subarray(16, 16 + pkt.capLen);
    }

    const pad = (4 - (frameBytes.length % 4)) % 4;
    const recLen = PCAP_REC + frameBytes.length + pad;
    ensure(recLen);
    const rh = new DataView(out.buffer, out.byteOffset + pos, PCAP_REC);
    rh.setUint32(0, tsSec, true);
    rh.setUint32(4, tsUsec, true);
    rh.setUint32(8, frameBytes.length, true);
    rh.setUint32(12, pkt.origLen || frameBytes.length, true);
    pos += PCAP_REC;
    out.set(frameBytes, pos);
    pos += frameBytes.length;
    // pcap 记录按 32bit 对齐，补零填充（读取器按同样规则跳过）
    if (pad) {
      out.fill(0, pos, pos + pad);
      pos += pad;
    }
    count++;
  }
  flush();
  return count;
}

function u32leAt(b: Uint8Array, o: number): number {
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}

/** 浏览器端：收集块并拼成 Blob 下载 */
export async function exportPcapToBlob(
  src: ChunkSource,
  frames: RawPacket[],
  linkType: number,
): Promise<Blob> {
  const chunks: Uint8Array[] = [];
  await exportPcap(src, frames, { linkType }, (c) => chunks.push(c));
  return new Blob(chunks as BlobPart[], { type: 'application/vnd.tcpdump.pcap' });
}
