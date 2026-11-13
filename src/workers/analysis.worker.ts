/**
 * 解析 Worker。
 * 主线程只传 File 句柄和参数，所有读文件、重组、检测都在本线程完成，
 * 主线程通过进度消息驱动进度条，不会被大文件解析阻塞。
 *
 * 大文件内存策略：引擎结果通过流式 sink 分块写入 IndexedDB，
 * Worker 内不累积全量 packets/modbus/alerts，常驻内存与文件大小解耦。
 */
import { BlobChunkSource } from '../core/chunk';
import { runAnalysis } from '../core/engine';
import type { Alert, ModbusFrame, ProgressEvent, RawPacket, SessionMeta, TcpConnStats } from '../core/types';
import { SessionStore } from '../storage/idb';

export interface WorkerStartMsg {
  type: 'start';
  sessionId: string;
  file: File;
  baselineWindowMs: number;
}
export type WorkerInMsg = WorkerStartMsg;

export interface WorkerProgressMsg {
  type: 'progress';
  progress: ProgressEvent;
}
export interface WorkerDoneMsg {
  type: 'done';
  meta: SessionMeta;
}
export interface WorkerErrorMsg {
  type: 'error';
  message: string;
}
export type WorkerOutMsg = WorkerProgressMsg | WorkerDoneMsg | WorkerErrorMsg;

const post = (m: WorkerOutMsg) => postMessage(m);
const FLUSH_AT = 1000; // 每攒够 1000 条落一批

self.onmessage = async (ev: MessageEvent<WorkerInMsg>) => {
  const msg = ev.data;
  if (msg.type !== 'start') return;
  const { sessionId, file, baselineWindowMs } = msg;
  const store = new SessionStore(sessionId);
  try {
    const src = new BlobChunkSource(file);

    // 分块缓冲：到量就落盘并清空，保证 Worker 常驻内存有界
    let packetBuf: RawPacket[] = [];
    let modbusBuf: ModbusFrame[] = [];
    let alertBuf: Alert[] = [];
    const flushPackets = async () => {
      if (packetBuf.length) {
        await store.appendPacketIndex(packetBuf);
        packetBuf = [];
      }
    };
    const flushModbus = async () => {
      if (modbusBuf.length) {
        await store.saveModbus(modbusBuf);
        modbusBuf = [];
      }
    };
    const flushAlerts = async () => {
      if (alertBuf.length) {
        await store.saveAlerts(alertBuf);
        alertBuf = [];
      }
    };

    const result = await runAnalysis(src, {
      baselineWindowMs,
      progressInterval: 2048,
      onProgress: (progress) => post({ type: 'progress', progress }),
      sink: {
        onPacket: (p) => {
          packetBuf.push(p);
          if (packetBuf.length >= FLUSH_AT) void flushPackets();
        },
        onModbus: (f) => {
          modbusBuf.push(f);
          if (modbusBuf.length >= FLUSH_AT) void flushModbus();
        },
        onAlert: (a) => {
          alertBuf.push(a);
          if (alertBuf.length >= FLUSH_AT) void flushAlerts();
        },
      },
    });

    // 冲刷残余缓冲
    await flushPackets();
    await flushModbus();
    await flushAlerts();

    const meta: SessionMeta = {
      id: sessionId,
      fileName: file.name,
      fileSize: file.size,
      linkType: result.header.linkType,
      snapLen: result.header.snapLen,
      packetCount: result.counts.packets,
      startMs: result.startMs,
      endMs: result.endMs,
      modbusCount: result.counts.modbus,
      alertCount: result.counts.alerts,
      importedAt: Date.now(),
    };

    post({
      type: 'progress',
      progress: {
        phase: 'store',
        packets: meta.packetCount,
        totalBytes: file.size,
        readBytes: file.size,
        modbusFrames: meta.modbusCount,
        alerts: meta.alertCount,
        message: '写入本地数据库…',
      },
    });

    await store.saveMeta(meta);
    const conns: TcpConnStats[] = result.conns;
    await store.saveConns(conns);
    if (result.baseline) await store.saveBaseline(result.baseline);
    await store.close();

    post({ type: 'done', meta });
  } catch (e) {
    await store.close().catch(() => undefined);
    post({ type: 'error', message: e instanceof Error ? e.message : String(e) });
  }
};
