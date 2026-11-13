/**
 * IndexedDB 持久层。
 * 设计取舍：
 *  - 原始 pcap 字节不入库（2GB 会撑爆 IDB 配额），只存结构化结果 + 帧定位索引
 *  - RawPacket 元数据压成二进制块（每块 256 帧 × 24B ≈ 6KB），记录数降两个数量级
 *  - Modbus 帧 / 告警 / 连接按索引查询，支持分页与筛选
 */
import type {
  Alert,
  Baseline,
  FilterState,
  ModbusFrame,
  RawPacket,
  SessionMeta,
  TcpConnStats,
} from '../core/types';

const DB_NAME = 'ics-traffic-bench';
const DB_VERSION = 1;
const STORE = {
  meta: 'meta',
  conns: 'conns',
  modbus: 'modbus',
  alerts: 'alerts',
  packetBlocks: 'packetBlocks',
  baseline: 'baseline',
} as const;

const BLOCK_SIZE = 256;
const PACKET_RECORD = 24; // 每帧定长 24B

function openDb(sessionId: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(`${DB_NAME}:${sessionId}`, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      db.createObjectStore(STORE.meta);
      const connStore = db.createObjectStore(STORE.conns, { keyPath: 'connId' });
      connStore.createIndex('startMs', 'startMs');
      const mbStore = db.createObjectStore(STORE.modbus, { keyPath: 'id' });
      mbStore.createIndex('tsMs', 'tsMs');
      mbStore.createIndex('connId', 'connId');
      mbStore.createIndex('fc', 'fc');
      const alertStore = db.createObjectStore(STORE.alerts, { keyPath: 'id' });
      alertStore.createIndex('tsMs', 'tsMs');
      alertStore.createIndex('type', 'type');
      alertStore.createIndex('status', 'status');
      db.createObjectStore(STORE.packetBlocks);
      db.createObjectStore(STORE.baseline);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx<T>(db: IDBDatabase, stores: string[], mode: IDBTransactionMode, fn: (t: IDBTransaction) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = db.transaction(stores, mode);
    const r = fn(t);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

function txDone(db: IDBDatabase, stores: string[], mode: IDBTransactionMode, fn: (t: IDBTransaction) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = db.transaction(stores, mode);
    fn(t);
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
  });
}

export class SessionStore {
  private dbp: Promise<IDBDatabase>;

  constructor(public readonly sessionId: string) {
    this.dbp = openDb(sessionId);
  }

  async close(): Promise<void> {
    const db = await this.dbp;
    db.close();
  }

  async destroy(): Promise<void> {
    const db = await this.dbp;
    db.close();
    await new Promise<void>((resolve, reject) => {
      const r = indexedDB.deleteDatabase(`${DB_NAME}:${this.sessionId}`);
      r.onsuccess = () => resolve();
      r.onerror = () => reject(r.error);
    });
  }

  async saveMeta(meta: SessionMeta): Promise<void> {
    const db = await this.dbp;
    await tx(db, [STORE.meta], 'readwrite', (t) => t.objectStore(STORE.meta).put(meta, 'meta'));
  }

  async getMeta(): Promise<SessionMeta | undefined> {
    const db = await this.dbp;
    return tx(db, [STORE.meta], 'readonly', (t) => t.objectStore(STORE.meta).get('meta'));
  }

  async saveBaseline(b: Baseline): Promise<void> {
    const db = await this.dbp;
    await tx(db, [STORE.baseline], 'readwrite', (t) => t.objectStore(STORE.baseline).put(b, 'baseline'));
  }

  async getBaseline(): Promise<Baseline | undefined> {
    const db = await this.dbp;
    return tx(db, [STORE.baseline], 'readonly', (t) => t.objectStore(STORE.baseline).get('baseline'));
  }

  async saveConns(conns: TcpConnStats[]): Promise<void> {
    const db = await this.dbp;
    await txDone(db, [STORE.conns], 'readwrite', (t) => {
      const s = t.objectStore(STORE.conns);
      for (const c of conns) s.put(c);
    });
  }

  async getAllConns(): Promise<TcpConnStats[]> {
    const db = await this.dbp;
    return new Promise((resolve, reject) => {
      const t = db.transaction(STORE.conns, 'readonly');
      const r = t.objectStore(STORE.conns).index('startMs').getAll();
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }

  async saveModbus(frames: ModbusFrame[]): Promise<void> {
    const db = await this.dbp;
    // 分批提交，单事务过大在 Safari 上会失败
    for (let i = 0; i < frames.length; i += 1000) {
      const batch = frames.slice(i, i + 1000);
      await txDone(db, [STORE.modbus], 'readwrite', (t) => {
        const s = t.objectStore(STORE.modbus);
        for (const f of batch) s.put(f);
      });
    }
  }

  async saveAlerts(alerts: Alert[]): Promise<void> {
    const db = await this.dbp;
    for (let i = 0; i < alerts.length; i += 1000) {
      const batch = alerts.slice(i, i + 1000);
      await txDone(db, [STORE.alerts], 'readwrite', (t) => {
        const s = t.objectStore(STORE.alerts);
        for (const a of batch) s.put(a);
      });
    }
  }

  async updateAlertStatus(id: number, status: Alert['status']): Promise<void> {
    const db = await this.dbp;
    await txDone(db, [STORE.alerts], 'readwrite', (t) => {
      const s = t.objectStore(STORE.alerts);
      const get = s.get(id);
      get.onsuccess = () => {
        const a = get.result as Alert | undefined;
        if (a) s.put({ ...a, status });
      };
    });
  }

  /** 帧索引定长打包：tsMs(f64) + offset(u32) + recLen(u32) + capLen(u32) + origLen(u32) = 24B */
  async savePacketIndex(packets: RawPacket[]): Promise<void> {
    const db = await this.dbp;
    const blocks: { key: number; buf: ArrayBuffer }[] = [];
    for (let i = 0; i < packets.length; i += BLOCK_SIZE) {
      const slice = packets.slice(i, i + BLOCK_SIZE);
      const buf = new ArrayBuffer(slice.length * PACKET_RECORD);
      const dv = new DataView(buf);
      slice.forEach((p, j) => {
        const o = j * PACKET_RECORD;
        dv.setFloat64(o, p.tsMs, true);
        dv.setUint32(o + 8, p.fileOffset, true);
        dv.setUint32(o + 12, p.fileRecordLen, true);
        dv.setUint32(o + 16, p.capLen, true);
        dv.setUint32(o + 20, p.origLen, true);
      });
      blocks.push({ key: i / BLOCK_SIZE, buf });
    }
    for (let i = 0; i < blocks.length; i += 50) {
      const batch = blocks.slice(i, i + 50);
      await txDone(db, [STORE.packetBlocks], 'readwrite', (t) => {
        const s = t.objectStore(STORE.packetBlocks);
        for (const b of batch) s.put(b.buf, b.key);
      });
    }
  }

  /**
   * 流式追加帧索引（Worker 大文件分块落盘用）。
   * 内部维护「当前块号 + 块内已写帧数」，跨块自动切分，已存在的块读回拼接后重写。
   */
  private packetCursor = { blockNo: 0, within: 0 };

  async appendPacketIndex(packets: RawPacket[]): Promise<void> {
    if (!packets.length) return;
    const db = await this.dbp;
    let i = 0;
    while (i < packets.length) {
      const blockStore = db.transaction(STORE.packetBlocks, 'readwrite').objectStore(STORE.packetBlocks);
      const existing = (await new Promise<ArrayBuffer | undefined>((res, rej) => {
        const r = blockStore.get(this.packetCursor.blockNo);
        r.onsuccess = () => res(r.result as ArrayBuffer | undefined);
        r.onerror = () => rej(r.error);
      }));
      const startWithin = this.packetCursor.within;
      const room = BLOCK_SIZE - startWithin;
      const slice = packets.slice(i, i + room);
      const recs = startWithin + slice.length;
      const buf = new ArrayBuffer(recs * PACKET_RECORD);
      const dv = new DataView(buf);
      if (existing) new Uint8Array(buf).set(new Uint8Array(existing), 0);
      slice.forEach((p, j) => {
        const o = (startWithin + j) * PACKET_RECORD;
        dv.setFloat64(o, p.tsMs, true);
        dv.setUint32(o + 8, p.fileOffset, true);
        dv.setUint32(o + 12, p.fileRecordLen, true);
        dv.setUint32(o + 16, p.capLen, true);
        dv.setUint32(o + 20, p.origLen, true);
      });
      await new Promise<void>((res, rej) => {
        const put = blockStore.put(buf, this.packetCursor.blockNo);
        put.onsuccess = () => res();
        put.onerror = () => rej(put.error);
      });
      i += slice.length;
      this.packetCursor.within += slice.length;
      if (this.packetCursor.within >= BLOCK_SIZE) {
        this.packetCursor.blockNo++;
        this.packetCursor.within = 0;
      }
    }
  }

  /**
   * 流式扫描时间范围内的帧定位信息（导出 pcap 用）。
   * 按 256 帧/块整块读取，每块只在回调期间驻留，内存与总帧数解耦。
   * 返回匹配帧的最小定位集合（不含 L3/L4 字段，导出只需文件定位）。
   */
  async scanPacketRange(
    startMs: number,
    endMs: number,
    totalPackets: number,
    onMatch: (p: RawPacket) => void,
  ): Promise<number> {
    const db = await this.dbp;
    const blockCount = Math.ceil(totalPackets / BLOCK_SIZE);
    let matched = 0;
    for (let b = 0; b < blockCount; b++) {
      const buf = (await tx(db, [STORE.packetBlocks], 'readonly', (t) =>
        t.objectStore(STORE.packetBlocks).get(b),
      )) as ArrayBuffer | undefined;
      if (!buf) continue;
      const dv = new DataView(buf);
      const recs = buf.byteLength / PACKET_RECORD;
      for (let j = 0; j < recs; j++) {
        const o = j * PACKET_RECORD;
        const tsMs = dv.getFloat64(o, true);
        if (tsMs < startMs || tsMs > endMs) continue;
        onMatch({
          index: b * BLOCK_SIZE + j,
          tsMs,
          fileOffset: dv.getUint32(o + 8, true),
          fileRecordLen: dv.getUint32(o + 12, true),
          capLen: dv.getUint32(o + 16, true),
          origLen: dv.getUint32(o + 20, true),
          l2: 'ethernet',
        });
        matched++;
      }
    }
    return matched;
  }

  /** 按全局帧序号取定位信息（跳原始报文 / 导出时用） */
  async getPacketLocator(index: number): Promise<{ tsMs: number; fileOffset: number; fileRecordLen: number; capLen: number; origLen: number }> {
    const blockNo = Math.floor(index / BLOCK_SIZE);
    const within = index % BLOCK_SIZE;
    const db = await this.dbp;
    const buf = (await tx(db, [STORE.packetBlocks], 'readonly', (t) =>
      t.objectStore(STORE.packetBlocks).get(blockNo),
    )) as ArrayBuffer | undefined;
    if (!buf) throw new Error(`帧 #${index} 的索引块不存在`);
    const dv = new DataView(buf, within * PACKET_RECORD, PACKET_RECORD);
    return {
      tsMs: dv.getFloat64(0, true),
      fileOffset: dv.getUint32(8, true),
      fileRecordLen: dv.getUint32(12, true),
      capLen: dv.getUint32(16, true),
      origLen: dv.getUint32(20, true),
    };
  }

  /** 按筛选条件游标查询 Modbus 帧（分页） */
  async queryModbus(filter: FilterState, limit = 200, offset = 0): Promise<ModbusFrame[]> {
    const db = await this.dbp;
    return this.cursorQuery<ModbusFrame>(db, STORE.modbus, 'tsMs', filter, limit, offset, (f) => {
      if (filter.connId && f.connId !== filter.connId) return false;
      if (filter.fc != null && f.fc !== filter.fc) return false;
      if (filter.unitId != null && f.unitId !== filter.unitId) return false;
      if (filter.q && !this.matchQ(f, filter.q)) return false;
      return true;
    });
  }

  async queryAlerts(filter: FilterState, limit = 200, offset = 0): Promise<Alert[]> {
    const db = await this.dbp;
    return this.cursorQuery<Alert>(db, STORE.alerts, 'tsMs', filter, limit, offset, (a) => {
      if (filter.type && a.type !== filter.type) return false;
      if (filter.status && filter.status !== 'all' && a.status !== filter.status) return false;
      if (filter.connId && a.connId !== filter.connId) return false;
      if (filter.q && !`${a.title} ${a.detail}`.includes(filter.q)) return false;
      return true;
    });
  }

  async countAlerts(status?: Alert['status'] | 'all'): Promise<number> {
    const db = await this.dbp;
    return new Promise((resolve, reject) => {
      if (!status || status === 'all') {
        const t = db.transaction(STORE.alerts, 'readonly');
        const req = t.objectStore(STORE.alerts).count();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
        return;
      }
      const t = db.transaction(STORE.alerts, 'readonly');
      const c = t.objectStore(STORE.alerts).index('status').count(status);
      c.onsuccess = () => resolve(c.result);
      c.onerror = () => reject(c.error);
    });
  }

  private async cursorQuery<T>(
    db: IDBDatabase,
    store: string,
    indexName: string,
    filter: FilterState,
    limit: number,
    offset: number,
    predicate: (v: T) => boolean,
  ): Promise<T[]> {
    return new Promise((resolve, reject) => {
      const t = db.transaction(store, 'readonly');
      const idx = t.objectStore(store).index(indexName);
      const range: IDBKeyRange | null =
        filter.startMs != null || filter.endMs != null
          ? IDBKeyRange.bound(filter.startMs ?? -Infinity, filter.endMs ?? Infinity)
          : null;
      const out: T[] = [];
      let skipped = 0;
      const req = idx.openCursor(range);
      req.onsuccess = () => {
        const cur = req.result;
        if (!cur) return resolve(out);
        const v = cur.value as T;
        if (predicate(v)) {
          if (skipped < offset) skipped++;
          else {
            out.push(v);
            if (out.length >= limit) return resolve(out);
          }
        }
        cur.continue();
      };
      req.onerror = () => reject(req.error);
    });
  }

  private matchQ(f: ModbusFrame, q: string): boolean {
    return `${f.connId} ${f.srcIp} ${f.dstIp} FC${f.fc} 地址${f.address ?? ''}`.includes(q);
  }
}

/** 列出所有本地会话（会话选择器用） */
export async function listSessions(): Promise<string[]> {
  const dbs = await indexedDB.databases();
  return dbs
    .map((d) => d.name ?? '')
    .filter((n) => n.startsWith(`${DB_NAME}:`))
    .map((n) => n.slice(DB_NAME.length + 1));
}
