/**
 * 核心数据类型。核心库（core/）不依赖 DOM / IndexedDB，可直接在 Node(vitest) 中测试。
 */

/** 一个链路帧的解析结果（只保留分析需要的字段，原始字节留在文件里按需回读） */
export interface RawPacket {
  /** 全局递增序号，从 0 开始 */
  index: number;
  /** 毫秒时间戳（捕获时刻，相对 epoch） */
  tsMs: number;
  /** 该帧在原文件中的字节偏移（导出新 pcap / 跳原始报文时使用） */
  fileOffset: number;
  /** 该帧在原文件中的记录长度（pcap 记录头+帧 / pcapng 整块） */
  fileRecordLen: number;
  /** 实际捕获到的帧长度（caplen） */
  capLen: number;
  /** 线缆上的原始长度（origlen） */
  origLen: number;
  /** L2 类型（目前支持 Ethernet） */
  l2: 'ethernet' | 'other';
  srcMac?: string;
  dstMac?: string;
  /** L3 */
  ipVer?: 4 | 6;
  srcIp?: string;
  dstIp?: string;
  ipProto?: number;
  /** L4（TCP） */
  srcPort?: number;
  dstPort?: number;
  seq?: number;
  ack?: number;
  tcpFlags?: number;
  /** TCP 载荷在该帧（caplen 数据）中的字节偏移；undefined 表示无载荷 */
  payloadOffset?: number;
  payloadLength?: number;
  /** 解析异常时的说明（如截断帧），不影响其它帧处理 */
  error?: string;
}

export const TCP_FIN = 0x01;
export const TCP_SYN = 0x02;
export const TCP_RST = 0x04;
export const TCP_PSH = 0x08;
export const TCP_ACK = 0x10;

/** TCP 流方向上的一段按序载荷 */
export interface StreamSegment {
  connId: string;
  /** 方向标识: "C2S" | "S2R"（请求端 -> 响应端） */
  dir: 'C2S' | 'S2R';
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  /** 载荷起始对应的 TCP 序列号（无符号 32 位语义） */
  seq: number;
  /** 载荷字节视图（仅在回调期间有效，不要长期持有） */
  data: Uint8Array;
  /** 该载荷第一个字节所属帧序号 */
  packetIndex: number;
  tsMs: number;
}

export interface TcpConnStats {
  connId: string;
  clientIp: string;
  clientPort: number;
  serverIp: string;
  serverPort: number;
  startMs: number;
  lastMs: number;
  packets: number;
  /** 乱序（到达时 seq 低于期望）报文数 */
  outOfOrder: number;
  /** 重传（载荷区间已被覆盖）报文数 */
  retransmits: number;
  /** 重组后上交的 Modbus 帧数 */
  modbusFrames: number;
  /** 是否看到过 SYN 握手 */
  established: boolean;
  closed: boolean;
}

/** Modbus 功能码（支持的子集，水厂场景够用） */
export const FC = {
  READ_COILS: 0x01,
  READ_DISCRETE: 0x02,
  READ_HOLDING: 0x03,
  READ_INPUT: 0x04,
  WRITE_SINGLE_COIL: 0x05,
  WRITE_SINGLE_REG: 0x06,
  WRITE_MULTI_COIL: 0x0f,
  WRITE_MULTI_REG: 0x10,
  READ_WRITE_MULTI: 0x17,
} as const;

export type ModbusKind = 'request' | 'response' | 'exception' | 'malformed';

export interface ModbusFrame {
  /** 唯一 id（解析顺序） */
  id: number;
  connId: string;
  /** 承载该 MBAP 帧首字节的帧序号 */
  packetIndex: number;
  /** 若跨段重组，参与的帧序号 */
  packetIndices: number[];
  tsMs: number;
  kind: ModbusKind;
  transId: number;
  protoId: number;
  unitId: number;
  fc: number;
  /** 异常码（kind=exception 时有值） */
  exceptionCode?: number;
  /** 起始地址 */
  address?: number;
  /** 寄存器/线圈数量 */
  quantity?: number;
  /** 写入的单值（FC5/6） */
  value?: number;
  /** 读出 / 批量写入的值数组；线圈为 0/1，寄存器为 u16 */
  values?: number[];
  /** 该帧完整 ADU 在原文件中的定位（跳原始报文用，取首个承载帧） */
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  /** 方向：请求端->服务端为 C2S */
  dir: 'C2S' | 'S2R';
  /** 该 ADU 的总字节长度（MBAP+PDU） */
  aduLen: number;
}

export type AlertType =
  | 'write-coil'
  | 'write-register'
  | 'out-of-range'
  | 'scan'
  | 'replay'
  | 'modbus-exception';

export type Severity = 'low' | 'medium' | 'high';

export interface Alert {
  id: number;
  type: AlertType;
  severity: Severity;
  tsMs: number;
  connId?: string;
  /** 关联的 Modbus 帧 id */
  modbusId?: number;
  /** 关联的原始帧序号（跳原始报文） */
  packetIndex: number;
  title: string;
  detail: string;
  status: 'open' | 'ack' | 'ignore';
  /** 基线窗口内产生的告警（学习期，默认折叠展示） */
  inBaselineWindow: boolean;
}

/** 单 (fc, 地址) 维度的基线 */
export interface AddressBaseline {
  key: string;
  fc: number;
  address: number;
  quantity: number;
  count: number;
  periodMs: { p50: number; p95: number; min: number; max: number };
  valueMin: number;
  valueMax: number;
  valueMean: number;
  lastSeenMs: number;
}

export interface ConnBaseline {
  connId: string;
  clientIp: string;
  clientPort: number;
  serverIp: string;
  serverPort: number;
  unitId: number;
  /** 轮询周期（请求间隔）统计，毫秒 */
  periodMs: { p50: number; p95: number; min: number; max: number };
  requestCount: number;
  /** 使用过的功能码 */
  fcs: number[];
  /** 访问过的地址范围并集 */
  addrMin: number;
  addrMax: number;
  addrs: AddressBaseline[];
}

export interface Baseline {
  learnedAtMs: number;
  windowStartMs: number;
  windowEndMs: number;
  conns: ConnBaseline[];
}

export interface SessionMeta {
  id: string;
  fileName: string;
  fileSize: number;
  linkType: number;
  snapLen: number;
  packetCount: number;
  startMs: number;
  endMs: number;
  modbusCount: number;
  alertCount: number;
  importedAt: number;
}

/** 列表筛选条件（会话 / 告警 / Modbus 页共用） */
export interface FilterState {
  q?: string;
  connId?: string;
  fc?: number;
  unitId?: number;
  type?: AlertType;
  status?: Alert['status'] | 'all';
  startMs?: number;
  endMs?: number;
}

export interface ProgressEvent {
  phase: 'read' | 'reassemble' | 'modbus' | 'detect' | 'store' | 'done' | 'error';
  packets: number;
  totalBytes: number;
  readBytes: number;
  modbusFrames: number;
  alerts: number;
  message?: string;
}
