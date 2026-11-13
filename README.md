# 工控流量分析台（Modbus/TCP）

纯浏览器端的工控（ICS）抓包分析工具。水厂运维场景下，动辄几个 GB 的 pcap 不再需要人工拖 Wireshark——
文件从不上传服务器，全部在本机浏览器内用 Web Worker 后台解析。

## 功能对应

| 需求 | 实现 |
| --- | --- |
| 导入 pcap / pcapng，分块读不卡 | `core/chunk.ts` 4MiB 滑动窗口 + `core/pcap.ts` 流式读取器，Web Worker 后台跑，主线程只收进度 |
| TCP 流重组，乱序/重传处理对 | `core/reassembly.ts`：32 位序号回绕、乱序 pending 表、重传/重叠去重，单测覆盖 |
| Modbus/TCP 按功能码解寄存器和值 | `core/modbus.ts`：MBAP 粘包/拆包，FC1/2/3/4/5/6/15/16/23，线圈与寄存器值 |
| 学轮询周期和取值范围 | `core/baseline.ts`：正常时段学连接级周期（p50/p95/min/max）与每地址值范围 |
| 标写线圈/越界地址/扫描/重放 | `core/detect.ts`：5 类规则 + Modbus 异常响应 |
| 告警跳原始报文，可确认/忽略 | 告警行「原始报文」按帧定位回读字节并逐层解码；状态写 IndexedDB |
| 会话/告警筛选，导出 CSV | 各页筛选器 + `core/exporter.ts`（带 UTF-8 BOM，Excel 中文不乱码） |
| 过滤结果导出新 pcap | `core/exporter.ts` 流式回读原始帧重打包，pcap/pcapng 源都能导出为标准 pcap |
| 2GB 不整读内存 | 见下方「内存模型」，压力测试实测文件翻倍而堆峰值不变 |

## 快速开始

```bash
npm install
npm run dev          # 浏览器打开 http://localhost:5173
```

构建与测试：

```bash
npm run build        # 类型检查 + 生产构建（含独立 worker bundle）
npm test             # vitest，24 个用例
npm run gen:testdata # 生成带攻击注入时间戳的合成 pcap/pcapng 到 tests/testdata
npm run stress -- 100   # 大文件流式压力测试（参数为目标 MB，默认 300）
```

## 架构

```
src/
├─ core/            # 纯逻辑，零 DOM 依赖，可直接在 Node 单测
│  ├─ chunk.ts      # ChunkSource 抽象 + ChunkPuller 滑动窗口（浏览器 File.slice / Node fd 同接口）
│  ├─ pcap.ts       # pcap & pcapng 流式读取器（SHB/IDB/EPB，字节序、tsresol、块对齐）
│  ├─ decode.ts     # Ethernet(含VLAN) / IPv4 / TCP 解码
│  ├─ reassembly.ts # TCP 重组：序号回绕、乱序缓存、重传与重叠去重
│  ├─ modbus.ts     # MBAP 流解析：跨段粘包/拆包，按功能码解 PDU
│  ├─ baseline.ts   # 正常时段基线学习
│  ├─ detect.ts     # 检测规则
│  ├─ engine.ts     # 单遍扫描编排 + AnalysisSink 流式下沉
│  └─ exporter.ts   # CSV 与 pcap 导出
├─ storage/idb.ts   # IndexedDB：结构化结果持久化，帧索引定长 24B/帧分块
├─ workers/         # 解析 Worker（sink 分块落盘，常驻内存有界）
└─ ui/              # React 五个页面：导入/会话/Modbus/告警/基线
```

### 解析管线（单遍扫描）

```
File.slice 分块 → pcap/pcapng 取帧 → L2/L3/L4 解码
      → TcpReassembler（按序字节流）→ ModbusParser（ADU 帧）
      → 前 60s 学基线 → 固化后 Detector 逐帧检测 → sink 落盘
```

## 内存模型（2GB 约束的核心）

- **原始字节从不驻留**：读取侧任意时刻只持有一个 4MiB 窗口；原始帧通过帧定位索引（`fileOffset/recordLen`）按需回读。
- **结构化结果走 sink**：`runAnalysis` 支持注入 `AnalysisSink`。Worker 注入分块 sink，每攒 1000 条写一次 IndexedDB 并清空，
  引擎和 Worker 都不累积全量结果。不传 sink 时才用数组收集（中小文件、单测路径）。
- **有界缓存**：事务配对 Map 与重传去重 Set 都有 1 万条上限，按最旧淘汰，常驻内存与总帧数解耦。
- **帧索引定长**：每帧 24B 打成 256 帧/块的 ArrayBuffer 存 IDB；10 万帧索引仅约 2.4MB。

压力测试实测（`npm run stress`，512MB 堆上限）：

| 文件大小 | Modbus 帧 | 堆峰值 |
| --- | --- | --- |
| 50MB | ~57 万 | 120.7MB |
| 100MB | ~114 万 | 119.6MB |

**文件翻倍，堆峰值基本不变**——证明常驻内存由有界缓存决定，而非文件大小。

## 检测规则与告警

| 类型 | 判定 |
| --- | --- |
| `write-coil` | FC5/FC15 写线圈（正常轮询基线通常只有读） |
| `write-register` | FC6/FC16/FC23 写寄存器 |
| `out-of-range` | 地址/功能码超出基线并集；或读响应值超出基线值范围 |
| `scan` | 5s 滑窗内同一源对同一单元访问 ≥20 个不同 (功能码,地址) |
| `replay` | 相同写请求签名重复出现且间隔明显偏离基线轮询周期 |
| `modbus-exception` | 设备返回异常码（辅助） |

每条告警都带 `packetIndex`，可一键跳回原始报文（hex dump + 逐层解码）。

## 测试数据与检出精度

`tests/gen/` 自己造包，ground truth 与 pcap 用同一绝对时间基准：

- 0–90s 正常 1s 周期轮询（基线窗口取前 60s）
- 20–22s 注入 TCP 拆段、乱序、重传
- 95s 写线圈、100s 写多寄存器、105s 越界地址、110s 扫描、120s 重放

端到端测试断言**每个注入事件都有同类型告警且时间误差 ≤1s**，并校验重传不产生重复 Modbus 帧、
基线周期 p50 落在 900–1100ms、值范围正确。pcap 与 pcapng 两种格式各跑一遍。

## 协议取舍

- 链路层聚焦水厂最常见的 Ethernet-II + IPv4 + TCP（含 802.1Q VLAN 剥标签）；IPv6/UDP 等识别后跳过不报错。
- Modbus 覆盖读线圈/离散/保持/输入寄存器、单写/多写/读写复合；异常响应按 `fc|0x80` 解析。
- 无 SYN 的中途抓包用首见 seq 推断 ISN 基准，仍可正确识别乱序。
- pcapng 按默认微秒 tick 处理，同时解析 IDB 的 `if_tsresol` 选项与块/选项 32bit 对齐。
