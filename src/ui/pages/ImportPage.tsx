import { useCallback, useEffect, useRef, useState } from 'react';
import { useApp } from '../state';
import { fmtBytes } from '../utils';
import { listSessions, SessionStore } from '../../storage/idb';
import type { SessionMeta } from '../../core/types';
import type { WorkerInMsg, WorkerOutMsg } from '../../workers/analysis.worker';
import AnalysisWorker from '../../workers/analysis.worker?worker';

export function ImportPage() {
  const { state, dispatch } = useApp();
  const [dragOver, setDragOver] = useState(false);
  const [windowSec, setWindowSec] = useState(60);
  const [history, setHistory] = useState<SessionMeta[]>([]);
  const workerRef = useRef<Worker | null>(null);

  const refreshHistory = useCallback(async () => {
    try {
      const ids = await listSessions();
      const metas: SessionMeta[] = [];
      for (const id of ids) {
        const store = new SessionStore(id);
        const meta = await store.getMeta();
        await store.close();
        if (meta) metas.push(meta);
      }
      metas.sort((a, b) => b.importedAt - a.importedAt);
      setHistory(metas);
    } catch {
      // 隐私模式等场景 IDB 不可用，忽略
    }
  }, []);

  useEffect(() => {
    void refreshHistory();
    return () => workerRef.current?.terminate();
  }, [refreshHistory]);

  const startImport = useCallback(
    (file: File) => {
      const sessionId = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      dispatch({ type: 'start-import', sessionId });
      const worker = new AnalysisWorker();
      workerRef.current = worker;
      worker.onmessage = (ev: MessageEvent<WorkerOutMsg>) => {
        const m = ev.data;
        if (m.type === 'progress') dispatch({ type: 'progress', progress: m.progress });
        if (m.type === 'done') {
          dispatch({ type: 'imported', meta: m.meta });
          worker.terminate();
          workerRef.current = null;
          void refreshHistory();
        }
        if (m.type === 'error') {
          dispatch({ type: 'import-error', message: m.message });
          worker.terminate();
          workerRef.current = null;
        }
      };
      const msg: WorkerInMsg = { type: 'start', sessionId, file, baselineWindowMs: windowSec * 1000 };
      worker.postMessage(msg);
    },
    [dispatch, refreshHistory, windowSec],
  );

  const p = state.progress;
  const pct = p && p.totalBytes > 0 ? Math.min(100, (p.readBytes / p.totalBytes) * 100) : 0;
  const phaseLabel: Record<string, string> = {
    read: '流式读取与协议解析',
    reassemble: 'TCP 重组',
    modbus: 'Modbus 解析',
    detect: '基线学习与检测',
    store: '写入本地数据库',
    done: '完成',
    error: '失败',
  };

  return (
    <div className="import-page">
      <section
        className={`dropzone ${dragOver ? 'over' : ''} ${state.importing ? 'busy' : ''}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          const f = e.dataTransfer.files[0];
          if (f && !state.importing) startImport(f);
        }}
      >
        <input
          id="pcap-file"
          type="file"
          accept=".pcap,.pcapng,.cap"
          hidden
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) startImport(f);
            e.target.value = '';
          }}
        />
        {!state.importing ? (
          <label htmlFor="pcap-file" className="drop-inner">
            <div className="drop-icon">📂</div>
            <h2>拖入 pcap / pcapng，或点击选择文件</h2>
            <p>分块流式读取，2GB 文件也不会整体进内存；数据仅在本机浏览器内处理</p>
          </label>
        ) : (
          <div className="drop-inner">
            <div className="spinner" />
            <h2>{p ? phaseLabel[p.phase] ?? p.phase : '启动解析…'}</h2>
            <div className="progress-bar">
              <div className="progress-fill" style={{ width: `${pct}%` }} />
            </div>
            <div className="progress-stats">
              <span>{p ? p.packets.toLocaleString() : 0} 帧</span>
              <span>{p?.modbusFrames ?? 0} Modbus</span>
              <span>{p?.alerts ?? 0} 告警</span>
              <span>
                {p ? fmtBytes(p.readBytes) : '0'} / {p ? fmtBytes(p.totalBytes) : '0'}
              </span>
            </div>
          </div>
        )}
        {state.error && <div className="error-banner">导入失败：{state.error}</div>}
      </section>

      <section className="config-card">
        <h3>基线学习窗口</h3>
        <p>取抓包开头的正常时段学习轮询周期与取值范围，窗口结束后开始正式检测。</p>
        <label>
          正常时段长度（秒）
          <input
            type="number"
            min={5}
            max={3600}
            value={windowSec}
            disabled={state.importing}
            onChange={(e) => setWindowSec(Number(e.target.value) || 60)}
          />
        </label>
      </section>

      {history.length > 0 && (
        <section className="history-card">
          <h3>本机历史会话（IndexedDB）</h3>
          <table>
            <thead>
              <tr>
                <th>文件</th>
                <th>大小</th>
                <th>帧数</th>
                <th>Modbus</th>
                <th>告警</th>
                <th>导入时间</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {history.map((m) => (
                <tr key={m.id}>
                  <td>{m.fileName}</td>
                  <td>{fmtBytes(m.fileSize)}</td>
                  <td>{m.packetCount.toLocaleString()}</td>
                  <td>{m.modbusCount}</td>
                  <td className={m.alertCount > 0 ? 'danger' : ''}>{m.alertCount}</td>
                  <td>{new Date(m.importedAt).toLocaleString()}</td>
                  <td>
                    <button className="btn small" onClick={() => dispatch({ type: 'open-session', meta: m })}>
                      打开
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="hint">
            注意：历史会话保留结构化分析结果与帧定位索引；重新打开后「跳原始报文/导出 pcap」需要重新选择同一份原文件。
          </p>
        </section>
      )}
    </div>
  );
}
