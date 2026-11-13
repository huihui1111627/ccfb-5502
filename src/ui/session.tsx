import { createContext, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { BlobChunkSource, type ChunkSource } from '../core/chunk';
import { SessionStore } from '../storage/idb';
import { useApp } from './state';

interface SessionCtxValue {
  store: SessionStore;
  /** 原文件数据源；未挂载原文件时为 null（历史会话场景） */
  source: ChunkSource | null;
  sourceName: string | null;
  attachFile: (f: File) => void;
  /** 读取某帧的原始字节（含链路层） */
  readFrame: (packetIndex: number) => Promise<{ data: Uint8Array; tsMs: number }>;
}

const SessionCtx = createContext<SessionCtxValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const { state } = useApp();
  const [source, setSource] = useState<ChunkSource | null>(null);
  const [sourceName, setSourceName] = useState<string | null>(null);
  const fileRef = useRef<File | null>(null);

  const store = useMemo(() => new SessionStore(state.sessionId!), [state.sessionId]);
  useEffect(() => () => void store.close(), [store]);

  const attachFile = (f: File) => {
    fileRef.current = f;
    setSourceName(f.name);
    setSource(new BlobChunkSource(f));
  };

  const readFrame = async (packetIndex: number) => {
    const loc = await store.getPacketLocator(packetIndex);
    if (!fileRef.current) throw new Error('原文件未挂载，请先重新选择 pcap/pcapng 文件');
    // 从记录头之后读 capLen 字节（pcap 记录头 16B；pcapng EPB 帧头 28B）
    const isPcapng = fileRef.current.name.endsWith('.pcapng');
    const headerSkip = isPcapng ? 28 : 16;
    const buf = await source!.read(loc.fileOffset + headerSkip, loc.capLen);
    return { data: new Uint8Array(buf), tsMs: loc.tsMs };
  };

  return (
    <SessionCtx.Provider value={{ store, source, sourceName, attachFile, readFrame }}>
      {children}
    </SessionCtx.Provider>
  );
}

export function useSession(): SessionCtxValue {
  const ctx = useContext(SessionCtx);
  if (!ctx) throw new Error('useSession 必须在 SessionProvider 内使用');
  return ctx;
}

/** 未挂载原文件时的提示条（历史会话重新打开场景） */
export function AttachFileBanner() {
  const { source, sourceName, attachFile } = useSession();
  const { state } = useApp();
  if (source) {
    return (
      <div className="attach-banner ok">
        原文件已挂载：<strong>{sourceName}</strong>
      </div>
    );
  }
  return (
    <div className="attach-banner">
      <span>
        原始报文回读 / 导出 pcap 需要原文件（结构化结果已在本地）。当前会话来自：
        <strong>{state.session?.fileName}</strong>
      </span>
      <label className="btn small">
        重新选择原文件
        <input
          type="file"
          accept=".pcap,.pcapng,.cap"
          hidden
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) attachFile(f);
          }}
        />
      </label>
    </div>
  );
}
