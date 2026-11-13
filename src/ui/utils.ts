/** 通用下载工具（浏览器） */
export function downloadText(name: string, text: string, mime = 'text/csv;charset=utf-8'): void {
  const blob = new Blob([text], { type: mime });
  downloadBlob(name, blob);
}

export function downloadBlob(name: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export function fmtTime(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number, l = 2) => String(n).padStart(l, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export const FC_NAMES: Record<number, string> = {
  1: '读线圈',
  2: '读离散输入',
  3: '读保持寄存器',
  4: '读输入寄存器',
  5: '写单个线圈',
  6: '写单个寄存器',
  15: '写多个线圈',
  16: '写多个寄存器',
  23: '读写多个寄存器',
};

export const ALERT_META: Record<string, { label: string; color: string }> = {
  'write-coil': { label: '写线圈', color: '#e5484d' },
  'write-register': { label: '写寄存器', color: '#e5484d' },
  'out-of-range': { label: '越界', color: '#f5a623' },
  scan: { label: '扫描', color: '#8e4ec6' },
  replay: { label: '重放', color: '#e5484d' },
  'modbus-exception': { label: '异常响应', color: '#71717a' },
};
