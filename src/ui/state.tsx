import { createContext, useContext, useMemo, useReducer, type ReactNode } from 'react';
import type { FilterState, ProgressEvent, SessionMeta } from '../core/types';

interface AppState {
  session: SessionMeta | null;
  sessionId: string | null;
  importing: boolean;
  progress: ProgressEvent | null;
  error: string | null;
  page: 'import' | 'sessions' | 'modbus' | 'alerts' | 'baseline';
  filter: FilterState;
  /** 跳原始报文时选中的帧序号 */
  focusPacketIndex: number | null;
}

type Action =
  | { type: 'start-import'; sessionId: string }
  | { type: 'progress'; progress: ProgressEvent }
  | { type: 'imported'; meta: SessionMeta }
  | { type: 'import-error'; message: string }
  | { type: 'open-session'; meta: SessionMeta }
  | { type: 'close-session' }
  | { type: 'page'; page: AppState['page'] }
  | { type: 'filter'; patch: Partial<FilterState> }
  | { type: 'reset-filter' }
  | { type: 'focus-packet'; index: number | null };

const initial: AppState = {
  session: null,
  sessionId: null,
  importing: false,
  progress: null,
  error: null,
  page: 'import',
  filter: { status: 'all' },
  focusPacketIndex: null,
};

function reducer(s: AppState, a: Action): AppState {
  switch (a.type) {
    case 'start-import':
      return { ...s, importing: true, progress: null, error: null, sessionId: a.sessionId };
    case 'progress':
      return { ...s, progress: a.progress };
    case 'imported':
      return { ...s, importing: false, progress: null, session: a.meta, sessionId: a.meta.id, page: 'sessions' };
    case 'import-error':
      return { ...s, importing: false, error: a.message, progress: null };
    case 'open-session':
      return { ...s, session: a.meta, sessionId: a.meta.id, page: 'sessions', focusPacketIndex: null };
    case 'close-session':
      return { ...initial };
    case 'page':
      return { ...s, page: a.page, focusPacketIndex: null };
    case 'filter':
      return { ...s, filter: { ...s.filter, ...a.patch } };
    case 'reset-filter':
      return { ...s, filter: { status: 'all' } };
    case 'focus-packet':
      return { ...s, focusPacketIndex: a.index };
    default:
      return s;
  }
}

interface Ctx {
  state: AppState;
  dispatch: React.Dispatch<Action>;
}
const AppCtx = createContext<Ctx | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initial);
  const value = useMemo(() => ({ state, dispatch }), [state]);
  return <AppCtx.Provider value={value}>{children}</AppCtx.Provider>;
}

export function useApp(): Ctx {
  const ctx = useContext(AppCtx);
  if (!ctx) throw new Error('useApp 必须在 AppProvider 内使用');
  return ctx;
}
