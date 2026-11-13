import { useApp } from './state';
import { SessionProvider } from './session';
import { ImportPage } from './pages/ImportPage';
import { SessionsPage } from './pages/SessionsPage';
import { ModbusPage } from './pages/ModbusPage';
import { AlertsPage } from './pages/AlertsPage';
import { BaselinePage } from './pages/BaselinePage';

const TABS = [
  { key: 'import', label: '导入' },
  { key: 'sessions', label: '会话' },
  { key: 'modbus', label: 'Modbus 解析' },
  { key: 'alerts', label: '告警' },
  { key: 'baseline', label: '基线' },
] as const;

export function App() {
  const { state, dispatch } = useApp();
  const hasSession = !!state.session;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo">⌁</span>
          <div>
            <h1>工控流量分析台</h1>
            <small>Modbus/TCP · 浏览器本地分析 · 文件不落服务器</small>
          </div>
        </div>
        {state.session && (
          <div className="session-info">
            <div>
              <strong>{state.session.fileName}</strong>
              <small>
                {state.session.packetCount.toLocaleString()} 帧 · {state.session.modbusCount.toLocaleString()} Modbus ·{' '}
                {state.session.alertCount} 告警
              </small>
            </div>
            <button className="btn ghost" onClick={() => dispatch({ type: 'close-session' })}>
              关闭会话
            </button>
          </div>
        )}
      </header>

      <nav className="tabs">
        {TABS.map((t) => (
          <button
            key={t.key}
            className={`tab ${state.page === t.key ? 'active' : ''}`}
            disabled={t.key !== 'import' && !hasSession}
            onClick={() => dispatch({ type: 'page', page: t.key })}
          >
            {t.label}
          </button>
        ))}
      </nav>

      <main className="content">
        {state.page === 'import' && <ImportPage />}
        {state.page !== 'import' && hasSession && (
          <SessionProvider>
            {state.page === 'sessions' && <SessionsPage />}
            {state.page === 'modbus' && <ModbusPage />}
            {state.page === 'alerts' && <AlertsPage />}
            {state.page === 'baseline' && <BaselinePage />}
          </SessionProvider>
        )}
      </main>
    </div>
  );
}
