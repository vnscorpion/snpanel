import { Play, RefreshCw, RotateCcw, Square } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

export default function ServicesPage() {
  const {
    checkAllServices,
    isAdmin,
    loading,
    runServiceAction,
    serviceNames,
    serviceStates,
  } = usePanel();

  function renderServices() {
    return <section className="section">
      <div className="section-title">
        <h2>Services Status</h2>
        <button disabled={!!loading} onClick={checkAllServices}><RefreshCw size={15}/> Refresh</button>
      </div>
      <div className="service-grid">
        {serviceNames.map(name => {
          const state = serviceStates[name];
          const text = `${state?.stdout || ''} ${state?.stderr || ''}`;
          const active = text.includes('active (running)');
          const inactive = text.includes('inactive') || text.includes('failed');
          return <div className="service-card" key={name}>
            <div><strong>{name}</strong><span className={active ? 'badge ok' : inactive ? 'badge bad' : 'badge'}>{active ? 'Running' : inactive ? 'Stopped' : '...'}</span></div>
            <small>Auto-refreshes every 10s</small>
            {isAdmin && <div className="service-actions">
              <button onClick={() => runServiceAction(name, 'start')}><Play size={13}/> Start</button>
              {!['snpanel-api', 'redis-server'].includes(name) && <button onClick={() => runServiceAction(name, 'stop')}><Square size={13}/> Stop</button>}
              <button onClick={() => runServiceAction(name, 'restart')}><RotateCcw size={13}/> Restart</button>
            </div>}
          </div>;
        })}
      </div>
    </section>;
  }

  return renderServices();
}
