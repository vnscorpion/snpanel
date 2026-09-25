import { Play, RefreshCw, RotateCcw, Square } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';

export default function ServicesPage() {
  const t = useT();
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
        <div><h2>{t('Services Status')}</h2><p className="hint">{t('Auto-refreshes every 10s')}</p></div>
        <button className="secondary-light" disabled={!!loading} onClick={checkAllServices}><RefreshCw size={15}/> {t('Refresh')}</button>
      </div>
      <div className="service-grid">
        {serviceNames.map(name => {
          const state = serviceStates[name];
          const text = `${state?.stdout || ''} ${state?.stderr || ''}`;
          const active = text.includes('active (running)');
          const inactive = text.includes('inactive') || text.includes('failed');
          return <div className="service-card" key={name}>
            <div><strong>{name}</strong><span className={active ? 'badge ok' : inactive ? 'badge bad' : 'badge'}>{active ? t('Running') : inactive ? t('Stopped') : '...'}</span></div>
            {/* Only what applies: a running service restarts or stops, a
                stopped one starts; while its state is unknown, both. */}
            {isAdmin && <div className="service-actions">
              {!active && <button className="mini" onClick={() => runServiceAction(name, 'start')}><Play size={13}/> {t('Start')}</button>}
              {!inactive && <button className="mini secondary-light" onClick={() => runServiceAction(name, 'restart')}><RotateCcw size={13}/> {t('Restart')}</button>}
              {active && !['snpanel-api', 'redis-server'].includes(name) && <button className="mini secondary-light" onClick={() => runServiceAction(name, 'stop')}><Square size={13}/> {t('Stop')}</button>}
            </div>}
          </div>;
        })}
      </div>
    </section>;
  }

  return renderServices();
}
