import { AlertCircle, Check, FileText, FolderOpen, Pencil, Play, Plus, RefreshCw, RotateCcw, Save, Server, Square, Trash2, X } from 'lucide-react';
import { SITE_APP_KINDS, SITE_APP_KIND_LABELS, composeWebPorts } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';

export default function ApplicationsPage() {
  const {
    EmptyState,
    checkComposeFile,
    checkSiteAppEdit,
    composePlan,
    controlSiteApp,
    createSiteApp,
    deleteSiteApp,
    deploySiteApp,
    installDockerEngine,
    installNodeMajor,
    isAdmin,
    loadSiteApps,
    loadSiteRuntimes,
    loading,
    openAppFileManager,
    openSiteAppEdit,
    openSiteAppLog,
    pruneDocker,
    saveSiteAppEdit,
    setComposePlan,
    setSiteAppDraft,
    setSiteAppEdit,
    setSiteAppEditPlan,
    setSiteAppLog,
    siteAppDraft,
    siteAppEdit,
    siteAppEditPlan,
    siteAppLog,
    siteApps,
    siteRuntimes,
    suggestSiteAppPort,
    updateSiteApp,
  } = usePanel();

  function renderApplications() {
    const [portFrom, portTo] = siteApps.port_range || [21000, 21999];
    const atLimit = !isAdmin && siteApps.limit > 0 && siteApps.used >= siteApps.limit;
    const dockerReady = !!siteRuntimes.docker?.installed;
    const kindHint = (SITE_APP_KINDS.find(([value]) => value === siteAppDraft.kind) || [])[2];
    return <>
      <section className="section">
        <div className="section-title">
          <div>
            <h2>Applications</h2>
            <p className="hint">
              Each application runs on its own port under its own systemd unit. Point a website at one by setting its
              mode to <strong>Application</strong>.
              {siteApps.limit > 0 && <> Using {siteApps.used} of {siteApps.limit} allowed.</>}
            </p>
          </div>
          <button disabled={!!loading} onClick={() => { loadSiteApps(); loadSiteRuntimes(); }}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="site-runtime-strip">
          <span>Docker: <strong>{dockerReady ? (siteRuntimes.docker.version || 'installed') : 'not installed'}</strong></span>
          <span>Node: <strong>{siteRuntimes.node_majors?.length ? siteRuntimes.node_majors.map(major => `v${major}`).join(', ') : 'system version only'}</strong></span>
          {isAdmin && !dockerReady && <button className="mini secondary-light" disabled={!!loading} onClick={installDockerEngine}>Install Docker</button>}
          {isAdmin && <button className="mini secondary-light" disabled={!!loading} onClick={() => { const major = prompt('Install which Node major version?', '22'); if (major) installNodeMajor(major.trim()); }}>Add Node version</button>}
        </div>
        {isAdmin && dockerReady && siteRuntimes.docker?.disk?.length > 0 && <div className="site-runtime-strip">
          <span>Đĩa Docker (toàn server, không tính vào quota khách):</span>
          {siteRuntimes.docker.disk.map(row => <span key={row.type}>
            {row.type}: <strong>{row.size}</strong>{row.reclaimable && !row.reclaimable.startsWith('0B') ? <> · dọn được {row.reclaimable}</> : null}
          </span>)}
          <button className="mini secondary-light" disabled={!!loading} onClick={pruneDocker}>Dọn layer không dùng</button>
        </div>}
        {!atLimit && <div className="site-app-form">
          <label><span>Name</span>
            <input value={siteAppDraft.name} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, name: e.target.value }))} />
          </label>
          <label><span>Runtime</span>
            <select value={siteAppDraft.kind} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, kind: e.target.value }))}>
              {SITE_APP_KINDS.map(([value, label]) => <option key={value} value={value} disabled={value === 'docker' && !dockerReady}>{label}</option>)}
            </select>
          </label>
          <label><span>Port</span>
            <input
              type="number"
              value={siteAppDraft.port}
              min={portFrom}
              max={portTo}
              disabled={!!loading}
              placeholder={`auto (${portFrom}-${portTo})`}
              onChange={e => setSiteAppDraft(prev => ({ ...prev, port: e.target.value }))}
            />
          </label>
          <label><span>Memory (MB)</span>
            <input
              type="number"
              value={siteAppDraft.memory_limit_mb}
              min={64}
              max={siteApps.memory_ceiling_mb || 512}
              disabled={!!loading}
              placeholder={String(siteApps.memory_ceiling_mb || 512)}
              onChange={e => setSiteAppDraft(prev => ({ ...prev, memory_limit_mb: e.target.value }))}
            />
          </label>
          {siteAppDraft.kind === 'node' && <>
            <label><span>Start with</span>
              <select value={siteAppDraft.start_kind} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, start_kind: e.target.value }))}>
                <option value="npm">npm run</option>
                <option value="npx">npx</option>
                <option value="yarn">yarn</option>
                <option value="node">node</option>
              </select>
            </label>
            <label><span>{siteAppDraft.start_kind === 'node' ? 'Entry file' : 'Script or package'}</span>
              <input value={siteAppDraft.start_arg} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, start_arg: e.target.value }))} placeholder={siteAppDraft.start_kind === 'node' ? 'server.js' : 'start'} />
            </label>
            <label><span>Node version</span>
              <select value={siteAppDraft.node_major} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, node_major: e.target.value }))}>
                {(siteRuntimes.node_majors?.length ? siteRuntimes.node_majors : ['22']).map(major => <option key={major} value={major}>Node {major}</option>)}
              </select>
            </label>
          </>}
          {siteAppDraft.kind === 'compose' && <>
            <label className="site-app-env"><span>docker-compose.yml</span>
              <textarea
                className="code-editor"
                rows={12}
                value={siteAppDraft.compose_source}
                disabled={!!loading}
                onChange={e => { setSiteAppDraft(prev => ({ ...prev, compose_source: e.target.value })); setComposePlan(null); }}
                placeholder={'services:\n  app:\n    image: myorg/app:1.0\n    ports: ["3000:3000"]\n  db:\n    image: postgres:16\n    volumes: ["pgdata:/var/lib/postgresql/data"]\nvolumes:\n  pgdata:'}
              />
            </label>
            {composePlan?.services?.length > 0 && <label><span>Service phục vụ domain</span>
              <select value={siteAppDraft.web_service} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, web_service: e.target.value }))}>
                <option value="">Tự chọn</option>
                {composePlan.services.map(service => <option key={service.name} value={service.name}>{service.name}{service.container_port ? ` · :${service.container_port}` : ''}</option>)}
              </select>
            </label>}
            {composeWebPorts(composePlan, siteAppDraft.web_service).length > 1 && <label><span>Cổng phục vụ domain</span>
              <select value={siteAppDraft.container_port} disabled={!!loading} onChange={e => { setSiteAppDraft(prev => ({ ...prev, container_port: e.target.value })); setComposePlan(null); }}>
                {composeWebPorts(composePlan, siteAppDraft.web_service).map(port => <option key={port} value={port}>{port}</option>)}
              </select>
            </label>}
            <label><span>CPU mỗi service</span>
              <input value={siteAppDraft.cpu_limit} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, cpu_limit: e.target.value }))} placeholder="1" />
            </label>
            <p className="compose-hint">File tham chiếu <code>{'${BIẾN}'}</code> thì khai giá trị ở ô <strong>.env</strong> bên dưới,
              đúng như file <code>.env</code> nằm cạnh <code>docker-compose.yml</code>. Riêng địa chỉ công khai
              (callback OAuth, webhook) dùng <code>{'${SNPANEL_URL}'}</code> / <code>{'${SNPANEL_DOMAIN}'}</code>:
              ứng dụng chỉ thấy cổng nội bộ, panel sẽ điền domain của website trỏ vào nó.</p>
          </>}
          {siteAppDraft.kind === 'docker' && <>
            <label><span>Image</span>
              <input value={siteAppDraft.image} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, image: e.target.value }))} placeholder="n8nio/n8n:latest" />
            </label>
            <label><span>Port in container</span>
              <input type="number" value={siteAppDraft.container_port} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, container_port: e.target.value }))} placeholder="3000" />
            </label>
            <label><span>CPU</span>
              <input value={siteAppDraft.cpu_limit} disabled={!!loading} onChange={e => setSiteAppDraft(prev => ({ ...prev, cpu_limit: e.target.value }))} placeholder="1" />
            </label>
          </>}
          <label className="site-app-env"><span>{siteAppDraft.kind === 'compose' ? '.env (KEY=value, one per line)' : 'Environment (KEY=value, one per line)'}</span>
            <textarea
              className="code-editor"
              rows={4}
              value={siteAppDraft.env}
              disabled={!!loading}
              onChange={e => setSiteAppDraft(prev => ({ ...prev, env: e.target.value }))}
              placeholder={'N8N_ENCRYPTION_KEY=...\nGENERIC_TIMEZONE=Asia/Ho_Chi_Minh'}
            />
          </label>
          <div className="site-app-form-actions">
            {siteAppDraft.kind === 'compose' && <button className="secondary-light" disabled={!!loading || !siteAppDraft.compose_source.trim()} onClick={checkComposeFile}>Check file</button>}
            <button className="secondary-light" disabled={!!loading} onClick={suggestSiteAppPort}>Pick free port</button>
            <button disabled={!!loading || !siteAppDraft.name.trim()} onClick={createSiteApp}><Plus size={14}/> Install application</button>
          </div>
          {composePlan && <div className={`compose-report ${composePlan.ok ? 'ok' : 'bad'}`}>
            {composePlan.ok
              ? <p><Check size={14}/> Chạy được {composePlan.services.length} service. <strong>{composePlan.web_service}</strong> phục vụ domain.</p>
              : <p><AlertCircle size={14}/> Còn {composePlan.issues.length} chỗ phải sửa trước khi import:</p>}
            {composePlan.issues.length > 0 && <ul>
              {composePlan.issues.map((issue, index) => <li key={index}>
                {issue.service && <code>{issue.service}</code>} {issue.message}
              </li>)}
            </ul>}
            {composePlan.notes?.length > 0 && <ul className="compose-notes">
              {composePlan.notes.map((note, index) => <li key={index}>{note}</li>)}
            </ul>}
            {composePlan.ok && <ul className="compose-services">
              {composePlan.services.map(service => <li key={service.name}>
                <code>{service.name}</code> {service.image}
                {service.web ? ' · phục vụ domain' : ' · chỉ nội bộ'}
                {service.container_port ? ` · cổng ${service.container_port}` : ''}
              </li>)}
            </ul>}
          </div>}
        </div>}
        {atLimit && <p className="hint">This package allows {siteApps.limit} application(s). Delete one to install another.</p>}
        {kindHint && <p className="hint site-apps-note">{kindHint} Containers publish on <code>127.0.0.1</code> only, run as your own user with no capabilities, and are capped at the memory shown. Images come from {(siteRuntimes.allowed_registries || []).join(', ') || 'the allowed registries'}.</p>}
      </section>

      <section className="section">
        <div className="section-title">
          <div><h2>Installed</h2><p className="hint">{siteApps.items.length} application(s)</p></div>
        </div>
        {siteApps.items.length === 0 && <EmptyState icon={Server} message="No applications yet. Install one above." />}
        <div className="site-app-list">
          {siteApps.items.map(app => <div className="site-app-item" key={app.id}>
            <div className="site-app-head">
              <strong>{app.name}</strong>
              <span className="badge">{SITE_APP_KIND_LABELS[app.kind] || app.kind}</span>
              <code>127.0.0.1:{app.port}</code>
              <span className={`badge ${app.status === 'running' ? 'ok' : app.status === 'error' ? 'bad' : ''}`}>
                {app.status === 'running' ? 'Running' : app.status === 'error' ? 'Failed' : 'Stopped'}
              </span>
              {app.websites?.length > 0 && <span className="site-app-domains">{app.websites.join(', ')}</span>}
            </div>
            {app.last_error && <p className="site-app-error">{app.last_error}</p>}
            <dl className="site-app-meta">
              <div><dt>Upload code to</dt><dd><code>{app.directory}</code></dd></div>
              {app.kind === 'node' && <div><dt>Start</dt><dd><code>{app.start_kind} {app.start_arg}</code></dd></div>}
              {app.kind === 'node' && <div><dt>Node</dt><dd>v{app.node_major || '22'}</dd></div>}
              {app.kind === 'compose' && <div><dt>Serves domain</dt><dd><code>{app.web_service}</code></dd></div>}
              {app.kind === 'docker' && <div><dt>Image</dt><dd><code>{app.image}</code></dd></div>}
              {app.kind === 'docker' && <div><dt>In container</dt><dd>port {app.container_port} · {app.cpu_limit} CPU</dd></div>}
              <div><dt>Unit</dt><dd><code>{app.unit}</code></dd></div>
            </dl>
            <div className="site-app-actions">
              <div className="site-app-fields">
                <label className="site-app-port">
                  <span>Port</span>
                  <input
                    type="number"
                    defaultValue={app.port}
                    min={portFrom}
                    max={portTo}
                    disabled={!!loading}
                    onBlur={e => {
                      const next = Number(e.target.value);
                      if (next && next !== app.port) updateSiteApp(app, { port: next }, 'Moving application port...');
                    }}
                  />
                </label>
                <label className="site-app-port">
                  <span>Memory (MB)</span>
                  <input
                    type="number"
                    defaultValue={app.memory_limit_mb}
                    min={64}
                    max={isAdmin ? 16384 : (siteApps.memory_ceiling_mb || 512)}
                    disabled={!!loading}
                    onBlur={e => {
                      const next = Number(e.target.value);
                      if (next && next !== app.memory_limit_mb) updateSiteApp(app, { memory_limit_mb: next }, 'Applying the new memory limit...');
                    }}
                  />
                </label>
                {app.kind === 'docker' && <label className="site-app-port">
                  <span>CPU</span>
                  <input
                    defaultValue={app.cpu_limit}
                    disabled={!!loading}
                    onBlur={e => {
                      const next = e.target.value.trim();
                      if (next && next !== app.cpu_limit) updateSiteApp(app, { cpu_limit: next }, 'Applying the new CPU limit...');
                    }}
                  />
                </label>}
              </div>
              <div className="site-app-buttons">
                <button className="mini secondary-light" disabled={!!loading} onClick={() => openSiteAppEdit(app)}><Pencil size={13}/> {app.kind === 'compose' ? 'Compose' : 'Environment'}</button>
                <button className="mini secondary-light" disabled={!!loading} onClick={() => openAppFileManager(app)}><FolderOpen size={13}/> Files</button>
                <button className="mini" disabled={!!loading} onClick={() => deploySiteApp(app)}><Play size={13}/> Deploy</button>
                <button className="mini secondary-light" disabled={!!loading} onClick={() => controlSiteApp(app, 'restart')}><RotateCcw size={13}/> Restart</button>
                <button className="mini secondary-light" disabled={!!loading} onClick={() => controlSiteApp(app, 'stop')}><Square size={13}/> Stop</button>
                <button className="mini secondary-light" disabled={!!loading} onClick={() => openSiteAppLog(app)}><FileText size={13}/> Log</button>
                <button className="mini danger" disabled={!!loading} onClick={() => deleteSiteApp(app)}><Trash2 size={13}/> Delete</button>
              </div>
            </div>
            {siteAppEdit?.id === app.id && <div className="site-app-editor">
              {app.kind === 'compose' ? <>
                <label className="site-app-env"><span>docker-compose.yml</span>
                  <textarea
                    className="code-editor"
                    rows={14}
                    value={siteAppEdit.compose_source}
                    disabled={!!loading}
                    onChange={e => { setSiteAppEdit(prev => ({ ...prev, compose_source: e.target.value })); setSiteAppEditPlan(null); }}
                  />
                </label>
                <p className="compose-hint">Panel đọc lại file này rồi tự sinh file chạy thật. Biến <code>{'${BIẾN}'}</code> lấy
                  từ ô .env; địa chỉ công khai dùng <code>{'${SNPANEL_URL}'}</code> / <code>{'${SNPANEL_DOMAIN}'}</code>
                  {app.websites?.length > 0 ? ` (hiện là ${app.websites[0]})` : ' (cần trỏ một website vào ứng dụng trước)'}.</p>
                <label className="site-app-env"><span>.env (KEY=value, one per line)</span>
                  <textarea
                    className="code-editor"
                    rows={6}
                    value={siteAppEdit.env}
                    disabled={!!loading}
                    onChange={e => { setSiteAppEdit(prev => ({ ...prev, env: e.target.value })); setSiteAppEditPlan(null); }}
                  />
                </label>
                {siteAppEditPlan?.services?.length > 0 && <label><span>Service phục vụ domain</span>
                  <select value={siteAppEdit.web_service} disabled={!!loading} onChange={e => setSiteAppEdit(prev => ({ ...prev, web_service: e.target.value }))}>
                    <option value="">Tự chọn</option>
                    {siteAppEditPlan.services.map(service => <option key={service.name} value={service.name}>{service.name}{service.container_port ? ` · :${service.container_port}` : ''}</option>)}
                  </select>
                </label>}
                {composeWebPorts(siteAppEditPlan, siteAppEdit.web_service).length > 1 && <label><span>Cổng phục vụ domain</span>
                  <select value={siteAppEdit.container_port} disabled={!!loading} onChange={e => { setSiteAppEdit(prev => ({ ...prev, container_port: e.target.value })); setSiteAppEditPlan(null); }}>
                    {composeWebPorts(siteAppEditPlan, siteAppEdit.web_service).map(port => <option key={port} value={port}>{port}</option>)}
                  </select>
                </label>}
              </> : <label className="site-app-env"><span>Environment (KEY=value, one per line)</span>
                <textarea
                  className="code-editor"
                  rows={8}
                  value={siteAppEdit.env}
                  disabled={!!loading}
                  onChange={e => setSiteAppEdit(prev => ({ ...prev, env: e.target.value }))}
                />
              </label>}
              <div className="site-app-form-actions">
                {app.kind === 'compose' && <button className="secondary-light" disabled={!!loading || !siteAppEdit.compose_source.trim()} onClick={checkSiteAppEdit}>Check file</button>}
                <button disabled={!!loading} onClick={() => saveSiteAppEdit(app)}><Save size={14}/> Save</button>
                <button className="secondary-light" disabled={!!loading} onClick={() => { setSiteAppEdit(null); setSiteAppEditPlan(null); }}><X size={14}/> Cancel</button>
              </div>
              {siteAppEditPlan && <div className={`compose-report ${siteAppEditPlan.ok ? 'ok' : 'bad'}`}>
                {siteAppEditPlan.ok
                  ? <p><Check size={14}/> Chạy được {siteAppEditPlan.services.length} service. <strong>{siteAppEditPlan.web_service}</strong> phục vụ domain.</p>
                  : <p><AlertCircle size={14}/> Còn {siteAppEditPlan.issues.length} chỗ phải sửa:</p>}
                {siteAppEditPlan.issues.length > 0 && <ul>
                  {siteAppEditPlan.issues.map((issue, index) => <li key={index}>
                    {issue.service && <code>{issue.service}</code>} {issue.message}
                  </li>)}
                </ul>}
                {siteAppEditPlan.notes?.length > 0 && <ul className="compose-notes">
                  {siteAppEditPlan.notes.map((note, index) => <li key={index}>{note}</li>)}
                </ul>}
              </div>}
            </div>}
          </div>)}
        </div>
        {siteAppLog && <div className="site-app-log">
          <div className="site-app-log-head">
            <h4>{siteAppLog.name} log</h4>
            <button className="mini secondary-light" onClick={() => setSiteAppLog(null)}><X size={13}/> Close</button>
          </div>
          <pre>{siteAppLog.log}</pre>
        </div>}
      </section>
    </>;
  }

  return renderApplications();
}
