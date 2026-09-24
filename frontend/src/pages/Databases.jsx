import { Check, Copy, Database, Dices, Download, KeyRound, Plus, RefreshCw, Search, Trash2, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

export default function DatabasesPage() {
  const {
    EmptyState,
    changeDbPassword,
    copiedField,
    createDatabase,
    createdDbInfo,
    databases,
    dbSearch,
    dbSearching,
    deleteDatabase,
    downloadDatabase,
    generateRandomPassword,
    loadDatabases,
    loading,
    newDatabase,
    openPhpMyAdmin,
    setCopiedField,
    setCreatedDbInfo,
    setDbSearch,
    setError,
    setNewDatabase,
  } = usePanel();

  function renderDatabases() {
    function copyToClipboard(text, field) {
      const doCopy = navigator.clipboard ? navigator.clipboard.writeText(text) : new Promise((resolve, reject) => {
        try { const ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); resolve(); } catch(e) { reject(e); }
      });
      doCopy.then(() => { setCopiedField(field); setTimeout(() => setCopiedField(null), 2000); }).catch(() => setError('Copy failed.'));
    }
    const dbSearchActive = !!dbSearch.trim();
    return <section className="section">
      <div className="section-title">
        <h2>Databases</h2>
        <button disabled={!!loading || dbSearching} onClick={() => loadDatabases(dbSearch, true)}><RefreshCw size={15} className={dbSearching ? 'spin' : ''}/> Refresh</button>
      </div>
      <div className="website-search-bar">
        <Search size={16}/>
        <input
          value={dbSearch}
          onChange={e => setDbSearch(e.target.value)}
          placeholder="Search by database or user name"
          aria-label="Search databases"
        />
        {dbSearch && <button className="secondary-light icon-button" type="button" onClick={() => setDbSearch('')} aria-label="Clear database search" title="Clear search"><X size={15}/></button>}
      </div>
      <div className="form-row">
        <input value={newDatabase.db_name} onChange={e => setNewDatabase(prev => ({ ...prev, db_name: e.target.value }))} placeholder="database_name" />
        <input value={newDatabase.db_user} onChange={e => setNewDatabase(prev => ({ ...prev, db_user: e.target.value }))} placeholder="db_user (default = db_name)" />
        <input value={newDatabase.db_password} onChange={e => setNewDatabase(prev => ({ ...prev, db_password: e.target.value }))} placeholder="password (min 12 chars)" />
        <button className="mini secondary-light" title="Generate random password" onClick={() => setNewDatabase(prev => ({ ...prev, db_password: generateRandomPassword() }))}><Dices size={13}/></button>
        <button disabled={!!loading || !newDatabase.db_name.trim()} onClick={createDatabase}><Plus size={15}/> Create database</button>
      </div>
      {createdDbInfo && <div className="info-box db-created-box">
        <div className="db-created-head"><strong>Database created successfully</strong><button className="mini secondary-light" onClick={() => setCreatedDbInfo(null)}><X size={13}/></button></div>
        <div className="db-created-grid">
          <label>Database</label><span>{createdDbInfo.db_name} <button className="mini secondary-light" title={copiedField === 'db_name' ? 'Copied!' : 'Copy'} onClick={() => copyToClipboard(createdDbInfo.db_name, 'db_name')}>{copiedField === 'db_name' ? <Check size={12} style={{color:'var(--green)'}}/> : <Copy size={12}/>}</button></span>
          <label>User</label><span>{createdDbInfo.db_user} <button className="mini secondary-light" title={copiedField === 'db_user' ? 'Copied!' : 'Copy'} onClick={() => copyToClipboard(createdDbInfo.db_user, 'db_user')}>{copiedField === 'db_user' ? <Check size={12} style={{color:'var(--green)'}}/> : <Copy size={12}/>}</button></span>
          <label>Password</label><span><code>{createdDbInfo.db_password}</code> <button className="mini secondary-light" title={copiedField === 'db_password' ? 'Copied!' : 'Copy'} onClick={() => copyToClipboard(createdDbInfo.db_password, 'db_password')}>{copiedField === 'db_password' ? <Check size={12} style={{color:'var(--green)'}}/> : <Copy size={12}/>}</button></span>
        </div>
      </div>}
      {databases.length === 0 && !createdDbInfo && <EmptyState icon={Database} message={dbSearchActive ? 'No databases match this search.' : 'No databases found.'} />}
      <div className="table">
        {databases.map(db => {
          return <div className="row db-row" key={db.id}>
          <span><strong>{db.db_name}</strong></span>
          <span style={{color:'var(--text-muted)'}}>{db.db_user}</span>
          <button disabled={!!loading} onClick={() => openPhpMyAdmin(db.id)}>phpMyAdmin</button>
          <button disabled={!!loading} onClick={() => downloadDatabase(db.id, db.db_name)}><Download size={14}/> SQL</button>
          <button disabled={!!loading} onClick={() => changeDbPassword(db.id)}><KeyRound size={14}/> Password</button>
          <button className="danger" disabled={!!loading} onClick={() => deleteDatabase(db.id, db.db_name)}><Trash2 size={14}/></button>
        </div>})}
      </div>
      <p className="hint">Click phpMyAdmin to sign in directly. Token expires after 60s.</p>
    </section>;
  }

  return renderDatabases();
}
