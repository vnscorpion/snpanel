import { useState } from 'react';
import { Check, Copy, Database, Dices, Download, Globe, KeyRound, Plus, RefreshCw, Search, Trash2, User, UserCog, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';
import { useT } from '../i18n/index.jsx';

export default function DatabasesPage() {
  const {
    EmptyState,
    changeDbPassword,
    copiedField,
    createDatabase,
    createdDbInfo,
    currentUser,
    databases,
    dbSearch,
    dbSearching,
    deleteDatabase,
    downloadDatabase,
    generateRandomPassword,
    isAdmin,
    loadDatabases,
    loading,
    newDatabase,
    openPhpMyAdmin,
    setCopiedField,
    setCreatedDbInfo,
    setDatabaseOwner,
    setDbSearch,
    setError,
    setNewDatabase,
    users,
    websites,
  } = usePanel();
  const t = useT();
  // The row whose owner is being changed, and the choice so far.
  const [moving, setMoving] = useState(null);

  // Whose a database is decides whose backup it is in, and a database is only
  // ever put on one of its owner's sites.
  const sitesOf = (ownerId) => websites.filter((site) => String(site.owner_id) === String(ownerId));
  const createOwner = newDatabase.owner_id || String(currentUser?.id || '');

  function copyToClipboard(text, field) {
    const doCopy = navigator.clipboard ? navigator.clipboard.writeText(text) : new Promise((resolve, reject) => {
      try { const ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); resolve(); } catch (e) { reject(e); }
    });
    doCopy.then(() => { setCopiedField(field); setTimeout(() => setCopiedField(null), 2000); }).catch(() => setError(t('Copy failed.')));
  }

  function copyButton(text, field) {
    return <button className="mini secondary-light" title={copiedField === field ? t('Copied') : t('Copy')} aria-label={t('Copy')}
      onClick={() => copyToClipboard(text, field)}>{copiedField === field ? <Check size={12} style={{ color: 'var(--green)' }}/> : <Copy size={12}/>}</button>;
  }

  async function saveOwner() {
    const db = databases.find((item) => item.id === moving.id);
    if (db && await setDatabaseOwner(db, moving.owner_id, moving.website_id)) setMoving(null);
  }

  const dbSearchActive = !!dbSearch.trim();
  return <section className="section">
    <div className="section-title">
      <h2>{t('Databases')}</h2>
      <button disabled={!!loading || dbSearching} onClick={() => loadDatabases(dbSearch, true)}><RefreshCw size={15} className={dbSearching ? 'spin' : ''}/> {t('Refresh')}</button>
    </div>
    <div className="website-search-bar">
      <Search size={16}/>
      <input value={dbSearch} onChange={e => setDbSearch(e.target.value)}
        placeholder={t('Search by database or user name')} aria-label={t('Search databases')} />
      {dbSearch && <button className="secondary-light icon-button" type="button" onClick={() => setDbSearch('')}
        aria-label={t('Clear the search')} title={t('Clear the search')}><X size={15}/></button>}
    </div>
    <div className="db-create">
      <input value={newDatabase.db_name} onChange={e => setNewDatabase(prev => ({ ...prev, db_name: e.target.value }))}
        placeholder="database_name" aria-label={t('Database name')} />
      <input value={newDatabase.db_user} onChange={e => setNewDatabase(prev => ({ ...prev, db_user: e.target.value }))}
        placeholder={t('db_user (the name, if left empty)')} aria-label={t('Database user')} />
      <div className="db-create-password">
        <input value={newDatabase.db_password} onChange={e => setNewDatabase(prev => ({ ...prev, db_password: e.target.value }))}
          placeholder={t('Password (at least 12 characters)')} aria-label={t('Password')} />
        <button className="secondary-light icon-button" title={t('Generate a random password')} aria-label={t('Generate a random password')}
          onClick={() => setNewDatabase(prev => ({ ...prev, db_password: generateRandomPassword() }))}><Dices size={15}/></button>
      </div>
      {isAdmin && <select value={createOwner} aria-label={t('Owner')}
        onChange={e => setNewDatabase(prev => ({ ...prev, owner_id: e.target.value, website_id: '' }))}>
        {users.map(user => <option key={user.id} value={user.id}>{t('For {name}', { name: user.username })}</option>)}
      </select>}
      <select value={newDatabase.website_id || ''} aria-label={t('Website')}
        onChange={e => setNewDatabase(prev => ({ ...prev, website_id: e.target.value }))}>
        <option value="">{t('No website')}</option>
        {sitesOf(createOwner).map(site => <option key={site.id} value={site.id}>{site.domain}</option>)}
      </select>
      <button disabled={!!loading || !newDatabase.db_name.trim()} onClick={createDatabase}><Plus size={15}/> {t('Create database')}</button>
    </div>
    {createdDbInfo && <div className="info-box db-created-box">
      <div className="db-created-head"><strong>{t('Database created')}</strong>
        <button className="mini secondary-light" onClick={() => setCreatedDbInfo(null)} aria-label={t('Close')}><X size={13}/></button></div>
      <div className="db-created-grid">
        <label>{t('Database')}</label><span>{createdDbInfo.db_name} {copyButton(createdDbInfo.db_name, 'db_name')}</span>
        <label>{t('User')}</label><span>{createdDbInfo.db_user} {copyButton(createdDbInfo.db_user, 'db_user')}</span>
        <label>{t('Password')}</label><span><code>{createdDbInfo.db_password}</code> {copyButton(createdDbInfo.db_password, 'db_password')}</span>
      </div>
    </div>}
    {databases.length === 0 && !createdDbInfo && <EmptyState icon={Database}
      message={dbSearchActive ? t('No databases match this search.') : t('No databases yet.')} />}
    <div className="table">
      {databases.map(db => <div className="db-entry" key={db.id}>
        <div className="row db-row">
          <span className="db-name"><strong>{db.db_name}</strong>
            <small className="db-where">
              <span>{db.db_user}</span>
              {isAdmin && <span title={t('Owner')}><User size={12} aria-hidden="true"/> {db.owner || '?'}</span>}
              <span title={t('Website')}><Globe size={12} aria-hidden="true"/> {db.website || t('No website')}</span>
            </small>
          </span>
          <button disabled={!!loading} onClick={() => openPhpMyAdmin(db.id)}>phpMyAdmin</button>
          <button disabled={!!loading} onClick={() => downloadDatabase(db.id, db.db_name)}><Download size={14}/> SQL</button>
          <button disabled={!!loading} onClick={() => changeDbPassword(db.id)}><KeyRound size={14}/> {t('Password')}</button>
          {isAdmin && <button className="secondary-light" disabled={!!loading} aria-expanded={moving?.id === db.id}
            onClick={() => setMoving(moving?.id === db.id ? null : { id: db.id, owner_id: String(db.owner_id), website_id: db.website_id ? String(db.website_id) : '' })}>
            <UserCog size={14}/> {t('Owner')}
          </button>}
          <button className="danger" disabled={!!loading} onClick={() => deleteDatabase(db.id, db.db_name)}
            aria-label={t('Delete {name}', { name: db.db_name })} title={t('Delete {name}', { name: db.db_name })}><Trash2 size={14}/></button>
        </div>
        {moving?.id === db.id && <div className="db-owner-editor">
          <p className="hint">{t('The owner\'s backups include this database. It can sit on one of their websites, or on none.')}</p>
          <label><span>{t('Owner')}</span>
            <select value={moving.owner_id} onChange={e => setMoving(prev => ({ ...prev, owner_id: e.target.value, website_id: '' }))}>
              {users.map(user => <option key={user.id} value={user.id}>{user.username}</option>)}
            </select>
          </label>
          <label><span>{t('Website')}</span>
            <select value={moving.website_id} onChange={e => setMoving(prev => ({ ...prev, website_id: e.target.value }))}>
              <option value="">{t('No website')}</option>
              {sitesOf(moving.owner_id).map(site => <option key={site.id} value={site.id}>{site.domain}</option>)}
            </select>
          </label>
          <div className="db-owner-actions">
            <button className="secondary-light" onClick={() => setMoving(null)}>{t('Cancel')}</button>
            <button disabled={!!loading} onClick={saveOwner}>{t('Save')}</button>
          </div>
        </div>}
      </div>)}
    </div>
    <p className="hint">{t('phpMyAdmin signs you in directly; the link works for 60 seconds.')}</p>
  </section>;
}
