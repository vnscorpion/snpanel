import { Ban, Globe, HardDrive, LogIn, Pencil, Play, Plus, RefreshCw, Save, Trash2, Users, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { usePanel } from '../lib/panel-context.jsx';
import { msg, useT } from '../i18n/index.jsx';
import SftpAccess from '../components/SftpAccess.jsx';

export default function UsersPage() {
  const {
    EmptyState,
    applyPackageToEditingUser,
    applyPackageToNewUser,
    assignDomainToUser,
    assignUserId,
    assignWebsiteId,
    cancelEditingPackage,
    cancelEditingUser,
    createPackage,
    createUser,
    currentUser,
    deletePackage,
    deletePanelUser,
    editingPackageForm,
    editingPackageId,
    editingUser,
    editingUserForm,
    isAdmin,
    isReseller,
    canManageUsers,
    request,
    loadPackages,
    loadUsers,
    loading,
    newPackage,
    newUser,
    packages,
    quickLoginUser,
    resetUserTwoFactor,
    roleLabel,
    setAssignUserId,
    setAssignWebsiteId,
    setEditingPackageForm,
    setEditingUserForm,
    setNewPackage,
    setNewUser,
    setUserTab,
    startEditingPackage,
    startEditingUser,
    storageUsageText,
    submitPasswordChange,
    suspendUser,
    unsuspendUser,
    updatePackage,
    updatePanelUser,
    userTab,
    users,
    websites,
  } = usePanel();
  const t = useT();
  // What the 2FA badge stands for: the app code, passkeys, or both.
  const twoStepOf = (user) => [
    user.totp_enabled ? t('Authenticator app') : '',
    user.passkeys > 0 ? t('{count} passkey(s)', { count: user.passkeys }) : '',
  ].filter(Boolean).join(' + ');

  function renderUsers() {
    if (!canManageUsers) return <section className="section"><h2>{t('Panel users')}</h2><p className="hint">{t('No permission.')}</p></section>;
    const activeUserTab = userTab || 'list';
    const userTabButton = (key, Icon, label) => (
      <button
        type="button"
        className={activeUserTab === key ? 'active' : ''}
        role="tab"
        aria-selected={activeUserTab === key}
        aria-controls={`users-tab-${key}`}
        id={`users-tab-button-${key}`}
        onClick={() => setUserTab(key)}
      >
        <Icon size={14}/> {label}
      </button>
    );

    return <section className="section users-page">
      <div className="section-title">
        {isReseller
          ? <div><h2>{t('Customers')}</h2><p className="hint">{t('The accounts you sell, and their packages. Log in as a customer to manage their websites.')}</p></div>
          : <div><h2>{t('Panel users')}</h2><p className="hint">{t('Manage users, packages, and domain ownership.')}</p></div>}
      </div>
      {isReseller && <ResellerUsage key={users.map(u => `${u.id}:${u.is_active}`).join(',')} userId={currentUser?.id} request={request} t={t} />}
      <div className="segmented user-tabs" role="tablist" aria-label={t('Panel user sections')}>
        {userTabButton('list', Users, t('Users'))}
        {userTabButton('packages', HardDrive, t('Packages'))}
        {userTabButton('add', Plus, t('Add user'))}
      </div>

      {activeUserTab === 'list' && <div className="user-tab-panel" id="users-tab-list" role="tabpanel" aria-labelledby="users-tab-button-list">
        <div className="section-title user-panel-title">
          <div><h2>{isReseller ? t('Customers') : t('Panel user list')}</h2><p className="hint">{t('Current panel users and service limits.')}</p></div>
          <button className="secondary-light" disabled={!!loading} onClick={loadUsers}><RefreshCw size={14}/> {t('Refresh')}</button>
        </div>
        {users.length === 0 && <EmptyState icon={Users} message={t('No users found.')} />}
        <div className="table">
          {users.map(user => <div className="row user-row" key={user.id}>
            <div className="user-main"><strong>{user.username}</strong><small>{user.email}</small></div>
            <div className="user-badges">
              <span className={user.is_active ? 'badge ok' : 'badge danger'}>{user.is_active ? t('Active') : t('Suspended')}</span>
              <span className="badge">{roleLabel(user.role)}{user.reseller ? ` · ${user.reseller.prefix}_` : ''}</span>
              {isAdmin && user.parent_username && <span className="badge" title={t('Reseller')}>{t('via {name}', { name: user.parent_username })}</span>}
              <span className="badge">{user.package_name || t('Custom')}</span>
              {(user.totp_enabled || user.passkeys > 0) && <span className="badge ok" title={twoStepOf(user)}>2FA</span>}
              {user.sftp && <span className={`badge ${user.sftp.enabled ? 'ok' : ''}`}>{user.sftp.enabled ? t('SFTP') : t('SFTP off')}</span>}
            </div>
            {/* The list arrives without this figure and each user's follows on
                its own (see loadUsers), so a slow account holds up only its cell. */}
            {user.storage_used_bytes == null
              ? <span className="user-metric usage-pending" aria-busy="true"><HardDrive size={13}/>{t('Measuring…')}</span>
              : <span className="user-metric"><HardDrive size={13}/>{storageUsageText(user)}</span>}
            <div className="row-actions">
              <button className="mini secondary-light" disabled={!!loading} onClick={() => startEditingUser(user)}><Pencil size={14}/> {t('Edit')}</button>
              <button className="mini secondary-light" disabled={!!loading} onClick={() => quickLoginUser(user)}><LogIn size={14}/> {t('Log in as')}</button>
              {(user.totp_enabled || user.passkeys > 0) && user.id !== currentUser?.id && <button className="mini secondary-light" disabled={!!loading} onClick={() => resetUserTwoFactor(user)}>{t('Reset 2FA')}</button>}
              {user.id !== currentUser?.id && (user.is_active
                ? <button className="mini secondary-light" disabled={!!loading} onClick={() => suspendUser(user)}><Ban size={14}/> {t('Suspend')}</button>
                : <button className="mini secondary-light" disabled={!!loading} onClick={() => unsuspendUser(user)}><Play size={14}/> {t('Unsuspend')}</button>
              )}
              {user.id !== currentUser?.id && <button className="mini danger" disabled={!!loading} onClick={() => deletePanelUser(user)}
                aria-label={t('Delete {name}', { name: user.username })} title={t('Delete {name}', { name: user.username })}><Trash2 size={14}/></button>}
            </div>
            {editingUser?.id === user.id && <div className="user-edit-panel">
              <div className="user-edit-heading">
                <div><strong>{t('Edit {name}', { name: user.username })}</strong><small>
                  {user.id === currentUser?.id ? t('The role is locked for the administrator signed in now.') : t('Changing the role signs the user out everywhere.')}
                  {editingUserForm.role === 'admin' ? ` ${t('Administrators are not bound by website or storage limits.')}` : ''}
                </small></div>
                <button className="user-edit-close secondary-light" onClick={cancelEditingUser} aria-label={t('Close the user editor')} title={t('Close the user editor')}><X size={16}/></button>
              </div>
              <div className="user-edit-grid">
                <label><span>{t('Email')}</span><input type="email" value={editingUserForm.email} onChange={e => setEditingUserForm(prev => ({ ...prev, email: e.target.value }))} /></label>
                {isAdmin && <label><span>{t('Role')}</span><select value={editingUserForm.role} disabled={user.id === currentUser?.id} onChange={e => setEditingUserForm(prev => ({ ...prev, role: e.target.value }))}>
                  <option value="end_user">{roleLabel('end_user')}</option><option value="reseller">{roleLabel('reseller')}</option><option value="admin">{roleLabel('admin')}</option>
                </select></label>}
                {isAdmin && editingUserForm.role === 'end_user' && <label><span>{t('Reseller')}</span><select value={editingUserForm.parent_id || ''} onChange={e => setEditingUserForm(prev => ({ ...prev, parent_id: e.target.value }))}>
                  <option value="">{t('None (administrator)')}</option>
                  {users.filter(u => u.role === 'reseller' && u.id !== user.id).map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
                </select></label>}
                <label><span>{t('Package')}</span><select value={editingUserForm.package_id} onChange={e => applyPackageToEditingUser(e.target.value)}>
                  {!isReseller && <option value="">{t('Custom limits')}</option>}
                  {packages.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
                </select></label>
                {!isReseller && <label><span>{t('Website limit')}</span><input type="number" min="0" max="1000" disabled={!!editingUserForm.package_id} value={editingUserForm.website_limit} onChange={e => setEditingUserForm(prev => ({ ...prev, website_limit: e.target.value }))} /></label>}
                {!isReseller && <label><span>{t('Storage limit (MB)')}</span><input type="number" min="0" max="1048576" disabled={!!editingUserForm.package_id} value={editingUserForm.storage_limit_mb} onChange={e => setEditingUserForm(prev => ({ ...prev, storage_limit_mb: e.target.value }))} /></label>}
              </div>
              {isAdmin && editingUserForm.role === 'reseller' && <div className="user-edit-section">
                <div className="user-edit-heading"><div><strong>{t('Reseller limits')}</strong><small>{t('On what the reseller and its accounts really use; its packages may promise more. 0 = no limit.')}</small></div></div>
                <ResellerFields value={editingUserForm.reseller || {}} onChange={reseller => setEditingUserForm(prev => ({ ...prev, reseller }))} t={t} />
                {user.role === 'reseller' && <ResellerUsage userId={user.id} request={request} t={t} />}
              </div>}
              <div className="user-edit-section">
                <div className="user-edit-heading"><div><strong>{t('Change password')}</strong><small>
                  {user.id === currentUser?.id
                    ? t('At least 12 characters. Needs the current password and a 2FA code.')
                    : t('At least 12 characters. An administrator can set it directly.')}
                </small></div></div>
                <div className="user-edit-grid">
                  <label><span>{t('New password')}</span><input type="password" placeholder={t('At least 12 characters')} value={editingUserForm.new_password} onChange={e => setEditingUserForm(prev => ({ ...prev, new_password: e.target.value }))} /></label>
                  <label><span>{t('Confirm password')}</span><input type="password" placeholder={t('Repeat the password')} value={editingUserForm.confirm_password} onChange={e => setEditingUserForm(prev => ({ ...prev, confirm_password: e.target.value }))} /></label>
                </div>
                <div className="user-edit-actions">
                  <button disabled={!!loading || !editingUserForm.new_password || editingUserForm.new_password.length < 12} onClick={() => submitPasswordChange(user)}>{t('Set password')}</button>
                </div>
              </div>
              {isAdmin && <div className="user-edit-section">
                <SftpAccess user={user} self={user.id === currentUser?.id} />
              </div>}
              <div className="user-edit-actions">
                <button className="secondary-light" onClick={cancelEditingUser}>{t('Cancel')}</button>
                <button disabled={!!loading || !editingUserForm.email.trim()} onClick={updatePanelUser}><Save size={14}/> {t('Save changes')}</button>
              </div>
            </div>}
          </div>)}
        </div>
        {isAdmin && <div className="user-action-panel">
          <div><h3>{t('Assign a domain to a user')}</h3><p className="hint">{t('Move an existing domain under a panel user.')}</p></div>
          <div className="assign-row">
            <select value={assignWebsiteId} onChange={e => setAssignWebsiteId(e.target.value)} aria-label={t('Domain')}>
              <option value="">{t('Select a domain')}</option>
              {websites.map(site => <option key={site.id} value={site.id}>{site.domain}</option>)}
            </select>
            <select value={assignUserId} onChange={e => setAssignUserId(e.target.value)} aria-label={t('User')}>
              <option value="">{t('Select a user')}</option>
              {users.map(user => <option key={user.id} value={user.id}>{user.username} ({roleLabel(user.role)})</option>)}
            </select>
            <button disabled={!assignWebsiteId || !assignUserId || !!loading} onClick={assignDomainToUser}>{t('Assign')}</button>
          </div>
        </div>}
      </div>}

      {activeUserTab === 'packages' && <div className="user-tab-panel" id="users-tab-packages" role="tabpanel" aria-labelledby="users-tab-button-packages">
        <div className="section-title user-panel-title">
          <div><h2>{t('Packages')}</h2><p className="hint">{t('Create, edit, delete, and review reusable user limits.')}</p></div>
          <button className="secondary-light" disabled={!!loading} onClick={loadPackages}><RefreshCw size={14}/> {t('Refresh')}</button>
        </div>
        <div className="user-create-card package-create-card">
          <label><span>{t('Package name')}</span><input value={newPackage.name} onChange={e => setNewPackage(prev => ({ ...prev, name: e.target.value }))} placeholder={t('Starter')} /></label>
          <label><span>{t('Website limit')}</span><input type="number" min="0" max="1000" value={newPackage.website_limit} onChange={e => setNewPackage(prev => ({ ...prev, website_limit: e.target.value }))} /></label>
          <label><span>{t('Storage (MB)')}</span><input type="number" min="0" max="1048576" value={newPackage.storage_limit_mb} onChange={e => setNewPackage(prev => ({ ...prev, storage_limit_mb: e.target.value }))} /></label>
          <button disabled={!!loading || !newPackage.name.trim()} onClick={createPackage}><Plus size={14}/> {t('Create package')}</button>
        </div>
        <div className="package-list">
          {packages.length === 0 && <EmptyState icon={HardDrive} message={t('No packages found.')} />}
          {packages.map(item => <div className="package-row" key={item.id}>
            {String(editingPackageId) === String(item.id) ? <>
              <label><span>{t('Name')}</span><input value={editingPackageForm.name} onChange={e => setEditingPackageForm(prev => ({ ...prev, name: e.target.value }))} /></label>
              <label><span>{t('Website limit')}</span><input type="number" min="0" max="1000" value={editingPackageForm.website_limit} onChange={e => setEditingPackageForm(prev => ({ ...prev, website_limit: e.target.value }))} /></label>
              <label><span>{t('Storage (MB)')}</span><input type="number" min="0" max="1048576" value={editingPackageForm.storage_limit_mb} onChange={e => setEditingPackageForm(prev => ({ ...prev, storage_limit_mb: e.target.value }))} /></label>
              <div className="row-actions">
                <button className="mini secondary-light" onClick={cancelEditingPackage}>{t('Cancel')}</button>
                <button className="mini" disabled={!!loading || !editingPackageForm.name.trim()} onClick={() => updatePackage(item.id)}><Save size={14}/> {t('Save')}</button>
              </div>
            </> : <>
              <div className="user-main"><strong>{item.name}</strong><small>{t('{sites} websites · {mb} MB', { sites: item.website_limit, mb: item.storage_limit_mb })}</small></div>
              <span className="user-metric"><Globe size={13}/>{t('{count} websites', { count: item.website_limit })}</span>
              <span className="user-metric"><HardDrive size={13}/>{item.storage_limit_mb} MB</span>
              <div className="row-actions">
                <button className="mini secondary-light" disabled={!!loading} onClick={() => startEditingPackage(item)}><Pencil size={14}/> {t('Edit')}</button>
                <button className="mini danger" disabled={!!loading || users.some(user => user.package_id === item.id)} onClick={() => deletePackage(item)}
                  aria-label={t('Delete {name}', { name: item.name })} title={t('Delete {name}', { name: item.name })}><Trash2 size={14}/></button>
              </div>
            </>}
          </div>)}
        </div>
      </div>}

      {activeUserTab === 'add' && <div className="user-tab-panel" id="users-tab-add" role="tabpanel" aria-labelledby="users-tab-button-add">
        <div className="section-title user-panel-title">
          <div><h2>{t('Add user')}</h2><p className="hint">{t('The panel username is also the Linux user. Log in as the user before creating websites for that account.')}</p></div>
        </div>
        <div className="user-create-card">
          <label><span>{t('Username')}</span>{isReseller
            ? <div className="user-prefix-input"><span>{currentUser?.reseller?.prefix || ''}_</span><input value={newUser.username} onChange={e => setNewUser(prev => ({ ...prev, username: e.target.value.toLowerCase() }))} placeholder="johndoe" /></div>
            : <input value={newUser.username} onChange={e => setNewUser(prev => ({ ...prev, username: e.target.value.toLowerCase() }))} placeholder="johndoe" />}</label>
          <label><span>{t('Email')}</span><input value={newUser.email} onChange={e => setNewUser(prev => ({ ...prev, email: e.target.value }))} placeholder="user@domain.com" /></label>
          <label><span>{t('Password')}</span><input value={newUser.password} onChange={e => setNewUser(prev => ({ ...prev, password: e.target.value }))} placeholder={t('At least 12 characters')} type="password" /></label>
          {isAdmin && <label><span>{t('Role')}</span><select value={newUser.role} onChange={e => setNewUser(prev => ({ ...prev, role: e.target.value }))}>
            <option value="end_user">{roleLabel('end_user')}</option><option value="reseller">{roleLabel('reseller')}</option><option value="admin">{roleLabel('admin')}</option>
          </select></label>}
          {isAdmin && newUser.role === 'end_user' && <label><span>{t('Reseller')}</span><select value={newUser.parent_id || ''} onChange={e => setNewUser(prev => ({ ...prev, parent_id: e.target.value }))}>
            <option value="">{t('None (administrator)')}</option>
            {users.filter(u => u.role === 'reseller').map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
          </select></label>}
          <label><span>{t('Package')}</span><select value={newUser.package_id} onChange={e => applyPackageToNewUser(e.target.value)}>
            <option value="">{isReseller ? t('Choose a package') : t('Custom limits')}</option>
            {packages.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select></label>
          {!isReseller && <label><span>{t('Website limit')}</span><input type="number" disabled={!!newUser.package_id} value={newUser.website_limit} onChange={e => setNewUser(prev => ({ ...prev, website_limit: e.target.value }))} /></label>}
          {!isReseller && <label><span>{t('Storage (MB)')}</span><input type="number" disabled={!!newUser.package_id} value={newUser.storage_limit_mb} onChange={e => setNewUser(prev => ({ ...prev, storage_limit_mb: e.target.value }))} /></label>}
          <button disabled={!!loading || !newUser.username || !newUser.password || (isReseller && !newUser.package_id)} onClick={createUser}><Plus size={14}/> {t('Create user')}</button>
        </div>
        {isAdmin && newUser.role === 'reseller' && <div className="user-edit-section reseller-create">
          <div className="user-edit-heading"><div><strong>{t('Reseller limits')}</strong><small>{t('On what the reseller and its accounts really use; its packages may promise more. 0 = no limit.')}</small></div></div>
          <ResellerFields value={newUser.reseller || {}} onChange={reseller => setNewUser(prev => ({ ...prev, reseller }))} t={t} />
        </div>}
      </div>}
    </section>;
  }

  return renderUsers();
}

const RESELLER_LIMITS = [
  ['max_accounts', msg('Accounts')],
  ['max_websites', msg('Websites')],
  ['max_databases', msg('Databases')],
  ['max_mailboxes', msg('Mailboxes')],
  ['max_disk_mb', msg('Disk (MB)')],
];

// The prefix of a reseller's usernames and its limits.
function ResellerFields({ value, onChange, t }) {
  const set = (key, v) => onChange({ ...value, [key]: v });
  return <div className="user-edit-grid reseller-fields">
    <label><span>{t('Username prefix')}</span><input value={value.prefix || ''} onChange={e => set('prefix', e.target.value.toLowerCase().replace(/[^a-z0-9]/g, ''))} placeholder="rs1" maxLength={8} /></label>
    {RESELLER_LIMITS.map(([key, label]) => <label key={key}><span>{t(label)}</span>
      <input type="number" min="0" value={value[key] ?? 0} onChange={e => set(key, e.target.value)} /></label>)}
  </div>;
}

function mb(bytes) {
  return Math.round((bytes || 0) / 1024 / 1024);
}

// What a reseller and its accounts use, beside its limits.
function ResellerUsage({ userId, request, t }) {
  const [data, setData] = useState(null);
  useEffect(() => {
    if (!userId) return;
    let live = true;
    request(`/users/${userId}/reseller-usage`, { silent: true }).then(d => { if (live) setData(d); });
    return () => { live = false; };
  }, [userId]);
  if (!data) return null;
  const { limits, usage } = data;
  const rows = [
    [msg('Accounts'), usage.accounts, limits.max_accounts],
    [msg('Websites'), usage.websites, limits.max_websites],
    [msg('Databases'), usage.databases, limits.max_databases],
    [msg('Mailboxes'), usage.mailboxes, limits.max_mailboxes],
    ['Disk (MB)', mb(usage.disk_bytes), limits.max_disk_mb],
  ];
  return <div className="reseller-usage" aria-label={t('Reseller usage')}>
    {rows.map(([label, used, max]) => {
      const percent = max ? Math.min(100, Math.round((used / max) * 100)) : 0;
      return <div className="reseller-meter" key={label} data-level={percent >= 90 ? 'high' : percent >= 70 ? 'mid' : 'low'}>
        <span>{t(label)}</span>
        <strong>{used} / {max ? max : '∞'}</strong>
        {max > 0 && <i><b style={{ width: `${percent}%` }} /></i>}
      </div>;
    })}
  </div>;
}
