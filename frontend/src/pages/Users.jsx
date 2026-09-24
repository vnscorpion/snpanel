import { Ban, Globe, HardDrive, LogIn, Pencil, Play, Plus, RefreshCw, Save, Trash2, Users, X } from 'lucide-react';
import { usePanel } from '../lib/panel-context.jsx';

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

  function renderUsers() {
    if (!isAdmin) return <section className="section"><h2>Users</h2><p className="hint">No permission.</p></section>;
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
        <div><h2>Panel users</h2><p className="hint">Manage users, packages, and domain ownership.</p></div>
      </div>
      <div className="segmented user-tabs" role="tablist" aria-label="Panel user sections">
        {userTabButton('list', Users, 'List user')}
        {userTabButton('packages', HardDrive, 'Package')}
        {userTabButton('add', Plus, 'Add User')}
      </div>

      {activeUserTab === 'list' && <div className="user-tab-panel" id="users-tab-list" role="tasnpanel" aria-labelledby="users-tab-button-list">
        <div className="section-title user-panel-title">
          <div><h2>Panel user list</h2><p className="hint">Current panel users and service limits.</p></div>
          <button disabled={!!loading} onClick={loadUsers}><RefreshCw size={14}/> Refresh</button>
        </div>
        {users.length === 0 && <EmptyState icon={Users} message="No users found." />}
        <div className="table">
          {users.map(user => <div className="row user-row" key={user.id}>
            <div className="user-main"><strong>{user.username}</strong><small>{user.email}</small></div>
            <div className="user-badges">
              <span className={user.is_active ? 'badge ok' : 'badge danger'}>{user.is_active ? 'Active' : 'Suspended'}</span>
              <span className="badge">{roleLabel(user.role)}</span>
              <span className="badge">{user.package_name || 'Custom'}</span>
              {user.totp_enabled && <span className="badge ok">2FA</span>}
            </div>
            <span className="user-metric"><HardDrive size={13}/>{storageUsageText(user)}</span>
            <div className="row-actions">
              <button className="mini secondary-light" disabled={!!loading} onClick={() => startEditingUser(user)}><Pencil size={14}/> Edit</button>
              <button className="mini secondary-light" disabled={!!loading} onClick={() => quickLoginUser(user)}><LogIn size={14}/> Login as</button>
              {user.totp_enabled && user.id !== currentUser?.id && <button className="mini secondary-light" disabled={!!loading} onClick={() => resetUserTwoFactor(user)}>Reset 2FA</button>}
              {user.id !== currentUser?.id && (user.is_active
                ? <button className="mini secondary-light" disabled={!!loading} onClick={() => suspendUser(user)}><Ban size={14}/> Suspend</button>
                : <button className="mini secondary-light" disabled={!!loading} onClick={() => unsuspendUser(user)}><Play size={14}/> Unsuspend</button>
              )}
              {user.id !== currentUser?.id && <button className="mini danger" disabled={!!loading} onClick={() => deletePanelUser(user)}><Trash2 size={14}/></button>}
            </div>
            {editingUser?.id === user.id && <div className="user-edit-panel">
              <div className="user-edit-heading">
                <div><strong>Edit {user.username}</strong><small>
                  {user.id === currentUser?.id ? 'Role is locked for the active admin session.' : 'Role changes sign the user out of existing sessions.'}
                  {editingUserForm.role === 'admin' ? ' Admin accounts bypass website and storage limits.' : ''}
                </small></div>
                <button className="user-edit-close secondary-light" onClick={cancelEditingUser} aria-label="Close user editor" title="Close user editor"><X size={16}/></button>
              </div>
              <div className="user-edit-grid">
                <label><span>Email</span><input type="email" value={editingUserForm.email} onChange={e => setEditingUserForm(prev => ({ ...prev, email: e.target.value }))} /></label>
                <label><span>Role</span><select value={editingUserForm.role} disabled={user.id === currentUser?.id} onChange={e => setEditingUserForm(prev => ({ ...prev, role: e.target.value }))}>
                  <option value="end_user">End user</option><option value="admin">Admin</option>
                </select></label>
                <label><span>Package</span><select value={editingUserForm.package_id} onChange={e => applyPackageToEditingUser(e.target.value)}>
                  <option value="">Custom limits</option>
                  {packages.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
                </select></label>
                <label><span>Website limit</span><input type="number" min="0" max="1000" disabled={!!editingUserForm.package_id} value={editingUserForm.website_limit} onChange={e => setEditingUserForm(prev => ({ ...prev, website_limit: e.target.value }))} /></label>
                <label><span>Storage limit (MB)</span><input type="number" min="0" max="1048576" disabled={!!editingUserForm.package_id} value={editingUserForm.storage_limit_mb} onChange={e => setEditingUserForm(prev => ({ ...prev, storage_limit_mb: e.target.value }))} /></label>
              </div>
              <div className="user-edit-section">
                <div className="user-edit-heading"><div><strong>Change password</strong><small>Minimum 12 characters. {user.id === currentUser?.id ? 'Requires current password + 2FA.' : 'Admin can set directly.'}</small></div></div>
                <div className="user-edit-grid">
                  <label><span>New password</span><input type="password" placeholder="Min 12 characters" value={editingUserForm.new_password} onChange={e => setEditingUserForm(prev => ({ ...prev, new_password: e.target.value }))} /></label>
                  <label><span>Confirm password</span><input type="password" placeholder="Repeat password" value={editingUserForm.confirm_password} onChange={e => setEditingUserForm(prev => ({ ...prev, confirm_password: e.target.value }))} /></label>
                </div>
                <div className="user-edit-actions">
                  <button disabled={!!loading || !editingUserForm.new_password || editingUserForm.new_password.length < 12} onClick={() => submitPasswordChange(user)}>Set password</button>
                </div>
              </div>
              <div className="user-edit-actions">
                <button className="secondary-light" onClick={cancelEditingUser}>Cancel</button>
                <button disabled={!!loading || !editingUserForm.email.trim()} onClick={updatePanelUser}><Save size={14}/> Save changes</button>
              </div>
            </div>}
          </div>)}
        </div>
        <div className="user-action-panel">
          <div><h3>Assign domain to user</h3><p className="hint">Move an existing domain under a selected panel user.</p></div>
          <div className="assign-row">
            <select value={assignWebsiteId} onChange={e => setAssignWebsiteId(e.target.value)}>
              <option value="">Select domain</option>
              {websites.map(site => <option key={site.id} value={site.id}>{site.domain}</option>)}
            </select>
            <select value={assignUserId} onChange={e => setAssignUserId(e.target.value)}>
              <option value="">Select user</option>
              {users.map(user => <option key={user.id} value={user.id}>{user.username} ({roleLabel(user.role)})</option>)}
            </select>
            <button disabled={!assignWebsiteId || !assignUserId || !!loading} onClick={assignDomainToUser}>Assign</button>
          </div>
        </div>
      </div>}

      {activeUserTab === 'packages' && <div className="user-tab-panel" id="users-tab-packages" role="tasnpanel" aria-labelledby="users-tab-button-packages">
        <div className="section-title user-panel-title">
          <div><h2>Package</h2><p className="hint">Create, edit, delete, and review reusable user limits.</p></div>
          <button disabled={!!loading} onClick={loadPackages}><RefreshCw size={14}/> Refresh</button>
        </div>
        <div className="user-create-card package-create-card">
          <label><span>Package name</span><input value={newPackage.name} onChange={e => setNewPackage(prev => ({ ...prev, name: e.target.value }))} placeholder="Starter" /></label>
          <label><span>Site limit</span><input type="number" min="0" max="1000" value={newPackage.website_limit} onChange={e => setNewPackage(prev => ({ ...prev, website_limit: e.target.value }))} /></label>
          <label><span>Storage MB</span><input type="number" min="0" max="1048576" value={newPackage.storage_limit_mb} onChange={e => setNewPackage(prev => ({ ...prev, storage_limit_mb: e.target.value }))} /></label>
          <button disabled={!!loading || !newPackage.name.trim()} onClick={createPackage}><Plus size={14}/> Create package</button>
        </div>
        <div className="package-list">
          {packages.length === 0 && <EmptyState icon={HardDrive} message="No packages found." />}
          {packages.map(item => <div className="package-row" key={item.id}>
            {String(editingPackageId) === String(item.id) ? <>
              <label><span>Name</span><input value={editingPackageForm.name} onChange={e => setEditingPackageForm(prev => ({ ...prev, name: e.target.value }))} /></label>
              <label><span>Site limit</span><input type="number" min="0" max="1000" value={editingPackageForm.website_limit} onChange={e => setEditingPackageForm(prev => ({ ...prev, website_limit: e.target.value }))} /></label>
              <label><span>Storage MB</span><input type="number" min="0" max="1048576" value={editingPackageForm.storage_limit_mb} onChange={e => setEditingPackageForm(prev => ({ ...prev, storage_limit_mb: e.target.value }))} /></label>
              <div className="row-actions">
                <button className="mini secondary-light" onClick={cancelEditingPackage}>Cancel</button>
                <button className="mini" disabled={!!loading || !editingPackageForm.name.trim()} onClick={() => updatePackage(item.id)}><Save size={14}/> Save</button>
              </div>
            </> : <>
              <div className="user-main"><strong>{item.name}</strong><small>{item.website_limit} sites - {item.storage_limit_mb} MB</small></div>
              <span className="user-metric"><Globe size={13}/>{item.website_limit} sites</span>
              <span className="user-metric"><HardDrive size={13}/>{item.storage_limit_mb} MB</span>
              <div className="row-actions">
                <button className="mini secondary-light" disabled={!!loading} onClick={() => startEditingPackage(item)}><Pencil size={14}/> Edit</button>
                <button className="mini danger" disabled={!!loading || users.some(user => user.package_id === item.id)} onClick={() => deletePackage(item)}><Trash2 size={14}/></button>
              </div>
            </>}
          </div>)}
        </div>
      </div>}

      {activeUserTab === 'add' && <div className="user-tab-panel" id="users-tab-add" role="tasnpanel" aria-labelledby="users-tab-button-add">
        <div className="section-title user-panel-title">
          <div><h2>Add User</h2><p className="hint">Panel username is also the Linux user. Login as a user before creating websites for that account.</p></div>
        </div>
        <div className="user-create-card">
          <label><span>Username</span><input value={newUser.username} onChange={e => setNewUser(prev => ({ ...prev, username: e.target.value.toLowerCase() }))} placeholder="johndoe" /></label>
          <label><span>Email</span><input value={newUser.email} onChange={e => setNewUser(prev => ({ ...prev, email: e.target.value }))} placeholder="user@domain.com" /></label>
          <label><span>Password</span><input value={newUser.password} onChange={e => setNewUser(prev => ({ ...prev, password: e.target.value }))} placeholder="Min 12 characters" type="password" /></label>
          <label><span>Role</span><select value={newUser.role} onChange={e => setNewUser(prev => ({ ...prev, role: e.target.value }))}>
            <option value="end_user">End user</option><option value="admin">Admin</option>
          </select></label>
          <label><span>Package</span><select value={newUser.package_id} onChange={e => applyPackageToNewUser(e.target.value)}>
            <option value="">Custom limits</option>
            {packages.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select></label>
          <label><span>Site limit</span><input type="number" disabled={!!newUser.package_id} value={newUser.website_limit} onChange={e => setNewUser(prev => ({ ...prev, website_limit: e.target.value }))} /></label>
          <label><span>Storage MB</span><input type="number" disabled={!!newUser.package_id} value={newUser.storage_limit_mb} onChange={e => setNewUser(prev => ({ ...prev, storage_limit_mb: e.target.value }))} /></label>
          <button disabled={!!loading || !newUser.username || !newUser.password} onClick={createUser}><Plus size={14}/> Create user</button>
        </div>
      </div>}
    </section>;
  }

  return renderUsers();
}
