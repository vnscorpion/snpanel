import { AlertCircle, Archive, ArchiveRestore, Check, Clock, Copy, Download, FileText, FolderOpen, Lock, MoveRight, Plus, RefreshCw, Trash2, Upload, X } from 'lucide-react';
import { PERMISSION_BITS, PERMISSION_CLASSES, PERMISSION_PRESETS, octalToPermissionBits, permissionBitsToOctal, permissionSymbols } from '../lib/panel.jsx';
import { usePanel } from '../lib/panel-context.jsx';

export default function FilesPage() {
  const {
    FileTargetSelect,
    applyChmod,
    archiveFormat,
    archiveSelectedFiles,
    chmodMode,
    chmodTarget,
    copySelectedFiles,
    currentFileApp,
    currentSite,
    currentUser,
    deleteSelectedFiles,
    dismissFileJob,
    downloadFile,
    extractArchiveFile,
    fileBreadcrumbs,
    fileJobs,
    fileListPath,
    fileTargetKey,
    files,
    formatBytes,
    hasFileTarget,
    isAdmin,
    isArchiveFile,
    isTextEditable,
    listFiles,
    loading,
    makeFile,
    makeFileDirectory,
    moveSelectedFiles,
    openChmodDialog,
    openFileEditorTab,
    parentFilePath,
    renameFileItem,
    selectedFilePaths,
    setArchiveFormat,
    setChmodMode,
    setChmodTarget,
    storageUsageText,
    toggleAllFiles,
    toggleFileSelection,
    uploadSiteFile,
  } = usePanel();

  function renderChmodDialog() {
    const targets = chmodTarget || [];
    if (targets.length === 0) return null;
    const bits = octalToPermissionBits(chmodMode);
    const onlyDirs = targets.every(item => item.is_dir);
    const hasFiles = targets.some(item => !item.is_dir);
    const worldWritable = !!(bits.other & 2);
    const setBit = (classKey, bitValue) => setChmodMode(permissionBitsToOctal({
      ...bits,
      [classKey]: bits[classKey] ^ bitValue,
    }));
    const title = targets.length === 1 ? targets[0].name : `${targets.length} selected items`;
    return <div className="chmod-backdrop" role="presentation" onClick={() => setChmodTarget(null)}>
      <div className="chmod-dialog" role="dialog" aria-modal="true" aria-label="Change permissions" onClick={e => e.stopPropagation()}>
        <div className="chmod-head">
          <div>
            <h3><Lock size={15}/> Permissions</h3>
            <p>{title}</p>
          </div>
          <button className="mini secondary-light" onClick={() => setChmodTarget(null)} aria-label="Close"><X size={14}/></button>
        </div>
        <table className="chmod-grid">
          <thead>
            <tr><th scope="col"></th>{PERMISSION_BITS.map(bit => <th scope="col" key={bit.key}>{bit.label}</th>)}</tr>
          </thead>
          <tbody>
            {PERMISSION_CLASSES.map(group => <tr key={group.key}>
              <th scope="row">{group.label}</th>
              {PERMISSION_BITS.map(bit => <td key={bit.key}>
                <input
                  type="checkbox"
                  aria-label={`${group.label} ${bit.label}`}
                  checked={!!(bits[group.key] & bit.value)}
                  onChange={() => setBit(group.key, bit.value)}
                />
              </td>)}
            </tr>)}
          </tbody>
        </table>
        <div className="chmod-value">
          <label>
            <span>Octal</span>
            <input value={chmodMode} inputMode="numeric" maxLength={4} onChange={e => setChmodMode(e.target.value.replace(/[^0-7]/g, '').slice(0, 4))} />
          </label>
          <code>{permissionSymbols(chmodMode)}</code>
        </div>
        <div className="chmod-presets">
          {(onlyDirs ? PERMISSION_PRESETS.dir : PERMISSION_PRESETS.file).map(([preset, label]) => <button
            key={preset}
            type="button"
            className={`mini ${chmodMode === preset ? '' : 'secondary-light'}`}
            onClick={() => setChmodMode(preset)}
          >{preset} <small>{label}</small></button>)}
        </div>
        {onlyDirs && <label className="chmod-setgid">
          <input
            type="checkbox"
            checked={bits.special === 2}
            onChange={() => setChmodMode(permissionBitsToOctal({ ...bits, special: bits.special === 2 ? 0 : 2 }))}
          />
          <span>Setgid — new files inside keep the folder's group. SNPanel sets this on site folders; leave it on unless you know otherwise.</span>
        </label>}
        {worldWritable && <p className="chmod-note warn">
          <AlertCircle size={13}/> World-writable: anyone with an account on the server can change
          {hasFiles ? ' these files' : ' what is inside these folders'}. Use 755 unless something really needs it.
        </p>}
        <p className="chmod-note">
          Any permission combination is allowed. The setuid and sticky bits are not — setgid on a folder is the
          only special bit the panel sets.
        </p>
        <div className="chmod-actions">
          <button className="secondary-light" disabled={!!loading} onClick={() => setChmodTarget(null)}>Cancel</button>
          <button disabled={!!loading} onClick={applyChmod}><Check size={14}/> Apply {chmodMode}</button>
        </div>
      </div>
    </div>;
  }

  function renderFiles() {
    const allSelected = files.length > 0 && selectedFilePaths.length === files.length;
    const selectedArchiveFile = selectedFilePaths.length === 1
      ? files.find(item => item.path === selectedFilePaths[0] && isArchiveFile(item))
      : null;
    const activeFileApp = currentFileApp();
    const targetKey = fileTargetKey();
    const visibleFileJobs = fileJobs
      .filter(job => (job.target_key || `site:${job.website_id}`) === targetKey && job.status !== 'done')
      .slice(0, 4);
    const selectedChmodItems = files.filter(item => selectedFilePaths.includes(item.path));
    return <section className="section">
      {renderChmodDialog()}
      <div className="section-title">
        <div><h2>File manager</h2></div>
        <button disabled={!hasFileTarget() || !!loading} onClick={() => listFiles(fileListPath)}><RefreshCw size={14}/> Refresh</button>
      </div>
      <div className="file-manager">
        <div className="file-panel">
          <div className="file-controls">
            <FileTargetSelect />
            {activeFileApp
              ? <div className="file-meta">
                <span>Application: <strong>{activeFileApp.name}</strong></span>
                <span>Root: <strong>{activeFileApp.directory}{fileListPath ? `/${fileListPath}` : ''}</strong></span>
                {currentUser && !isAdmin && <span>Storage: <strong>{storageUsageText(currentUser)}</strong></span>}
              </div>
              : currentSite && <div className="file-meta">
                <span>Website: <strong>{currentSite.domain}</strong></span>
                <span>Root: <strong>{currentSite.root_path}{fileListPath ? `/${fileListPath}` : ''}</strong></span>
                {currentUser && !isAdmin && <span>Storage: <strong>{storageUsageText(currentUser)}</strong></span>}
              </div>}
            <div className="path-pill breadcrumb-line">
              <button className="crumb" disabled={!hasFileTarget() || fileListPath === ''} onClick={() => listFiles('')}>root</button>
              {fileBreadcrumbs(fileListPath).map(crumb => <button className="crumb" key={crumb.path} onClick={() => listFiles(crumb.path)}>{crumb.label}</button>)}
            </div>
            <div className="file-toolbar">
              <button disabled={!hasFileTarget() || fileListPath === '' || !!loading} onClick={() => listFiles(parentFilePath(fileListPath))}>Up</button>
              <button disabled={!hasFileTarget() || !!loading} onClick={makeFileDirectory}><Plus size={14}/> Folder</button>
              <button disabled={!hasFileTarget() || !!loading} onClick={makeFile}><FileText size={14}/> File</button>
              <label className={`upload-button ${(!hasFileTarget() || !!loading) ? 'disabled' : ''}`}>
                <Upload size={14}/> Upload
                <input type="file" disabled={!hasFileTarget() || !!loading} onChange={e => { uploadSiteFile(e.target.files?.[0]); e.target.value = ''; }} />
              </label>
              <select value={archiveFormat} onChange={e => setArchiveFormat(e.target.value)} disabled={!hasFileTarget() || !!loading}>
                <option value="zip">zip</option>
                <option value="tar.gz">tar.gz</option>
              </select>
              <button disabled={selectedFilePaths.length === 0 || !!loading} onClick={copySelectedFiles}><Copy size={14}/> Copy</button>
              <button disabled={selectedFilePaths.length === 0 || !!loading} onClick={moveSelectedFiles}><MoveRight size={14}/> Move</button>
              <button disabled={selectedFilePaths.length === 0 || !!loading} onClick={archiveSelectedFiles}><Archive size={14}/> Archive</button>
              <button disabled={!selectedArchiveFile || !!loading} onClick={() => extractArchiveFile(selectedArchiveFile.path)}><ArchiveRestore size={14}/> Extract</button>
              <button disabled={selectedChmodItems.length === 0 || !!loading} onClick={() => openChmodDialog(selectedChmodItems)}><Lock size={14}/> Permissions</button>
              <button className="danger" disabled={selectedFilePaths.length === 0 || !!loading} onClick={deleteSelectedFiles}><Trash2 size={14}/> Delete</button>
            </div>
            {visibleFileJobs.length > 0 && <div className="file-job-list">
              {visibleFileJobs.map(job => <div className={`file-job ${job.status}`} key={job.job_id}>
                <Clock size={14}/>
                <span><strong>{job.archive_path?.split('/').pop() || 'Archive'}</strong> {job.status === 'error' ? 'failed' : job.status}</span>
                {job.error && <small>{job.error}</small>}
                <button className="file-job-dismiss" onClick={() => dismissFileJob(job.job_id)} aria-label="Dismiss"><X size={13}/></button>
              </div>)}
            </div>}
          </div>
          <div className="file-list-header">
            <label><input type="checkbox" checked={allSelected} onChange={toggleAllFiles} disabled={files.length === 0} /> Select</label>
            <span>{files.length} item(s)</span>
          </div>
          <div className="file-list">
            {files.length === 0 && <div className="empty-box">No files in this folder.</div>}
            {files.map(item => <div className={`file-item ${selectedFilePaths.includes(item.path) ? 'selected' : ''}`} key={item.path}>
              <input type="checkbox" checked={selectedFilePaths.includes(item.path)} onChange={() => toggleFileSelection(item.path)} />
              <button className="file-name" onClick={() => item.is_dir ? listFiles(item.path) : (isTextEditable(item) ? openFileEditorTab(item.path) : downloadFile(item.path))}>
                {item.is_dir ? <FolderOpen size={16}/> : <FileText size={16}/>} <strong>{item.name}</strong>
              </button>
              <button
                className="file-mode"
                type="button"
                disabled={!!loading}
                title={`Permissions ${item.mode || '---'} (${permissionSymbols(item.mode)}) - click to change`}
                onClick={() => openChmodDialog(item)}
              >{item.mode || '---'}</button>
              <span className="file-size">{item.is_dir ? 'Folder' : formatBytes(item.size)}</span>
              <div className="file-row-actions">
                {!item.is_dir && <button className="mini secondary-light" disabled={!!loading} onClick={() => downloadFile(item.path)}><Download size={13}/></button>}
                {isArchiveFile(item) && <button className="mini secondary-light" disabled={!!loading} onClick={() => extractArchiveFile(item.path)}><ArchiveRestore size={13}/> Extract</button>}
                <button className="mini secondary-light" disabled={!!loading} onClick={() => openChmodDialog(item)}><Lock size={13}/> Perms</button>
                <button className="mini secondary-light" disabled={!!loading} onClick={() => renameFileItem(item)}>Rename</button>
              </div>
            </div>)}
          </div>
        </div>
      </div>
    </section>;
  }

  return renderFiles();
}
