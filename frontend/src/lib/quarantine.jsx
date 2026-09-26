import { msg } from '../i18n/index.jsx';

// What became of a file a scan found. See crates/snpanel-api/src/malware_quarantine.rs.
export const THREAT_STATES = {
  quarantined: msg('Quarantined'),
  whitelisted: msg('Whitelisted'),
  restored: msg('Restored'),
  deleted: msg('Deleted'),
  missing: msg('Gone'),
  left: msg('Left in place'),
  failed: msg('Not moved'),
};

// The folders a file may be moved out of; a hit anywhere else is left for
// an administrator to judge, and can only be whitelisted.
export const QUARANTINE_ROOTS = ['/home/', '/tmp/', '/var/tmp/', '/dev/shm/'];
export const movable = (path) => QUARANTINE_ROOTS.some((root) => String(path || '').startsWith(root));

// Still where the scan found it: red. Set aside or judged fine: green.
export function threatBadgeClass(state) {
  if (['quarantined', 'whitelisted', 'deleted'].includes(state)) return 'badge ok';
  if (state === 'missing') return 'badge';
  return 'badge danger';
}

export const QUESTIONS = {
  restore: msg('Put {path} back where it was? It is not judged safe: the next scan that finds it sets it aside again.'),
  'restore-whitelist': msg('Put {path} back and never flag it again? If its content changes it is scanned again.'),
  delete: msg('Delete {path} for good? It cannot be put back after this.'),
  quarantine: msg('Set {path} aside now?'),
  whitelist: msg('Leave {path} where it is and never flag it again? If its content changes it is scanned again.'),
};

// One administrator's word on a file, as the API takes it. `item` is a
// threat of a scan (with `job_id` beside it) or an item of the quarantine.
export function quarantineAction(request, t, kind, item, jobId) {
  const id = item.quarantine_id || item.id;
  switch (kind) {
    case 'restore':
      return request(`/malware/quarantine/${id}/restore`, { method: 'POST' }, t('Putting it back...'));
    case 'restore-whitelist':
      return request(`/malware/quarantine/${id}/whitelist`, { method: 'POST' }, t('Putting it back...'));
    case 'delete':
      return request(`/malware/quarantine/${id}`, { method: 'DELETE' }, t('Deleting...'));
    case 'quarantine':
      return request('/malware/threats/quarantine', { method: 'POST', body: JSON.stringify({ job_id: jobId, path: item.path }) }, t('Setting it aside...'));
    default:
      return request('/malware/threats/whitelist', { method: 'POST', body: JSON.stringify({ job_id: jobId, path: item.path }) }, t('Whitelisting...'));
  }
}
