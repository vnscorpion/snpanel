import { Bell, Bot, Boxes, Network, Puzzle, ScanSearch, ShieldBan } from 'lucide-react';

// The page and icon of each addon that has a page of its own. An addon not
// listed here opens the Addons page, under the generic puzzle piece.
export const ADDON_META = {
  application: { page: 'applications', icon: Boxes },
  dns: { page: 'dns', icon: Network },
  fail2ban: { page: 'fail2ban', icon: ShieldBan },
  malware: { page: 'malware', icon: ScanSearch },
  mcp: { page: 'mcp', icon: Bot },
  notifications: { page: 'notifications', icon: Bell },
};

export const addonPage = (slug) => ADDON_META[slug]?.page || 'addons';
export const addonIcon = (slug) => ADDON_META[slug]?.icon || Puzzle;
