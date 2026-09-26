import { Bot, Boxes, Puzzle, ShieldBan } from 'lucide-react';

// The page and icon of each addon that has a page of its own. An addon not
// listed here opens the Addons page, under the generic puzzle piece.
export const ADDON_META = {
  application: { page: 'applications', icon: Boxes },
  fail2ban: { page: 'fail2ban', icon: ShieldBan },
  mcp: { page: 'mcp', icon: Bot },
};

export const addonPage = (slug) => ADDON_META[slug]?.page || 'addons';
export const addonIcon = (slug) => ADDON_META[slug]?.icon || Puzzle;
