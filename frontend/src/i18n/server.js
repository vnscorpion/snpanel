// The server's messages in the viewer's language.
//
// The API answers in English. Its messages come from templates in the Rust
// sources - "Website {0} already exists" - which scripts/server-messages.mjs
// collects and vi-server.js translates. Matching a message against the
// templates recovers the values; the translation is the Vietnamese template
// with those values put back. A value that is itself a message - the {e} in
// "Cannot write the manifest: {e}" - is translated the same way.
//
// Plain JavaScript, no React: scripts/i18n-check.mjs runs every template
// through this same code.

const PLACEHOLDER = /\{(\w+)\}/g;
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Deep enough for "Backup failed: Cannot write the manifest: <os error>".
const MAX_DEPTH = 2;
const CACHE_SIZE = 500;
const KEYED = /^([^\s:]{1,64}): ([\s\S]+)$/;

export function compile(catalog) {
  const exact = new Map();
  const patterns = [];
  for (const [en, vi] of Object.entries(catalog)) {
    const matches = [...en.matchAll(PLACEHOLDER)];
    if (matches.length === 0) {
      exact.set(en, vi);
      continue;
    }
    const groups = new Map(); // placeholder -> capture group number
    let source = '';
    let literal = 0;
    let last = 0;
    for (const m of matches) {
      const piece = en.slice(last, m.index);
      source += escape(piece);
      literal += piece.length;
      // A value may be empty: " ({note})" is left out when there is none.
      if (groups.has(m[1])) source += `\\${groups.get(m[1])}`;
      else {
        groups.set(m[1], groups.size + 1);
        source += '([\\s\\S]*?)';
      }
      last = m.index + m[0].length;
    }
    source += escape(en.slice(last));
    literal += en.length - last;
    patterns.push({ en, re: new RegExp(`^${source}$`), names: [...groups.keys()], vi, literal });
  }
  // The template with the most fixed text first: "Could not install PHP
  // {version}: {e}" before "Could not install {0}: {1}".
  patterns.sort((a, b) => b.literal - a.literal || a.en.localeCompare(b.en));
  return { exact, patterns, cache: new Map() };
}

function translateLine(compiled, line, depth) {
  const trimmed = line.trim();
  if (!trimmed) return line;
  const hit = compiled.exact.get(trimmed);
  if (hit !== undefined) return line.replace(trimmed, () => hit);
  for (const p of compiled.patterns) {
    const m = p.re.exec(trimmed);
    if (!m) continue;
    const values = {};
    p.names.forEach((name, i) => {
      values[name] = depth < MAX_DEPTH ? translateLine(compiled, m[i + 1], depth + 1) : m[i + 1];
    });
    const out = p.vi.replace(PLACEHOLDER, (all, name) => (name in values ? values[name] : all));
    return line.replace(trimmed, () => out);
  }
  // "privileged: runs the container in privileged mode", "domain: Invalid
  // domain" - a field or key, then a message about it.
  const keyed = KEYED.exec(trimmed);
  if (keyed && depth < MAX_DEPTH) {
    const rest = translateLine(compiled, keyed[2], depth + 1);
    if (rest !== keyed[2]) return line.replace(trimmed, () => `${keyed[1]}: ${rest}`);
  }
  return line;
}

/// The translation of one message, or the message itself when no template
/// fits. A message of several lines - a list of validation errors - is
/// translated line by line.
export function translateMessage(compiled, text) {
  if (!compiled || typeof text !== 'string' || !text) return text;
  const cached = compiled.cache.get(text);
  if (cached !== undefined) return cached;
  const out = text.split('\n').map((line) => translateLine(compiled, line, 0)).join('\n');
  if (compiled.cache.size >= CACHE_SIZE) compiled.cache.delete(compiled.cache.keys().next().value);
  compiled.cache.set(text, out);
  return out;
}
