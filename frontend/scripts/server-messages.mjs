// The server's English, as templates the panel can translate.
//
//     node scripts/server-messages.mjs [--sites | --rejected | --vietnamese]
//
// --sites prints where each template was found, --rejected the strings left
// out that look most like prose, --vietnamese any Vietnamese in the server.
//
// The API answers in English - its primary language, and what the CLI, the
// MCP tools and anyone's scripts read. The panel shows those answers in
// Vietnamese by matching each against the templates collected here from the
// Rust sources: a template is a message with its values as {placeholders},
// so a match recovers the values, and src/i18n/vi-server.js maps the
// template to Vietnamese with the same placeholders.
//
// No Rust parser, but not a regular expression over lines either: a small
// tokenizer that knows comments (nested), strings (escaped, raw, continued
// across lines), char literals and lifetimes, and which call each string
// sits in. So a log line, an assertion, SQL, a command's arguments and
// anything under #[cfg(test)] stay out, and a format string's {} and {:?}
// become {0}, {1}... in the order Rust fills them.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = fileURLToPath(new URL('../..', import.meta.url));
// The crates whose text can reach a response.
// The CLI and the installer print to a terminal, in English, and so does
// snpanel-osabi, which only they and the helper's startup read.
const CRATES = ['snpanel-api', 'snpanel-core', 'snpanel-db', 'snpanel-helper', 'snpanel-ipc', 'snpanel-nginx'];

// Calls whose strings never reach a response: logs, assertions, panics,
// compile-time includes, commands and their arguments, SQL, patterns.
const SKIP_CALLS = new Set([
  'info!', 'warn!', 'error!', 'debug!', 'trace!', 'event!', 'span!', 'info_span!',
  'println!', 'eprintln!', 'print!', 'eprint!', 'dbg!',
  'assert!', 'assert_eq!', 'assert_ne!', 'debug_assert!', 'debug_assert_eq!', 'debug_assert_ne!', 'matches!',
  'panic!', 'unreachable!', 'todo!', 'unimplemented!', '.expect', '.expect_err',
  'include_str!', 'include_bytes!', 'env!', 'option_env!', 'concat!', 'stringify!',
  'Command::new', '.arg', '.args', '.env', '.envs', '.current_dir', 'sh', 'run', 'run_cmd',
  'query', 'query_as', 'query_scalar', 'sqlx::query', '.execute', '.prepare', '.query_row', '.query_map', 'execute_batch',
  'Regex::new', 'RegexBuilder::new', 'regex!',
  '.header', 'HeaderValue::from_static', 'HeaderName::from_static',
]);
// Calls that take a message: an error answer, an Err, a thiserror
// attribute, a Display impl's write!.
const MESSAGE_CALLS = new Set([
  'bad_request', 'not_found', 'conflict', 'error', 'forbidden', 'unauthorized', 'unprocessable',
  'value_error', 'value_error_entry', 'failure_detail', 'too_many_requests', 'service_unavailable',
  'Err', '.ok_or', 'anyhow!', 'bail!', '#error', 'Error::new', 'Error::other', 'io::Error::new', 'io::Error::other',
  'Issue::new',
]);
const FORMAT_CALLS = new Set(['format!', 'write!', 'writeln!', 'anyhow!', 'bail!', 'format_args!', '#error', 'panic!']);
// A message key in a json!() body or a struct literal.
const MESSAGE_KEY = /(?:"(?:message|detail|error|warning|note|hint|reason|status_text|summary)"|\b(?:message|detail|warning|note|hint|reason))\s*:\s*(?:&?format!\(\s*|Some\(\s*|&?)$/;

// Words that mark English prose rather than a token, a path or a command.
const HINTS = new Set(`a an the is are was were be been being not no nor to of for in on at by with from into onto and or but if than then so
this that these those it its has have had do does did can cannot could must should will would may might shall only already still yet any all
each every some none more less too very also just again once here there which who what when where why how whether because while until unless
before after during without within outside inside over under above below between invalid failed failure unknown missing required unable
denied allowed forbidden exists exist found running installed enabled disabled needs need use used using please try retry now currently
created deleted updated saved removed added started stopped restarted reloaded queued scheduled uninstalled changed reset cleared applied
issued renewed revoked blocked unblocked imported exported restored suspended unsuspended finished completed done busy empty full too
expired wrong incorrect correct valid supported unsupported available unavailable enough own your you out off up down
adds sets changes overrides borrows declares shares passes runs reads builds uses makes keeps`.split(/\s+/));

// Not the MCP tools: what they say goes to an AI assistant, which reads
// English, and the panel never shows it. Not the helper's argv parser
// either: the API checks what it sends first, and those checks say it.
const SKIP_DIRS = new Set(['tests', 'benches', 'target', 'mcp']);
// And not what only a console or a log reads: the ctl and initdb commands,
// the startup checks of the configuration, the helper's usage text.
const SKIP_FILES = new Set([
  'crates/snpanel-ipc/src/argv.rs',
  'crates/snpanel-api/src/ctl.rs',
  'crates/snpanel-api/src/initdb.rs',
  'crates/snpanel-core/src/config.rs',
  'crates/snpanel-helper/src/main.rs',
  // A passkey that fails says "The passkey could not be verified"; why goes
  // to the log.
  'crates/snpanel-core/src/crypto/webauthn.rs',
  // Checked when the API starts, before anyone can see a page.
  'crates/snpanel-db/src/lib.rs',
  'crates/snpanel-db/src/schema.rs',
  'crates/snpanel-api/src/listen.rs',
  'crates/snpanel-helper/src/peercred.rs',
]);

// Strings the rules below take for messages and are not: keys the helper
// parses out of fail2ban's and semanage's output, lines of a status dump
// shown as it is, lock labels, the scheduler's own outcomes, dry-run text
// and the helper protocol's refusals of a request the API built.
const IGNORED = new Set([
  'Jail list', 'Currently failed', 'Total failed', 'Currently banned', 'Total banned', 'Banned IP list', 'already defined',
  'Engine: nftables', 'Chain active: {0}', 'Default incoming: deny (unlisted ports)', 'Protected ports (tcp): {0}', 'any port',
  'Unattended upgrades:', 'Panel update service:', 'Panel update log:', 'Failed to open /run/systemd/transient',
  'Node install', 'Docker install', 'enabled: none', 'not due', 'no scan engine',
  'the decision half of a scheduler runner that is not wired yet; see the module docs',
  "{0} does not look like the panel's database (no users/websites table)",
  'Would {action} php{php_version} and SNPanel extensions',
  'request is {0} bytes, over the limit', 'request is malformed: {0}', 'protocol version {got}, but this helper speaks {expected}',
  'available upgrades', 'Last metadata expiration',
  'this server', '{0} backup(s) from {from}', 'larger than',
  'WHITELISTED {path}: left in place', 'LEFT {path}: outside the folders files are moved out of', 'NOT MOVED {path}: {0}', 'is gone',
  '{0} is mounted already',
  'Automatic updates (dnf-automatic):', 'when needed', 'LocalSocket /run/clamd.scan/clamd.sock', 'apt-get install unattended-upgrades', 'dnf install dnf-automatic', 'curl docker-ce.repo', 'apt-get install ca-certificates curl gnupg', 'curl docker gpg key',
]);

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return SKIP_DIRS.has(name) ? [] : walk(p);
    if (SKIP_FILES.has(relative(REPO, p))) return [];
    return name.endsWith('.rs') && name !== 'tests.rs' && !name.endsWith('_tests.rs') ? [p] : [];
  });
}

// Every string literal in a Rust file, with the calls it sits in.
export function scan(src) {
  const found = [];
  const stack = []; // open delimiters: { ch, callee, test }
  let i = 0;
  let line = 1;
  let pendingTest = false;
  const inTest = () => stack.some((d) => d.test);
  const calleeBefore = (at) => {
    const m = /(#\[)?(\.)?([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*!?)\s*$/.exec(src.slice(Math.max(0, at - 160), at));
    if (!m) return null;
    const path = m[3];
    if (m[1]) return `#${path}`;
    if (m[2]) return `.${path}`;
    return path;
  };
  const push = (value, raw, startLine, at) => {
    if (inTest()) return;
    const callees = stack.filter((d) => d.callee).map((d) => d.callee);
    found.push({ value, raw, line: startLine, callees, before: src.slice(Math.max(0, at - 80), at) });
  };
  while (i < src.length) {
    const c = src[i];
    const next = src[i + 1];
    if (c === '\n') { line++; i++; continue; }
    if (c === '/' && next === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '/' && next === '*') {
      let depth = 0;
      while (i < src.length) {
        if (src[i] === '/' && src[i + 1] === '*') { depth++; i += 2; continue; }
        if (src[i] === '*' && src[i + 1] === '/') { depth--; i += 2; if (depth === 0) break; continue; }
        if (src[i] === '\n') line++;
        i++;
      }
      continue;
    }
    // Raw and byte strings: r"..", r#".."#, b"..", br#".."#.
    const rawMatch = /^(b?)r(#*)"/.exec(src.slice(i, i + 12));
    if (rawMatch && !/[A-Za-z0-9_]/.test(src[i - 1] || '')) {
      const hashes = rawMatch[2];
      const start = i + rawMatch[0].length;
      const end = src.indexOf(`"${hashes}`, start);
      const value = src.slice(start, end);
      const startLine = line;
      line += (value.match(/\n/g) || []).length;
      if (!rawMatch[1]) push(value, true, startLine, i);
      i = end + 1 + hashes.length;
      continue;
    }
    if (c === '"' || (c === 'b' && next === '"' && !/[A-Za-z0-9_]/.test(src[i - 1] || ''))) {
      const isByte = c === 'b';
      const at = i;
      i += isByte ? 2 : 1;
      const startLine = line;
      let value = '';
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\') {
          const e = src[i + 1];
          if (e === '\n') { // a continued line drops the newline and the indent
            i += 2; line++;
            while (/[ \t\n\r]/.test(src[i])) { if (src[i] === '\n') line++; i++; }
            continue;
          }
          if (e === 'n') value += '\n';
          else if (e === 't') value += '\t';
          else if (e === 'r') value += '\r';
          else if (e === '0') value += '\0';
          else if (e === 'u') {
            const m = /^\\u\{([0-9a-fA-F]+)\}/.exec(src.slice(i, i + 12));
            value += String.fromCodePoint(parseInt(m[1], 16));
            i += m[0].length;
            continue;
          } else if (e === 'x') {
            value += String.fromCharCode(parseInt(src.slice(i + 2, i + 4), 16));
            i += 4;
            continue;
          } else value += e;
          i += 2;
          continue;
        }
        if (src[i] === '\n') line++;
        value += src[i];
        i++;
      }
      i++;
      if (!isByte) push(value, false, startLine, at);
      continue;
    }
    if (c === "'") {
      // A char literal - 'a', '\n', '\u{1F600}' - or a lifetime or label.
      if (next === '\\') { i = src.indexOf("'", i + 3) + 1; continue; }
      const cp = src.codePointAt(i + 1);
      const width = cp > 0xffff ? 2 : 1;
      if (src[i + 1 + width] === "'") { i += 2 + width; continue; }
      i++;
      continue;
    }
    if (c === '#' && src.startsWith('#[cfg(test)]', i)) { pendingTest = true; i += 12; continue; }
    if (c === '#' && src.startsWith('#[test]', i)) { pendingTest = true; i += 7; continue; }
    if (c === '(' || c === '[' || c === '{') {
      const callee = c === '(' ? calleeBefore(i) : (c === '[' || c === '{') && /!\s*$/.test(src.slice(Math.max(0, i - 40), i)) ? calleeBefore(i) : null;
      const test = c === '{' && pendingTest;
      if (test) pendingTest = false;
      stack.push({ ch: c, callee, test });
      i++;
      continue;
    }
    if (c === ')' || c === ']' || c === '}') { stack.pop(); i++; continue; }
    if (c === ';' && pendingTest) {
      // `#[cfg(test)] use ...;` or `mod tests;` - an item with no body here.
      const last = stack[stack.length - 1];
      if (!last || last.ch === '{') pendingTest = false;
    }
    i++;
  }
  return found;
}

// The file's `const NAME: &str = "..."` values, which a format string may
// name - format!("{PARSE_FAILED}{}") - and which are text, not values.
export function stringConsts(src) {
  const out = new Map();
  for (const m of src.matchAll(/\bconst\s+([A-Z][A-Z0-9_]*)\s*:\s*&(?:'static\s+)?str\s*=\s*"((?:\\[\s\S]|[^"\\])*)"\s*;/g)) {
    out.set(m[1], m[2].replace(/\\\n\s*/g, '').replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\\\/g, '\\'));
  }
  return out;
}

// A format string with its {} numbered the way Rust fills them and its
// string constants written out; any other string keeps its {name}s, which a
// .replace() fills.
export function template(value, format, consts = new Map()) {
  if (!format) return value;
  let next = 0;
  return value.replace(/\{\{|\}\}|\{([A-Za-z_][A-Za-z0-9_]*|\d+)?(?::[^}]*)?\}/g, (m, name) => {
    if (m === '{{') return '{';
    if (m === '}}') return '}';
    if (name === undefined) return `{${next++}}`;
    if (consts.has(name)) return consts.get(name);
    return `{${name}}`;
  });
}

const PLACEHOLDER = /\{(\w+)\}/g;
const lastSegment = (callee) => {
  const bang = callee.endsWith('!');
  const parts = callee.replace(/!$/, '').split('::');
  const tail = parts.slice(-2).join('::');
  return { full: callee, last: parts[parts.length - 1] + (bang ? '!' : ''), tail: tail + (bang ? '!' : '') };
};
const inSet = (set, callee) => {
  const { full, last, tail } = lastSegment(callee);
  return set.has(full) || set.has(last) || set.has(tail) || (callee.startsWith('.') && set.has(callee)) || (callee.startsWith('#') && set.has(callee));
};

// Why a string is not a message, or null when it is one.
export function rejection(item, consts) {
  const { value, callees, before } = item;
  if (callees.some((c) => inSet(SKIP_CALLS, c))) return 'call';
  const innermost = callees[callees.length - 1];
  const format = innermost ? inSet(FORMAT_CALLS, innermost) : false;
  const text = template(value, format, consts);
  const literal = text.replace(PLACEHOLDER, ' ');
  const words = literal.match(/[A-Za-z][A-Za-z']*/g) || [];
  if (words.length === 0) return 'no words';
  // A column list: "id, name, token_hash, ...".
  if (/^[\w.]+(?: AS \w+)?(?:, [\w.]+(?: AS \w+)?)+$/.test(text.trim())) return 'sql';
  if (/^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|PRAGMA|WITH|BEGIN|COMMIT|REPLACE|GRANT|REVOKE|FLUSH|SHOW|SET|USE|AND|OR|WHERE|ORDER BY|GROUP BY|LIMIT|JOIN|LEFT JOIN|FROM|VALUES|ON CONFLICT|IDENTIFIED)\b/.test(text) || / = \?/.test(text)) return 'sql';
  if (/^\s*(Sec[A-Z]|location |server |listen |include |Include |proxy_|fastcgi_|add_header|return |root |try_files|if \(|\[[A-Z][a-z]+\]|; |ct state |no-cache)/.test(text)) return 'config';
  // Shell, a regular expression, a key=, a marker, a redacted Debug.
  if (/^echo\b|^\^|=\s*$|^internal:|<redacted>/.test(text.trim())) return 'code';
  // A leading ${NAME} is a message about a variable, not shell.
  if (/::|=>|&&|\|\||==|^\s*(?:[/.<#-]|\$(?!\{))|^\s*\{"|;\s*$|\n.*[;{=]|\b\w+=\S| --?[a-z]/.test(text)) return 'code';
  if (/^[A-Za-z0-9_.:/@*+{}-]+$/.test(text.trim())) return 'token';
  if (IGNORED.has(text.trim())) return 'ignored';
  const message = callees.some((c) => inSet(MESSAGE_CALLS, c)) || MESSAGE_KEY.test(before);
  const hinted = words.some((w) => HINTS.has(w.toLowerCase()));
  const sentence = /^(\{\w+\}\s*)?[A-Z][a-z]/.test(text.trim());
  if (words.length >= 2 && (hinted || sentence)) return null;
  // A message call's text is a message whatever its case: compose issues
  // start in lower case, after the service they are about.
  if (message && words.length >= 1) return null;
  return words.length >= 2 ? 'no hint' : 'one word';
}

// Vietnamese in the server: text that must become English, the primary
// language, with its Vietnamese moved into the catalog.
export const VIETNAMESE = /[ăâđêôơưĂÂĐÊÔƠƯàáảãạằắẳẵặầấẩẫậèéẻẽẹềếểễệìíỉĩịòóỏõọồốổỗộờớởỡợùúủũụừứửữựỳýỷỹỵ]/;

export function serverTemplates(repo = REPO) {
  const templates = new Map(); // template -> [site]
  const rejected = [];
  for (const crate of CRATES) {
    for (const file of walk(join(repo, 'crates', crate, 'src'))) {
      const rel = relative(repo, file);
      const source = readFileSync(file, 'utf8');
      const consts = stringConsts(source);
      for (const item of scan(source)) {
        const why = rejection(item, consts);
        const innermost = item.callees[item.callees.length - 1];
        const text = template(item.value, innermost ? inSet(FORMAT_CALLS, innermost) : false, consts).trim();
        if (why) { rejected.push({ why, text, site: `${rel}:${item.line}` }); continue; }
        if (!templates.has(text)) templates.set(text, []);
        templates.get(text).push(`${rel}:${item.line}`);
      }
    }
  }
  return { templates, rejected };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { templates, rejected } = serverTemplates();
  if (process.argv.includes('--vietnamese')) {
    for (const [text, sites] of templates) if (VIETNAMESE.test(text)) console.log(`${sites.join(' ')}\t${JSON.stringify(text)}`);
    for (const r of rejected) if (VIETNAMESE.test(r.text)) console.log(`(${r.why}) ${r.site}\t${JSON.stringify(r.text)}`);
  } else if (process.argv.includes('--rejected')) {
    for (const r of rejected) if (r.why === 'no hint' || r.why === 'one word') console.log(`${r.why}\t${r.site}\t${JSON.stringify(r.text)}`);
  } else {
    for (const [text, sites] of templates) console.log(process.argv.includes('--sites') ? `${sites[0]}\t${JSON.stringify(text)}` : JSON.stringify(text));
  }
  console.error(`${templates.size} templates, ${rejected.length} strings left out`);
}
