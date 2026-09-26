// The MCP tools' own words, as the AI assistants page documents them.
//
//     node scripts/mcp-texts.mjs
//
// Every tool's title and description, and every argument's description, as
// crates/snpanel-api/src/mcp/tools.rs declares them - the English that
// GET /api/mcp/tools sends and src/i18n/vi-mcp.js translates. What a tool
// answers an assistant is not here: the assistant reads English, and the
// panel never shows it.
//
// A regular expression over the declarations, not a parser: a Tool literal's
// `title:` and `description:` fields, and the second string of a
// Param::text/number/flag/one_of call, each a plain string literal - which
// is how every one of them is written. The test module is left out.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const TOOLS = fileURLToPath(new URL('../../crates/snpanel-api/src/mcp/tools.rs', import.meta.url));
const STRING = '"((?:\\\\.|[^"\\\\])*)"';
const FIELD = new RegExp(`\\b(?:title|description):\\s*${STRING}`, 'g');
const PARAM = new RegExp(`Param::(?:text|number|flag|one_of)\\(\\s*${STRING},\\s*${STRING}`, 'g');
const unescape = (s) => JSON.parse(`"${s}"`);

export function mcpTexts(path = TOOLS) {
  const declarations = readFileSync(path, 'utf8').split('#[cfg(test)]')[0];
  const texts = new Set();
  for (const m of declarations.matchAll(FIELD)) texts.add(unescape(m[1]));
  for (const m of declarations.matchAll(PARAM)) texts.add(unescape(m[2]));
  return texts;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  for (const text of mcpTexts()) console.log(JSON.stringify(text));
}
