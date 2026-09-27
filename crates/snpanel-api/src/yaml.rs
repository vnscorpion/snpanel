//! A YAML reader that answers the way PyYAML's `safe_load` does.
//!
//! The panel reads one kind of YAML: a compose file a customer pasted into a
//! box. It never round-trips that file — it reads it, checks it, and writes a
//! fresh one — so what matters here is not that the reader is complete but
//! that it agrees with the reader the panel used before, down to the types.
//!
//! That last part is why this is hand-written rather than a crate. PyYAML
//! resolves plain scalars against **YAML 1.1**, and the differences are the
//! kind that change what runs: `yes` is a boolean, `012` is the number ten,
//! and `1:30` is ninety. A 1.2 parser reads all three as text, and the panel
//! would quietly start accepting compose files it used to refuse — or worse,
//! refusing ones it used to run.
//!
//! What is deliberately missing: more than one document in a stream (compose
//! is a single document), and the error *text*. A parse failure here says what
//! went wrong in this reader's own words, which will not match libyaml's
//! phrasing character for character; the caller shows it to the customer
//! behind the same prefix either way.

/// A node of a parsed document, tagged the way PyYAML's resolver tags it.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(String),
    /// A date or a moment. Held as the text Python's `str()` would print,
    /// because printing it is the only thing the panel ever does with one.
    Timestamp(String),
    List(Vec<Value>),
    /// Insertion-ordered, like the `dict` PyYAML builds. A repeated key keeps
    /// the position it first took and takes the later value, which is what
    /// assigning into a `dict` does.
    Map(Vec<(Value, Value)>),
}

impl Value {
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// `mapping.get(key)` for a string key, or `None` when this is not a
    /// mapping or has no such key.
    pub fn get(&self, key: &str) -> Option<&Value> {
        let entries = self.as_map()?;
        entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Str(text) if text == key))
            .map(|(_, value)| value)
    }

    /// `bool(value)` — Python truthiness, not `== true`.
    pub fn truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(flag) => *flag,
            Value::Int(number) => *number != 0,
            Value::Float(number) => *number != 0.0,
            Value::Str(text) => !text.is_empty(),
            Value::Timestamp(_) => true,
            Value::List(items) => !items.is_empty(),
            Value::Map(entries) => !entries.is_empty(),
        }
    }

    /// Python's `str(value)`, which is how nearly every value here reaches a
    /// message or a generated line.
    pub fn python_str(&self) -> String {
        match self {
            Value::Null => "None".to_string(),
            Value::Bool(true) => "True".to_string(),
            Value::Bool(false) => "False".to_string(),
            Value::Int(number) => number.to_string(),
            Value::Float(number) => python_float_str(*number),
            Value::Str(text) => text.clone(),
            Value::Timestamp(text) => text.clone(),
            Value::List(items) => {
                let inner: Vec<String> = items.iter().map(Value::python_repr).collect();
                format!("[{}]", inner.join(", "))
            }
            Value::Map(entries) => {
                let inner: Vec<String> = entries
                    .iter()
                    .map(|(key, value)| format!("{}: {}", key.python_repr(), value.python_repr()))
                    .collect();
                format!("{{{}}}", inner.join(", "))
            }
        }
    }

    /// `repr(value)`, which is what `str()` of a list or a dict prints for the
    /// things inside it.
    fn python_repr(&self) -> String {
        match self {
            Value::Str(text) => python_repr_str(text),
            _ => self.python_str(),
        }
    }
}

/// `repr()` of a string: single quotes, unless the text holds one and no
/// double quote, in which case Python switches rather than escape.
fn python_repr_str(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `str(float)`: the shortest text that reads back as the same number, with a
/// trailing `.0` on a whole one so it still looks like a float.
pub fn python_float_str(number: f64) -> String {
    if number.is_nan() {
        return "nan".to_string();
    }
    if number.is_infinite() {
        return if number > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    let mut significant = 17;
    for precision in 1..=17 {
        let candidate = format!("{number:.*e}", precision - 1);
        if candidate.parse::<f64>() == Ok(number) {
            significant = precision;
            break;
        }
    }
    format_repr(number, significant)
}

/// Python prints a float in positional form while the exponent is small and
/// switches to `e` notation outside roughly `1e-5 .. 1e16`.
fn format_repr(number: f64, significant: usize) -> String {
    let exponent = if number == 0.0 {
        0
    } else {
        // Read the exponent back out of the scientific form rather than from
        // `log10`, which lands on the wrong side for values like 1e-5.
        let scientific = format!("{number:.*e}", significant - 1);
        scientific
            .split('e')
            .nth(1)
            .and_then(|tail| tail.parse::<i32>().ok())
            .unwrap_or(0)
    };
    if (-4..16).contains(&exponent) {
        let decimals = (significant as i32 - 1 - exponent).max(0) as usize;
        let mut text = format!("{number:.decimals$}");
        if text.contains('.') {
            while text.ends_with('0') {
                text.pop();
            }
            if text.ends_with('.') {
                text.push('0');
            }
        } else {
            text.push_str(".0");
        }
        text
    } else {
        let mut text = format!("{number:.*e}", significant - 1);
        // Rust writes `1e20`; Python writes `1e+20`.
        if let Some(at) = text.find('e') {
            let (head, tail) = text.split_at(at);
            let digits = &tail[1..];
            let (sign, digits) = match digits.strip_prefix('-') {
                Some(rest) => ("-", rest),
                None => ("+", digits),
            };
            // No `.0` here: Python writes `1e+16`, not `1.0e+16`.
            text = format!("{head}e{sign}{digits:0>2}");
        }
        text
    }
}

// --- the resolver ----------------------------------------------------------
//
// PyYAML matches a plain scalar against a list of patterns chosen by its first
// character, in the order they were registered: bool, float, int, merge, null,
// timestamp. The order is load-bearing — `0` matches both the float and the
// int pattern if you let it, and float is asked first.

/// What a plain (unquoted) scalar means.
///
/// One departure, documented rather than hidden: an integer too large for an
/// `i64` keeps its own digits as text. Python would hold it exactly, and every
/// use the panel makes of one goes through `str()`, so the digits are what is
/// actually read either way.
pub fn resolve_plain(text: &str) -> Value {
    if let Some(flag) = as_bool(text) {
        return Value::Bool(flag);
    }
    if let Some(number) = as_float(text) {
        return Value::Float(number);
    }
    if let Some(number) = as_int(text) {
        return number;
    }
    if is_null(text) {
        return Value::Null;
    }
    if let Some(stamp) = as_timestamp(text) {
        return Value::Timestamp(stamp);
    }
    Value::Str(text.to_string())
}

fn as_bool(text: &str) -> Option<bool> {
    // The pattern lists each spelling in three casings — all lower, all upper
    // and capitalised — and nothing else. `yEs` is a string.
    const TRUE: &[&str] = &[
        "yes", "Yes", "YES", "true", "True", "TRUE", "on", "On", "ON",
    ];
    const FALSE: &[&str] = &[
        "no", "No", "NO", "false", "False", "FALSE", "off", "Off", "OFF",
    ];
    if TRUE.contains(&text) {
        Some(true)
    } else if FALSE.contains(&text) {
        Some(false)
    } else {
        None
    }
}

fn is_null(text: &str) -> bool {
    matches!(text, "" | "~" | "null" | "Null" | "NULL")
}

/// `[-+]?` followed by the body, or nothing.
fn split_sign(text: &str) -> (i64, &str) {
    match text.as_bytes().first() {
        Some(b'-') => (-1, &text[1..]),
        Some(b'+') => (1, &text[1..]),
        _ => (1, text),
    }
}

/// Every character is a digit of *radix* or an underscore, and there is at
/// least one digit.
fn digits_ok(body: &str, radix: u32) -> bool {
    let mut seen = false;
    for ch in body.chars() {
        if ch == '_' {
            continue;
        }
        if !ch.is_digit(radix) {
            return false;
        }
        seen = true;
    }
    seen
}

fn digits_ok_or_empty(body: &str, radix: u32) -> bool {
    body.chars().all(|c| c == '_' || c.is_digit(radix))
}

/// `(:[0-5]?[0-9])+` — the sexagesimal tail, where `1:30` is ninety.
fn sexagesimal_tail_ok(tail: &str) -> bool {
    for part in tail.split(':') {
        if part.is_empty() || part.len() > 2 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if part.len() == 2 && !(b'0'..=b'5').contains(&part.as_bytes()[0]) {
            return false;
        }
    }
    true
}

fn as_int(text: &str) -> Option<Value> {
    let (sign, body) = split_sign(text);
    if body.is_empty() {
        return None;
    }
    let cleaned: String = body.chars().filter(|c| *c != '_').collect();

    // `0b…` and `0x…` come before the bare-octal rule, which would otherwise
    // swallow the leading zero and choke on the letter.
    if let Some(rest) = body.strip_prefix("0b") {
        return digits_ok(rest, 2).then(|| from_radix(sign, &cleaned[2..], 2, text));
    }
    if let Some(rest) = body.strip_prefix("0x") {
        return digits_ok(rest, 16).then(|| from_radix(sign, &cleaned[2..], 16, text));
    }
    if let Some((head, tail)) = body.split_once(':') {
        // `[1-9][0-9_]*(:[0-5]?[0-9])+`
        if !head.starts_with('0') && digits_ok(head, 10) && sexagesimal_tail_ok(tail) {
            return Some(from_sexagesimal(sign, &cleaned));
        }
        return None;
    }
    if cleaned == "0" {
        return Some(Value::Int(0));
    }
    if let Some(rest) = body.strip_prefix('0') {
        // `0[0-7_]+` — octal, and the reason `012` is ten.
        if digits_ok(rest, 8) {
            return Some(from_radix(sign, &cleaned[1..], 8, text));
        }
        return None;
    }
    digits_ok(body, 10).then(|| from_radix(sign, &cleaned, 10, text))
}

/// An integer that does not fit keeps its digits; see `resolve_plain`.
fn from_radix(sign: i64, digits: &str, radix: u32, original: &str) -> Value {
    match i128::from_str_radix(digits, radix) {
        Ok(number) => Value::Int(i128::from(sign) * number),
        Err(_) => Value::Str(original.to_string()),
    }
}

fn from_sexagesimal(sign: i64, cleaned: &str) -> Value {
    let mut total: i128 = 0;
    for part in cleaned.split(':') {
        let digit: i128 = match part.parse() {
            Ok(value) => value,
            Err(_) => return Value::Str(cleaned.to_string()),
        };
        total = match total.checked_mul(60).and_then(|v| v.checked_add(digit)) {
            Some(value) => value,
            None => return Value::Str(cleaned.to_string()),
        };
    }
    Value::Int(i128::from(sign) * total)
}

fn as_float(text: &str) -> Option<f64> {
    let (sign, body) = split_sign(text);
    if body.eq_ignore_ascii_case(".inf") && matches!(body, ".inf" | ".Inf" | ".INF") {
        return Some(sign as f64 * f64::INFINITY);
    }
    // `.nan` carries no sign in the pattern, so `-.nan` is a string.
    if matches!(text, ".nan" | ".NaN" | ".NAN") {
        return Some(f64::NAN);
    }
    if body.is_empty() {
        return None;
    }
    let cleaned: String = body.chars().filter(|c| *c != '_').collect();

    let (head, tail) = body.split_once('.')?;
    if let Some((whole, minutes)) = head.split_once(':') {
        // `[0-9][0-9_]*(:[0-5]?[0-9])+\.[0-9_]*` — a sexagesimal float.
        if !digits_ok(whole, 10) || !sexagesimal_tail_ok(minutes) || !digits_ok_or_empty(tail, 10) {
            return None;
        }
        let (integral, fraction) = cleaned.split_once('.')?;
        let base = match from_sexagesimal(1, integral) {
            Value::Int(number) => number as f64,
            _ => return None,
        };
        let fraction: f64 = if fraction.is_empty() {
            0.0
        } else {
            format!("0.{fraction}").parse().ok()?
        };
        return Some(sign as f64 * (base + fraction));
    }

    // `[0-9][0-9_]*\.[0-9_]*([eE][-+][0-9]+)?`, or the leading-dot form.
    let (fraction, exponent) = split_exponent(tail);
    if head.is_empty() {
        // The leading-dot form carries no sign in the pattern, so `-.5` is
        // text, and it needs a digit straight after the dot.
        if text.len() != body.len() || !digits_ok(fraction, 10) {
            return None;
        }
    } else if !digits_ok(head, 10) || !digits_ok_or_empty(fraction, 10) {
        return None;
    }
    if let Some(exponent) = exponent {
        // The sign is **required**: PyYAML reads `1.0e5` as text, not a float.
        let signed = exponent.starts_with(['-', '+']);
        if !signed || exponent.len() < 2 || !exponent[1..].bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    Some(sign as f64 * cleaned.parse::<f64>().ok()?)
}

/// Split `12e+3` into its digits and its exponent, or say there is none.
fn split_exponent(tail: &str) -> (&str, Option<&str>) {
    match tail.find(['e', 'E']) {
        Some(at) => (&tail[..at], Some(&tail[at + 1..])),
        None => (tail, None),
    }
}

/// `YYYY-MM-DD`, optionally followed by a time and a zone, rendered as the
/// text Python's `str()` gives the `date` or `datetime` PyYAML builds.
///
/// A zone is **kept**, not applied: PyYAML attaches it as the value's tzinfo,
/// so the wall-clock reading does not move and `str()` prints the offset
/// after it.
fn as_timestamp(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    if bytes.len() < 8 || !bytes[..4].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let (year, rest) = (&text[..4], text.get(4..)?);
    let rest = rest.strip_prefix('-')?;
    let (month, rest) = take_digits(rest, 2)?;
    let rest = rest.strip_prefix('-')?;
    let (day, rest) = take_digits(rest, 2)?;
    if rest.is_empty() {
        // A bare date. The date-only pattern spells every part out in full,
        // so `2024-1-5` is text unless a time follows it.
        return (month.len() == 2 && day.len() == 2).then(|| text.to_string());
    }

    let rest = rest.strip_prefix(['T', 't', ' ', '\t'])?;
    let rest = rest.trim_start_matches([' ', '\t']);
    let (hour, rest) = take_digits(rest, 2)?;
    let rest = rest.strip_prefix(':')?;
    let (minute, rest) = take_digits(rest, 2)?;
    let rest = rest.strip_prefix(':')?;
    let (second, rest) = take_digits(rest, 2)?;
    let (fraction, rest) = match rest.strip_prefix('.') {
        Some(after) => {
            let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
            let used = digits.len();
            (digits, &after[used..])
        }
        None => (String::new(), rest),
    };
    let rest = rest.trim_start_matches([' ', '\t']);
    let zone = read_zone(rest)?;

    let (year, month, day): (i64, i64, i64) =
        (year.parse().ok()?, month.parse().ok()?, day.parse().ok()?);
    let (hour, minute, second): (i64, i64, i64) = (
        hour.parse().ok()?,
        minute.parse().ok()?,
        second.parse().ok()?,
    );
    // `datetime` stops at microseconds, so PyYAML pads or truncates to six.
    let micros: u32 = format!("{fraction:0<6}")[..6].parse().ok()?;
    let mut out = format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}");
    if micros != 0 {
        out.push_str(&format!(".{micros:06}"));
    }
    out.push_str(&zone);
    Some(out)
}

/// `Z`, `+HH`, `+HH:MM`, or nothing — as the suffix `str()` prints for it.
fn read_zone(text: &str) -> Option<String> {
    if text.is_empty() {
        return Some(String::new());
    }
    if text == "Z" {
        return Some("+00:00".to_string());
    }
    let sign = match text.as_bytes()[0] {
        b'+' => '+',
        b'-' => '-',
        _ => return None,
    };
    let (hours, rest) = take_digits(&text[1..], 2)?;
    let minutes = match rest.strip_prefix(':') {
        Some(after) => {
            let (digits, tail) = take_digits(after, 2)?;
            if !tail.is_empty() || digits.len() != 2 {
                return None;
            }
            digits.parse::<i64>().ok()?
        }
        None if rest.is_empty() => 0,
        None => return None,
    };
    let hours: i64 = hours.parse().ok()?;
    Some(format!("{sign}{hours:02}:{minutes:02}"))
}

/// Up to *most* leading digits, and what follows. `None` when there are none.
fn take_digits(text: &str, most: usize) -> Option<(&str, &str)> {
    let taken = text
        .bytes()
        .take(most)
        .take_while(u8::is_ascii_digit)
        .count();
    (taken > 0).then(|| text.split_at(taken))
}

// --- the reader ------------------------------------------------------------

/// Read a whole document.
///
/// Block mappings and sequences, flow collections, quoted and block scalars,
/// anchors, aliases and merge keys: everything a compose file is written with.
/// A second document in the same stream is refused rather than silently
/// dropped, because `safe_load` refuses it too.
pub fn parse(source: &str) -> Result<Value, String> {
    let mut reader = Reader::new(source)?;
    reader.read_document()
}

struct Line {
    /// Columns of leading space. A tab here is refused outright, the way YAML
    /// refuses one: it has no agreed width, so it cannot mean a level.
    indent: usize,
    /// The line with its indentation removed, and nothing else removed.
    text: String,
    number: usize,
}

struct Reader {
    lines: Vec<Line>,
    pos: usize,
    anchors: Vec<(String, Value)>,
}

impl Reader {
    fn new(source: &str) -> Result<Reader, String> {
        let mut lines = Vec::new();
        // A file saved from an editor can start with a byte order mark, and
        // the one that ends in a newline does not have an empty last line.
        let source = source.strip_prefix('\u{feff}').unwrap_or(source);
        let body = source
            .strip_suffix('\n')
            .map(|head| head.strip_suffix('\r').unwrap_or(head))
            .unwrap_or(source);
        for (index, raw) in body.split('\n').enumerate() {
            let raw = raw.strip_suffix('\r').unwrap_or(raw);
            let indent = raw.len() - raw.trim_start_matches(' ').len();
            let text = raw[indent..].to_string();
            if text.starts_with('\t') && !text.trim().is_empty() {
                return Err(format!("line {}: tabs cannot be used to indent", index + 1));
            }
            lines.push(Line {
                indent,
                text,
                number: index + 1,
            });
        }
        Ok(Reader {
            lines,
            pos: 0,
            anchors: Vec::new(),
        })
    }

    fn read_document(&mut self) -> Result<Value, String> {
        self.skip_blank();
        // A directive, then the `---` that ends the directive block.
        while self.pos < self.lines.len() && self.lines[self.pos].text.starts_with('%') {
            self.pos += 1;
            self.skip_blank();
        }
        if self.pos < self.lines.len() {
            let text = self.lines[self.pos].text.clone();
            if text == "---" || text.starts_with("--- ") {
                let rest = text[3..].trim_start().to_string();
                if rest.is_empty() {
                    self.pos += 1;
                } else if find_key_colon(&rest).is_some() {
                    // `--- a: 1` is refused rather than read as a mapping.
                    return Err(format!(
                        "line {}: a mapping cannot start on the `---` line",
                        self.lines[self.pos].number
                    ));
                } else {
                    let indent = self.lines[self.pos].indent + 4;
                    self.lines[self.pos] = Line {
                        indent,
                        text: rest,
                        number: self.lines[self.pos].number,
                    };
                }
            }
        }
        let value = self.parse_node(0)?;
        self.skip_blank();
        if self.pos < self.lines.len() {
            let line = &self.lines[self.pos];
            if line.text == "..." {
                self.pos += 1;
                self.skip_blank();
            }
        }
        if self.pos < self.lines.len() {
            let line = &self.lines[self.pos];
            if line.text.starts_with("---") {
                return Err(format!(
                    "line {}: a stream with more than one document is not supported",
                    line.number
                ));
            }
            return Err(format!(
                "line {}: unexpected content after the document",
                line.number
            ));
        }
        Ok(value)
    }

    /// Step over lines that carry nothing: empty, or a comment on their own.
    fn skip_blank(&mut self) {
        while self.pos < self.lines.len() {
            let text = self.lines[self.pos].text.trim();
            if text.is_empty() || text.starts_with('#') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    /// Whatever stands at *indent* — a mapping, a sequence or a scalar.
    fn parse_node(&mut self, indent: usize) -> Result<Value, String> {
        self.skip_blank();
        if self.pos >= self.lines.len() || self.lines[self.pos].indent < indent {
            return Ok(Value::Null);
        }
        if is_document_marker(&self.lines[self.pos].text) {
            return Ok(Value::Null);
        }
        let own = self.lines[self.pos].indent;
        if starts_item(&self.lines[self.pos].text) {
            return self.parse_sequence(own);
        }
        if self.line_is_mapping()? {
            return self.parse_mapping(own);
        }
        let text = self.lines[self.pos].text.clone();
        self.read_inline(own, &text)
    }

    /// Does the line at the cursor open a mapping — is there a `:` on it that
    /// separates a key from a value?
    fn line_is_mapping(&self) -> Result<bool, String> {
        let line = &self.lines[self.pos];
        Ok(find_key_colon(&line.text).is_some())
    }

    fn parse_sequence(&mut self, indent: usize) -> Result<Value, String> {
        let mut items = Vec::new();
        loop {
            self.skip_blank();
            if self.pos >= self.lines.len() {
                break;
            }
            let line = &self.lines[self.pos];
            if line.indent != indent || !starts_item(&line.text) || is_document_marker(&line.text) {
                break;
            }
            let rest = line.text[1..].to_string();
            let number = line.number;
            let trimmed = rest.trim_start_matches(' ');
            if trimmed.is_empty() || trimmed.starts_with('#') {
                // The item's content is on the lines below, indented under the
                // dash. Nothing there at all means an empty item.
                self.pos += 1;
                items.push(self.parse_node(indent + 1)?);
                continue;
            }
            // `- name: value` puts a mapping on the same line as the dash. The
            // mapping's own indentation is the column its first key starts in,
            // which is what the lines below it line up against.
            let offset = 1 + (rest.len() - trimmed.len());
            self.lines[self.pos] = Line {
                indent: indent + offset,
                text: trimmed.to_string(),
                number,
            };
            items.push(self.parse_node(indent + offset)?);
        }
        Ok(Value::List(items))
    }

    fn parse_mapping(&mut self, indent: usize) -> Result<Value, String> {
        let mut entries: Vec<(Value, Value)> = Vec::new();
        let mut merged: Vec<(Value, Value)> = Vec::new();
        loop {
            self.skip_blank();
            if self.pos >= self.lines.len() {
                break;
            }
            let line = &self.lines[self.pos];
            if line.indent != indent || starts_item(&line.text) || is_document_marker(&line.text) {
                break;
            }
            let number = line.number;
            let text = line.text.clone();
            let Some((key_end, value_start)) = find_key_colon(&text) else {
                return Err(format!(
                    "line {number}: expected a `key: value` pair, found `{}`",
                    clip_line(&text)
                ));
            };
            let key = self.read_key(&text[..key_end], number)?;
            let rest = text[value_start..]
                .trim_start_matches([' ', '\t'])
                .to_string();
            let value = if strip_comment(&rest).is_empty() {
                // The value is on the lines below. A block sequence is allowed
                // to sit at the key's own indentation, so it gets asked for by
                // name rather than by being more indented.
                self.pos += 1;
                self.parse_value_below(indent)?
            } else {
                self.read_inline(indent, &rest)?
            };
            if matches!(&key, Value::Str(name) if name == "<<") {
                // `<<: *base` — what it brings in goes ahead of what is
                // written here, so a key written out wins over the merge.
                for pair in merge_pairs(value, number)? {
                    insert(&mut merged, pair.0, pair.1);
                }
                continue;
            }
            insert(&mut entries, key, value);
        }
        for (key, value) in entries {
            insert(&mut merged, key, value);
        }
        Ok(Value::Map(merged))
    }

    /// What follows a `key:` whose line ended there.
    fn parse_value_below(&mut self, key_indent: usize) -> Result<Value, String> {
        self.skip_blank();
        if self.pos >= self.lines.len() {
            return Ok(Value::Null);
        }
        let line = &self.lines[self.pos];
        if line.indent > key_indent {
            let own = line.indent;
            return self.parse_node(own);
        }
        if line.indent == key_indent && starts_item(&line.text) {
            return self.parse_sequence(key_indent);
        }
        Ok(Value::Null)
    }

    fn read_key(&mut self, text: &str, number: usize) -> Result<Value, String> {
        let text = text.trim_end_matches([' ', '\t']);
        if let Some(rest) = text.strip_prefix('?') {
            if rest.is_empty() || rest.starts_with(' ') {
                return Err(format!(
                    "line {number}: an explicit `? key` is not supported here"
                ));
            }
        }
        let (_, _, body) = strip_properties(text);
        if body.starts_with('"') || body.starts_with('\'') {
            let (value, rest) = read_quoted_str(body)
                .ok_or_else(|| format!("line {number}: the quoted key is not closed"))?;
            if !strip_comment(rest.trim_start()).is_empty() {
                return Err(format!("line {number}: unexpected text after the key"));
            }
            return Ok(Value::Str(value));
        }
        if body.starts_with('[') || body.starts_with('{') {
            let mut flow = Flow::new(body, &self.anchors);
            return flow.read_value();
        }
        Ok(resolve_plain(body.trim_end_matches([' ', '\t'])))
    }

    /// A value written on the same line as its key or its dash.
    fn read_inline(&mut self, parent_indent: usize, text: &str) -> Result<Value, String> {
        let number = self.lines[self.pos].number;
        let (anchor, tag, body) = strip_properties(text);
        let body = body.to_string();

        if body.is_empty() || strip_comment(&body).is_empty() {
            // `key: &name` — the anchor is on the value below it.
            self.pos += 1;
            let value = self.parse_value_below(parent_indent)?;
            return self.finish(anchor, tag, value, number);
        }
        let first = body.as_bytes()[0];
        let value = match first {
            b'|' | b'>' => self.read_block_scalar(parent_indent, &body)?,
            b'*' => {
                self.pos += 1;
                let name = strip_comment(&body[1..]).trim_end().to_string();
                self.anchors
                    .iter()
                    .rev()
                    .find(|(known, _)| *known == name)
                    .map(|(_, value)| value.clone())
                    .ok_or_else(|| format!("line {number}: no anchor named {name}"))?
            }
            b'[' | b'{' => {
                let joined = self.gather_flow(&body)?;
                let mut flow = Flow::new(&joined, &self.anchors);
                let value = flow.read_value()?;
                flow.expect_end()?;
                value
            }
            b'"' | b'\'' => {
                let joined = self.gather_quoted(&body, parent_indent)?;
                let (value, rest) = read_quoted_str(&joined)
                    .ok_or_else(|| format!("line {number}: the quoted value is not closed"))?;
                if !strip_comment(rest.trim_start()).is_empty() {
                    return Err(format!(
                        "line {number}: unexpected text after a quoted value"
                    ));
                }
                Value::Str(value)
            }
            _ => {
                let joined = self.gather_plain(&body, parent_indent);
                check_plain(&joined, number)?;
                resolve_plain(&joined)
            }
        };
        self.finish(anchor, tag, value, number)
    }

    fn finish(
        &mut self,
        anchor: Option<String>,
        tag: Option<String>,
        value: Value,
        number: usize,
    ) -> Result<Value, String> {
        let value = apply_tag(tag, value, number)?;
        if let Some(name) = anchor {
            self.anchors.push((name, value.clone()));
        }
        Ok(value)
    }

    /// `|`, `>`, with their chomping and indentation indicators.
    fn read_block_scalar(&mut self, parent_indent: usize, header: &str) -> Result<Value, String> {
        let number = self.lines[self.pos].number;
        let folded = header.starts_with('>');
        let mut chomp = b'\0';
        let mut explicit: Option<usize> = None;
        for ch in header[1..].chars() {
            match ch {
                '-' | '+' => chomp = ch as u8,
                '0'..='9' => {
                    let digit = ch as usize - '0' as usize;
                    if digit == 0 {
                        return Err(format!(
                            "line {number}: a block scalar cannot be indented 0"
                        ));
                    }
                    explicit = Some(parent_indent + digit);
                }
                ' ' | '\t' => break,
                '#' => break,
                _ => return Err(format!("line {number}: `{header}` is not a block scalar")),
            }
        }
        self.pos += 1;

        // The block's indentation is the first non-empty line's, unless the
        // header named one.
        let mut body_indent = explicit;
        let mut collected: Vec<(usize, String)> = Vec::new();
        while self.pos < self.lines.len() {
            let line = &self.lines[self.pos];
            let blank = line.text.trim().is_empty();
            if !blank {
                let found = *body_indent.get_or_insert(line.indent);
                if line.indent < found {
                    break;
                }
                collected.push((line.indent - found, line.text.clone()));
            } else {
                collected.push((0, String::new()));
            }
            self.pos += 1;
        }
        let mut out = String::new();
        if folded {
            // Folding joins two plain lines with a space. A blank line
            // between them keeps one break per blank instead, and a line
            // indented further than the block keeps its own breaks.
            let mut blanks = 0usize;
            let mut started = false;
            let mut previous_literal = false;
            for (extra, text) in &collected {
                let body = format!("{}{}", " ".repeat(*extra), text);
                if text.is_empty() {
                    blanks += 1;
                    continue;
                }
                let literal = *extra > 0;
                if started {
                    if blanks > 0 {
                        out.push_str(&"\n".repeat(blanks));
                    } else if literal || previous_literal {
                        out.push('\n');
                    } else {
                        out.push(' ');
                    }
                }
                out.push_str(&body);
                blanks = 0;
                started = true;
                previous_literal = literal;
            }
            if started {
                // The last line's own break, and any blank lines after it.
                out.push_str(&"\n".repeat(blanks + 1));
            }
        } else {
            for (extra, text) in &collected {
                if !text.is_empty() {
                    out.push_str(&" ".repeat(*extra));
                    out.push_str(text);
                }
                out.push('\n');
            }
        }

        match chomp {
            // `-` keeps none of the breaks at the end, `+` keeps all of them,
            // and the default keeps exactly one.
            b'-' => out = out.trim_end_matches('\n').to_string(),
            b'+' => {}
            _ => {
                let body = out.trim_end_matches('\n');
                out = if body.is_empty() {
                    String::new()
                } else {
                    format!("{body}\n")
                };
            }
        }
        Ok(Value::Str(out))
    }

    /// Collect a flow collection that runs past the end of its first line.
    fn gather_flow(&mut self, first: &str) -> Result<String, String> {
        let mut out = first.to_string();
        let number = self.lines[self.pos].number;
        self.pos += 1;
        while !flow_is_closed(&out) {
            if self.pos >= self.lines.len() {
                return Err(format!("line {number}: the flow collection is not closed"));
            }
            let text = self.lines[self.pos].text.trim();
            self.pos += 1;
            if text.is_empty() || text.starts_with('#') {
                continue;
            }
            out.push(' ');
            out.push_str(text);
        }
        Ok(out)
    }

    /// Collect a quoted scalar that runs past the end of its first line.
    fn gather_quoted(&mut self, first: &str, parent_indent: usize) -> Result<String, String> {
        let mut out = first.to_string();
        let number = self.lines[self.pos].number;
        self.pos += 1;
        while read_quoted_str(&out).is_none() {
            if self.pos >= self.lines.len() || self.lines[self.pos].indent <= parent_indent {
                return Err(format!("line {number}: the quoted value is not closed"));
            }
            let text = self.lines[self.pos].text.trim();
            self.pos += 1;
            // A break inside a quoted scalar folds to a space, and a blank
            // line to a newline.
            if text.is_empty() {
                out.push('\n');
            } else {
                if !out.ends_with('\n') {
                    out.push(' ');
                }
                out.push_str(text);
            }
        }
        Ok(out)
    }

    /// A plain scalar carries on across lines indented under it.
    fn gather_plain(&mut self, first: &str, parent_indent: usize) -> String {
        let mut parts = vec![strip_comment(first).trim_end().to_string()];
        self.pos += 1;
        let mut blanks = 0;
        while self.pos < self.lines.len() {
            let line = &self.lines[self.pos];
            if line.text.trim().is_empty() {
                blanks += 1;
                self.pos += 1;
                continue;
            }
            if line.indent <= parent_indent
                || starts_item(&line.text)
                || line.text.trim_start().starts_with('#')
                || find_key_colon(&line.text).is_some()
            {
                break;
            }
            let text = strip_comment(&line.text).trim().to_string();
            for _ in 1..blanks {
                parts.push(String::new());
            }
            if blanks > 0 {
                parts.push(format!("\n{text}"));
            } else {
                parts.push(text);
            }
            blanks = 0;
            self.pos += 1;
        }
        // Rewind over the blank lines that turned out to belong to nothing.
        self.pos -= blanks;
        let mut out = String::new();
        for (index, part) in parts.iter().enumerate() {
            if index > 0 && !part.starts_with('\n') && !out.ends_with('\n') {
                out.push(' ');
            }
            out.push_str(part);
        }
        out
    }
}

/// Refuse the plain scalars YAML has no way to read.
///
/// A plain scalar cannot carry `: ` — that is a mapping, and a second one on
/// a line that already has a key is what PyYAML calls "mapping values are not
/// allowed here". It cannot open with an indicator either. And `=` on its own
/// resolves to a tag `safe_load` has no constructor for, which is a refusal
/// rather than a parse failure but reaches the caller the same way.
fn check_plain(text: &str, number: usize) -> Result<(), String> {
    if text == "=" {
        return Err(format!(
            "line {number}: could not determine a constructor for the tag 'tag:yaml.org,2002:value'"
        ));
    }
    if text == "-" || text.starts_with("- ") {
        return Err(format!(
            "line {number}: sequence entries are not allowed in this context"
        ));
    }
    if text.starts_with(['@', '`']) {
        return Err(format!(
            "line {number}: found a reserved indicator character `{}`",
            &text[..1]
        ));
    }
    if text.starts_with('%') {
        return Err(format!(
            "line {number}: a directive is only allowed at the top"
        ));
    }
    if find_key_colon(text).is_some() {
        return Err(format!(
            "line {number}: mapping values are not allowed here"
        ));
    }
    Ok(())
}

/// `---` or `...` on its own line: the end of what is being read.
fn is_document_marker(text: &str) -> bool {
    text == "..." || text == "---" || text.starts_with("--- ") || text.starts_with("... ")
}

/// `- ` or a dash alone: the start of a sequence item.
fn starts_item(text: &str) -> bool {
    text == "-" || text.starts_with("- ") || text.starts_with("-\t")
}

fn clip_line(text: &str) -> String {
    text.chars().take(60).collect()
}

/// Add a pair the way assigning into a `dict` does: a repeated key keeps the
/// place it first took and takes the newer value.
fn insert(entries: &mut Vec<(Value, Value)>, key: Value, value: Value) {
    if let Some(slot) = entries.iter_mut().find(|(known, _)| *known == key) {
        slot.1 = value;
        return;
    }
    entries.push((key, value));
}

/// What a `<<` key brings in: one mapping, or a list of them.
fn merge_pairs(value: Value, number: usize) -> Result<Vec<(Value, Value)>, String> {
    match value {
        Value::Map(entries) => Ok(entries),
        Value::List(items) => {
            let mut out = Vec::new();
            // Reversed, which is what PyYAML does with a list of merges:
            // the **last** one named wins over the ones before it.
            for item in items.into_iter().rev() {
                match item {
                    Value::Map(entries) => out.extend(entries),
                    _ => return Err(format!("line {number}: `<<` can only merge mappings")),
                }
            }
            Ok(out)
        }
        _ => Err(format!("line {number}: `<<` can only merge mappings")),
    }
}

/// Strip a leading `&anchor` and `!tag`, in either order.
fn strip_properties(text: &str) -> (Option<String>, Option<String>, &str) {
    let mut anchor = None;
    let mut tag = None;
    let mut rest = text;
    loop {
        let trimmed = rest.trim_start_matches([' ', '\t']);
        let marker = match trimmed.as_bytes().first() {
            Some(b'&') if anchor.is_none() => b'&',
            Some(b'!') if tag.is_none() => b'!',
            _ => break,
        };
        let token: String = trimmed[1..]
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();
        if token.is_empty() && marker == b'&' {
            break;
        }
        if marker == b'&' {
            anchor = Some(token.clone());
        } else {
            tag = Some(token.clone());
        }
        rest = &trimmed[1 + token.len()..];
    }
    (anchor, tag, rest.trim_start_matches([' ', '\t']))
}

/// The handful of tags `safe_load` knows. Anything else is refused by name,
/// which is what its constructor does with a tag it has no rule for.
fn apply_tag(tag: Option<String>, value: Value, number: usize) -> Result<Value, String> {
    let Some(tag) = tag else {
        return Ok(value);
    };
    match tag.as_str() {
        "!str" => Ok(Value::Str(value.python_str())),
        "!int" => match resolve_plain(&value.python_str()) {
            Value::Int(number) => Ok(Value::Int(number)),
            _ => Err(format!("line {number}: `!!int` on a value that is not one")),
        },
        "!float" => match resolve_plain(&value.python_str()) {
            Value::Float(number) => Ok(Value::Float(number)),
            Value::Int(number) => Ok(Value::Float(number as f64)),
            _ => Err(format!(
                "line {number}: `!!float` on a value that is not one"
            )),
        },
        "!bool" => match resolve_plain(&value.python_str()) {
            Value::Bool(flag) => Ok(Value::Bool(flag)),
            _ => Err(format!(
                "line {number}: `!!bool` on a value that is not one"
            )),
        },
        "!null" => Ok(Value::Null),
        "!seq" | "!map" | "!omap" | "!set" => Ok(value),
        other => Err(format!(
            "line {number}: could not determine a constructor for the tag '!{other}'"
        )),
    }
}

/// Where a line's content stops and its comment starts.
///
/// A `#` opens a comment only at the start or after a space, so `a#b` is a
/// three-character scalar and `url: http://x#y` keeps its fragment.
fn strip_comment(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut quote = 0u8;
    let mut index = 0;
    while index < bytes.len() {
        let ch = bytes[index];
        if quote != 0 {
            if ch == quote {
                quote = 0;
            }
        } else if ch == b'"' || ch == b'\'' {
            quote = ch;
        } else if ch == b'#'
            && (index == 0 || bytes[index - 1] == b' ' || bytes[index - 1] == b'\t')
        {
            return &text[..index];
        }
        index += 1;
    }
    text
}

/// Find the `:` that separates a key from its value on a block line.
///
/// Returns where the key ends and where the value begins. A colon inside a
/// quoted scalar or a flow collection is part of the key, and a plain key's
/// colon has to be followed by a space or end the content — which is why
/// `image: redis:7` is one pair rather than two.
fn find_key_colon(text: &str) -> Option<(usize, usize)> {
    let content = strip_comment(text);
    let bytes = content.as_bytes();
    let mut depth = 0usize;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' | b'\'' => {
                let rest = &content[index..];
                let (_, tail) = read_quoted_str(rest)?;
                index = content.len() - tail.len();
                continue;
            }
            b'[' | b'{' => depth += 1,
            b']' | b'}' => depth = depth.saturating_sub(1),
            b':' if depth == 0 => {
                let after = index + 1;
                if after >= bytes.len() {
                    return Some((index, after));
                }
                if bytes[after] == b' ' || bytes[after] == b'\t' {
                    return Some((index, after));
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// Has every bracket a flow collection opened been closed again?
fn flow_is_closed(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' | b'\'' => match read_quoted_str(&text[index..]) {
                Some((_, tail)) => {
                    index = text.len() - tail.len();
                    continue;
                }
                None => return false,
            },
            b'[' | b'{' => depth += 1,
            b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    return true;
                }
            }
            b'#' if index > 0 && bytes[index - 1] == b' ' => return depth == 0,
            _ => {}
        }
        index += 1;
    }
    depth == 0
}

/// Read one quoted scalar from the start of *text*, and say what follows it.
fn read_quoted_str(text: &str) -> Option<(String, &str)> {
    let bytes = text.as_bytes();
    let quote = *bytes.first()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let mut out = String::new();
    let mut index = 1;
    while index < bytes.len() {
        let ch = bytes[index];
        if ch == quote {
            if quote == b'\'' && bytes.get(index + 1) == Some(&b'\'') {
                // `''` is how a single-quoted scalar carries a quote.
                out.push('\'');
                index += 2;
                continue;
            }
            return Some((out, &text[index + 1..]));
        }
        if quote == b'"' && ch == b'\\' {
            let (piece, used) = read_escape(&text[index + 1..])?;
            out.push_str(&piece);
            index += 1 + used;
            continue;
        }
        let rest = &text[index..];
        let next = rest.chars().next()?;
        out.push(next);
        index += next.len_utf8();
    }
    None
}

/// One escape inside a double-quoted scalar, and how many bytes it took.
fn read_escape(text: &str) -> Option<(String, usize)> {
    let ch = text.chars().next()?;
    let simple = |c: char| Some((c.to_string(), 1));
    match ch {
        '0' => simple('\0'),
        'a' => simple('\u{7}'),
        'b' => simple('\u{8}'),
        't' | '\t' => simple('\t'),
        'n' => simple('\n'),
        'v' => simple('\u{b}'),
        'f' => simple('\u{c}'),
        'r' => simple('\r'),
        'e' => simple('\u{1b}'),
        ' ' => simple(' '),
        '"' => simple('"'),
        '/' => simple('/'),
        '\\' => simple('\\'),
        'N' => simple('\u{85}'),
        '_' => simple('\u{a0}'),
        'L' => simple('\u{2028}'),
        'P' => simple('\u{2029}'),
        'x' => read_hex(&text[1..], 2).map(|(value, used)| (value, used + 1)),
        'u' => read_hex(&text[1..], 4).map(|(value, used)| (value, used + 1)),
        'U' => read_hex(&text[1..], 8).map(|(value, used)| (value, used + 1)),
        _ => None,
    }
}

fn read_hex(text: &str, width: usize) -> Option<(String, usize)> {
    let digits = text.get(..width)?;
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let code = u32::from_str_radix(digits, 16).ok()?;
    Some((char::from_u32(code)?.to_string(), width))
}

// --- flow collections ------------------------------------------------------

/// A reader over `[a, b]` and `{a: b}`, which have their own grammar.
struct Flow<'a> {
    text: &'a str,
    at: usize,
    /// So `<<: [*a, *b]` reaches the mappings it names rather than two
    /// strings that happen to start with a star.
    anchors: &'a [(String, Value)],
}

impl<'a> Flow<'a> {
    fn new(text: &'a str, anchors: &'a [(String, Value)]) -> Flow<'a> {
        Flow {
            text,
            at: 0,
            anchors,
        }
    }

    fn rest(&self) -> &'a str {
        &self.text[self.at..]
    }

    fn skip_space(&mut self) {
        let rest = self.rest();
        let trimmed = rest.trim_start_matches([' ', '\t', '\n']);
        self.at += rest.len() - trimmed.len();
    }

    fn peek(&mut self) -> Option<u8> {
        self.skip_space();
        self.rest().as_bytes().first().copied()
    }

    fn expect_end(&mut self) -> Result<(), String> {
        self.skip_space();
        let rest = strip_comment(self.rest()).trim();
        if rest.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "unexpected `{}` after a flow collection",
                clip_line(rest)
            ))
        }
    }

    fn read_value(&mut self) -> Result<Value, String> {
        match self.peek() {
            Some(b'[') => self.read_sequence(),
            Some(b'{') => self.read_mapping(),
            Some(b'"') | Some(b'\'') => {
                let (value, tail) = read_quoted_str(self.rest())
                    .ok_or_else(|| "a quoted value in the flow is not closed".to_string())?;
                self.at = self.text.len() - tail.len();
                Ok(Value::Str(value))
            }
            Some(b'*') => {
                self.at += 1;
                let name = self.read_plain();
                self.anchors
                    .iter()
                    .rev()
                    .find(|(known, _)| *known == name)
                    .map(|(_, value)| value.clone())
                    .ok_or_else(|| format!("no anchor named {name}"))
            }
            Some(_) => Ok(resolve_plain(&self.read_plain())),
            None => Ok(Value::Null),
        }
    }

    /// A plain scalar inside a flow ends at a comma, a bracket or a `: `.
    fn read_plain(&mut self) -> String {
        let rest = self.rest();
        let bytes = rest.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            match bytes[index] {
                b',' | b']' | b'}' => break,
                b':' if index + 1 >= bytes.len() || bytes[index + 1] == b' ' => break,
                b'#' if index > 0 && bytes[index - 1] == b' ' => break,
                _ => index += 1,
            }
        }
        self.at += index;
        rest[..index].trim_end().to_string()
    }

    fn read_sequence(&mut self) -> Result<Value, String> {
        self.at += 1; // `[`
        let mut items = Vec::new();
        loop {
            match self.peek() {
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::List(items));
                }
                None => return Err("the flow sequence is not closed".to_string()),
                _ => {}
            }
            items.push(self.read_entry()?);
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {}
                Some(other) => {
                    return Err(format!(
                        "expected `,` or `]` in the flow sequence, found `{}`",
                        other as char
                    ))
                }
                None => return Err("the flow sequence is not closed".to_string()),
            }
        }
    }

    /// An item of a flow sequence may itself be a one-pair mapping: the
    /// `[a: 1, b: 2]` form, which is how a compose `ports` list can be
    /// written by hand.
    fn read_entry(&mut self) -> Result<Value, String> {
        let key = self.read_value()?;
        self.skip_space();
        if self.rest().starts_with(':') {
            let after = self.rest().as_bytes().get(1).copied();
            if after.is_none() || after == Some(b' ') || after == Some(b',') || after == Some(b']')
            {
                self.at += 1;
                let value = match self.peek() {
                    Some(b',') | Some(b']') | None => Value::Null,
                    _ => self.read_value()?,
                };
                return Ok(Value::Map(vec![(key, value)]));
            }
        }
        Ok(key)
    }

    fn read_mapping(&mut self) -> Result<Value, String> {
        self.at += 1; // `{`
        let mut entries: Vec<(Value, Value)> = Vec::new();
        loop {
            match self.peek() {
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Map(entries));
                }
                None => return Err("the flow mapping is not closed".to_string()),
                _ => {}
            }
            let key = self.read_value()?;
            self.skip_space();
            let value = if self.rest().starts_with(':') {
                self.at += 1;
                match self.peek() {
                    Some(b',') | Some(b'}') | None => Value::Null,
                    _ => self.read_value()?,
                }
            } else {
                Value::Null
            };
            insert(&mut entries, key, value);
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {}
                Some(other) => {
                    return Err(format!(
                        "expected `,` or `}}` in the flow mapping, found `{}`",
                        other as char
                    ))
                }
                None => return Err("the flow mapping is not closed".to_string()),
            }
        }
    }
}

// --- writing ---------------------------------------------------------------

/// Write a document out in block style, the way `yaml.safe_dump` does with
/// `sort_keys=False`, `allow_unicode=True` and `default_flow_style=False`.
///
/// One difference, and it is deliberate. PyYAML wraps a long scalar at about
/// the eightieth column, breaking at a space; this does not. The file being
/// written here is read by `docker compose` and by nobody else — it is never
/// read back by the panel — so the wrapping is presentation, and reproducing
/// libyaml's column arithmetic would be a large amount of code standing
/// between a value and the container that receives it. Everything that
/// changes *meaning* — which scalars may go unquoted, how a repeated key is
/// ordered, where a nested block sits — is reproduced exactly, and the tests
/// hold the output to that by parsing both and comparing.
pub fn dump(value: &Value) -> String {
    let mut out = String::new();
    match value {
        Value::Map(entries) if !entries.is_empty() => write_mapping(&mut out, entries, 0),
        Value::List(items) if !items.is_empty() => write_sequence(&mut out, items, 0),
        other => {
            out.push_str(&write_scalar(other));
            out.push('\n');
        }
    }
    out
}

fn write_mapping(out: &mut String, entries: &[(Value, Value)], indent: usize) {
    for (key, value) in entries {
        out.push_str(&" ".repeat(indent));
        out.push_str(&write_scalar(key));
        out.push(':');
        write_value(out, value, indent);
    }
}

/// What follows a `key:` — on the same line, or underneath it.
fn write_value(out: &mut String, value: &Value, indent: usize) {
    match value {
        Value::Map(entries) if !entries.is_empty() => {
            out.push('\n');
            write_mapping(out, entries, indent + 2);
        }
        Value::List(items) if !items.is_empty() => {
            // A block sequence under a mapping key is **not** indented
            // further, which is what PyYAML writes and what Compose reads.
            out.push('\n');
            write_sequence(out, items, indent);
        }
        other => {
            out.push(' ');
            out.push_str(&write_scalar(other));
            out.push('\n');
        }
    }
}

fn write_sequence(out: &mut String, items: &[Value], indent: usize) {
    for item in items {
        out.push_str(&" ".repeat(indent));
        out.push_str("- ");
        match item {
            Value::Map(entries) if !entries.is_empty() => {
                // The first pair shares the line with the dash; the rest line
                // up underneath it.
                let (key, value) = &entries[0];
                out.push_str(&write_scalar(key));
                out.push(':');
                write_value(out, value, indent + 2);
                write_mapping(out, &entries[1..], indent + 2);
            }
            Value::List(inner) if !inner.is_empty() => {
                // `- - 1`, with the rest of the inner sequence underneath.
                let mut nested = String::new();
                write_sequence(&mut nested, inner, indent + 2);
                out.push_str(nested.trim_start_matches(' '));
            }
            other => {
                out.push_str(&write_scalar(other));
                out.push('\n');
            }
        }
    }
}

fn write_scalar(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(true) => "true".to_string(),
        Value::Bool(false) => "false".to_string(),
        Value::Int(number) => number.to_string(),
        Value::Float(number) => write_float(*number),
        Value::Timestamp(text) => text.clone(),
        Value::Str(text) => write_string(text),
        // A collection cannot be a key or an inline value here; the callers
        // above handle every non-empty one, so this is the empty pair.
        Value::List(_) => "[]".to_string(),
        Value::Map(_) => "{}".to_string(),
    }
}

/// `represent_float`: `repr()` in lower case, with `.0` put back when the
/// exponent form dropped it, and the three special values spelled the way
/// YAML spells them.
fn write_float(number: f64) -> String {
    if number.is_nan() {
        return ".nan".to_string();
    }
    if number.is_infinite() {
        return if number > 0.0 { ".inf" } else { "-.inf" }.to_string();
    }
    let text = python_float_str(number).to_lowercase();
    if !text.contains('.') && text.contains('e') {
        return text.replacen('e', ".0e", 1);
    }
    text
}

/// Plain if it can be read back as itself, single-quoted if it cannot, and
/// double-quoted when even that would lose something.
fn write_string(text: &str) -> String {
    if plain_is_safe(text) {
        return text.to_string();
    }
    if text
        .chars()
        .all(|c| c == '\t' || (c >= ' ' && c != '\u{7f}'))
    {
        return format!("'{}'", text.replace('\'', "''"));
    }
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\0' => out.push_str("\\0"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Can this text be written with no quotes and read back unchanged?
fn plain_is_safe(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    // It has to resolve back to itself, or `yes` would come back a boolean
    // and `012` a number.
    if resolve_plain(text) != Value::Str(text.to_string()) {
        return false;
    }
    if text.starts_with([' ', '\t']) || text.ends_with([' ', '\t']) {
        return false;
    }
    if text.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}') {
        return false;
    }
    // The indicators that cannot open a plain scalar at all.
    if text.starts_with([
        '#', ',', '[', ']', '{', '}', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`',
    ]) {
        return false;
    }
    // `-`, `?` and `:` may open one only when a non-space follows.
    if text.starts_with(['-', '?', ':']) {
        let next = text[1..].chars().next();
        if !matches!(next, Some(c) if c != ' ' && c != '\t') {
            return false;
        }
    }
    // A `:` that ends the text or is followed by a space would read as a key,
    // and a `#` after a space would open a comment.
    if text.ends_with(':') || text.contains(": ") || text.contains(":\t") {
        return false;
    }
    if text.contains(" #") || text.contains("\t#") {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> serde_json::Value {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/golden/yaml.json"
        ))
        .expect("the corpus");
        serde_json::from_str(&text).expect("the corpus parses")
    }

    /// The same shape the generator records, so a difference in **type** shows
    /// up and not only a difference in text.
    fn shape(value: &Value) -> String {
        match value {
            Value::Null => "null".to_string(),
            Value::Bool(true) => "bool:true".to_string(),
            Value::Bool(false) => "bool:false".to_string(),
            Value::Int(number) => format!("int:{number}"),
            Value::Float(number) => format!("float:{}", python_float_str(*number)),
            Value::Str(text) => format!("str:{}", json_string(text)),
            Value::Timestamp(text) => format!("time:{text}"),
            Value::List(items) => {
                let inner: Vec<String> = items.iter().map(shape).collect();
                format!("[{}]", inner.join(","))
            }
            Value::Map(entries) => {
                let inner: Vec<String> = entries
                    .iter()
                    .map(|(key, value)| format!("{}={}", shape(key), shape(value)))
                    .collect();
                format!("{{{}}}", inner.join(","))
            }
        }
    }

    /// `json.dumps(text, ensure_ascii=False)`.
    fn json_string(text: &str) -> String {
        let mut out = String::from("\"");
        for ch in text.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    #[test]
    fn a_plain_scalar_resolves_the_way_python_resolves_it() {
        let corpus = corpus();
        let cases = corpus["scalars"].as_array().expect("the cases");
        assert_eq!(cases.len(), 113, "the corpus changed size");
        let mut failures = Vec::new();
        for case in cases {
            let raw = case["raw"].as_str().expect("the text");
            let source = if raw.is_empty() {
                "value:\n".to_string()
            } else {
                format!("value: {raw}\n")
            };
            let parsed = parse(&source);
            if !case["ok"].as_bool().unwrap_or(false) {
                // The generator records why. `YAMLError` is a parse failure
                // and has to fail here too; anything else is a constructor
                // refusing what it was handed, which the importer does not
                // catch — a 500 in the Python. This reader answers instead of
                // falling over, which is a difference in its favour and one
                // the case records rather than hides.
                if case["why"].as_str() == Some("YAMLError") && parsed.is_ok() {
                    failures.push(format!("{raw:?}: parsed, Python refused it"));
                }
                continue;
            }
            match parsed {
                Ok(document) => {
                    let got = document
                        .get("value")
                        .map(shape)
                        .unwrap_or_else(|| "missing".to_string());
                    let want = case["shape"].as_str().expect("the shape");
                    if got != want {
                        failures.push(format!("{raw:?}: want {want}, got {got}"));
                    }
                }
                Err(why) => failures.push(format!("{raw:?}: {why}")),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn a_document_parses_the_way_python_parses_it() {
        let corpus = corpus();
        let cases = corpus["documents"].as_array().expect("the cases");
        assert_eq!(cases.len(), 79, "the corpus changed size");
        let mut failures = Vec::new();
        for case in cases {
            let name = case["name"].as_str().expect("the name");
            let source = case["source"].as_str().expect("the source");
            let parsed = parse(source);
            if !case["ok"].as_bool().unwrap_or(false) {
                if case["why"].as_str() == Some("YAMLError") && parsed.is_ok() {
                    failures.push(format!("{name}: parsed, Python refused it"));
                }
                continue;
            }
            match parsed {
                Ok(document) => {
                    let got = shape(&document);
                    let want = case["shape"].as_str().expect("the shape");
                    if got != want {
                        failures.push(format!("{name}:\n    want {want}\n    got  {got}"));
                    }
                }
                Err(why) => failures.push(format!("{name}: {why}")),
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn a_float_prints_the_way_python_prints_it() {
        let corpus = corpus();
        let cases = corpus["floats"].as_array().expect("the cases");
        let mut failures = Vec::new();
        for case in cases {
            let raw = case["raw"].as_str().expect("the text");
            let number: f64 = raw.parse().expect("a float");
            let got = python_float_str(number);
            let want = case["repr"].as_str().expect("the repr");
            if got != want {
                failures.push(format!("{raw}: want {want}, got {got}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn a_repeated_key_keeps_its_place_and_takes_the_later_value() {
        let document = parse("a: 1\nb: 2\na: 3\n").expect("it parses");
        assert_eq!(shape(&document), "{str:\"a\"=int:3,str:\"b\"=int:2}");
    }
}
