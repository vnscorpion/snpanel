//! `shlex.split`, reproduced.
//!
//! Source: CPython's `Lib/shlex.py`, as `shlex.split(s)` configures it -
//! `posix=True`, `whitespace_split=True`, `commenters=''`, no
//! `punctuation_chars`.
//!
//! This is the only lexer in the panel a customer writes input for directly.
//! `terminal.split_command` hands it the box that says "php artisan migrate",
//! and `cron._validate_command` hands it the cron command. Both then check
//! `argv[0]` against an allow-list and pass the *split* argv to the helper, so
//! a disagreement here is not cosmetic: a string that Python splits as
//! `["php", "x"]` and a port splits as `["php x"]` is either a command the
//! panel refuses that Python runs, or - the direction that matters - one that
//! passes the allow-list check and then reaches the helper as something else.
//!
//! Written out rather than approximated with a pattern, because the parts that
//! are easy to get wrong are the ones no obvious command reaches: the empty
//! token that `''` produces and posix mode keeps, and the rule that a
//! backslash is literal inside single quotes but not inside double ones.
//! 2,937 recorded answers from the real `shlex` are in
//! `tests/golden/shlex_split.json`.

#[derive(Debug, PartialEq, Eq)]
pub enum LexError {
    /// Source: `raise ValueError("No closing quotation")`.
    NoClosingQuotation,
    /// Source: `raise ValueError("No escaped character")`.
    NoEscapedCharacter,
}

impl std::fmt::Display for LexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The text matters: `split_command` puts it in the message a customer
        // reads, as `Invalid command syntax: {exc}`.
        match self {
            Self::NoClosingQuotation => write!(f, "No closing quotation"),
            Self::NoEscapedCharacter => write!(f, "No escaped character"),
        }
    }
}

/// Source: `shlex.whitespace`.
const WHITESPACE: &[char] = &[' ', '\t', '\r', '\n'];
/// Source: `shlex.quotes`.
const QUOTES: &[char] = &['\'', '"'];
/// Source: `shlex.escape`.
const ESCAPE: char = '\\';
/// Source: `shlex.escapedquotes` - the single quote is deliberately absent.
/// Inside `'...'` a backslash is an ordinary character, and that is why
/// `'\''` lexes to a backslash and not to a quote.
const ESCAPED_QUOTES: char = '"';

/// Source: `shlex.state`. Python holds it as a character - `' '`, `'a'`, a
/// quote character, or the escape character - and `None` for end of file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// Python's `None`.
    Eof,
    /// Python's `' '`.
    Space,
    /// Python's `'a'`.
    Word,
    /// Python's state being the quote character itself.
    Quote(char),
    /// Python's state being the escape character.
    Escape,
}

/// Source: `shlex.split(s)`.
///
/// The state carries **between** tokens, exactly as it does in Python, where
/// it lives on the lexer and `read_token` is called again and again. Resetting
/// it per token would be a different lexer.
pub fn split(input: &str) -> Result<Vec<String>, LexError> {
    let mut chars = input.chars();
    let mut state = State::Space;
    let mut out: Vec<String> = Vec::new();
    // Source: `list(lex)`, which stops at the first `None`.
    while let Some(token) = read_token(&mut chars, &mut state)? {
        out.push(token);
    }
    Ok(out)
}

/// Source: `shlex.read_token`, with the branches Python cannot reach under
/// `split`'s settings left out: `commenters` is empty, `punctuation_chars` is
/// empty (so state `'c'` never happens and nothing is ever pushed back), and
/// `whitespace_split` being true makes the `wordchars` test redundant - both
/// its branch and the `whitespace_split` branch do the same two assignments.
fn read_token(
    chars: &mut std::str::Chars<'_>,
    state: &mut State,
) -> Result<Option<String>, LexError> {
    let mut token = String::new();
    let mut quoted = false;
    // Source: `escapedstate = ' '`. Only ever read in the escape state, which
    // is only ever entered with it set, so the initial value is Python's
    // placeholder and nothing more.
    let mut escapedstate = State::Space;

    loop {
        let next = chars.next();
        match *state {
            State::Eof => {
                token.clear();
                break;
            }
            State::Space => match next {
                None => {
                    *state = State::Eof;
                    break;
                }
                Some(c) if WHITESPACE.contains(&c) => {
                    if !token.is_empty() || quoted {
                        break;
                    }
                }
                Some(c) if c == ESCAPE => {
                    escapedstate = State::Word;
                    *state = State::Escape;
                }
                Some(c) if QUOTES.contains(&c) => *state = State::Quote(c),
                Some(c) => {
                    token.push(c);
                    *state = State::Word;
                }
            },
            State::Quote(quote) => {
                // Set before the end-of-file check, as Python does, so that an
                // unterminated quote is an error rather than a silent token.
                quoted = true;
                let Some(c) = next else {
                    return Err(LexError::NoClosingQuotation);
                };
                if c == quote {
                    *state = State::Word;
                } else if c == ESCAPE && quote == ESCAPED_QUOTES {
                    escapedstate = State::Quote(quote);
                    *state = State::Escape;
                } else {
                    token.push(c);
                }
            }
            State::Escape => {
                let Some(c) = next else {
                    return Err(LexError::NoEscapedCharacter);
                };
                // Source: "In posix shells, only the quote itself or the
                // escape character may be escaped by it." Anything else keeps
                // its backslash, so `"\a"` is a backslash and an `a`.
                if let State::Quote(quote) = escapedstate {
                    if c != ESCAPE && c != quote {
                        token.push(ESCAPE);
                    }
                }
                token.push(c);
                *state = escapedstate;
            }
            State::Word => match next {
                None => {
                    *state = State::Eof;
                    break;
                }
                Some(c) if WHITESPACE.contains(&c) => {
                    *state = State::Space;
                    if !token.is_empty() || quoted {
                        break;
                    }
                }
                Some(c) if QUOTES.contains(&c) => *state = State::Quote(c),
                Some(c) if c == ESCAPE => {
                    escapedstate = State::Word;
                    *state = State::Escape;
                }
                Some(c) => token.push(c),
            },
        }
    }

    // Source: `if self.posix and not quoted and result == '': result = None`.
    // The `quoted` half is the whole reason `''` is an argument: an empty
    // token that was written with quotes is a real, empty argument, and one
    // that was not is the end of the input.
    if !quoted && token.is_empty() {
        return Ok(None);
    }
    Ok(Some(token))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every answer here came from running the real `shlex.split`. A
    /// disagreement is a command that reaches the helper split differently
    /// from the one the allow-list approved.
    #[test]
    fn the_lexer_agrees_with_python() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/shlex_split.json");
        let corpus: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the shlex corpus"))
                .expect("the corpus parses");
        let cases = corpus["cases"].as_array().expect("the cases");
        assert!(cases.len() > 2000, "the corpus shrank to {}", cases.len());

        let mut failures: Vec<String> = Vec::new();
        let mut raised = 0usize;
        for case in cases {
            let input = case["input"].as_str().unwrap_or("");
            let got = split(input);
            match case.get("argv") {
                Some(argv) => {
                    let want: Vec<String> = argv
                        .as_array()
                        .expect("argv is a list")
                        .iter()
                        .map(|v| v.as_str().unwrap_or("").to_string())
                        .collect();
                    match got {
                        Ok(have) if have == want => {}
                        Ok(have) => {
                            failures.push(format!("{input:?}: python {want:?}, rust {have:?}"))
                        }
                        Err(e) => {
                            failures.push(format!("{input:?}: python {want:?}, rust raised {e}"))
                        }
                    }
                }
                None => {
                    raised += 1;
                    let want = case["error"].as_str().unwrap_or("");
                    match got {
                        Err(e) if e.to_string() == want => {}
                        Err(e) => failures.push(format!(
                            "{input:?}: python {want:?}, rust {:?}",
                            e.to_string()
                        )),
                        Ok(have) => failures
                            .push(format!("{input:?}: python raised {want:?}, rust {have:?}")),
                    }
                }
            }
        }
        assert!(
            raised > 100,
            "only {raised} error cases; the corpus is thin"
        );
        assert!(
            failures.is_empty(),
            "{} of {} disagree:\n{}",
            failures.len(),
            cases.len(),
            failures
                .iter()
                .take(25)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// The three the corpus proves but that are worth saying out loud, because
    /// each one is a place a hand-written splitter goes wrong quietly.
    #[test]
    fn the_cases_a_naive_splitter_gets_wrong() {
        // An empty quoted string is an argument, not nothing.
        assert_eq!(split("wp x ''").unwrap(), vec!["wp", "x", ""]);
        // A backslash is literal inside single quotes and not inside double.
        assert_eq!(split(r"'\a'").unwrap(), vec![r"\a"]);
        assert_eq!(split(r#""\a""#).unwrap(), vec![r"\a"]);
        assert_eq!(split(r#""\""#).unwrap_err(), LexError::NoClosingQuotation);
        // Quotes glue rather than separate: this is one argument.
        assert_eq!(split(r#"a"b c"d"#).unwrap(), vec!["ab cd"]);
    }
}
