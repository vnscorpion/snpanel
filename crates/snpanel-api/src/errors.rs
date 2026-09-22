//! FastAPI's error shapes, and Pydantic's.
//!
//! The frontend reads these, so they are part of the contract as much as any
//! success body is (NT7). Two shapes, and they are not interchangeable:
//!
//! - `HTTPException(status_code, detail="...")` puts a **string** under
//!   `detail`;
//! - a validation failure puts a **list of objects** there.
//!
//! `App.jsx` walks the list. Sending the string shape where Python sends the
//! list prints "[object Object]" in the UI, and sending the list where Python
//! sends a string prints nothing useful at all.
//!
//! Every entry shape below was read off the running Python rather than from
//! the Pydantic documentation, because the documentation does not say what
//! `input` holds for a form field (`null`) as against a JSON body (the parsed
//! object), and that difference is a diff on every validation case.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};

/// `HTTPException(status_code=..., detail=...)`.
pub fn error(status: StatusCode, detail: &str) -> Response {
    (status, axum::Json(json!({ "detail": detail }))).into_response()
}

pub fn not_found(detail: &str) -> Response {
    error(StatusCode::NOT_FOUND, detail)
}

pub fn bad_request(detail: &str) -> Response {
    error(StatusCode::BAD_REQUEST, detail)
}

pub fn conflict(detail: &str) -> Response {
    error(StatusCode::CONFLICT, detail)
}

/// Source: `ensure_role` when the caller is below the minimum.
pub fn not_enough_permissions() -> Response {
    error(StatusCode::FORBIDDEN, "Not enough permissions")
}

pub fn internal_error() -> Response {
    error(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
}

/// A 422 carrying one or more Pydantic entries.
///
/// Pydantic reports **every** problem it found, not the first, so this takes a
/// list. A port that stopped at the first would send the user round the loop
/// once per bad field.
pub fn validation_error(entries: Vec<Value>) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        axum::Json(json!({ "detail": entries })),
    )
        .into_response()
}

/// One `missing` entry.
///
/// `input` is whatever Pydantic was looking at: the parsed body for a JSON
/// request, `null` for a form - Starlette hands form fields over one at a
/// time, so there is no object to show.
pub fn missing_entry(field: &str, input: Value) -> Value {
    json!({
        "type": "missing",
        "loc": ["body", field],
        "msg": "Field required",
        "input": input,
    })
}

pub fn missing_field(field: &str, input: Value) -> Response {
    validation_error(vec![missing_entry(field, input)])
}

/// `HTTPException` whose detail is not a sentence.
///
/// FastAPI passes the detail through as it was given, so a handler that
/// raises with a dict answers with that dict under `detail` — which is how
/// the compose importer returns a message and a list of issues together.
pub fn detail(status: StatusCode, detail: Value) -> Response {
    (status, axum::Json(json!({ "detail": detail }))).into_response()
}

/// `literal_error`: a field declared `Literal[...]` given something else.
///
/// Pydantic prints the options back in the order they were declared, joined
/// with commas and a final "or" — and puts the same text in `ctx.expected`.
pub fn literal_entry(field: &str, input: &Value, allowed: &[&str]) -> Value {
    let quoted: Vec<String> = allowed.iter().map(|option| format!("'{option}'")).collect();
    let expected = match quoted.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        None => String::new(),
    };
    json!({
        "type": "literal_error",
        "loc": ["body", field],
        "msg": format!("Input should be {expected}"),
        "input": input,
        "ctx": { "expected": expected },
    })
}

/// Source: `Field(min_length=..., max_length=...)`.
pub fn length_entry(field: &str, value: &str, min: usize, max: usize) -> Option<Value> {
    // Characters, not bytes: Pydantic counts characters, so a name of accented
    // letters is measured the way the user sees it.
    let chars = value.chars().count();
    if chars < min {
        return Some(json!({
            "type": "string_too_short",
            "loc": ["body", field],
            "msg": format!("String should have at least {min} characters"),
            "input": value,
            "ctx": { "min_length": min },
        }));
    }
    if chars > max {
        return Some(json!({
            "type": "string_too_long",
            "loc": ["body", field],
            "msg": format!("String should have at most {max} characters"),
            "input": value,
            "ctx": { "max_length": max },
        }));
    }
    None
}

pub fn check_length(field: &str, value: &str, min: usize, max: usize) -> Result<(), Response> {
    match length_entry(field, value, min, max) {
        Some(entry) => Err(validation_error(vec![entry])),
        None => Ok(()),
    }
}

/// Source: `Field(ge=..., le=...)`.
pub fn range_entry(field: &str, value: i64, min: i64, max: i64) -> Option<Value> {
    if value < min {
        return Some(json!({
            "type": "greater_than_equal",
            "loc": ["body", field],
            "msg": format!("Input should be greater than or equal to {min}"),
            "input": value,
            "ctx": { "ge": min },
        }));
    }
    if value > max {
        return Some(json!({
            "type": "less_than_equal",
            "loc": ["body", field],
            "msg": format!("Input should be less than or equal to {max}"),
            "input": value,
            "ctx": { "le": max },
        }));
    }
    None
}

pub fn check_range(field: &str, value: i64, min: i64, max: i64) -> Result<(), Response> {
    match range_entry(field, value, min, max) {
        Some(entry) => Err(validation_error(vec![entry])),
        None => Ok(()),
    }
}

/// Source: `int_parsing` - a value that is not an integer at all.
/// `int_type`: the field is there and is not a number at all.
///
/// Distinct from `int_parsing`, which is a string that *looks* like it
/// might be one. A list where an integer belongs is the wrong kind; `"12x"`
/// is the right kind badly written, and the panel shows the difference.
pub fn int_type_entry(field: &str, input: &Value) -> Value {
    json!({
        "type": "int_type",
        "loc": ["body", field],
        "msg": "Input should be a valid integer",
        "input": input,
    })
}

pub fn int_type(field: &str, input: &Value) -> Response {
    validation_error(vec![int_type_entry(field, input)])
}

/// Source: pydantic's **lax** integer, which is what FastAPI validates a
/// JSON body with.
///
/// Reading only `Value::Number` is wrong in both directions. The Python
/// accepts `"3"`, `" 3 "`, `"+3"`, `"1_0"`, `"3.0"`, `3.0` and `true`, and
/// it refuses an explicit `null` that a field left out would have
/// defaulted. All measured, in `tests/golden/account_create.json`.
///
/// The three error types are not interchangeable:
///
/// - `int_type` — the wrong *kind* entirely: `null`, a list, an object.
/// - `int_parsing` — a **string** that is not an integer: `"three"`,
///   `"0x3"`, `"3.5"`, `""`, and `"۳"`, which Python's own `int()` would
///   have taken but pydantic will not.
/// - `int_from_float` — a **float** with a fractional part: `3.5`. A float
///   that is whole, like `3.0`, is simply the integer.
///
/// A value larger than `i64` is a valid integer to pydantic, which has no
/// bound. It is saturated here rather than refused, because every caller
/// uses the result as a row id and a saturated one matches no row - the
/// same 404 the Python reaches by looking it up.
pub fn read_int(field: &str, value: Option<&Value>) -> Result<Option<i64>, Response> {
    read_int_entry(field, value).map_err(|entry| validation_error(vec![entry]))
}

pub fn read_int_entry(field: &str, value: Option<&Value>) -> Result<Option<i64>, Value> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        // `True` is `1` to pydantic, as it is to Python.
        Value::Bool(flag) => Ok(Some(i64::from(*flag))),
        Value::Number(n) => {
            if let Some(exact) = n.as_i64() {
                return Ok(Some(exact));
            }
            // A number above `i64::MAX` reads as a float here, is whole,
            // and saturates - so it needs no branch of its own.
            match n.as_f64() {
                Some(f) if f.fract() == 0.0 => Ok(Some(saturate(f))),
                _ => Err(int_from_float_entry(field, value)),
            }
        }
        Value::String(raw) => match parse_lax_int(raw) {
            Some(parsed) => Ok(Some(parsed)),
            None => Err(int_parsing_entry(field, value)),
        },
        _ => Err(int_type_entry(field, value)),
    }
}

fn saturate(f: f64) -> i64 {
    if f >= i64::MAX as f64 {
        i64::MAX
    } else if f <= i64::MIN as f64 {
        i64::MIN
    } else {
        f as i64
    }
}

/// The string half of [`read_int`].
///
/// Whitespace is trimmed first - including a non-breaking space, which the
/// corpus has - and then the text must be an integer with an optional sign
/// and **single** underscores between digits, or a decimal that happens to
/// be whole. The digits are ASCII only: `"۳"` is a digit to Python's
/// `int()` and is not one here, because it is not one to pydantic either.
fn parse_lax_int(raw: &str) -> Option<i64> {
    let text = raw.trim();
    if text.is_empty() {
        return None;
    }
    if let Some(cleaned) = strip_underscores(text) {
        if let Ok(parsed) = cleaned.parse::<i64>() {
            return Some(parsed);
        }
    }
    // `"3.0"` is an integer to pydantic; `"3.5"` is not. `inf` and `NaN`
    // have no whole part, so the same test refuses them.
    //
    // This is also what catches an integer too long for `i64`: it parses
    // as a float, is whole, and saturates - see the note on saturation
    // above. A branch of its own for that case could not change the answer.

    match text.parse::<f64>() {
        Ok(f) if f.fract() == 0.0 => Some(saturate(f)),
        _ => None,
    }
}

/// `1_0` is ten; `1__0`, `_1` and `1_` are not numbers at all.
fn strip_underscores(text: &str) -> Option<String> {
    if !text.contains('_') {
        return Some(text.to_string());
    }
    let bytes = text.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b != b'_' {
            continue;
        }
        let before = i.checked_sub(1).map(|j| bytes[j]);
        let after = bytes.get(i + 1).copied();
        if !matches!(before, Some(c) if c.is_ascii_digit())
            || !matches!(after, Some(c) if c.is_ascii_digit())
        {
            return None;
        }
    }
    Some(text.replace('_', ""))
}

/// A float where an integer belongs, with something after the point.
pub fn int_from_float_entry(field: &str, input: &Value) -> Value {
    json!({
        "type": "int_from_float",
        "loc": ["body", field],
        "msg": "Input should be a valid integer, got a number with a fractional part",
        "input": input,
    })
}

pub fn int_parsing_entry(field: &str, input: &Value) -> Value {
    json!({
        "type": "int_parsing",
        "loc": ["body", field],
        "msg": "Input should be a valid integer, unable to parse string as an integer",
        "input": input,
    })
}

pub fn int_parsing(field: &str, input: &Value) -> Response {
    validation_error(vec![int_parsing_entry(field, input)])
}

/// Source: pydantic's **lax** boolean, which is what FastAPI validates a
/// JSON body with.
///
/// Reading only `true` and `false` is wrong in both directions: it refuses
/// `"true"`, `"on"`, `"y"`, `1` and `1.0`, all of which the Python accepts,
/// and it accepts an explicit `null`, which the Python refuses. A field the
/// body leaves out takes the model's default; a field set to `null` does
/// not.
///
/// The two error types are not interchangeable either. A value of the right
/// *kind* that cannot be read is `bool_parsing` (`2`, `"maybe"`, `"01"`,
/// and `" true"` — there is no trimming); a value of the wrong kind is
/// `bool_type` (`null`, a list, an object, and a float that is not 0 or 1).
pub fn read_bool_entry(field: &str, value: Option<&Value>, default: bool) -> Result<bool, Value> {
    let Some(value) = value else {
        return Ok(default);
    };
    match value {
        Value::Bool(flag) => Ok(*flag),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                match i {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(bool_parsing_entry(field, value)),
                }
            } else if let Some(f) = n.as_f64() {
                // A float is the wrong *kind* unless it is exactly 0 or 1.
                if f == 0.0 {
                    Ok(false)
                } else if f == 1.0 {
                    Ok(true)
                } else {
                    Err(bool_type_entry(field, value))
                }
            } else {
                Err(bool_type_entry(field, value))
            }
        }
        Value::String(text) => match text.to_lowercase().as_str() {
            "1" | "on" | "t" | "true" | "y" | "yes" => Ok(true),
            "0" | "off" | "f" | "false" | "n" | "no" => Ok(false),
            _ => Err(bool_parsing_entry(field, value)),
        },
        _ => Err(bool_type_entry(field, value)),
    }
}

pub fn read_bool(field: &str, value: Option<&Value>, default: bool) -> Result<bool, Response> {
    read_bool_entry(field, value, default).map_err(|entry| validation_error(vec![entry]))
}

/// `bool_type`: the value is not something a boolean can be read from.
pub fn bool_type_entry(field: &str, input: &Value) -> Value {
    json!({
        "type": "bool_type",
        "loc": ["body", field],
        "msg": "Input should be a valid boolean",
        "input": input,
    })
}

pub fn bool_parsing_entry(field: &str, input: &Value) -> Value {
    json!({
        "type": "bool_parsing",
        "loc": ["body", field],
        "msg": "Input should be a valid boolean, unable to interpret input",
        "input": input,
    })
}

/// `list_type`: the field is there and is not a list.
pub fn list_type_entry(field: &str, input: &Value) -> Value {
    json!({
        "type": "list_type",
        "loc": ["body", field],
        "msg": "Input should be a valid list",
        "input": input,
    })
}

pub fn list_type(field: &str, input: &Value) -> Response {
    validation_error(vec![list_type_entry(field, input)])
}

pub fn string_type_entry(field: &str, input: &Value) -> Value {
    json!({
        "type": "string_type",
        "loc": ["body", field],
        "msg": "Input should be a valid string",
        "input": input,
    })
}

pub fn string_type(field: &str, input: &Value) -> Response {
    validation_error(vec![string_type_entry(field, input)])
}

/// Source: `model_attributes_type` - a body that is valid JSON but not an
/// object.
pub fn not_a_dictionary(input: Value) -> Response {
    validation_error(vec![json!({
        "type": "model_attributes_type",
        "loc": ["body"],
        "msg": "Input should be a valid dictionary or object to extract fields from",
        "input": input,
    })])
}

/// A `value_error` from a `field_validator` that raised.
///
/// `ctx.error` holds the **exception object**, and FastAPI's JSON encoder
/// renders an exception it does not recognise as `{}` - so the message appears
/// once, in `msg`, and `ctx.error` is an empty object. Putting the message
/// there as well would be the more useful answer and the wrong one (NT1); the
/// shadow diff caught it doing exactly that.
pub fn value_error_entry(field: &str, message: &str, input: &Value) -> Value {
    json!({
        "type": "value_error",
        "loc": ["body", field],
        "msg": format!("Value error, {message}"),
        "input": input,
        "ctx": { "error": {} },
    })
}

pub fn value_error(field: &str, message: &str, input: &Value) -> Response {
    validation_error(vec![value_error_entry(field, message, input)])
}

/// Turn a SQLite `DateTime` column into the JSON Pydantic emits.
///
/// SQLAlchemy stores `YYYY-MM-DD HH:MM:SS[.ffffff]`; Pydantic serialises
/// through `datetime.isoformat()`, which uses a `T` separator and **omits the
/// microseconds when they are zero**. Emitting `.000000` unconditionally is a
/// difference on every row that happens to land on a whole second.
pub fn iso_datetime(stored: Option<&str>) -> Value {
    let Some(raw) = stored else {
        return Value::Null;
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Value::Null;
    }
    // Already ISO, or a format this does not recognise: pass it through rather
    // than mangling it.
    let normalised = raw.replacen(' ', "T", 1);
    let trimmed = match normalised.split_once('.') {
        Some((head, frac)) if frac.chars().all(|c| c == '0') => head.to_string(),
        _ => normalised,
    };
    Value::String(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account_corpus() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/account_create.json");
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the account corpus"))
            .expect("the corpus parses")
    }

    /// pydantic's lax integer, against pydantic.
    ///
    /// The corpus was taken through `package_id`, which carries `ge=1`, so
    /// a `greater_than_equal` in it means the **coercion succeeded** and the
    /// bound refused the result - which is what pins `"0"`, `False` and
    /// `"-3"` as integers rather than as unreadable text.
    #[test]
    fn the_lax_integer_is_pydantics() {
        let corpus = account_corpus();
        let cases = corpus["package_id"].as_array().expect("the cases");
        assert_eq!(cases.len(), 33, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        for case in cases {
            let raw = &case["body"]["package_id"];
            let got = read_int_entry("package_id", Some(raw));
            let want_type = case
                .get("errors")
                .and_then(Value::as_array)
                .and_then(|e| e.first())
                .and_then(|e| e["type"].as_str());
            match want_type {
                // The coercion failed: the type is the one pydantic gave.
                Some(kind @ ("int_type" | "int_parsing" | "int_from_float")) => match got {
                    Err(entry) if entry["type"] == kind => {}
                    other => failures.push(format!("{raw}: python {kind}, rust {other:?}")),
                },
                // The coercion succeeded and `ge=1` refused the value.
                Some("greater_than_equal") => {
                    if let Err(entry) = got {
                        failures.push(format!("{raw}: python read it, rust {entry}"));
                    }
                }
                Some(other) => failures.push(format!("{raw}: unexpected {other}")),
                None => {
                    // The corpus holds one value above `i64::MAX`, which is
                    // an integer to pydantic and saturates here; see
                    // `an_integer_too_large_to_hold_saturates_rather_than_failing`.
                    let stored = &case["value"]["package_id"];
                    let want = stored
                        .as_i64()
                        .unwrap_or_else(|| stored.as_u64().map(|_| i64::MAX).expect("an integer"));
                    match got {
                        Ok(Some(value)) if value == want => {}
                        other => failures.push(format!("{raw}: python {want}, rust {other:?}")),
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The ones worth stating without opening the JSON.
    #[test]
    fn the_lax_integer_reads_what_looks_like_text() {
        let read = |v: Value| read_int_entry("f", Some(&v)).map(|o| o.expect("a value"));
        // A string of digits, with or without room around it.
        assert_eq!(read(json!("3")), Ok(3));
        assert_eq!(read(json!("  3  ")), Ok(3));
        // Python's own underscore separators, but only between digits.
        assert_eq!(read(json!("1_0")), Ok(10));
        assert!(read(json!("1__0")).is_err());
        assert!(read(json!("_1")).is_err());
        // A whole decimal is an integer and a fractional one is not - and
        // the two failures differ: a string gets `int_parsing`, a float
        // gets `int_from_float`.
        assert_eq!(read(json!("3.0")), Ok(3));
        assert_eq!(read(json!(3.0)), Ok(3));
        assert_eq!(
            read(json!("3.5")).unwrap_err()["type"],
            json!("int_parsing")
        );
        assert_eq!(
            read(json!(3.5)).unwrap_err()["type"],
            json!("int_from_float")
        );
        // `True` is one, as it is to Python.
        assert_eq!(read(json!(true)), Ok(1));
        assert_eq!(read(json!(false)), Ok(0));
        // A non-ASCII digit is a digit to `int()` and not to pydantic.
        assert_eq!(
            read(json!("\u{6f3}")).unwrap_err()["type"],
            json!("int_parsing")
        );
        // A missing field is not an error; an explicit null is.
        assert_eq!(read_int_entry("f", None), Ok(None));
        assert_eq!(
            read_int_entry("f", Some(&json!(null))).unwrap_err()["type"],
            json!("int_type")
        );
    }

    /// An integer larger than this machine can hold is still an integer.
    ///
    /// pydantic has no bound, so it accepts one; every caller here uses the
    /// result as a row id, and a saturated one matches no row - which is
    /// the same 404 the Python reaches by looking the real value up.
    #[test]
    fn an_integer_too_large_to_hold_saturates_rather_than_failing() {
        assert_eq!(
            read_int_entry("f", Some(&json!(9223372036854775808u64))),
            Ok(Some(i64::MAX))
        );
        assert_eq!(
            read_int_entry("f", Some(&json!("99999999999999999999"))),
            Ok(Some(i64::MAX))
        );
        assert_eq!(
            read_int_entry("f", Some(&json!("-99999999999999999999"))),
            Ok(Some(i64::MIN))
        );
    }

    #[test]
    fn a_whole_second_loses_its_microseconds() {
        // isoformat() omits them; emitting .000000 is a difference on every
        // row that lands on a whole second.
        assert_eq!(
            iso_datetime(Some("2026-09-17 17:07:20.000000")),
            json!("2026-09-17T17:07:20")
        );
        assert_eq!(
            iso_datetime(Some("2026-09-17 17:07:20")),
            json!("2026-09-17T17:07:20")
        );
    }

    #[test]
    fn a_fractional_second_keeps_them() {
        assert_eq!(
            iso_datetime(Some("2026-09-17 17:07:20.123456")),
            json!("2026-09-17T17:07:20.123456")
        );
    }

    #[test]
    fn a_missing_timestamp_is_null() {
        assert_eq!(iso_datetime(None), Value::Null);
        assert_eq!(iso_datetime(Some("")), Value::Null);
        assert_eq!(iso_datetime(Some("   ")), Value::Null);
    }

    #[test]
    fn only_the_first_space_becomes_a_t() {
        // Defensive: a value with trailing text must not have every space
        // rewritten into the middle of a timestamp.
        assert_eq!(
            iso_datetime(Some("2026-09-17 17:07:20 UTC")),
            json!("2026-09-17T17:07:20 UTC")
        );
    }

    #[test]
    fn a_range_check_names_the_bound_that_failed() {
        assert!(check_range("website_limit", 5, 0, 1000).is_ok());
        assert!(check_range("website_limit", 0, 0, 1000).is_ok());
        assert!(check_range("website_limit", 1000, 0, 1000).is_ok());
        assert!(check_range("website_limit", -1, 0, 1000).is_err());
        assert!(check_range("website_limit", 1001, 0, 1000).is_err());
    }

    #[test]
    fn a_value_errors_ctx_holds_an_empty_object_not_the_message() {
        // `ctx.error` is the exception object, which FastAPI's encoder renders
        // as {}. The message belongs in `msg` and appears nowhere else.
        let resp = value_error("name", "name is required", &json!("   "));
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn a_length_check_counts_characters_not_bytes() {
        // "Gói cơ bản" is 10 characters and more bytes than that.
        assert!(check_length("name", "Gói cơ bản", 1, 10).is_ok());
        assert!(check_length("name", "", 1, 100).is_err());
    }

    /// Every value pydantic was asked about, and what it said.
    ///
    /// This is a body field, so lax mode applies: the strings and the two
    /// integers are booleans. What makes it worth a corpus rather than a
    /// reading of the documentation is the shape of the refusals — `2` and
    /// `"01"` are `bool_parsing`, `null` and `0.5` are `bool_type`, and the
    /// panel's error box shows the message.
    #[test]
    fn a_body_bool_is_read_the_way_pydantic_reads_it() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/pydantic_bool.json");
        let corpus: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("the bool corpus"))
                .expect("the corpus parses");
        let cases = corpus["cases"].as_array().expect("the cases");
        assert_eq!(cases.len(), 43, "the corpus changed size");

        let mut failures: Vec<String> = Vec::new();
        let mut accepted = 0usize;
        let mut parsing = 0usize;
        let mut wrong_type = 0usize;
        for case in cases {
            let input = &case["input"];
            let got = read_bool("enabled", Some(input), true);
            match (case.get("value").and_then(Value::as_bool), &case["error"]) {
                (Some(want), _) => {
                    accepted += 1;
                    match got {
                        Ok(flag) if flag == want => {}
                        Ok(flag) => failures.push(format!("{input}: python {want}, rust {flag}")),
                        Err(_) => failures.push(format!("{input}: python {want}, rust refused")),
                    }
                }
                (None, error) => {
                    let want_type = error["type"].as_str().unwrap_or("");
                    match want_type {
                        "bool_parsing" => parsing += 1,
                        "bool_type" => wrong_type += 1,
                        other => failures.push(format!("{input}: unexpected {other}")),
                    }
                    match got {
                        Ok(flag) => {
                            failures.push(format!("{input}: python refused, rust {flag}"));
                        }
                        Err(response) => {
                            let body = body_type_of(response);
                            if body != want_type {
                                failures.push(format!("{input}: python {want_type}, rust {body}"));
                            }
                        }
                    }
                }
            }
        }
        assert!(
            failures.is_empty(),
            "{} of {} disagree:\n{}",
            failures.len(),
            cases.len(),
            failures.join("\n")
        );
        assert!(accepted >= 25, "only {accepted} accepted");
        assert!(parsing >= 8, "only {parsing} were bool_parsing");
        assert!(wrong_type >= 4, "only {wrong_type} were bool_type");

        // A field the body leaves out takes the default; `null` does not.
        assert_eq!(read_bool("enabled", None, true).ok(), Some(true));
        assert_eq!(read_bool("enabled", None, false).ok(), Some(false));
        assert!(read_bool("enabled", Some(&Value::Null), true).is_err());
    }

    /// The `type` of the single error a refusal carries.
    fn body_type_of(response: Response) -> String {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");
        let bytes = runtime
            .block_on(axum::body::to_bytes(response.into_body(), 64 * 1024))
            .expect("the body");
        let parsed: Value = serde_json::from_slice(&bytes).expect("the body parses");
        parsed["detail"][0]["type"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}
