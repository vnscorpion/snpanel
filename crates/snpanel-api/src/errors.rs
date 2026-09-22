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

/// Source: `Field(min_length=..., max_length=...)`.
pub fn check_length(field: &str, value: &str, min: usize, max: usize) -> Result<(), Response> {
    // Characters, not bytes: Pydantic counts characters, so a name of accented
    // letters is measured the way the user sees it.
    let chars = value.chars().count();
    if chars < min {
        return Err(validation_error(vec![json!({
            "type": "string_too_short",
            "loc": ["body", field],
            "msg": format!("String should have at least {min} characters"),
            "input": value,
            "ctx": { "min_length": min },
        })]));
    }
    if chars > max {
        return Err(validation_error(vec![json!({
            "type": "string_too_long",
            "loc": ["body", field],
            "msg": format!("String should have at most {max} characters"),
            "input": value,
            "ctx": { "max_length": max },
        })]));
    }
    Ok(())
}

/// Source: `Field(ge=..., le=...)`.
pub fn check_range(field: &str, value: i64, min: i64, max: i64) -> Result<(), Response> {
    if value < min {
        return Err(validation_error(vec![json!({
            "type": "greater_than_equal",
            "loc": ["body", field],
            "msg": format!("Input should be greater than or equal to {min}"),
            "input": value,
            "ctx": { "ge": min },
        })]));
    }
    if value > max {
        return Err(validation_error(vec![json!({
            "type": "less_than_equal",
            "loc": ["body", field],
            "msg": format!("Input should be less than or equal to {max}"),
            "input": value,
            "ctx": { "le": max },
        })]));
    }
    Ok(())
}

/// Source: `int_parsing` - a value that is not an integer at all.
pub fn int_parsing(field: &str, input: &Value) -> Response {
    validation_error(vec![json!({
        "type": "int_parsing",
        "loc": ["body", field],
        "msg": "Input should be a valid integer, unable to parse string as an integer",
        "input": input,
    })])
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
pub fn read_bool(field: &str, value: Option<&Value>, default: bool) -> Result<bool, Response> {
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
                    _ => Err(bool_parsing(field, value)),
                }
            } else if let Some(f) = n.as_f64() {
                // A float is the wrong *kind* unless it is exactly 0 or 1.
                if f == 0.0 {
                    Ok(false)
                } else if f == 1.0 {
                    Ok(true)
                } else {
                    Err(bool_type(field, value))
                }
            } else {
                Err(bool_type(field, value))
            }
        }
        Value::String(text) => match text.to_lowercase().as_str() {
            "1" | "on" | "t" | "true" | "y" | "yes" => Ok(true),
            "0" | "off" | "f" | "false" | "n" | "no" => Ok(false),
            _ => Err(bool_parsing(field, value)),
        },
        _ => Err(bool_type(field, value)),
    }
}

/// `bool_type`: the value is not something a boolean can be read from.
pub fn bool_type(field: &str, input: &Value) -> Response {
    validation_error(vec![json!({
        "type": "bool_type",
        "loc": ["body", field],
        "msg": "Input should be a valid boolean",
        "input": input,
    })])
}

pub fn bool_parsing(field: &str, input: &Value) -> Response {
    validation_error(vec![json!({
        "type": "bool_parsing",
        "loc": ["body", field],
        "msg": "Input should be a valid boolean, unable to interpret input",
        "input": input,
    })])
}

pub fn string_type(field: &str, input: &Value) -> Response {
    validation_error(vec![json!({
        "type": "string_type",
        "loc": ["body", field],
        "msg": "Input should be a valid string",
        "input": input,
    })])
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
pub fn value_error(field: &str, message: &str, input: &Value) -> Response {
    validation_error(vec![json!({
        "type": "value_error",
        "loc": ["body", field],
        "msg": format!("Value error, {message}"),
        "input": input,
        "ctx": { "error": {} },
    })])
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
