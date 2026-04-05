//! Lightweight comment stripping for JavaScript/TypeScript source lines.
//!
//! This module provides a state-machine that tracks multiline `/* ... */`
//! comment blocks across lines and strips single-line `//` comments while
//! respecting string literals (single-quoted, double-quoted, and template
//! literals).  It intentionally does **not** use a full parser — it only needs
//! to be correct enough to prevent commented-out code from triggering pattern
//! matches.

/// Persistent state that must be carried across lines within a single file.
#[derive(Clone, Debug, Default)]
pub struct CommentState {
    /// `true` while we are inside an open `/* ... */` block.
    pub in_block_comment: bool,
}

/// Strip comments from `line`, mutating `state` to track multiline blocks.
///
/// Returns the portion of the line that is *outside* any comment.  The returned
/// string may be empty (the entire line was inside a block comment) or shorter
/// than the original (trailing `//` comment removed, etc.).
///
/// Performance: single pass over the bytes of the line — no allocations when
/// the line contains no comments at all (returns a slice via `Cow` semantics,
/// though we use a simple `String` here for clarity).
pub fn strip_comments(line: &str, state: &mut CommentState) -> String {
    let bytes = line.as_bytes();
    let len = bytes.len();

    // Fast path: if we are NOT in a block comment and the line contains
    // neither '/' nor '*' it cannot start or contain any comment.
    if !state.in_block_comment && !bytes.contains(&b'/') && !bytes.contains(&b'*') {
        return line.to_string();
    }

    let mut result = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        // --- inside a block comment: scan for closing */ ---
        if state.in_block_comment {
            if i + 1 < len && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                state.in_block_comment = false;
                i += 2; // skip past */
            } else {
                i += 1;
            }
            continue;
        }

        let ch = bytes[i];

        // --- string literals: copy verbatim until the closing quote ---
        if ch == b'"' || ch == b'\'' || ch == b'`' {
            let quote = ch;
            result.push(ch as char);
            i += 1;
            while i < len {
                let c = bytes[i];
                result.push(c as char);
                if c == b'\\' {
                    // escaped character — copy next byte too
                    i += 1;
                    if i < len {
                        result.push(bytes[i] as char);
                    }
                } else if c == quote {
                    break;
                }
                i += 1;
            }
            i += 1;
            continue;
        }

        // --- possible comment start ---
        if ch == b'/' && i + 1 < len {
            let next = bytes[i + 1];
            if next == b'/' {
                // single-line comment — rest of line is a comment
                break;
            }
            if next == b'*' {
                // block comment starts
                state.in_block_comment = true;
                i += 2;
                continue;
            }
        }

        // --- regular character ---
        result.push(ch as char);
        i += 1;
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn strip(line: &str) -> String {
        let mut state = CommentState::default();
        strip_comments(line, &mut state)
    }

    fn strip_multi(lines: &[&str]) -> Vec<String> {
        let mut state = CommentState::default();
        lines
            .iter()
            .map(|l| strip_comments(l, &mut state))
            .collect()
    }

    #[test]
    fn no_comment() {
        assert_eq!(strip("let x = 42;"), "let x = 42;");
    }

    #[test]
    fn single_line_comment() {
        assert_eq!(strip("let x = 1; // comment"), "let x = 1; ");
    }

    #[test]
    fn full_line_comment() {
        assert_eq!(strip("// this is a comment"), "");
    }

    #[test]
    fn inline_block_comment() {
        assert_eq!(strip("let x = /* hidden */ 1;"), "let x =  1;");
    }

    #[test]
    fn block_comment_to_end() {
        let mut state = CommentState::default();
        let r = strip_comments("let x = /* start", &mut state);
        assert_eq!(r, "let x = ");
        assert!(state.in_block_comment);
    }

    #[test]
    fn multiline_block_comment() {
        let results = strip_multi(&[
            "/* this is a",
            "   multiline comment",
            "   eval(dangerous) */",
            "let x = 1;",
        ]);
        assert_eq!(results[0], "");
        assert_eq!(results[1], "");
        assert_eq!(results[2], "");
        assert_eq!(results[3], "let x = 1;");
    }

    #[test]
    fn string_with_double_slash() {
        assert_eq!(
            strip(r#"let url = "http://example.com";"#),
            r#"let url = "http://example.com";"#
        );
    }

    #[test]
    fn string_with_block_comment_chars() {
        assert_eq!(
            strip(r#"let s = "/* not a comment */";"#),
            r#"let s = "/* not a comment */";"#
        );
    }

    #[test]
    fn single_quoted_string_with_comment() {
        assert_eq!(
            strip("let s = '// not a comment';"),
            "let s = '// not a comment';"
        );
    }

    #[test]
    fn template_literal_with_comment() {
        assert_eq!(
            strip("let s = `// not a comment`;"),
            "let s = `// not a comment`;"
        );
    }

    #[test]
    fn escaped_quote_in_string() {
        assert_eq!(
            strip(r#"let s = "he said \"// hi\""; // real comment"#),
            r#"let s = "he said \"// hi\""; "#
        );
    }

    #[test]
    fn hash_comment_not_stripped() {
        // We do not strip # comments — they are not JS comments.
        // The old is_comment_line checked for # but that is a shell thing;
        // in JS files # only appears in shebangs which are line 1.
        assert_eq!(strip("# this stays"), "# this stays");
    }

    #[test]
    fn block_comment_with_eval_inside() {
        let results = strip_multi(&[
            "/*",
            " * eval(something_dangerous)",
            " * new Function('bad')",
            " */",
            "console.log('safe');",
        ]);
        assert_eq!(results[0], "");
        assert_eq!(results[1], "");
        assert_eq!(results[2], "");
        assert_eq!(results[3], "");
        assert_eq!(results[4], "console.log('safe');");
    }

    #[test]
    fn regex_with_slash_not_confused() {
        // This is a tricky case. A regex like /foo/ looks like division.
        // We don't try to parse regexes — but this should at least not crash
        // or strip the line incorrectly.
        let r = strip("let re = /foo/;");
        assert_eq!(r, "let re = /foo/;");
    }
}
