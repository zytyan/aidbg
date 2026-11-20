use serde::Serialize;

#[derive(Clone, Serialize)]
pub(crate) struct Names {
    pub mangled_name: Option<String>,
    pub demangled_name: Option<String>,
    pub display_name: String,
}

pub(crate) fn names(raw: &str) -> Names {
    let demangled_name = cpp_demangle::Symbol::new(raw.as_bytes())
        .ok()
        .and_then(|symbol| symbol.demangle().ok());
    Names {
        mangled_name: demangled_name.as_ref().map(|_| raw.to_owned()),
        display_name: demangled_name
            .as_deref()
            .map(display)
            .unwrap_or_else(|| raw.to_owned()),
        demangled_name,
    }
}

fn template(text: &str) -> Option<(Vec<&str>, usize)> {
    let mut nesting = 0;
    let mut parentheses = 0;
    let mut start = 1;
    let mut args = Vec::new();
    for (index, c) in text.char_indices() {
        match c {
            '(' | '[' | '{' => parentheses += 1,
            ')' | ']' | '}' => parentheses -= 1,
            '<' if parentheses == 0 => nesting += 1,
            '>' if parentheses == 0 => {
                nesting -= 1;
                if nesting == 0 {
                    args.push(text[start..index].trim());
                    return Some((args, index + 1));
                }
            }
            ',' if nesting == 1 && parentheses == 0 => {
                args.push(text[start..index].trim());
                start = index + 1;
            }
            _ => (),
        }
    }
    None
}

fn alias(base: &str, args: &[String]) -> Option<String> {
    let first = args.first()?;
    let traits = format!("std::char_traits<{first}>");
    let allocator = format!("std::allocator<{first}>");
    let string = match first.as_str() {
        "char" => "string",
        "wchar_t" => "wstring",
        "char8_t" => "u8string",
        "char16_t" => "u16string",
        "char32_t" => "u32string",
        _ => "",
    };
    match (base, args) {
        ("basic_string", [_, t, a]) if !string.is_empty() && *t == traits && *a == allocator => {
            Some(format!("std::{string}"))
        }
        ("basic_string_view", [_, t]) if !string.is_empty() && *t == traits => {
            Some(format!("std::{string}_view"))
        }
        ("vector" | "list" | "deque" | "forward_list", [_, a]) if *a == allocator => {
            Some(format!("std::{base}<{first}>"))
        }
        ("unique_ptr", [_, d]) if *d == format!("std::default_delete<{first}>") => {
            Some(format!("std::{base}<{first}>"))
        }
        _ => None,
    }
}

fn display(name: &str) -> String {
    rewrite(name, 0)
}

fn rewrite(mut text: &str, depth: usize) -> String {
    if depth >= 32 {
        return text.to_owned();
    }
    let mut output = String::new();
    let mut boundary = true;
    while !text.is_empty() {
        let standard = boundary
            .then(|| {
                ["std::__cxx11::", "std::__1::", "std::__ndk1::", "std::"]
                    .into_iter()
                    .find_map(|prefix| text.strip_prefix(prefix))
            })
            .flatten();
        if let Some(tail) = standard {
            let end = tail
                .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .unwrap_or(tail.len());
            let base = &tail[..end];
            let rest = &tail[end..];
            if rest.starts_with('<')
                && let Some((args, size)) = template(rest)
            {
                let args: Vec<_> = args
                    .into_iter()
                    .map(|arg| rewrite(arg, depth + 1))
                    .collect();
                output.push_str(
                    &alias(base, &args)
                        .unwrap_or_else(|| format!("std::{base}<{}>", args.join(", "))),
                );
                text = &rest[size..];
            } else {
                output.push_str("std::");
                output.push_str(base);
                text = rest;
            }
            boundary = true;
        } else {
            let c = text.chars().next().expect("nonempty");
            output.push(c);
            text = &text[c.len_utf8()..];
            boundary = !c.is_alphanumeric() && c != '_' && c != ':';
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::display;

    #[test]
    fn aliases_standard_default_parameters_only() {
        for abi in ["__cxx11", "__1"] {
            let string = format!(
                "std::{abi}::basic_string<char, std::{abi}::char_traits<char>, std::{abi}::allocator<char> >"
            );
            assert_eq!(display(&string), "std::string");
            assert_eq!(
                display(&format!(
                    "f(std::{abi}::vector<{string}, std::{abi}::allocator<{string}> >)"
                )),
                "f(std::vector<std::string>)"
            );
        }
        assert_eq!(
            display("std::__1::basic_string<char, my::traits, my::allocator>"),
            "std::basic_string<char, my::traits, my::allocator>"
        );
        assert_eq!(
            display("my::std::__1::vector<int>"),
            "my::std::__1::vector<int>"
        );
    }
}
