/// Lowercase file extension of a request path (query string ignored), or `""`.
pub(crate) fn path_ext(path: &str) -> String {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let last = path.rsplit('/').next().unwrap_or_default();
    match last.rsplit_once('.') {
        Some((_, ext)) if !ext.is_empty() && ext.len() <= 8 => ext.to_ascii_lowercase(),
        _ => String::new(),
    }
}

pub(crate) const STATIC_EXTS: &[&str] = &[
    "js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "ico", "bmp",
    "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm", "mp3", "ogg", "wav",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext() {
        assert_eq!(path_ext("/a/b.JS?x=1.png"), "js");
        assert_eq!(path_ext("/a.b/c"), "");
        assert_eq!(path_ext("/"), "");
        assert_eq!(path_ext("/x.tar.gz"), "gz");
    }
}
