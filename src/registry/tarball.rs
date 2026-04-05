use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use tar::Archive;
use tempfile::TempDir;

/// Download a `.tgz` tarball from `tarball_url`, extract it into `dest`, and
/// return the path to the top-level package directory inside the extraction.
///
/// npm tarballs conventionally contain a single top-level directory called
/// `package/`.  We return that inner directory so callers can work with it
/// directly.
pub async fn download_and_extract(tarball_url: &str, dest: &Path) -> Result<PathBuf> {
    tracing::info!(url = %tarball_url, "downloading tarball");

    let client = reqwest::Client::builder()
        .user_agent(concat!("aegis-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build HTTP client")?;

    let response = client
        .get(tarball_url)
        .send()
        .await
        .with_context(|| format!("failed to download tarball from {tarball_url}"))?;

    if !response.status().is_success() {
        anyhow::bail!("tarball download returned HTTP {}", response.status());
    }

    let bytes = response
        .bytes()
        .await
        .context("failed to read tarball bytes")?;

    tracing::debug!(bytes = bytes.len(), "tarball downloaded, extracting");

    // Decompress gzip, then untar — with path-traversal protection.
    let gz = GzDecoder::new(bytes.as_ref());
    let mut archive = Archive::new(gz);
    safe_unpack(&mut archive, dest).context("failed to extract tarball")?;

    // npm tarballs almost always contain a single `package/` directory at the
    // root.  Walk the destination to find it; fall back to `dest` itself.
    let package_dir = find_package_dir(dest)?;

    tracing::info!(path = %package_dir.display(), "extraction complete");
    Ok(package_dir)
}

/// Convenience wrapper that creates its own temp directory, extracts there,
/// and returns `(TempDir, PathBuf)`.  The caller must hold on to the `TempDir`
/// handle to keep the directory alive.
pub async fn download_and_extract_temp(tarball_url: &str) -> Result<(TempDir, PathBuf)> {
    let tmp = TempDir::new().context("failed to create temp directory")?;
    let package_dir = download_and_extract(tarball_url, tmp.path()).await?;
    Ok((tmp, package_dir))
}

/// Locate the top-level directory inside an extracted npm tarball.
fn find_package_dir(dest: &Path) -> Result<PathBuf> {
    let entries: Vec<_> = std::fs::read_dir(dest)
        .context("failed to read extraction directory")?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
        .collect();

    // Prefer a directory literally named "package" (the npm convention).
    if let Some(pkg) = entries.iter().find(|e| e.file_name() == "package") {
        return Ok(pkg.path());
    }

    // Otherwise fall back to the first (and presumably only) directory.
    if let Some(first) = entries.into_iter().next() {
        return Ok(first.path());
    }

    // If there are no subdirectories at all, just use dest.
    Ok(dest.to_path_buf())
}

// ---------------------------------------------------------------------------
// Safe extraction
// ---------------------------------------------------------------------------

/// Returns `true` if a tar entry path contains any `..` component, which could
/// be used to escape the extraction directory (path-traversal attack).
fn has_parent_dir_component(path: &Path) -> bool {
    path.components().any(|c| matches!(c, Component::ParentDir))
}

/// Extract a tar archive entry-by-entry, skipping any entry whose path
/// contains `..` components that would escape the destination directory.
fn safe_unpack<R: std::io::Read>(archive: &mut Archive<R>, dest: &Path) -> Result<()> {
    for entry_result in archive.entries().context("failed to read tar entries")? {
        let mut entry = entry_result.context("failed to read tar entry")?;
        let entry_path = entry
            .path()
            .context("failed to read entry path")?
            .into_owned();

        // Reject entries with `..` components.
        if has_parent_dir_component(&entry_path) {
            tracing::warn!(
                path = %entry_path.display(),
                "skipping tar entry with path-traversal component (\"..\")"
            );
            continue;
        }

        // Double-check: the resolved destination must stay within `dest`.
        let full_dest = dest.join(&entry_path);
        // Use a normalising check that doesn't require the path to exist yet.
        if !normalised_starts_with(&full_dest, dest) {
            tracing::warn!(
                path = %entry_path.display(),
                "skipping tar entry that resolves outside the extraction directory"
            );
            continue;
        }

        entry
            .unpack_in(dest)
            .with_context(|| format!("failed to extract entry: {}", entry_path.display()))?;
    }
    Ok(())
}

/// Check that `child` (which may not exist on disk yet) is logically inside
/// `parent` after normalising away any `.` or redundant separators.  This
/// intentionally does NOT resolve symlinks so it works before extraction.
fn normalised_starts_with(child: &Path, parent: &Path) -> bool {
    let normalise = |p: &Path| -> PathBuf {
        p.components().fold(PathBuf::new(), |mut acc, c| {
            match c {
                Component::ParentDir => {
                    acc.pop();
                }
                Component::CurDir => {}
                other => acc.push(other),
            }
            acc
        })
    };
    normalise(child).starts_with(normalise(parent))
}

// ---------------------------------------------------------------------------
// File collection
// ---------------------------------------------------------------------------

/// File extensions we consider "JavaScript-family" source files.
const JS_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "ts"];

/// Recursively walk `dir` and collect all files whose extension is in
/// [`JS_EXTENSIONS`].
pub fn collect_js_files(dir: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    collect_js_files_inner(dir, &mut result);
    result
}

fn collect_js_files_inner(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(err) => {
            tracing::debug!(path = %dir.display(), %err, "skipping unreadable directory");
            return;
        }
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            // Skip node_modules — we only care about the package's own code.
            if path
                .file_name()
                .map(|n| n == "node_modules")
                .unwrap_or(false)
            {
                continue;
            }
            collect_js_files_inner(&path, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if JS_EXTENSIONS.contains(&ext) {
                out.push(path);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tar::{Builder, Header};

    /// Helper: build a `.tar.gz` in memory containing the given `(path, content)` entries.
    /// Uses the tar `Builder` which validates paths (no `..` allowed).
    fn build_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = Builder::new(&mut tar_bytes);
            for &(path, data) in entries {
                let mut header = Header::new_gnu();
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, path, data).unwrap();
            }
            builder.finish().unwrap();
        }

        let mut gz_bytes = Vec::new();
        {
            let mut encoder = GzEncoder::new(&mut gz_bytes, Compression::fast());
            encoder.write_all(&tar_bytes).unwrap();
            encoder.finish().unwrap();
        }
        gz_bytes
    }

    /// Build a tar.gz with raw path names, bypassing the tar crate's path
    /// validation so we can craft malicious `..` entries for testing.
    fn build_tar_gz_raw(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_bytes: Vec<u8> = Vec::new();

        for &(name, data) in entries {
            // Build a 512-byte tar header manually (POSIX ustar-ish).
            let mut header = [0u8; 512];

            // name field: bytes 0..100
            let name_bytes = name.as_bytes();
            let copy_len = name_bytes.len().min(100);
            header[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

            // mode field: bytes 100..108  (octal ASCII, NUL terminated)
            header[100..107].copy_from_slice(b"0000644");

            // uid/gid: leave as zeros

            // size field: bytes 124..136  (octal ASCII)
            let size_str = format!("{:011o}", data.len());
            header[124..135].copy_from_slice(size_str.as_bytes());

            // mtime: bytes 136..148
            header[136..147].copy_from_slice(b"00000000000");

            // typeflag: byte 156, '0' = regular file
            header[156] = b'0';

            // magic: bytes 257..263 = "ustar\0"
            header[257..263].copy_from_slice(b"ustar\0");
            // version: bytes 263..265 = "00"
            header[263..265].copy_from_slice(b"00");

            // Compute checksum (bytes 148..156 treated as spaces during calc)
            header[148..156].copy_from_slice(b"        ");
            let cksum: u32 = header.iter().map(|&b| b as u32).sum();
            let cksum_str = format!("{:06o}\0 ", cksum);
            header[148..156].copy_from_slice(cksum_str.as_bytes());

            tar_bytes.extend_from_slice(&header);

            // Write file data, padded to 512-byte boundary.
            tar_bytes.extend_from_slice(data);
            let padding = (512 - (data.len() % 512)) % 512;
            tar_bytes.extend(std::iter::repeat_n(0u8, padding));
        }

        // Two 512-byte zero blocks mark end of archive.
        tar_bytes.extend(std::iter::repeat_n(0u8, 1024));

        let mut gz_bytes = Vec::new();
        {
            let mut encoder = GzEncoder::new(&mut gz_bytes, Compression::fast());
            encoder.write_all(&tar_bytes).unwrap();
            encoder.finish().unwrap();
        }
        gz_bytes
    }

    #[test]
    fn safe_unpack_normal_entries() {
        let gz = build_tar_gz(&[
            ("package/index.js", b"console.log('hi');"),
            ("package/lib/util.js", b"module.exports = {};"),
        ]);

        let tmp = tempfile::tempdir().unwrap();
        let gz_decoded = GzDecoder::new(gz.as_slice());
        let mut archive = Archive::new(gz_decoded);
        safe_unpack(&mut archive, tmp.path()).unwrap();

        assert!(tmp.path().join("package/index.js").exists());
        assert!(tmp.path().join("package/lib/util.js").exists());
    }

    #[test]
    fn safe_unpack_rejects_path_traversal() {
        let gz = build_tar_gz_raw(&[
            ("package/safe.js", b"ok"),
            ("../../evil.txt", b"malicious content"),
            ("package/../../../etc/passwd", b"root::0:0"),
        ]);

        let tmp = tempfile::tempdir().unwrap();
        let gz_decoded = GzDecoder::new(gz.as_slice());
        let mut archive = Archive::new(gz_decoded);
        safe_unpack(&mut archive, tmp.path()).unwrap();

        // The safe entry should be extracted.
        assert!(tmp.path().join("package/safe.js").exists());

        // The malicious entries must NOT exist — not inside or outside the dest.
        assert!(!tmp.path().join("evil.txt").exists());
        assert!(!tmp.path().join("etc/passwd").exists());

        // Also verify nothing was written above the temp directory.
        let parent = tmp.path().parent().unwrap();
        assert!(!parent.join("evil.txt").exists());
    }

    #[test]
    fn has_parent_dir_component_detects_traversal() {
        assert!(has_parent_dir_component(Path::new("../foo")));
        assert!(has_parent_dir_component(Path::new("a/../../b")));
        assert!(has_parent_dir_component(Path::new("a/..")));
        assert!(!has_parent_dir_component(Path::new("a/b/c")));
        assert!(!has_parent_dir_component(Path::new("package/index.js")));
    }
}
