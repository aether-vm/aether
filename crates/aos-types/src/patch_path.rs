//! Path validation for patches exported from untrusted sandboxes.
//!
//! A sandbox hands back a *set of tree changes* ([`PatchSet`]); before any of it is applied to a
//! host-side tree the paths and entry kinds must pass [`PatchPathValidator`]. The validator
//! rejects:
//!
//! * empty / over-long paths and components, NUL bytes, absolute paths, backslashes,
//!   non-canonical components (`.`, `..`, empty);
//! * every spelling of `.git` (case, trailing dots/spaces, NTFS `GIT~1`, NTFS alternate data
//!   streams, HFS+ ignorable code points) at **any** depth;
//! * Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM0-9`, `LPT0-9`, including
//!   the superscript digits `¹²³`) and reserved characters (`<>:"|?*`, control chars) [cross-platform];
//! * Gitlinks (submodules) unless the exact path is explicitly allowed;
//! * duplicate entries;
//! * symlinks that escape the tree, point into `.git`, or *are* `.gitmodules`, and any entry whose
//!   path traverses a symlink created by the same patch (or already present in the base tree);
//! * case-folding / Unicode-NFD collisions inside the patch **and** against the base tree
//!   (a pure case rename that removes the old spelling is allowed; collisions that already exist in
//!   the base tree and are not touched by the patch are not blamed on the patch).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Bound;

use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

use crate::untrusted::Validator;

/// Maximum accepted total path length in bytes (`PATH_MAX`).
pub const MAX_PATH_BYTES: usize = 4096;
/// Maximum accepted single path component length in bytes (`NAME_MAX`).
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Which filesystems the patch must be safe to materialise on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathPolicy {
    /// Linux-only consumers: byte-exact names; only structural attacks and exact `.git` are blocked.
    PosixOnly,
    /// (default) Also safe on Windows/NTFS and macOS (HFS+/APFS): reserved names/characters,
    /// `.git` aliases and case/Unicode folding collisions are blocked.
    #[default]
    CrossPlatform,
}

/// Kind of tree entry a patch creates or replaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// Regular file.
    File,
    /// Symbolic link with the given (untrusted) target.
    Symlink {
        /// Link target text.
        target: String,
    },
    /// Gitlink / submodule commit pointer.
    Gitlink,
}

/// Operation on one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchOp {
    /// Create or replace the entry at the path.
    Put(EntryKind),
    /// Delete the entry at the path.
    Remove,
}

/// One path + operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchEntry {
    /// Repository-relative, `/`-separated path.
    pub path: String,
    /// What to do at `path`.
    pub op: PatchOp,
}

impl PatchEntry {
    /// `Put(File)` at `path`.
    pub fn file(path: impl Into<String>) -> Self {
        Self { path: path.into(), op: PatchOp::Put(EntryKind::File) }
    }
    /// `Put(Symlink)` at `path`.
    pub fn symlink(path: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            op: PatchOp::Put(EntryKind::Symlink { target: target.into() }),
        }
    }
    /// `Put(Gitlink)` at `path`.
    pub fn gitlink(path: impl Into<String>) -> Self {
        Self { path: path.into(), op: PatchOp::Put(EntryKind::Gitlink) }
    }
    /// `Remove` at `path`.
    pub fn remove(path: impl Into<String>) -> Self {
        Self { path: path.into(), op: PatchOp::Remove }
    }
}

/// Unvalidated set of changes (wrap in `Untrusted` at the boundary).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PatchSet {
    /// All changes.
    pub entries: Vec<PatchEntry>,
}

/// A patch that passed [`PatchPathValidator`]; can only be built by it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPatch {
    entries: Vec<PatchEntry>,
}

impl ValidatedPatch {
    /// Validated entries.
    #[must_use]
    pub fn entries(&self) -> &[PatchEntry] {
        &self.entries
    }
    /// Consume into the entries.
    #[must_use]
    pub fn into_entries(self) -> Vec<PatchEntry> {
        self.entries
    }
}

/// Kind of a leaf in the (trusted) base tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseKind {
    /// Regular file.
    File,
    /// Symbolic link.
    Symlink,
    /// Gitlink.
    Gitlink,
}

/// The trusted tree a patch will be applied on (leaves only; directories are implied).
#[derive(Debug, Clone, Default)]
pub struct BaseTree {
    leaves: BTreeMap<String, BaseKind>,
    dirs: BTreeSet<String>,
}

impl BaseTree {
    /// Empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a leaf (parent directories are created implicitly).
    pub fn insert(&mut self, path: impl Into<String>, kind: BaseKind) {
        let path = path.into();
        let mut idx = 0;
        while let Some(pos) = path[idx..].find('/') {
            idx += pos;
            self.dirs.insert(path[..idx].to_owned());
            idx += 1;
        }
        self.leaves.insert(path, kind);
    }

    /// Build from `(path, kind)` pairs.
    pub fn from_entries<I, S>(iter: I) -> Self
    where
        I: IntoIterator<Item = (S, BaseKind)>,
        S: Into<String>,
    {
        let mut t = Self::new();
        for (p, k) in iter {
            t.insert(p, k);
        }
        t
    }

    /// Kind of the leaf at exactly `path`.
    #[must_use]
    pub fn leaf(&self, path: &str) -> Option<BaseKind> {
        self.leaves.get(path).copied()
    }

    fn leaves_under<'a>(&'a self, dir: &str) -> impl Iterator<Item = &'a String> + 'a {
        let lo = format!("{dir}/");
        let hi = format!("{dir}0"); // '0' == '/' + 1
        self.leaves
            .range::<str, _>((Bound::Included(lo.as_str()), Bound::Excluded(hi.as_str())))
            .map(|(k, _)| k)
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// Why a path/entry was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PatchPathViolation {
    /// Empty path.
    #[error("empty path")]
    Empty,
    /// Path longer than [`MAX_PATH_BYTES`].
    #[error("path too long ({len} > {max} bytes)")]
    PathTooLong {
        /// Observed length.
        len: usize,
        /// Maximum.
        max: usize,
    },
    /// A component longer than [`MAX_COMPONENT_BYTES`].
    #[error("path component too long ({len} > {max} bytes)")]
    ComponentTooLong {
        /// Observed length.
        len: usize,
        /// Maximum.
        max: usize,
    },
    /// NUL byte.
    #[error("NUL byte in path")]
    NulByte,
    /// Absolute path (leading `/` or drive letter).
    #[error("absolute path")]
    Absolute,
    /// Backslash.
    #[error("backslash in path")]
    Backslash,
    /// `.`, `..` or empty component.
    #[error("non-canonical path component {component:?}")]
    NonCanonical {
        /// The component.
        component: String,
    },
    /// Some spelling of `.git`.
    #[error("reserved .git component {component:?}")]
    DotGit {
        /// The component.
        component: String,
    },
    /// Windows reserved device name.
    #[error("Windows reserved device name {component:?}")]
    ReservedDeviceName {
        /// The component.
        component: String,
    },
    /// Windows reserved or control character.
    #[error("reserved character {ch:?}")]
    ReservedChar {
        /// The character.
        ch: char,
    },
    /// Component ends in `.` or space (NTFS strips it).
    #[error("component {component:?} ends with '.' or ' '")]
    TrailingDotOrSpace {
        /// The component.
        component: String,
    },
    /// Gitlink not on the allow-list.
    #[error("gitlink (submodule) not explicitly allowed")]
    GitlinkNotAllowed,
    /// Same path listed twice.
    #[error("duplicate entry")]
    DuplicateEntry,
    /// Malformed symlink target.
    #[error("invalid symlink target: {reason}")]
    SymlinkTargetInvalid {
        /// Reason.
        reason: &'static str,
    },
    /// Symlink target leaves the tree.
    #[error("symlink target {target:?} escapes the tree")]
    SymlinkEscape {
        /// The target.
        target: String,
    },
    /// Symlink target mentions `.git`.
    #[error("symlink target {target:?} points into .git")]
    SymlinkToDotGit {
        /// The target.
        target: String,
    },
    /// The symlink itself is named `.gitmodules`.
    #[error("symlinked .gitmodules")]
    SymlinkedGitmodules,
    /// The path goes through a symlink.
    #[error("path traverses symlink {symlink:?}")]
    PathThroughSymlink {
        /// The symlink being traversed.
        symlink: String,
    },
    /// A path is both a file and a directory.
    #[error("file/directory conflict with {other:?}")]
    FileDirectoryConflict {
        /// The conflicting path.
        other: String,
    },
    /// Two entries in the patch collide on a case-insensitive / normalising filesystem.
    #[error("case/Unicode-fold collision with {other:?} in the same patch")]
    FoldCollision {
        /// The colliding path.
        other: String,
    },
    /// An entry collides with an existing, untouched base-tree path.
    #[error("case/Unicode-fold collision with existing base path {existing:?}")]
    BaseCollision {
        /// Existing path.
        existing: String,
    },
}

/// A violation together with the offending path.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("rejected path {path:?}: {kind}")]
pub struct PatchPathError {
    /// The offending path (as supplied).
    pub path: String,
    /// What is wrong with it.
    pub kind: PatchPathViolation,
}

fn err(path: &str, kind: PatchPathViolation) -> PatchPathError {
    PatchPathError { path: path.to_owned(), kind }
}

/// HFS+ ignores these code points when comparing names (same list as git's `is_hfs_dotgit`).
fn is_hfs_ignorable(c: char) -> bool {
    matches!(c,
        '\u{200c}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}' | '\u{feff}')
}

/// NTFS/HFS+-style normalisation of a component for dot-file alias detection.
fn alias_normalize(component: &str) -> String {
    // NTFS alternate data streams: `.git::$INDEX_ALLOCATION`, `.git:foo`.
    let head = component.split(':').next().unwrap_or("");
    let stripped: String = head.chars().filter(|c| !is_hfs_ignorable(*c)).collect();
    stripped.trim_end_matches(['.', ' ']).to_lowercase()
}

fn is_short_name(normalized: &str, prefix: &str) -> bool {
    normalized
        .strip_prefix(prefix)
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
}

fn is_windows_reserved_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or("").trim_end_matches(' ');
    let up = stem.to_ascii_uppercase();
    if matches!(up.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") {
        return true;
    }
    for prefix in ["COM", "LPT"] {
        if let Some(rest) = up.strip_prefix(prefix) {
            let mut it = rest.chars();
            if let (Some(d), None) = (it.next(), it.next()) {
                if d.is_ascii_digit() || matches!(d, '\u{b9}' | '\u{b2}' | '\u{b3}') {
                    return true;
                }
            }
        }
    }
    false
}

fn fold_component(component: &str) -> String {
    let no_ignorable: String = component.chars().filter(|c| !is_hfs_ignorable(*c)).collect();
    let decomposed: String = no_ignorable.nfd().collect();
    let lowered = decomposed.to_lowercase();
    lowered.nfd().collect()
}

#[derive(Debug, Clone)]
struct BaseIndex {
    tree: BaseTree,
    /// fold key -> [(exact path, is_dir)]
    fold: HashMap<String, Vec<(String, bool)>>,
}

/// Validates the paths and entry kinds of a [`PatchSet`].
#[derive(Debug, Clone)]
pub struct PatchPathValidator {
    policy: PathPolicy,
    allowed_gitlinks: BTreeSet<String>,
    base: Option<BaseIndex>,
}

impl Default for PatchPathValidator {
    fn default() -> Self {
        Self::new(PathPolicy::CrossPlatform)
    }
}

impl PatchPathValidator {
    /// New validator with the given policy, no allowed gitlinks and no base tree.
    #[must_use]
    pub fn new(policy: PathPolicy) -> Self {
        Self { policy, allowed_gitlinks: BTreeSet::new(), base: None }
    }

    /// Explicitly allow a gitlink at exactly `path`.
    #[must_use]
    pub fn allow_gitlink(mut self, path: impl Into<String>) -> Self {
        self.allowed_gitlinks.insert(path.into());
        self
    }

    /// Check collisions against this base tree as well (policy must already be final).
    #[must_use]
    pub fn with_base_tree(mut self, tree: BaseTree) -> Self {
        let mut fold: HashMap<String, Vec<(String, bool)>> = HashMap::new();
        for p in tree.leaves.keys() {
            fold.entry(self.fold_path(p)).or_default().push((p.clone(), false));
        }
        for d in &tree.dirs {
            fold.entry(self.fold_path(d)).or_default().push((d.clone(), true));
        }
        self.base = Some(BaseIndex { tree, fold });
        self
    }

    /// Active policy.
    #[must_use]
    pub fn policy(&self) -> PathPolicy {
        self.policy
    }

    fn cross(&self) -> bool {
        self.policy == PathPolicy::CrossPlatform
    }

    fn fold_path(&self, path: &str) -> String {
        if self.cross() {
            path.split('/').map(fold_component).collect::<Vec<_>>().join("/")
        } else {
            path.to_owned()
        }
    }

    fn is_dotgit(&self, component: &str) -> bool {
        if self.cross() {
            let n = alias_normalize(component);
            n == ".git" || is_short_name(&n, "git~")
        } else {
            component == ".git"
        }
    }

    fn is_gitmodules(&self, component: &str) -> bool {
        if self.cross() {
            let n = alias_normalize(component);
            n == ".gitmodules" || is_short_name(&n, "gitmod~")
        } else {
            component == ".gitmodules"
        }
    }

    /// Purely syntactic check of one path; returns its components.
    pub fn check_path_syntax<'a>(&self, path: &'a str) -> Result<Vec<&'a str>, PatchPathError> {
        if path.is_empty() {
            return Err(err(path, PatchPathViolation::Empty));
        }
        if path.len() > MAX_PATH_BYTES {
            return Err(err(
                path,
                PatchPathViolation::PathTooLong { len: path.len(), max: MAX_PATH_BYTES },
            ));
        }
        if path.contains('\0') {
            return Err(err(path, PatchPathViolation::NulByte));
        }
        if path.starts_with('/') {
            return Err(err(path, PatchPathViolation::Absolute));
        }
        if path.contains('\\') {
            return Err(err(path, PatchPathViolation::Backslash));
        }
        let cross = self.cross();
        if cross {
            let b = path.as_bytes();
            if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
                return Err(err(path, PatchPathViolation::Absolute));
            }
        }
        let comps: Vec<&str> = path.split('/').collect();
        for c in &comps {
            if c.is_empty() || *c == "." || *c == ".." {
                return Err(err(
                    path,
                    PatchPathViolation::NonCanonical { component: (*c).to_owned() },
                ));
            }
            if c.len() > MAX_COMPONENT_BYTES {
                return Err(err(
                    path,
                    PatchPathViolation::ComponentTooLong { len: c.len(), max: MAX_COMPONENT_BYTES },
                ));
            }
            if self.is_dotgit(c) {
                return Err(err(path, PatchPathViolation::DotGit { component: (*c).to_owned() }));
            }
            if cross {
                if let Some(ch) = c.chars().find(|ch| {
                    matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*')
                        || (*ch as u32) < 0x20
                        || *ch == '\u{7f}'
                }) {
                    return Err(err(path, PatchPathViolation::ReservedChar { ch }));
                }
                if c.ends_with('.') || c.ends_with(' ') {
                    return Err(err(
                        path,
                        PatchPathViolation::TrailingDotOrSpace { component: (*c).to_owned() },
                    ));
                }
                if is_windows_reserved_name(c) {
                    return Err(err(
                        path,
                        PatchPathViolation::ReservedDeviceName { component: (*c).to_owned() },
                    ));
                }
            }
        }
        Ok(comps)
    }

    fn check_entry_kind(&self, entry: &PatchEntry, comps: &[&str]) -> Result<(), PatchPathError> {
        let path = entry.path.as_str();
        match &entry.op {
            PatchOp::Remove | PatchOp::Put(EntryKind::File) => Ok(()),
            PatchOp::Put(EntryKind::Gitlink) => {
                if self.allowed_gitlinks.contains(path) {
                    Ok(())
                } else {
                    Err(err(path, PatchPathViolation::GitlinkNotAllowed))
                }
            }
            PatchOp::Put(EntryKind::Symlink { target }) => {
                if comps.last().is_some_and(|c| self.is_gitmodules(c)) {
                    return Err(err(path, PatchPathViolation::SymlinkedGitmodules));
                }
                self.check_symlink_target(path, comps, target)
            }
        }
    }

    fn check_symlink_target(
        &self,
        path: &str,
        comps: &[&str],
        target: &str,
    ) -> Result<(), PatchPathError> {
        let invalid = |reason| err(path, PatchPathViolation::SymlinkTargetInvalid { reason });
        let escape = || err(path, PatchPathViolation::SymlinkEscape { target: target.to_owned() });
        if target.is_empty() {
            return Err(invalid("empty target"));
        }
        if target.contains('\0') {
            return Err(invalid("NUL byte in target"));
        }
        if target.len() > MAX_PATH_BYTES {
            return Err(invalid("target too long"));
        }
        if target.starts_with('/') {
            return Err(escape());
        }
        if self.cross() {
            if target.contains('\\') {
                return Err(invalid("backslash in target"));
            }
            let b = target.as_bytes();
            if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
                return Err(escape());
            }
        }
        let mut stack: Vec<&str> = comps[..comps.len() - 1].to_vec();
        for t in target.split('/') {
            if self.is_dotgit(t) {
                return Err(err(
                    path,
                    PatchPathViolation::SymlinkToDotGit { target: target.to_owned() },
                ));
            }
            match t {
                "" | "." => {}
                ".." => {
                    if stack.pop().is_none() {
                        return Err(escape());
                    }
                }
                other => stack.push(other),
            }
        }
        Ok(())
    }

    /// Validate every entry and the relations between them (and the base tree, if configured).
    pub fn validate_entries(&self, entries: &[PatchEntry]) -> Result<(), PatchPathError> {
        // 1. per-entry syntax, duplicates, entry-kind rules
        let mut parsed: Vec<(&PatchEntry, Vec<&str>)> = Vec::with_capacity(entries.len());
        let mut seen: HashSet<&str> = HashSet::with_capacity(entries.len());
        for e in entries {
            let comps = self.check_path_syntax(&e.path)?;
            if !seen.insert(e.path.as_str()) {
                return Err(err(&e.path, PatchPathViolation::DuplicateEntry));
            }
            self.check_entry_kind(e, &comps)?;
            parsed.push((e, comps));
        }

        let ops: HashMap<&str, &PatchOp> =
            parsed.iter().map(|(e, _)| (e.path.as_str(), &e.op)).collect();
        let removed: HashSet<&str> = parsed
            .iter()
            .filter(|(e, _)| e.op == PatchOp::Remove)
            .map(|(e, _)| e.path.as_str())
            .collect();

        // 2. no path may traverse a symlink (created by this patch, or existing in the base)
        let mut patch_symlinks: HashMap<String, &str> = HashMap::new();
        for (e, _) in &parsed {
            if matches!(e.op, PatchOp::Put(EntryKind::Symlink { .. })) {
                patch_symlinks.insert(self.fold_path(&e.path), e.path.as_str());
            }
        }
        for (e, comps) in &parsed {
            let mut prefix = String::new();
            for (i, c) in comps[..comps.len() - 1].iter().enumerate() {
                if i > 0 {
                    prefix.push('/');
                }
                prefix.push_str(c);
                let key = self.fold_path(&prefix);
                if let Some(link) = patch_symlinks.get(&key) {
                    return Err(err(
                        &e.path,
                        PatchPathViolation::PathThroughSymlink { symlink: (*link).to_owned() },
                    ));
                }
                if let Some(base) = &self.base {
                    for (q, is_dir) in base.fold.get(&key).into_iter().flatten() {
                        if !is_dir
                            && base.tree.leaf(q) == Some(BaseKind::Symlink)
                            && !ops.contains_key(q.as_str())
                        {
                            return Err(err(
                                &e.path,
                                PatchPathViolation::PathThroughSymlink { symlink: q.clone() },
                            ));
                        }
                    }
                }
            }
        }

        // 3. collisions and file/directory conflicts among the patch's own `Put`s
        let mut put_keys: HashMap<String, &str> = HashMap::new();
        for (e, _) in &parsed {
            if matches!(e.op, PatchOp::Put(_)) {
                if let Some(prev) = put_keys.insert(self.fold_path(&e.path), e.path.as_str()) {
                    return Err(err(
                        &e.path,
                        PatchPathViolation::FoldCollision { other: prev.to_owned() },
                    ));
                }
            }
        }
        for (e, comps) in &parsed {
            if !matches!(e.op, PatchOp::Put(_)) {
                continue;
            }
            let mut prefix = String::new();
            for (i, c) in comps[..comps.len() - 1].iter().enumerate() {
                if i > 0 {
                    prefix.push('/');
                }
                prefix.push_str(c);
                if let Some(other) = put_keys.get(&self.fold_path(&prefix)) {
                    return Err(err(
                        &e.path,
                        PatchPathViolation::FileDirectoryConflict { other: (*other).to_owned() },
                    ));
                }
            }
        }

        // 4. new entries against the base tree
        if let Some(base) = &self.base {
            for (e, comps) in &parsed {
                if !matches!(e.op, PatchOp::Put(_)) {
                    continue;
                }
                if base.tree.leaf(&e.path).is_some() {
                    // Modification of an existing leaf: it cannot introduce a *new* collision.
                    continue;
                }
                let key = self.fold_path(&e.path);
                for (q, is_dir) in base.fold.get(&key).into_iter().flatten() {
                    if *is_dir {
                        if base.tree.leaves_under(q).all(|l| removed.contains(l.as_str())) {
                            continue;
                        }
                        let kind = if *q == e.path {
                            PatchPathViolation::FileDirectoryConflict { other: q.clone() }
                        } else {
                            PatchPathViolation::BaseCollision { existing: q.clone() }
                        };
                        return Err(err(&e.path, kind));
                    }
                    if removed.contains(q.as_str()) {
                        continue; // pure rename: the old spelling is going away
                    }
                    return Err(err(
                        &e.path,
                        PatchPathViolation::BaseCollision { existing: q.clone() },
                    ));
                }
                let mut prefix = String::new();
                for (i, c) in comps[..comps.len() - 1].iter().enumerate() {
                    if i > 0 {
                        prefix.push('/');
                    }
                    prefix.push_str(c);
                    for (q, is_dir) in base.fold.get(&self.fold_path(&prefix)).into_iter().flatten()
                    {
                        if !is_dir && !removed.contains(q.as_str()) {
                            return Err(err(
                                &e.path,
                                PatchPathViolation::FileDirectoryConflict { other: q.clone() },
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl Validator<PatchSet> for PatchPathValidator {
    type Output = ValidatedPatch;
    type Error = PatchPathError;

    fn validate(&self, input: PatchSet) -> Result<ValidatedPatch, PatchPathError> {
        self.validate_entries(&input.entries)?;
        Ok(ValidatedPatch { entries: input.entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::untrusted::Untrusted;
    use super::PatchPathViolation as V;

    fn cross() -> PatchPathValidator {
        PatchPathValidator::new(PathPolicy::CrossPlatform)
    }
    fn posix() -> PatchPathValidator {
        PatchPathValidator::new(PathPolicy::PosixOnly)
    }
    fn kind_of(v: &PatchPathValidator, entries: &[PatchEntry]) -> Option<V> {
        v.validate_entries(entries).err().map(|e| e.kind)
    }
    fn files(paths: &[&str]) -> Vec<PatchEntry> {
        paths.iter().map(|p| PatchEntry::file(*p)).collect()
    }
    fn syntax_kind(v: &PatchPathValidator, p: &str) -> Option<V> {
        v.check_path_syntax(p).err().map(|e| e.kind)
    }

    #[test]
    fn t01_structural_rejections() {
        for v in [cross(), posix()] {
            assert_eq!(syntax_kind(&v, ""), Some(V::Empty));
            assert!(matches!(
                syntax_kind(&v, &"a/".repeat(2100)),
                Some(V::PathTooLong { .. })
            ));
            assert!(matches!(
                syntax_kind(&v, &format!("dir/{}", "x".repeat(256))),
                Some(V::ComponentTooLong { len: 256, max: 255 })
            ));
            assert!(syntax_kind(&v, &format!("dir/{}", "x".repeat(255))).is_none());
            assert_eq!(syntax_kind(&v, "a\0b"), Some(V::NulByte));
            assert_eq!(syntax_kind(&v, "/etc/passwd"), Some(V::Absolute));
            assert_eq!(syntax_kind(&v, "a\\b"), Some(V::Backslash));
            assert_eq!(syntax_kind(&v, "..\\..\\x"), Some(V::Backslash));
            for p in ["./a", "a/./b", "a/../b", "..", "../a", "a//b", "a/", "a/.."] {
                assert!(
                    matches!(syntax_kind(&v, p), Some(V::NonCanonical { .. })),
                    "{p:?} must be non-canonical"
                );
            }
        }
        assert_eq!(syntax_kind(&cross(), "C:/Windows/x"), Some(V::Absolute));
    }

    #[test]
    fn t02_accepts_ordinary_paths() {
        let ok = [
            "src/lib.rs",
            "README.md",
            ".gitignore",
            ".gitattributes",
            ".github/workflows/ci.yml",
            "a b/c d.txt",
            "git",
            "gitx",
            "foo.git",
            "dir/.hidden",
            "\u{4e2d}\u{6587}/\u{6587}\u{4ef6}.txt",
            "CONSOLE.txt",
            "COM10",
            "com",
            "lpt",
            ".gitmodules",
            "a/b/c/d/e/f/g",
        ];
        for p in ok {
            assert!(syntax_kind(&cross(), p).is_none(), "cross rejected {p:?}");
            assert!(syntax_kind(&posix(), p).is_none(), "posix rejected {p:?}");
        }
        assert!(cross().validate_entries(&files(&ok)).is_ok());
    }

    #[test]
    fn t03_dotgit_variants_cross_platform() {
        let bad = [
            ".git",
            ".GIT",
            ".Git",
            ".gIt/config",
            "a/.git/hooks/pre-commit",
            "a/b/.GIT",
            ".git.",
            ".git ",
            ".git. .",
            ".git...",
            "GIT~1",
            "git~1/config",
            "GIT~2",
            "x/Git~12",
            ".gi\u{200c}t",
            ".\u{200d}git",
            "\u{feff}.git",
            ".git\u{200e}",
            ".\u{202e}g\u{202c}it",
            ".\u{206a}git",
            ".git::$INDEX_ALLOCATION",
            ".git:stream",
        ];
        for p in bad {
            let k = syntax_kind(&cross(), p);
            assert!(
                matches!(k, Some(V::DotGit { .. })),
                "{p:?} must be DotGit, got {k:?}"
            );
        }
        for p in [".gitx", "x.git", ".gitt", ".gi", "git~", "git~a", ".git-keep", "gith~1"] {
            assert!(
                !matches!(syntax_kind(&cross(), p), Some(V::DotGit { .. })),
                "{p:?} wrongly flagged as .git"
            );
        }
    }

    #[test]
    fn t04_posix_policy_is_exact_and_lenient() {
        for p in [".git", "a/.git/config", "x/y/.git"] {
            assert!(matches!(syntax_kind(&posix(), p), Some(V::DotGit { .. })), "{p:?}");
        }
        // Valid byte-exact POSIX names that CrossPlatform refuses:
        for p in [".GIT", "GIT~1", "con", "NUL.txt", "a:b", "a?b", "trail.", "trail ", "x\u{1}y", ".git."] {
            assert!(syntax_kind(&posix(), p).is_none(), "posix must allow {p:?}");
            assert!(syntax_kind(&cross(), p).is_some(), "cross must reject {p:?}");
        }
        // structural attacks stay blocked under PosixOnly
        assert_eq!(syntax_kind(&posix(), "a\\b"), Some(V::Backslash));
        assert_eq!(syntax_kind(&posix(), "a\0"), Some(V::NulByte));
        assert_eq!(PatchPathValidator::default().policy(), PathPolicy::CrossPlatform);
    }

    #[test]
    fn t05_windows_reserved_device_names() {
        let bad = [
            "CON", "con", "Prn", "AUX", "nul", "con.txt", "NUL.tar.gz", "dir/aux.c", "COM0", "COM1",
            "com9", "LPT0", "lpt7", "LPT9.log", "COM\u{b9}", "com\u{b2}", "LPT\u{b3}.txt", "CONIN$",
            "conout$", "con .txt",
        ];
        for p in bad {
            let k = syntax_kind(&cross(), p);
            assert!(
                matches!(k, Some(V::ReservedDeviceName { .. })),
                "{p:?} must be a reserved device name, got {k:?}"
            );
        }
        for p in ["CON", "COM1", "lpt\u{b9}"] {
            assert!(syntax_kind(&posix(), p).is_none(), "posix allows {p:?}");
        }
    }

    #[test]
    fn t06_reserved_chars_and_trailing_dot_space() {
        for ch in ['<', '>', ':', '"', '|', '?', '*', '\u{1}', '\u{1f}', '\u{7f}', '\n', '\t'] {
            let p = format!("dir/a{ch}b");
            assert!(
                matches!(syntax_kind(&cross(), &p), Some(V::ReservedChar { .. })),
                "{p:?}"
            );
            assert!(syntax_kind(&posix(), &p).is_none(), "posix allows {p:?}");
        }
        for p in ["a.", "a ", "dir./file", "dir /file", "...", "a. ."] {
            assert!(
                matches!(syntax_kind(&cross(), p), Some(V::TrailingDotOrSpace { .. })),
                "{p:?}"
            );
        }
        assert!(syntax_kind(&cross(), "a.b").is_none());
    }

    #[test]
    fn t07_gitlink_requires_explicit_allowance() {
        let e = vec![PatchEntry::gitlink("vendor/lib")];
        assert_eq!(kind_of(&cross(), &e), Some(V::GitlinkNotAllowed));
        assert_eq!(kind_of(&posix(), &e), Some(V::GitlinkNotAllowed));
        let allowed = cross().allow_gitlink("vendor/lib");
        assert!(allowed.validate_entries(&e).is_ok());
        assert_eq!(
            kind_of(&allowed, &[PatchEntry::gitlink("vendor/other")]),
            Some(V::GitlinkNotAllowed)
        );
        assert_eq!(
            kind_of(&allowed, &[PatchEntry::gitlink("VENDOR/LIB")]),
            Some(V::GitlinkNotAllowed),
            "allow-list is exact"
        );
    }

    #[test]
    fn t08_duplicate_entries() {
        assert_eq!(
            kind_of(&cross(), &files(&["a/b", "c", "a/b"])),
            Some(V::DuplicateEntry)
        );
        assert_eq!(
            kind_of(&posix(), &[PatchEntry::remove("x"), PatchEntry::file("x")]),
            Some(V::DuplicateEntry)
        );
    }

    #[test]
    fn t09_symlink_target_rules() {
        let v = cross();
        let one = |p: &str, t: &str| kind_of(&v, &[PatchEntry::symlink(p, t)]);
        assert!(one("link", "target").is_none());
        assert!(one("a/link", "../x").is_none());
        assert!(one("a/b/link", "../../x").is_none());
        assert!(one("a/b/link", "sibling/./deep").is_none());
        assert!(matches!(one("link", "/etc/passwd"), Some(V::SymlinkEscape { .. })));
        assert!(matches!(one("link", "../x"), Some(V::SymlinkEscape { .. })));
        assert!(matches!(one("a/link", "../../x"), Some(V::SymlinkEscape { .. })));
        assert!(matches!(one("a/link", "b/../../../x"), Some(V::SymlinkEscape { .. })));
        assert!(matches!(one("link", "C:/Windows"), Some(V::SymlinkEscape { .. })));
        assert!(matches!(one("link", ""), Some(V::SymlinkTargetInvalid { .. })));
        assert!(matches!(one("link", "a\0b"), Some(V::SymlinkTargetInvalid { .. })));
        assert!(matches!(one("link", "a\\b"), Some(V::SymlinkTargetInvalid { .. })));
        // pointing into .git, in every spelling
        for t in [".git", ".git/config", "a/.git/hooks", "sub/../.GIT", "GIT~1", ".git.", ".gi\u{200c}t/x"] {
            assert!(
                matches!(one("a/link", t), Some(V::SymlinkToDotGit { .. })),
                "target {t:?}"
            );
        }
        assert!(
            matches!(
                kind_of(&posix(), &[PatchEntry::symlink("l", ".git/config")]),
                Some(V::SymlinkToDotGit { .. })
            )
        );
        // posix allows a backslash in a target (valid byte name)
        assert!(kind_of(&posix(), &[PatchEntry::symlink("l", "a\\b")]).is_none());
    }

    #[test]
    fn t10_symlinked_gitmodules() {
        for p in [".gitmodules", ".GITMODULES", "sub/.gitmodules", "GITMOD~1", ".gitmodules.", ".git\u{200b}modules"] {
            let k = kind_of(&cross(), &[PatchEntry::symlink(p, "target")]);
            // `.git\u{200b}modules` (ZERO WIDTH SPACE) is not HFS-ignorable => not an alias.
            if p.contains('\u{200b}') {
                assert!(k.is_none() || !matches!(k, Some(V::SymlinkedGitmodules)));
                continue;
            }
            assert!(
                matches!(k, Some(V::SymlinkedGitmodules) | Some(V::TrailingDotOrSpace { .. })),
                "{p:?}: {k:?}"
            );
        }
        assert_eq!(
            kind_of(&posix(), &[PatchEntry::symlink(".gitmodules", "x")]),
            Some(V::SymlinkedGitmodules)
        );
        // a regular .gitmodules file is fine
        assert!(kind_of(&cross(), &[PatchEntry::file(".gitmodules")]).is_none());
        assert_eq!(
            kind_of(&cross(), &[PatchEntry::symlink(".gitmodules", "x")]),
            Some(V::SymlinkedGitmodules)
        );
    }

    #[test]
    fn t11_path_through_symlink_created_by_patch() {
        let v = cross();
        let e = vec![PatchEntry::symlink("link", "dir"), PatchEntry::file("link/evil")];
        assert!(matches!(kind_of(&v, &e), Some(V::PathThroughSymlink { .. })));
        // order independent
        let e = vec![PatchEntry::file("link/a/b/evil"), PatchEntry::symlink("link", "dir")];
        assert!(matches!(kind_of(&v, &e), Some(V::PathThroughSymlink { .. })));
        // even deletions through the link
        let e = vec![PatchEntry::symlink("link", "dir"), PatchEntry::remove("link/x")];
        assert!(matches!(kind_of(&v, &e), Some(V::PathThroughSymlink { .. })));
        // case-insensitive FS: `LINK/x` is `link/x`
        let e = vec![PatchEntry::symlink("link", "dir"), PatchEntry::file("LINK/x")];
        assert!(matches!(kind_of(&v, &e), Some(V::PathThroughSymlink { .. })));
        assert!(kind_of(&posix(), &e).is_none(), "byte-exact fs: different name");
        // the symlink alone, and siblings, are fine
        let e = vec![PatchEntry::symlink("link", "dir"), PatchEntry::file("links/x")];
        assert!(kind_of(&v, &e).is_none());
    }

    #[test]
    fn t12_path_through_base_symlink() {
        let base = BaseTree::from_entries([
            ("bl", BaseKind::Symlink),
            ("d/inner", BaseKind::Symlink),
            ("f", BaseKind::File),
        ]);
        let v = cross().with_base_tree(base);
        assert!(matches!(
            kind_of(&v, &files(&["bl/x"])),
            Some(V::PathThroughSymlink { .. })
        ));
        assert!(matches!(
            kind_of(&v, &files(&["d/inner/x/y"])),
            Some(V::PathThroughSymlink { .. })
        ));
        assert!(matches!(
            kind_of(&v, &files(&["BL/x"])),
            Some(V::PathThroughSymlink { .. })
        ));
        // replacing the base symlink first (remove) makes the path ordinary again
        let e = vec![PatchEntry::remove("bl"), PatchEntry::file("bl/x")];
        assert!(kind_of(&v, &e).is_none());
        // unrelated stuff is untouched
        assert!(kind_of(&v, &files(&["d/other", "f"])).is_none());
    }

    #[test]
    fn t13_file_directory_conflicts_inside_patch() {
        let v = cross();
        assert!(matches!(
            kind_of(&v, &files(&["a", "a/b"])),
            Some(V::FileDirectoryConflict { .. })
        ));
        assert!(matches!(
            kind_of(&v, &files(&["a/b/c", "a/b"])),
            Some(V::FileDirectoryConflict { .. })
        ));
        assert!(matches!(
            kind_of(&v, &files(&["A", "a/b"])),
            Some(V::FileDirectoryConflict { .. })
        ));
        assert!(kind_of(&posix(), &files(&["A", "a/b"])).is_none());
        // replacing a (base) file by a directory is expressed with an explicit Remove
        let e = vec![PatchEntry::remove("a"), PatchEntry::file("a/b")];
        assert!(v.validate_entries(&e).is_ok());
        // gitlink is a leaf too
        let g = cross().allow_gitlink("m");
        assert!(matches!(
            kind_of(&g, &[PatchEntry::gitlink("m"), PatchEntry::file("m/x")]),
            Some(V::FileDirectoryConflict { .. })
        ));
    }

    #[test]
    fn t14_fold_collisions_inside_patch() {
        let v = cross();
        assert!(matches!(
            kind_of(&v, &files(&["README", "readme"])),
            Some(V::FoldCollision { .. })
        ));
        assert!(matches!(
            kind_of(&v, &files(&["Dir/File.TXT", "dir/file.txt"])),
            Some(V::FoldCollision { .. })
        ));
        // NFC vs NFD
        assert!(matches!(
            kind_of(&v, &files(&["caf\u{e9}", "cafe\u{301}"])),
            Some(V::FoldCollision { .. })
        ));
        // HFS+ ignorable code point
        assert!(matches!(
            kind_of(&v, &files(&["ab", "a\u{200c}b"])),
            Some(V::FoldCollision { .. })
        ));
        // KELVIN SIGN lower-cases to ASCII k
        assert!(matches!(
            kind_of(&v, &files(&["k", "\u{212a}"])),
            Some(V::FoldCollision { .. })
        ));
        // same directory spelled differently is fine when the leaf names differ
        assert!(kind_of(&v, &files(&["Dir/a", "dir/b"])).is_none());
        // byte-exact policy: all of the above are distinct names
        assert!(kind_of(&posix(), &files(&["README", "readme", "caf\u{e9}", "cafe\u{301}"])).is_none());
    }

    #[test]
    fn t15_collisions_against_base_tree() {
        let base = BaseTree::from_entries([
            ("Docs/Guide.md", BaseKind::File),
            ("Readme.md", BaseKind::File),
            ("caf\u{e9}.txt", BaseKind::File),
            ("Foo", BaseKind::File),
            ("A", BaseKind::File),
            ("a", BaseKind::File), // pre-existing conflict in the base tree
            ("src/main.rs", BaseKind::File),
        ]);
        let v = cross().with_base_tree(base);

        // new spelling that folds onto an untouched base path
        assert!(matches!(
            kind_of(&v, &files(&["docs/guide.md"])),
            Some(V::BaseCollision { existing }) if existing == "Docs/Guide.md"
        ));
        assert!(matches!(
            kind_of(&v, &files(&["cafe\u{301}.txt"])),
            Some(V::BaseCollision { .. })
        ));
        assert!(matches!(
            kind_of(&v, &files(&["README.md"])),
            Some(V::BaseCollision { .. })
        ));
        // base file `Foo` vs new directory `foo/`
        assert!(matches!(
            kind_of(&v, &files(&["foo/bar"])),
            Some(V::FileDirectoryConflict { .. })
        ));
        // base *directory* `Docs/` vs new file `docs`
        assert!(matches!(
            kind_of(&v, &files(&["docs"])),
            Some(V::BaseCollision { .. })
        ));

        // PURE CASE RENAME (old spelling removed) is allowed
        let rename = vec![PatchEntry::remove("Readme.md"), PatchEntry::file("README.md")];
        assert!(v.validate_entries(&rename).is_ok());
        let rename_nfd = vec![PatchEntry::remove("caf\u{e9}.txt"), PatchEntry::file("cafe\u{301}.txt")];
        assert!(v.validate_entries(&rename_nfd).is_ok());
        // ... but not if the old spelling is merely *added to*
        assert!(v.validate_entries(&files(&["README.md"])).is_err());

        // modifying an existing path is allowed even though the base has an old A/a conflict
        assert!(v.validate_entries(&files(&["A"])).is_ok());
        assert!(v.validate_entries(&files(&["a"])).is_ok());
        // unrelated, untouched pre-existing conflicts are not blamed on the patch
        assert!(v.validate_entries(&files(&["src/main.rs", "src/new.rs", "brand_new"])).is_ok());
        // directory-level case differences merge harmlessly on case-insensitive filesystems
        assert!(v.validate_entries(&files(&["docs/Other.md"])).is_ok());

        // under PosixOnly none of these folds apply
        let base = BaseTree::from_entries([("Docs/Guide.md", BaseKind::File)]);
        let p = posix().with_base_tree(base);
        assert!(p.validate_entries(&files(&["docs/guide.md"])).is_ok());
    }

    #[test]
    fn t16_dir_replace_requires_removing_all_children() {
        let base = BaseTree::from_entries([("dir/a", BaseKind::File), ("dir/b/c", BaseKind::File)]);
        let v = cross().with_base_tree(base);
        // file `dir` on top of a populated directory
        assert!(matches!(
            kind_of(&v, &files(&["dir"])),
            Some(V::FileDirectoryConflict { .. })
        ));
        let partial = vec![PatchEntry::remove("dir/a"), PatchEntry::file("dir")];
        assert!(v.validate_entries(&partial).is_err());
        let full = vec![
            PatchEntry::remove("dir/a"),
            PatchEntry::remove("dir/b/c"),
            PatchEntry::file("dir"),
        ];
        assert!(v.validate_entries(&full).is_ok());
    }

    #[test]
    fn t17_untrusted_pipeline_end_to_end() {
        let v = cross();
        let good = PatchSet { entries: files(&["src/a.rs", "src/b.rs"]) };
        let u = Untrusted::new(good.clone());
        assert_eq!(format!("{u:?}"), "Untrusted(<redacted>)");
        let validated = u.validate(&v).expect("valid patch");
        assert_eq!(validated.entries(), good.entries.as_slice());
        assert_eq!(validated.into_entries().len(), 2);

        let evil = PatchSet {
            entries: vec![PatchEntry::file("ok.txt"), PatchEntry::file("sub/.git/hooks/post-checkout")],
        };
        let e = Untrusted::new(evil).validate(&v).unwrap_err();
        assert_eq!(e.path, "sub/.git/hooks/post-checkout");
        assert!(matches!(e.kind, V::DotGit { .. }));
        assert!(e.to_string().contains("post-checkout"));
    }

    #[test]
    fn t18_remove_ops_are_path_checked_too() {
        assert!(matches!(
            kind_of(&cross(), &[PatchEntry::remove(".git/HEAD")]),
            Some(V::DotGit { .. })
        ));
        assert!(matches!(
            kind_of(&cross(), &[PatchEntry::remove("../outside")]),
            Some(V::NonCanonical { .. })
        ));
        assert!(kind_of(&cross(), &[PatchEntry::remove("obsolete.txt")]).is_none());
    }

    #[test]
    fn t19_empty_patch_and_large_valid_patch() {
        assert!(cross().validate_entries(&[]).is_ok());
        let many: Vec<PatchEntry> = (0..5000).map(|i| PatchEntry::file(format!("d{}/f{i}.txt", i % 50))).collect();
        assert!(cross().validate_entries(&many).is_ok());
    }
}
