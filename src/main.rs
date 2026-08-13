use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use rayon::prelude::*;
use serde::Serialize;
use walkdir::WalkDir;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HIGH_RUN: usize = 10;
const CRITICAL_RUN: usize = 40;
const SPARSE_HIGH_TOTAL: usize = 100;

const EXCLUDED_DIRS: &[&str] = &[".git"];

// File extensions likely to be ingested by AI harnesses (docs, prompts,
// configs, pipeline files). Restricting the scan to these types eliminates
// the vast majority of false positives from source code and vendored assets
// while keeping the attack surface AI modules actually read.
const AI_HARNESS_EXTS: &[&str] = &[
    "md", "markdown", "mdx",
    "txt", "text",
    "yaml", "yml",
    "toml",
    "config", "ini", "cfg", "conf", "env",
    "rst", "adoc",
];

// Well-known AI-harness rule/instruction files that live at the repo root or
// in tool-specific directories and typically have no standard extension.
// Matched by exact filename (case-insensitive).
const AI_HARNESS_FILENAMES: &[&str] = &[
    ".cursorrules",
    ".clinerules",
    ".windsurfrules",
    ".aiderignore",
    ".roomodes",
    ".continuerc",
    ".goosehints",
];

// ---------------------------------------------------------------------------
// Character classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CharType {
    Invisible,
    Tag,
    SpaceLike,
    Cc,
    Zs,
}

#[derive(Debug, Clone)]
struct CharFinding {
    ch: char,
    name: Cow<'static, str>,
    char_type: CharType,
    position: usize,
    decoded: Option<String>, // non-None only for Tag chars
}

/// Classify a codepoint. Returns (name, type, decoded) or None.
/// The compiler turns the `match` into an efficient dispatch (jump table / binary search).
fn classify_cp(cp: u32, opts: &ScanOptions) -> Option<(Cow<'static, str>, CharType, Option<String>)> {
    // --- Static table ---
    let s: Option<(&'static str, CharType)> = match cp {
        // Format controls / joiners
        0x034F => Some(("COMBINING GRAPHEME JOINER",   CharType::Invisible)),
        0x061C => Some(("ARABIC LETTER MARK",           CharType::Invisible)),
        0x180E => Some(("MONGOLIAN VOWEL SEPARATOR",    CharType::Invisible)),
        // Arabic number signs / format controls
        0x0600 => Some(("ARABIC NUMBER SIGN",           CharType::Invisible)),
        0x0601 => Some(("ARABIC SIGN SANAH",            CharType::Invisible)),
        0x0602 => Some(("ARABIC FOOTNOTE MARKER",       CharType::Invisible)),
        0x0603 => Some(("ARABIC SIGN SAFHA",            CharType::Invisible)),
        0x0604 => Some(("ARABIC SIGN SAMVAT",           CharType::Invisible)),
        0x0605 => Some(("ARABIC NUMBER MARK ABOVE",     CharType::Invisible)),
        0x0890 => Some(("ARABIC POUND MARK ABOVE",      CharType::Invisible)),
        0x0891 => Some(("ARABIC PIASTRE MARK ABOVE",    CharType::Invisible)),
        0x08E2 => Some(("ARABIC DISPUTED END OF AYAH",  CharType::Invisible)),
        // Zero-width
        0x200B => Some(("ZERO WIDTH SPACE",             CharType::Invisible)),
        0x200C => Some(("ZERO WIDTH NON-JOINER",        CharType::Invisible)),
        0x200D => Some(("ZERO WIDTH JOINER",            CharType::Invisible)),
        0x2060 => Some(("WORD JOINER",                  CharType::Invisible)),
        // Directional / bidi
        0x200E => Some(("LEFT-TO-RIGHT MARK",           CharType::Invisible)),
        0x200F => Some(("RIGHT-TO-LEFT MARK",           CharType::Invisible)),
        0x202A => Some(("LEFT-TO-RIGHT EMBEDDING",      CharType::Invisible)),
        0x202B => Some(("RIGHT-TO-LEFT EMBEDDING",      CharType::Invisible)),
        0x202C => Some(("POP DIRECTIONAL FORMATTING",   CharType::Invisible)),
        0x202D => Some(("LEFT-TO-RIGHT OVERRIDE",       CharType::Invisible)),
        0x202E => Some(("RIGHT-TO-LEFT OVERRIDE",       CharType::Invisible)),
        0x2066 => Some(("LEFT-TO-RIGHT ISOLATE",        CharType::Invisible)),
        0x2067 => Some(("RIGHT-TO-LEFT ISOLATE",        CharType::Invisible)),
        0x2068 => Some(("FIRST STRONG ISOLATE",         CharType::Invisible)),
        0x2069 => Some(("POP DIRECTIONAL ISOLATE",      CharType::Invisible)),
        // Line / paragraph separators
        0x2028 => Some(("LINE SEPARATOR",               CharType::Invisible)),
        0x2029 => Some(("PARAGRAPH SEPARATOR",          CharType::Invisible)),
        // Invisible math operators
        0x2061 => Some(("FUNCTION APPLICATION",         CharType::Invisible)),
        0x2062 => Some(("INVISIBLE TIMES",              CharType::Invisible)),
        0x2063 => Some(("INVISIBLE SEPARATOR",          CharType::Invisible)),
        0x2064 => Some(("INVISIBLE PLUS",               CharType::Invisible)),
        // Deprecated format controls
        0x206A => Some(("INHIBIT SYMMETRIC SWAPPING",   CharType::Invisible)),
        0x206B => Some(("ACTIVATE SYMMETRIC SWAPPING",  CharType::Invisible)),
        0x206C => Some(("INHIBIT ARABIC FORM SHAPING",  CharType::Invisible)),
        0x206D => Some(("ACTIVATE ARABIC FORM SHAPING", CharType::Invisible)),
        0x206E => Some(("NATIONAL DIGIT SHAPES",        CharType::Invisible)),
        0x206F => Some(("NOMINAL DIGIT SHAPES",         CharType::Invisible)),
        // Kaithi number signs
        0x110BD => Some(("KAITHI NUMBER SIGN",          CharType::Invisible)),
        0x110CD => Some(("KAITHI NUMBER SIGN ABOVE",    CharType::Invisible)),
        // Interlinear annotation
        0xFFF9 => Some(("INTERLINEAR ANNOTATION ANCHOR",    CharType::Invisible)),
        0xFFFA => Some(("INTERLINEAR ANNOTATION SEPARATOR", CharType::Invisible)),
        0xFFFB => Some(("INTERLINEAR ANNOTATION TERMINATOR",CharType::Invisible)),
        // BOM / ZWNBSP
        0xFEFF => Some(("ZERO WIDTH NO-BREAK SPACE",    CharType::Invisible)),
        // Variation selectors VS-1 through VS-16
        0xFE00 => Some(("VARIATION SELECTOR-1",  CharType::Invisible)),
        0xFE01 => Some(("VARIATION SELECTOR-2",  CharType::Invisible)),
        0xFE02 => Some(("VARIATION SELECTOR-3",  CharType::Invisible)),
        0xFE03 => Some(("VARIATION SELECTOR-4",  CharType::Invisible)),
        0xFE04 => Some(("VARIATION SELECTOR-5",  CharType::Invisible)),
        0xFE05 => Some(("VARIATION SELECTOR-6",  CharType::Invisible)),
        0xFE06 => Some(("VARIATION SELECTOR-7",  CharType::Invisible)),
        0xFE07 => Some(("VARIATION SELECTOR-8",  CharType::Invisible)),
        0xFE08 => Some(("VARIATION SELECTOR-9",  CharType::Invisible)),
        0xFE09 => Some(("VARIATION SELECTOR-10", CharType::Invisible)),
        0xFE0A => Some(("VARIATION SELECTOR-11", CharType::Invisible)),
        0xFE0B => Some(("VARIATION SELECTOR-12", CharType::Invisible)),
        0xFE0C => Some(("VARIATION SELECTOR-13", CharType::Invisible)),
        0xFE0D => Some(("VARIATION SELECTOR-14", CharType::Invisible)),
        0xFE0E => Some(("VARIATION SELECTOR-15", CharType::Invisible)),
        0xFE0F => Some(("VARIATION SELECTOR-16", CharType::Invisible)),
        _ => None,
    };
    if let Some((name, ctype)) = s {
        return Some((Cow::Borrowed(name), ctype, None));
    }

    // --- Optional: confusable spaces ---
    if opts.include_confusable_spaces {
        let cs: Option<&'static str> = match cp {
            0x00A0 => Some("NO-BREAK SPACE"),
            0x00AD => Some("SOFT HYPHEN"),
            0x2000 => Some("EN QUAD"),
            0x2001 => Some("EM QUAD"),
            0x2002 => Some("EN SPACE"),
            0x2003 => Some("EM SPACE"),
            0x2004 => Some("THREE-PER-EM SPACE"),
            0x2005 => Some("FOUR-PER-EM SPACE"),
            0x2006 => Some("SIX-PER-EM SPACE"),
            0x2007 => Some("FIGURE SPACE"),
            0x2008 => Some("PUNCTUATION SPACE"),
            0x2009 => Some("THIN SPACE"),
            0x200A => Some("HAIR SPACE"),
            0x202F => Some("NARROW NO-BREAK SPACE"),
            0x205F => Some("MEDIUM MATHEMATICAL SPACE"),
            0x2800 => Some("BRAILLE PATTERN BLANK"),
            0x3000 => Some("IDEOGRAPHIC SPACE"),
            0x3164 => Some("HANGUL FILLER"),
            0xFFA0 => Some("HALFWIDTH HANGUL FILLER"),
            _ => None,
        };
        if let Some(name) = cs {
            return Some((Cow::Borrowed(name), CharType::SpaceLike, None));
        }
    }

    // --- Range-based (only codepoints > U+2FFF reach here) ---
    if cp > 0x2FFF {
        // Unicode tags U+E0000–U+E007F
        if (0xE0000..=0xE007F).contains(&cp) {
            let decoded = decode_tag_cp(cp);
            return Some((Cow::Borrowed("UNICODE TAG"), CharType::Tag, Some(decoded)));
        }
        // Variation Selectors Supplement U+E0100–U+E01EF
        if (0xE0100..=0xE01EF).contains(&cp) {
            let n = cp - 0xE0100 + 17;
            return Some((Cow::Owned(format!("VARIATION SELECTOR-{n}")), CharType::Invisible, None));
        }
        // Musical symbol format controls U+1D173–U+1D17A
        if (0x1D173..=0x1D17A).contains(&cp) {
            let name: &'static str = match cp {
                0x1D173 => "MUSICAL SYMBOL BEGIN BEAM",
                0x1D174 => "MUSICAL SYMBOL END BEAM",
                0x1D175 => "MUSICAL SYMBOL BEGIN TIE",
                0x1D176 => "MUSICAL SYMBOL END TIE",
                0x1D177 => "MUSICAL SYMBOL BEGIN SLUR",
                0x1D178 => "MUSICAL SYMBOL END SLUR",
                0x1D179 => "MUSICAL SYMBOL BEGIN PHRASE",
                0x1D17A => "MUSICAL SYMBOL END PHRASE",
                _ => unreachable!(),
            };
            return Some((Cow::Borrowed(name), CharType::Invisible, None));
        }
        // Egyptian Hieroglyph Format Controls U+13430–U+1343F
        if (0x13430..=0x1343F).contains(&cp) {
            return Some((Cow::Owned(format!("EGYPTIAN HIEROGLYPH FORMAT U+{cp:05X}")), CharType::Invisible, None));
        }
        // Shorthand Format Controls U+1BCA0–U+1BCA3
        if (0x1BCA0..=0x1BCA3).contains(&cp) {
            let name: &'static str = match cp {
                0x1BCA0 => "SHORTHAND FORMAT LETTER OVERLAP",
                0x1BCA1 => "SHORTHAND FORMAT CONTINUING OVERLAP",
                0x1BCA2 => "SHORTHAND FORMAT DOWN STEP",
                0x1BCA3 => "SHORTHAND FORMAT UP STEP",
                _ => unreachable!(),
            };
            return Some((Cow::Borrowed(name), CharType::Invisible, None));
        }
    }

    // --- Optional: Cc control characters (U+0000–U+001F, U+007F–U+009F) ---
    if opts.include_cc
        && (cp <= 0x001F || (0x007F..=0x009F).contains(&cp))
        && !matches!(cp, 0x0009 | 0x000A | 0x000D)
    {
        return Some((Cow::Owned(format!("CONTROL CHARACTER U+{cp:04X}")), CharType::Cc, None));
    }

    // --- Optional: Zs space separators ---
    if opts.include_zs && cp != 0x0020 {
        let zs_name: Option<&'static str> = match cp {
            0x00A0 => Some("NO-BREAK SPACE"),
            0x1680 => Some("OGHAM SPACE MARK"),
            0x2000 => Some("EN QUAD"),
            0x2001 => Some("EM QUAD"),
            0x2002 => Some("EN SPACE"),
            0x2003 => Some("EM SPACE"),
            0x2004 => Some("THREE-PER-EM SPACE"),
            0x2005 => Some("FOUR-PER-EM SPACE"),
            0x2006 => Some("SIX-PER-EM SPACE"),
            0x2007 => Some("FIGURE SPACE"),
            0x2008 => Some("PUNCTUATION SPACE"),
            0x2009 => Some("THIN SPACE"),
            0x200A => Some("HAIR SPACE"),
            0x202F => Some("NARROW NO-BREAK SPACE"),
            0x205F => Some("MEDIUM MATHEMATICAL SPACE"),
            0x3000 => Some("IDEOGRAPHIC SPACE"),
            _ => None,
        };
        if let Some(name) = zs_name {
            return Some((Cow::Borrowed(name), CharType::Zs, None));
        }
    }

    None
}

fn decode_tag_cp(cp: u32) -> String {
    match cp {
        0xE0001 => "[TAG_START]".to_string(),
        0xE007F => "[TAG_END]".to_string(),
        0xE0020..=0xE007E => char::from_u32(cp - 0xE0000)
            .map(|c| c.to_string())
            .unwrap_or_default(),
        _ => format!("[TAG:{cp:#X}]"),
    }
}

// ---------------------------------------------------------------------------
// Binary file detection
// ---------------------------------------------------------------------------

const BINARY_EXTS: &[&str] = &[
    "png","jpg","jpeg","gif","ico","bmp","webp","tiff","tif",
    "pdf","doc","docx","xls","xlsx","ppt","pptx",
    "zip","tar","gz","bz2","xz","7z","rar","zst",
    "exe","dll","so","dylib","a","o","lib",
    "pyc","pyo","class","jar","war","ear","wasm",
    "bin","dat","db","sqlite","sqlite3",
    "mp3","mp4","mov","avi","mkv","webm","ogg","flac","wav",
    "ttf","otf","woff","woff2","eot",
];

const TEXT_EXTS: &[&str] = &[
    "py","pyi","pyw","js","jsx","mjs","cjs","ts","tsx",
    "rs","go","java","c","cpp","cc","cxx","c++","h","hpp","hh","hxx",
    "cs","vb","rb","php","sh","bash","zsh","fish","ksh","csh",
    "yaml","yml","toml","json","jsonl","ndjson","xml","html","htm","xhtml","xsl","xslt",
    "css","scss","sass","less","styl",
    "md","markdown","rst","txt","text","log","adoc",
    "sql","csv","tsv","svg","vue","svelte","elm","ex","exs",
    "hs","lhs","ml","mli","fs","fsx","fsi","kt","kts","swift","m","mm",
    "lua","pl","pm","r","jl","nim","zig","v","vhd","vhdl","verilog",
    "conf","cfg","ini","env","gitignore","gitattributes","dockerignore","editorconfig",
    "makefile","cmake","gradle","bazel","build",
    "lock","sum","mod",
];

/// Returns true if the file should be skipped as binary. None = read error.
fn is_binary(path: &Path) -> Option<bool> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_lowercase);

    if let Some(ref e) = ext {
        if TEXT_EXTS.contains(&e.as_str()) {
            return Some(false);
        }
        if BINARY_EXTS.contains(&e.as_str()) {
            return Some(true);
        }
    }

    // Fall back to null-byte sniff (512 bytes is sufficient)
    let mut buf = [0u8; 512];
    let mut f = fs::File::open(path).ok()?;
    let n = f.read(&mut buf).ok()?;
    Some(buf[..n].contains(&0))
}

// ---------------------------------------------------------------------------
// Scan options
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ScanOptions {
    include_cc: bool,
    include_zs: bool,
    include_confusable_spaces: bool,
    strict: bool,
}

/// Returns true if a file is considered relevant to AI-harness ingestion:
/// either its extension is in the allowlist, or its filename matches a
/// well-known AI-tool rule/instruction file.
fn is_ai_harness_ext(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if AI_HARNESS_EXTS.contains(&ext.to_ascii_lowercase().as_str()) {
            return true;
        }
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let lower = name.to_ascii_lowercase();
        if AI_HARNESS_FILENAMES.contains(&lower.as_str()) {
            return true;
        }
    }
    false
}

/// Returns true if a codepoint is in the emoji base character ranges.
/// Covers common emoji blocks in Unicode.
fn is_emoji_base(cp: u32) -> bool {
    matches!(cp,
        // Emoticons
        0x1F600..=0x1F64F |
        // Miscellaneous Symbols and Pictographs
        0x1F300..=0x1F5FF |
        // Transport and Map Symbols
        0x1F680..=0x1F6FF |
        // Supplemental Symbols and Pictographs
        0x1F900..=0x1F9FF |
        // Symbols and Pictographs Extended-A
        0x1FA70..=0x1FAFF |
        // Miscellaneous Symbols
        0x2600..=0x26FF |
        // Dingbats
        0x2700..=0x27BF |
        // Enclosed Alphanumeric Supplement (some emoji)
        0x1F100..=0x1F1FF |
        // Enclosed Ideographic Supplement
        0x1F200..=0x1F2FF |
        // Regional Indicator Symbols (flags)
        0x1F1E6..=0x1F1FF |
        // Mahjong Tiles, Domino Tiles
        0x1F000..=0x1F02F |
        // Playing Cards
        0x1F0A0..=0x1F0FF |
        // Additional commonly used emoji symbols
        0x231A..=0x231B |  // Watch, Hourglass
        0x2328 |           // Keyboard
        0x23CF |           // Eject
        0x23E9..=0x23F3 |  // Media controls
        0x23F8..=0x23FA |  // Media controls
        0x24C2 |           // Circled M
        0x25AA..=0x25AB |  // Squares
        0x25B6 |           // Play button
        0x25C0 |           // Reverse button
        0x25FB..=0x25FE |  // Squares
        0x2600..=0x2604 |  // Weather
        0x260E |           // Telephone
        0x2611 |           // Ballot box with check
        0x2614..=0x2615 |  // Umbrella, Hot beverage
        0x2618 |           // Shamrock
        0x261D |           // Pointing finger
        0x2620 |           // Skull and crossbones
        0x2622..=0x2623 |  // Radioactive, Biohazard
        0x2626 |           // Orthodox cross
        0x262A |           // Star and crescent
        0x262E..=0x262F |  // Peace, Yin yang
        0x2638..=0x263A |  // Wheel of dharma, Smiley
        0x2640 |           // Female sign
        0x2642 |           // Male sign
        0x2648..=0x2653 |  // Zodiac signs
        0x265F..=0x2660 |  // Chess pieces
        0x2663 |           // Club suit
        0x2665..=0x2666 |  // Heart, Diamond suits
        0x2668 |           // Hot springs
        0x267B |           // Recycling
        0x267E..=0x267F |  // Infinity, Wheelchair
        0x2692..=0x2697 |  // Hammer, Alembic
        0x2699 |           // Gear
        0x269B..=0x269C |  // Atom, Fleur-de-lis
        0x26A0..=0x26A1 |  // Warning, High voltage
        0x26A7 |           // Transgender symbol
        0x26AA..=0x26AB |  // Circles
        0x26B0..=0x26B1 |  // Coffin, Funeral urn
        0x26BD..=0x26BE |  // Soccer, Baseball
        0x26C4..=0x26C5 |  // Snowman, Sun
        0x26C8 |           // Thunder cloud and rain
        0x26CE |           // Ophiuchus
        0x26CF |           // Pick
        0x26D1 |           // Helmet
        0x26D3..=0x26D4 |  // Chains, No entry
        0x26E9..=0x26EA |  // Shinto shrine, Church
        0x26F0..=0x26F5 |  // Mountain, Sailboat
        0x26F7..=0x26FA |  // Skier, Tent
        0x26FD |           // Fuel pump
        0x2702 |           // Scissors
        0x2705 |           // Check mark
        0x2708..=0x2709 |  // Airplane, Envelope
        0x270A..=0x270B |  // Fist, Raised hand
        0x270C..=0x270D |  // Victory, Writing hand
        0x270F |           // Pencil
        0x2712 |           // Nib
        0x2714 |           // Check mark
        0x2716 |           // X mark
        0x271D |           // Latin cross
        0x2721 |           // Star of David
        0x2728 |           // Sparkles
        0x2733..=0x2734 |  // Eight-spoked asterisk
        0x2744 |           // Snowflake
        0x2747 |           // Sparkle
        0x274C |           // Cross mark
        0x274E |           // Cross mark button
        0x2753..=0x2755 |  // Question marks
        0x2757 |           // Exclamation mark
        0x2763..=0x2764 |  // Heart exclamation, Heavy heart
        0x2795..=0x2797 |  // Plus, Minus, Division
        0x27A1 |           // Right arrow
        0x27B0 |           // Curly loop
        0x27BF |           // Double curly loop
        0x2934..=0x2935 |  // Arrows
        0x2B05..=0x2B07 |  // Arrows
        0x2B1B..=0x2B1C |  // Squares
        0x2B50 |           // Star
        0x2B55 |           // Circle
        0x3030 |           // Wavy dash
        0x303D |           // Part alternation mark
        0x3297 |           // Circled ideograph congratulation
        0x3299             // Circled ideograph secret
    )
}

/// Returns true if a codepoint is an emoji modifier (skin tone, etc.)
fn is_emoji_modifier(cp: u32) -> bool {
    matches!(cp,
        0x1F3FB..=0x1F3FF  // Emoji skin tone modifiers (Type-1 through Type-6)
    )
}

/// Returns true if a flagged codepoint should be treated as benign in this
/// position. Now includes comprehensive emoji context detection:
///   - U+FEFF as the very first character of the file (UTF-8 BOM)
///   - U+FE0F (VS-16) after emoji base characters
///   - U+200D (ZWJ) after emoji base characters (for emoji sequences)
///   - Skin tone modifiers after emoji base characters
///   - Variation selectors after emoji base characters
fn is_benign(cp: u32, line_idx: usize, pos: usize, prev_cp: Option<u32>, _prev_flagged: bool) -> bool {
    // UTF-8 BOM at file start
    if cp == 0xFEFF && line_idx == 0 && pos == 0 {
        return true;
    }

    // Check if previous character exists and is an emoji base
    let prev_is_emoji = prev_cp.map_or(false, is_emoji_base);

    match cp {
        // Variation Selector-16 (emoji presentation) after emoji base
        0xFE0F => prev_is_emoji,

        // Zero-Width Joiner in emoji sequences (e.g., family, professions)
        // Only benign when following an emoji base
        0x200D => prev_is_emoji,

        // Emoji skin tone modifiers after emoji base
        0x1F3FB..=0x1F3FF => prev_is_emoji,

        // Other variation selectors (VS-1 through VS-15) after emoji
        // These are less common but can appear with some emoji
        0xFE00..=0xFE0E => prev_is_emoji,

        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Core file scanning
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LineFinding {
    line_num: usize,
    line: String,
    char_groups: Vec<Vec<CharFinding>>,
}

fn group_consecutive(mut findings: Vec<CharFinding>) -> Vec<Vec<CharFinding>> {
    if findings.is_empty() {
        return vec![];
    }
    // findings arrive in position order from the char enumeration — no sort needed
    let mut groups: Vec<Vec<CharFinding>> = Vec::new();
    let mut current = vec![findings.remove(0)];
    for f in findings {
        if f.position == current.last().unwrap().position + 1 {
            current.push(f);
        } else {
            groups.push(current);
            current = vec![f];
        }
    }
    groups.push(current);
    groups
}

fn scan_file(path: &Path, base: &Path, opts: &ScanOptions) -> Option<FileResult> {
    let bytes = fs::read(path).ok()?;
    let content = String::from_utf8_lossy(&bytes);
    let file_size = bytes.len() as u64;

    let rel = path
        .strip_prefix(base)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| {
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        });

    let mut findings: Vec<LineFinding> = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        let mut line_findings: Vec<CharFinding> = Vec::new();
        let mut prev_cp: Option<u32> = None;
        let mut prev_was_flagged = false;
        for (pos, ch) in line.chars().enumerate() {
            let cp = ch as u32;
            let classified = classify_cp(cp, opts);
            let mut flagged = false;
            if let Some((name, char_type, decoded)) = classified {
                let skip = !opts.strict && is_benign(cp, idx, pos, prev_cp, prev_was_flagged);
                if !skip {
                    line_findings.push(CharFinding { ch, name, char_type, position: pos, decoded });
                    flagged = true;
                }
            }
            prev_cp = Some(cp);
            prev_was_flagged = flagged;
        }
        if !line_findings.is_empty() {
            findings.push(LineFinding {
                line_num: idx + 1,
                line: line.to_owned(),
                char_groups: group_consecutive(line_findings),
            });
        }
    }

    if findings.is_empty() {
        return None;
    }

    let total_chars: usize = findings
        .iter()
        .flat_map(|f| f.char_groups.iter())
        .map(|g| g.len())
        .sum();

    let suspicion = calculate_suspicion(&findings);

    Some(FileResult { file_path: rel, file_size, findings, total_chars, suspicion })
}

// ---------------------------------------------------------------------------
// Suspicion scoring
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
enum SuspicionLevel {
    Info,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for SuspicionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info     => write!(f, "info"),
            Self::Medium   => write!(f, "medium"),
            Self::High     => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone)]
struct SuspicionResult {
    total_code_points: usize,
    unique_code_points: usize,
    max_consecutive_code_points: usize,
    max_consecutive_unicode_tags: usize,
    suspicion_level: SuspicionLevel,
}

fn calculate_suspicion(findings: &[LineFinding]) -> SuspicionResult {
    let mut total = 0usize;
    let mut unique: HashSet<u32> = HashSet::new();
    let mut max_run = 0usize;
    let mut max_tag_run = 0usize;

    for lf in findings {
        for group in &lf.char_groups {
            total += group.len();
            max_run = max_run.max(group.len());
            if group.iter().all(|c| c.char_type == CharType::Tag) {
                max_tag_run = max_tag_run.max(group.len());
            }
            for c in group {
                unique.insert(c.ch as u32);
            }
        }
    }

    let level = if max_run >= CRITICAL_RUN {
        SuspicionLevel::Critical
    } else if max_run >= HIGH_RUN || total > SPARSE_HIGH_TOTAL {
        SuspicionLevel::High
    } else if total < 10 {
        SuspicionLevel::Info
    } else {
        SuspicionLevel::Medium
    };

    SuspicionResult {
        total_code_points: total,
        unique_code_points: unique.len(),
        max_consecutive_code_points: max_run,
        max_consecutive_unicode_tags: max_tag_run,
        suspicion_level: level,
    }
}

// ---------------------------------------------------------------------------
// File result and stats
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FileResult {
    file_path: String,
    file_size: u64,
    findings: Vec<LineFinding>,
    total_chars: usize,
    suspicion: SuspicionResult,
}

#[derive(Debug, Default)]
struct Stats {
    files_scanned: usize,
    files_with_findings: usize,
    total_invisible_chars: usize,
    skipped_binary: usize,
    file_read_errors: usize,
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

fn summarize_chars(findings: &[LineFinding]) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for lf in findings {
        for group in &lf.char_groups {
            for c in group {
                *counts.entry(c.name.to_string()).or_insert(0) += 1;
            }
        }
    }
    let mut v: Vec<_> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v
}

fn summarize_tag_runs(findings: &[LineFinding]) -> String {
    let mut seen: HashSet<String> = HashSet::new();
    let mut runs: Vec<String> = Vec::new();
    for lf in findings {
        for group in &lf.char_groups {
            if group.iter().all(|c| c.char_type == CharType::Tag) {
                let payload: String = group
                    .iter()
                    .filter_map(|c| c.decoded.as_deref())
                    .filter(|d| !d.starts_with('['))
                    .collect();
                if !payload.is_empty() && seen.insert(payload.clone()) {
                    let safe = payload.replace('\\', "\\\\").replace('\'', "\\'");
                    runs.push(format!("'{safe}'"));
                }
            }
        }
    }
    if runs.is_empty() {
        return String::new();
    }
    const MAX: usize = 5;
    if runs.len() > MAX {
        let extra = runs.len() - MAX;
        runs.truncate(MAX);
        format!("{}; +{extra} more", runs.join("; "))
    } else {
        runs.join("; ")
    }
}

#[derive(Serialize)]
struct ReportRow {
    file_path: String,
    file_size_bytes: u64,
    suspicion_level: String,
    total_invisible_code_points: usize,
    unique_invisible_code_points: usize,
    invisible_chars: String,
    longest_consecutive_run: usize,
    longest_unicode_tag_run: usize,
    notes: String,
}

fn build_rows(results: &[FileResult]) -> Vec<ReportRow> {
    let mut rows: Vec<ReportRow> = results
        .iter()
        .map(|r| {
            let char_list = summarize_chars(&r.findings)
                .iter()
                .map(|(n, c)| format!("{n} ({c})"))
                .collect::<Vec<_>>()
                .join("; ");
            ReportRow {
                file_path: r.file_path.clone(),
                file_size_bytes: r.file_size,
                suspicion_level: r.suspicion.suspicion_level.to_string(),
                total_invisible_code_points: r.suspicion.total_code_points,
                unique_invisible_code_points: r.suspicion.unique_code_points,
                invisible_chars: char_list,
                longest_consecutive_run: r.suspicion.max_consecutive_code_points,
                longest_unicode_tag_run: r.suspicion.max_consecutive_unicode_tags,
                notes: summarize_tag_runs(&r.findings),
            }
        })
        .collect();
    rows.sort_by(|a, b| a.file_path.cmp(&b.file_path));
    rows
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

fn generate_csv(results: &[FileResult]) -> String {
    let header = "file_path,file_size_bytes,suspicion_level,total_invisible_code_points,\
                  unique_invisible_code_points,invisible_chars,longest_consecutive_run,\
                  longest_unicode_tag_run,notes";
    let mut lines = vec![header.to_owned()];
    for row in build_rows(results) {
        lines.push(format!(
            "{},{},{},{},{},{},{},{},{}",
            csv_escape(&row.file_path),
            row.file_size_bytes,
            csv_escape(&row.suspicion_level),
            row.total_invisible_code_points,
            row.unique_invisible_code_points,
            csv_escape(&row.invisible_chars),
            row.longest_consecutive_run,
            row.longest_unicode_tag_run,
            csv_escape(&row.notes),
        ));
    }
    lines.join("\n")
}

#[derive(Serialize)]
struct JsonReport<'a> {
    metadata: JsonMeta<'a>,
    files: Vec<ReportRow>,
}

#[derive(Serialize)]
struct JsonMeta<'a> {
    target: &'a str,
    files_scanned: usize,
    binary_files_skipped: usize,
    file_read_errors: usize,
    files_with_findings: usize,
    total_invisible_code_points: usize,
}

fn generate_json(results: &[FileResult], stats: &Stats, target: &str) -> String {
    let report = JsonReport {
        metadata: JsonMeta {
            target,
            files_scanned: stats.files_scanned,
            binary_files_skipped: stats.skipped_binary,
            file_read_errors: stats.file_read_errors,
            files_with_findings: results.len(),
            total_invisible_code_points: stats.total_invisible_chars,
        },
        files: build_rows(results),
    };
    serde_json::to_string_pretty(&report).unwrap_or_default()
}

fn generate_text(results: &[FileResult], stats: &Stats, target: &str) -> String {
    let mut out = format!(
        "ASCII SMUGGLING DETECTION REPORT\nTarget: {target}\n\
         Files Scanned: {}\nBinary Files Skipped: {}\n",
        stats.files_scanned, stats.skipped_binary,
    );
    if results.is_empty() {
        out.push_str("No invisible unicode characters detected.\n");
        return out;
    }
    out.push_str(&format!(
        "Files with Findings: {}\nTotal Invisible Code Points: {}\n\n",
        results.len(), stats.total_invisible_chars
    ));
    out.push_str("file_path | total | unique | chars | longest_run | longest_tag_run | notes\n");
    for row in build_rows(results) {
        out.push_str(&format!(
            "{} | {} | {} | {} | {} | {} | {}\n",
            row.file_path, row.total_invisible_code_points, row.unique_invisible_code_points,
            row.invisible_chars, row.longest_consecutive_run,
            row.longest_unicode_tag_run, row.notes,
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const EPILOG: &str = "\
SUSPICION LEVELS
  info      < 10 invisible chars, no consecutive run. Common in legitimate files
            (e.g. a single BOM). Investigate before dismissing.
  medium    10-100 invisible chars, no long run. May indicate obfuscation.
  high      Consecutive run >= 10 chars OR sparse volume > 100.
            Strong indicator of intentional smuggling or BiDi attack.
  critical  Consecutive run >= 40 chars. High-confidence active payload.

EXIT CODES
  0   Clean scan, or no findings met the --threshold level.
  1   One or more files triggered the --threshold level.
  2   Usage / configuration error.

EXAMPLES
  poltergeist --target ./myrepo
  poltergeist --target src/main.py --output - --format text
  poltergeist --target . --threshold high --format json --output /tmp/report.json
  git diff --name-only HEAD | xargs -I{} poltergeist --target {} --output - --threshold info
  poltergeist --target ./src --include-cc --include-zs --workers 8
  poltergeist --list-chars";

const LIST_CHARS_TEXT: &str = "\
poltergeist detects the following invisible/format Unicode character classes by default.

DEFAULT DETECTION
  Zero-width & joiners
    U+034F  COMBINING GRAPHEME JOINER
    U+180E  MONGOLIAN VOWEL SEPARATOR
    U+200B  ZERO WIDTH SPACE
    U+200C  ZERO WIDTH NON-JOINER
    U+200D  ZERO WIDTH JOINER
    U+2060  WORD JOINER
    U+FEFF  ZERO WIDTH NO-BREAK SPACE (BOM)

  Bidirectional / directional marks
    U+061C  ARABIC LETTER MARK
    U+200E  LEFT-TO-RIGHT MARK          U+200F  RIGHT-TO-LEFT MARK
    U+202A  LEFT-TO-RIGHT EMBEDDING     U+202B  RIGHT-TO-LEFT EMBEDDING
    U+202C  POP DIRECTIONAL FORMATTING  U+202D  LEFT-TO-RIGHT OVERRIDE
    U+202E  RIGHT-TO-LEFT OVERRIDE      U+2066  LEFT-TO-RIGHT ISOLATE
    U+2067  RIGHT-TO-LEFT ISOLATE       U+2068  FIRST STRONG ISOLATE
    U+2069  POP DIRECTIONAL ISOLATE

  Line / paragraph separators
    U+2028  LINE SEPARATOR    U+2029  PARAGRAPH SEPARATOR

  Invisible math operators
    U+2061  FUNCTION APPLICATION  U+2062  INVISIBLE TIMES
    U+2063  INVISIBLE SEPARATOR   U+2064  INVISIBLE PLUS

  Deprecated format controls   (U+206A-U+206F)
  Arabic format controls       (U+0600-U+0605, U+0890, U+0891, U+08E2)
  Kaithi number signs          (U+110BD, U+110CD)
  Variation selectors          (U+FE00-U+FE0F, U+E0100-U+E01EF)
  Unicode tags                 (U+E0000-U+E007F — decoded to ASCII payload)
  Musical format controls      (U+1D173-U+1D17A)
  Egyptian Hieroglyph format   (U+13430-U+1343F)
  Shorthand format controls    (U+1BCA0-U+1BCA3)
  Interlinear annotation       (U+FFF9-U+FFFB)

OPTIONAL DETECTION
  --include-confusable-spaces
    U+00A0  NO-BREAK SPACE      U+00AD  SOFT HYPHEN
    U+2000-U+200A  width spaces U+202F  NARROW NO-BREAK SPACE
    U+205F  MEDIUM MATH SPACE   U+2800  BRAILLE PATTERN BLANK
    U+3000  IDEOGRAPHIC SPACE   U+3164  HANGUL FILLER
    U+FFA0  HALFWIDTH HANGUL FILLER

  --include-cc   All Unicode Cc control chars except TAB/LF/CR
  --include-zs   All Unicode Zs space separators except U+0020
";

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Csv,
    Json,
    Text,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Csv  => write!(f, "csv"),
            Self::Json => write!(f, "json"),
            Self::Text => write!(f, "text"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "poltergeist",
    version = VERSION,
    about = "poltergeist — ASCII/Unicode Invisible-character Detection\n\
             Scans files for invisible Unicode characters used in prompt injection,\n\
             BiDi spoofing, ASCII smuggling, and hidden-payload attacks.",
    after_help = EPILOG,
)]
struct Cli {
    /// Print all detectable character classes, then exit
    #[arg(long)]
    list_chars: bool,

    /// File or directory to scan (directories are walked recursively)
    #[arg(long, value_name = "PATH")]
    target: Option<PathBuf>,

    /// Write report to FILE; pass \"-\" for stdout
    #[arg(long, value_name = "FILE")]
    output: Option<String>,

    /// Report format: csv (default), json, or text
    #[arg(long, value_name = "FMT", default_value = "csv")]
    format: OutputFormat,

    /// Suspicion level that triggers exit code 1 [info|medium|high|critical]
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    threshold: SuspicionLevel,

    /// Parallel scan workers (0 = auto-select up to 8)
    #[arg(long, value_name = "N", default_value = "1")]
    workers: usize,

    /// Print scanning progress to stderr
    #[arg(long, short = 'v')]
    verbose: bool,

    /// Also detect Cc control characters (excludes TAB/LF/CR)
    #[arg(long)]
    include_cc: bool,

    /// Also detect Zs space separators (excludes U+0020)
    #[arg(long)]
    include_zs: bool,

    /// Also detect confusable/suspicious spaces and fillers (e.g. U+00A0)
    #[arg(long)]
    include_confusable_spaces: bool,

    /// Report all occurrences, disabling benign-context skips
    /// (file-leading BOM, VS-16 after emoji base characters)
    #[arg(long)]
    strict: bool,

    /// Scan every text file, not just AI-harness-relevant types
    /// (.md, .yaml, .json, .toml, .txt, .config, etc.)
    #[arg(long)]
    all_files: bool,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.list_chars {
        print!("{LIST_CHARS_TEXT}");
        std::process::exit(0);
    }

    let target = match cli.target.as_ref() {
        Some(t) => t.clone(),
        None => bail!("--target is required (use --list-chars or --version without it)"),
    };

    if !target.exists() {
        eprintln!("Error: Target '{}' does not exist.", target.display());
        std::process::exit(2);
    }

    // Resolve workers
    let workers = if cli.workers == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get().min(8))
            .unwrap_or(4)
    } else {
        cli.workers
    };

    rayon::ThreadPoolBuilder::new()
        .num_threads(workers)
        .build_global()
        .ok();

    let opts = ScanOptions {
        include_cc: cli.include_cc,
        include_zs: cli.include_zs,
        include_confusable_spaces: cli.include_confusable_spaces,
        strict: cli.strict,
    };

    let stdout_mode = cli.output.as_deref() == Some("-");

    let output_path: Option<PathBuf> = if stdout_mode {
        None
    } else {
        let ext = match cli.format {
            OutputFormat::Csv  => "csv",
            OutputFormat::Json => "json",
            OutputFormat::Text => "txt",
        };
        let p = cli.output.clone()
            .unwrap_or_else(|| format!("poltergeist-report-{}.{ext}", utc_timestamp()));
        Some(PathBuf::from(p))
    };

    // Validate output path
    if let Some(ref op) = output_path {
        if let Some(parent) = op.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                eprintln!("Error: Output directory '{}' does not exist.", parent.display());
                std::process::exit(2);
            }
        }
    }

    // Set of paths to exclude from scanning
    let excluded: HashSet<PathBuf> = output_path
        .iter()
        .filter_map(|p| p.canonicalize().ok())
        .collect();

    // Collect all candidate files
    let base: PathBuf = if target.is_file() {
        target.parent().unwrap_or(&target).to_owned()
    } else {
        target.clone()
    };

    let harness_only = !cli.all_files;
    let files: Vec<PathBuf> = if target.is_file() {
        vec![target.clone()]
    } else {
        WalkDir::new(&target)
            .into_iter()
            .filter_entry(|e| {
                e.file_type().is_file()
                    || !EXCLUDED_DIRS.contains(&e.file_name().to_str().unwrap_or(""))
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.into_path())
            .filter(|p| p.canonicalize().map_or(true, |cp| !excluded.contains(&cp)))
            .filter(|p| !harness_only || is_ai_harness_ext(p))
            .collect()
    };

    let total = files.len();

    if !cli.verbose && !stdout_mode {
        let note = if workers > 1 { format!(" ({workers} workers)") } else { String::new() };
        eprintln!("Scanning {}{note}...", target.display());
    }

    // Atomic counters for progress and stats
    let n_scanned  = AtomicUsize::new(0);
    let n_binary   = AtomicUsize::new(0);
    let n_errors   = AtomicUsize::new(0);
    let n_found    = AtomicUsize::new(0);

    // Parallel scan
    let results: Vec<FileResult> = files
        .par_iter()
        .filter_map(|path| {
            let outcome = match is_binary(path) {
                Some(true) => {
                    n_binary.fetch_add(1, Ordering::Relaxed);
                    None
                }
                None => {
                    n_errors.fetch_add(1, Ordering::Relaxed);
                    eprintln!("Warning: could not read '{}'", path.display());
                    None
                }
                Some(false) => {
                    let r = scan_file(path, &base, &opts);
                    let done = n_scanned.fetch_add(1, Ordering::Relaxed) + 1;
                    if r.is_some() {
                        n_found.fetch_add(1, Ordering::Relaxed);
                    }
                    if cli.verbose {
                        let f = n_found.load(Ordering::Relaxed);
                        eprint!("\r[{done}/{total}] scanned, {f} with findings          ");
                    }
                    r
                }
            };
            outcome
        })
        .collect();

    if cli.verbose {
        eprintln!("\r{:<80}", "");
    }

    let stats = Stats {
        files_scanned: n_scanned.load(Ordering::Relaxed),
        files_with_findings: n_found.load(Ordering::Relaxed),
        total_invisible_chars: results.iter().map(|r| r.total_chars).sum(),
        skipped_binary: n_binary.load(Ordering::Relaxed),
        file_read_errors: n_errors.load(Ordering::Relaxed),
    };

    // Generate report
    if !stdout_mode {
        eprintln!("Generating {} report...", cli.format);
    }

    let target_str = target.to_string_lossy();
    let report = match cli.format {
        OutputFormat::Json => generate_json(&results, &stats, &target_str),
        OutputFormat::Csv  => generate_csv(&results),
        OutputFormat::Text => generate_text(&results, &stats, &target_str),
    };

    if stdout_mode {
        println!("{report}");
    } else {
        let op = output_path.as_ref().unwrap();
        fs::write(op, &report)
            .with_context(|| format!("failed to write report to '{}'", op.display()))?;
    }

    // Console summary
    if !stdout_mode {
        eprintln!("  Files scanned:  {}", stats.files_scanned);
        eprintln!("  Binary skipped: {}", stats.skipped_binary);
        if stats.file_read_errors > 0 {
            eprintln!("  Warning: file read errors: {}", stats.file_read_errors);
        }
        if !results.is_empty() {
            let mut counts = BTreeMap::new();
            for r in &results {
                *counts.entry(r.suspicion.suspicion_level.to_string()).or_insert(0usize) += 1;
            }
            eprintln!("  Files with findings: {}", results.len());
            for (level, count) in &counts {
                eprintln!("    {}: {count}", level_cap(level));
            }
            eprintln!("  Total invisible code points: {}", stats.total_invisible_chars);
            if cli.include_cc { eprintln!("  Extra: Cc control chars (excl. TAB/LF/CR)"); }
            if cli.include_zs { eprintln!("  Extra: Zs space separators (excl. U+0020)"); }
            if cli.include_confusable_spaces { eprintln!("  Extra: confusable/suspicious spaces"); }
            eprintln!("  Reminder: manually inspect flagged files to verify intent/context.");
        } else {
            eprintln!("  No invisible code points found.");
        }
        eprintln!("Report written to {}", output_path.as_ref().unwrap().display());
    }

    // Exit code
    let threshold_met = results.iter().any(|r| r.suspicion.suspicion_level >= cli.threshold);
    std::process::exit(if threshold_met { 1 } else { 0 });
}

/// UTC timestamp as `YYYYMMDD-HHMMSS`. Uses Howard Hinnant's
/// days_from_civil algorithm for the calendar conversion.
fn utc_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let hour = (secs / 3600) % 24;
    let minute = (secs / 60) % 60;
    let second = secs % 60;

    let days = (secs / 86400) as i64 + 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 { year += 1; }

    format!("{:04}{:02}{:02}-{:02}{:02}{:02}", year, month, day, hour, minute, second)
}

fn level_cap(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().to_string() + c.as_str(),
    }
}
