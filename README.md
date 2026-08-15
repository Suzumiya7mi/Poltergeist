# Poltergeist

> A high-performance invisible Unicode character detection tool for security auditing

**Poltergeist** scans files for invisible and zero-width Unicode characters that could be exploited in prompt injection, BiDi spoofing, ASCII smuggling, and hidden-payload attacks—particularly targeting AI tool ecosystems.

## Why Poltergeist?

Modern AI-assisted development tools (Claude Code, Cursor, Cline, Windsurf, etc.) ingest configuration files, markdown documentation, and YAML pipelines. Attackers can embed invisible Unicode characters in these files to:

- **Inject hidden prompts** that manipulate AI behavior
- **Smuggle malicious instructions** in documentation
- **Execute BiDi attacks** that reverse displayed text
- **Hide backdoors** in plain sight using zero-width characters

Poltergeist detects these threats by scanning for 100+ classes of invisible Unicode characters and scoring their suspicion level.

## Features

- **Comprehensive Detection**: Identifies zero-width characters, BiDi marks, Unicode tags, variation selectors, format controls, and more
- **Suspicion Scoring**: Automatically classifies findings as `info`, `medium`, `high`, or `critical` based on character count and consecutive runs
- **AI-Harness Focused**: Targets file types commonly ingested by AI tools (.md, .yaml, .toml, .cursorrules, etc.)
- **Fast Parallel Scanning**: Multi-threaded processing with configurable worker counts
- **Multiple Output Formats**: CSV, JSON, or human-readable text
- **Unicode Tag Decoding**: Extracts and displays hidden ASCII payloads from tag characters
- **Smart Filtering**: Skips benign contexts (UTF-8 BOM, emoji sequence components) unless in strict mode
- **Grapheme-Aware**: Emoji are recognized via Unicode grapheme segmentation (UAX #29), not a hand-maintained emoji list

## Installation

### From Source

```bash
git clone https://github.com/Suzumiya7mi/Poltergeist.git
cd Poltergeist
cargo build --release
```

The binary will be at `target/release/poltergeist`.

### Quick Start

```bash
# Scan current directory
poltergeist --target .

# Scan with high threshold, JSON output
poltergeist --target ./repo --threshold high --format json --output report.json

# Scan specific file with verbose progress
poltergeist --target README.md --verbose --output - --format text

# Scan git diff for suspicious characters
git diff --name-only HEAD | xargs -I{} poltergeist --target {} --threshold info
```

## Suspicion Levels

Poltergeist assigns each file a suspicion level based on the quantity and distribution of invisible characters:

| Level | Criteria | Interpretation |
|-------|----------|----------------|
| **info** | < 10 chars, no consecutive run | Common in legitimate files (e.g., UTF-8 BOM). Verify before dismissing. |
| **medium** | 10–100 chars, no long run | May indicate obfuscation or accidental inclusion. |
| **high** | Consecutive run ≥ 10 OR total > 100 | Strong indicator of intentional smuggling or BiDi attack. |
| **critical** | Consecutive run ≥ 40 | High-confidence active payload. Investigate immediately. |

## Character Classes Detected

### Default Detection

- **Zero-width & Joiners**: `U+200B` (ZERO WIDTH SPACE), `U+200C/D` (joiners), `U+2060` (WORD JOINER), `U+FEFF` (BOM)
- **Bidirectional Marks**: `U+200E/F` (LTR/RTL marks), `U+202A–E` (embeddings/overrides), `U+2066–2069` (isolates)
- **Line/Paragraph Separators**: `U+2028`, `U+2029`
- **Invisible Math Operators**: `U+2061–2064` (function application, invisible times/plus/separator)
- **Variation Selectors**: `U+FE00–FE0F`, `U+E0100–E01EF`
- **Unicode Tags**: `U+E0000–E007F` (decoded to ASCII payload)
- **Format Controls**: Arabic, Kaithi, Musical, Egyptian Hieroglyph, Shorthand

### Optional Detection

```bash
--include-confusable-spaces  # Detect NO-BREAK SPACE, IDEOGRAPHIC SPACE, etc.
--include-cc                 # Detect control characters (excludes TAB/LF/CR)
--include-zs                 # Detect all space separators except U+0020
```

## Command-Line Options

```
Options:
  --target <PATH>             File or directory to scan (required)
  --output <FILE>             Output file path (use "-" for stdout)
  --format <FMT>              Report format: csv (default), json, text
  --threshold <LEVEL>         Suspicion level that triggers exit code 1 [default: info]
  --workers <N>               Parallel workers (0 = auto, max 8) [default: 1]
  -v, --verbose               Print scanning progress to stderr
  --include-cc                Also detect Cc control characters (excludes TAB/LF/CR)
  --include-zs                Also detect Zs space separators (excludes U+0020)
  --include-confusable-spaces Also detect confusable/suspicious spaces
  --strict                    Report all occurrences, disable benign-context skips
  --all-files                 Scan all text files, not just AI-harness types
  --list-chars                Print all detectable character classes and exit
  -h, --help                  Print help
  -V, --version               Print version
```

## Output Formats

### CSV (Default)

```csv
file_path,file_size_bytes,suspicion_level,total_invisible_code_points,unique_invisible_code_points,invisible_chars,longest_consecutive_run,longest_unicode_tag_run,notes
docs/guide.md,4521,high,87,12,"ZERO WIDTH SPACE (45); RIGHT-TO-LEFT OVERRIDE (42)",42,0,
```

### JSON

```json
{
  "metadata": {
    "target": "./repo",
    "files_scanned": 247,
    "binary_files_skipped": 18,
    "file_read_errors": 0,
    "files_with_findings": 3,
    "total_invisible_code_points": 152
  },
  "files": [...]
}
```

### Text

```
ASCII SMUGGLING DETECTION REPORT
Target: ./repo
Files Scanned: 247
Files with Findings: 3
Total Invisible Code Points: 152

file_path | total | unique | chars | longest_run | longest_tag_run | notes
docs/guide.md | 87 | 12 | ZERO WIDTH SPACE (45); RIGHT-TO-LEFT OVERRIDE (42) | 42 | 0 | 
```

## Exit Codes

- **0**: Clean scan, or no findings met the `--threshold` level
- **1**: One or more files triggered the `--threshold` level
- **2**: Usage or configuration error

## Use Cases

- **Pre-commit Hooks**: Block commits containing suspicious invisible characters
- **CI/CD Pipelines**: Audit codebases before deployment
- **Security Reviews**: Scan documentation and configs for hidden payloads
- **AI Tool Auditing**: Verify `.cursorrules`, `.clinerules`, `CLAUDE.md` files
- **BiDi Attack Detection**: Find directional override attacks in source code

## AI-Harness File Types

By default, Poltergeist scans only files likely to be ingested by AI tools:

**Extensions**: `.md`, `.mdx`, `.txt`, `.yaml`, `.yml`, `.toml`, `.config`, `.ini`, `.cfg`, `.conf`, `.env`, `.rst`, `.adoc`

**Well-known AI rule files**: `.cursorrules`, `.clinerules`, `.windsurfrules`, `.aiderignore`, `.roomodes`, `.continuerc`, `.goosehints`

Use `--all-files` to scan every text file in the repository.

## Examples

### CI/CD Integration

```bash
# Fail build if critical findings detected
poltergeist --target . --threshold critical --format json --output security-audit.json
exit_code=$?
if [ $exit_code -eq 1 ]; then
  echo "CRITICAL invisible characters detected!"
  exit 1
fi
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
git diff --cached --name-only | xargs -I{} poltergeist --target {} --threshold high --output -
if [ $? -eq 1 ]; then
  echo "Commit blocked: suspicious invisible characters detected"
  exit 1
fi
```

### Scan Changed Files

```bash
# Check only modified files
git diff --name-only HEAD~1 | xargs -I{} poltergeist --target {} --threshold info
```

## Performance

Poltergeist is optimized for speed:

- **Release build**: Link-time optimization (LTO), single codegen unit, stripped binaries
- **Parallel processing**: Rayon-based multi-threading scales to available CPUs
- **Smart filtering**: Binary detection via extension + null-byte sniffing
- **Zero-copy parsing**: Uses `Cow<'static, str>` for efficient character classification

Typical performance: ~2000 files/second (single-threaded) on modern hardware.

## How It Works

1. **Walk directory tree**: Collect files matching AI-harness extensions (or all text files with `--all-files`)
2. **Binary detection**: Skip files with known binary extensions or null bytes
3. **Grapheme segmentation**: Split each line into grapheme clusters (UAX #29) so emoji sequences are judged as a unit
4. **Character classification**: Classify codepoints via lookup table + range checks, excusing only valid emoji components
5. **Grouping**: Consecutive invisible characters are grouped into runs
6. **Suspicion scoring**: Calculate based on total count, unique characters, and longest run
7. **Unicode tag decoding**: Extract ASCII payloads from tag character sequences
8. **Report generation**: Output CSV/JSON/text with per-file findings

## False Positives

Poltergeist minimizes false positives by:

- **Skipping benign BOMs**: UTF-8 BOM (U+FEFF) at file start is ignored by default
- **Emoji tolerance**: invisible characters that are structurally part of a valid emoji sequence are allowed
- **Strict mode**: Use `--strict` to disable these skips for forensic analysis

Always manually inspect flagged files to verify intent and context.

### How emoji are recognized

Emoji are not matched against a list of codepoint ranges. Each line is split
into grapheme clusters with [`unicode-segmentation`](https://crates.io/crates/unicode-segmentation)
(UAX #29), and a character is excused only when the segmenter itself has bound
it to a pictographic base. The `Extended_Pictographic` property is read out of
the crate's UCD tables by probing grapheme break rule GB11
(`\p{Extended_Pictographic} Extend* ZWJ × \p{Extended_Pictographic}`), so
support tracks the crate's Unicode version instead of a table that goes stale.

This fixes false positives a range list misses — legacy pictographs such as
`©️`, `®️`, `™️`, `‼️`, `ℹ️`, `↔️`, `↩️`; keycaps such as `1️⃣`; and ZWJ sequences
where the joiner follows a skin-tone modifier (`👨🏻‍💻`) rather than the base
emoji.

Emoji context excuses only what a valid sequence actually needs, and only where
it needs it:

| Situation | Result |
|-----------|--------|
| `😀` + one VS-16, `©️`, `1️⃣` | benign |
| ZWJ that joins two pictographs (`👨‍👩‍👧`, `👨🏻‍💻`) | benign |
| The three RGI subdivision flags (`🏴󠁧󠁢󠁥󠁮󠁧󠁿`, `🏴󠁧󠁢󠁳󠁣󠁴󠁿`, `🏴󠁧󠁢󠁷󠁬󠁳󠁿`) | benign — fixed sequences, zero payload capacity |
| A **run** of variation selectors after an emoji | reported (only the first is meaningful) |
| VS-1 … VS-14 after an emoji | reported (not presentation selectors) |
| Variation Selector Supplement (U+E0100–U+E01EF) | always reported |
| Any other tag sequence behind `🏴` | always reported — this is the smuggling channel |
| Trailing ZWJ that joins nothing (`😀‍`) | reported |
| VS-16 after a non-pictographic base (`a︎`) | reported |

## Contributing

Contributions welcome! Areas for improvement:

- Additional character class detection
- Language-specific benign context rules
- Integration with linters and formatters
- Performance optimizations

## License

See [LICENSE](LICENSE) file for details.

## Acknowledgments

Poltergeist was built to address the emerging threat landscape in AI-assisted development environments, where invisible characters can be weaponized to manipulate tool behavior.

---

**Stay vigilant. Trust but verify.**
