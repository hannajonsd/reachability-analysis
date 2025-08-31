# reachability-analysis

A CLI tool that identifies known vulnerabilities in third-party dependencies and determines whether the vulnerable code is actually reachable from your project. Instead of flagging all vulnerabilities in dependencies, this tool filters results to highlight only those that pose a real risk based on actual usage.

## Features

- **Multi-language support** - Analyzes JavaScript, Python, and Go codebases
- **Reachability analysis** - Uses tree-sitter parsing to detect actual function calls to vulnerable code
- **Hierarchical dependency resolution** - Finds vulnerabilities in parent packages (e.g., `golang.org/x/text` for `golang.org/x/text/language`)
- **Version-aware analysis** - Integrates with manifest files (package.json, go.mod, requirements.txt) for precise vulnerability matching
- **OSV database integration** - Queries the Open Source Vulnerabilities database for up-to-date security advisories
- **Noise reduction** - Only flags vulnerabilities in code that's actually called, reducing false positives
- **Robust error handling** - Continues analysis even when individual packages fail
- **CI/CD ready** - Proper exit codes for automated pipelines

## Installation

```bash
# Clone the repository (outside of projects you want to scan)
git clone https://github.com/hannajonsd/reachability-analysis
cd reachability-analysis
go build -o vulnerability-scanner

# Install globally (recommended)
sudo mv vulnerability-scanner /usr/local/bin/
# Or install to user directory
mkdir -p ~/bin
mv vulnerability-scanner ~/bin/
# Add ~/bin to PATH: 
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
```

## Usage

### Basic scan
```bash
# Navigate to your project
cd /path/to/your/project
vulnerability-scanner .
```

### Verbose output
```bash
vulnerability-scanner /path/to/your/project -verbose
```

### Scan current directory
```bash
# From within your project directory
vulnerability-scanner
```

## If not installed globally, copy scanner to your project
```bash
cp /path/to/reachability-analysis/vulnerability-scanner ./
./vulnerability-scanner .
```

## Example Output

```
=== Vulnerability Reachability Analysis ===
Analyzing repository: .
Found 22 source files for analysis

------------------------------------------------------------
VULNERABILITY ANALYSIS BY FILE

External dependencies discovered: 3
  - With exact versions (in manifests): 2
  - With semver ranges (in manifests): 0
  - Unknown versions (in manifests): 1
  - Unknown versions (code-only): 0

❌ Found vulnerabilities in 3 files, packages with vulnerabilities 3:

 testdata/example.js
  lodash@unknown (2 reachable vulnerabilities + 1 requires manual review)
   - lod.trim (GHSA-29mw-wpgm-hmr9)
   - lod.toNumber (GHSA-29mw-wpgm-hmr9)

  Advisories with no extracted symbols (package-wide):
   - GHSA-x5rq-j2xg-h7qm: "Regular Expression Denial of Service (ReDoS) in lodash"
     https://osv.dev/vulnerability/GHSA-x5rq-j2xg-h7qm

 testdata/example.py
  requests@2.30.0 (1 vulnerable function + 3 require manual review)
   - Session (GHSA-9wx4-h78v-vm56)

  Advisories with no extracted symbols (package-wide):
   - GHSA-9hjg-9r4m-mvj7: "Requests vulnerable to .netrc credentials leak via malicious URLs"
     https://osv.dev/vulnerability/GHSA-9hjg-9r4m-mvj7
   - GHSA-j8r2-6x86-q33q: "Unintended leak of Proxy-Authorization header in requests"
     https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q
   - PYSEC-2023-74: ""
     https://osv.dev/vulnerability/PYSEC-2023-74

 testdata/example.go
  golang.org/x/text/language@v0.3.7 (2 vulnerable functions + 2 require manual review)
   - language.ParseAcceptLanguage (GO-2021-0113)
   - language.MatchStrings (GO-2021-0113)

  Advisories with no extracted symbols (package-wide):
   - GHSA-69ch-w2m2-3vjp: "golang.org/x/text/language Denial of service via crafted Accept-Language header"
     https://osv.dev/vulnerability/GHSA-69ch-w2m2-3vjp
   - GHSA-ppp9-7jff-5vj2: "golang.org/x/text/language Out-of-bounds Read vulnerability"
     https://osv.dev/vulnerability/GHSA-ppp9-7jff-5vj2

```

## How It Works

1. **Discovery** - Recursively finds source files (.js, .py, .go) in your project
2. **Import Analysis** - Uses tree-sitter to parse import statements and extract dependencies
3. **Version Lookup** - Matches discovered dependencies with versions from manifest files
4. **Vulnerability Query** - Queries OSV database for known vulnerabilities
5. **Reachability Check** - Analyzes your code to determine if vulnerable functions are actually called
6. **Results** - Reports only vulnerabilities in code paths that are reachable

## Supported Languages & Ecosystems

| Language   | Package Manager | Manifest Files |
|------------|----------------|----------------|
| JavaScript | npm            | package.json   |
| Python     | pip            | requirements.txt |
| Go         | go modules     | go.mod         |

## Exit Codes

- `0` - No reachable vulnerabilities found
- `1` - Reachable vulnerabilities detected OR analysis failed

## Use Cases

- **Developer workflow** - Quick local checks before pushing code
- **Pre-commit hooks** - Block commits that introduce reachable vulnerabilities

## Pre-commit Hook Setup

1. Install pre-commit:
```bash
pip install pre-commit
```

Create `.pre-commit-config.yaml` in your project root:

```yaml
repos:
  - repo: local
    hooks:
      - id: vulnerability-scan
        name: Vulnerability Reachability Analysis
        entry: ./vulnerability-scanner
        language: system
        pass_filenames: false
        args: ["--path", "."]
        always_run: true
```

Install the hook:
```bash
pre-commit install
```

Now every commit will be scanned for reachable vulnerabilities!

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details