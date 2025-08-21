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
git clone https://github.com/hannajonsd/reachability-analysis
cd reachability-analysis
go build -o vulnerability-scanner
```

## Usage

### Basic scan
```bash
./vulnerability-scanner --path /path/to/project
```

### Verbose output
```bash
./vulnerability-scanner --path /path/to/project --verbose
```

### Scan current directory
```bash
./vulnerability-scanner
```

## Example Output

```
=== Vulnerability Reachability Analysis ===
Analyzing repository: .
Found 21 source files for analysis

Found vulnerabilities in 3 files:

 testdata/example.js
    lodash@unknown (7 potential advisories used in code - unknown version)
       Specify exact version for precise analysis
     - lod.trim
     - lod.toNumber
     - lod.forEach

 testdata/example.py
  ❌ requests@==2.30.0 (4 vulnerable functions)
     - requests.get
     - requests.post
     - Session
     - HTTPAdapter

 testdata/example.go
  ❌ golang.org/x/text/language@v0.3.7 (2 vulnerable functions)
     - language.ParseAcceptLanguage
     - language.MatchStrings

SUMMARY
External dependencies discovered: 3
Packages with vulnerabilities: 3
Total vulnerability advisories: 13
Files with reachable vulnerabilities: 3
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

Build the scanner:
```bash
go build -o vulnerability-scanner
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