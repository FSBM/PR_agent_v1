# PR-Agent: Enhanced Security-First GitHub Pull Request Review System

A sophisticated multi-agent system built with CrewAI that performs comprehensive security-focused analysis of GitHub Pull Requests using specialized AI agents.

## 🎯 Overview

PR-Agent is an advanced CLI tool where a crew of AI security experts collaborates to review GitHub Pull Requests with a security-first approach:

- **Fetches** PR diffs from GitHub with comprehensive content analysis
- **Scans** ALL dependencies for known vulnerabilities using multiple security databases  
- **Analyzes** large changes by dividing them into manageable, reviewable chunks
- **Performs** deep security analysis covering all attack vectors and vulnerability patterns
- **Conducts** heuristic scanning for code smells and quality issues
- **Reviews** architectural decisions and design patterns
- **Posts** a comprehensive security-focused summary report back to the GitHub PR

## 🛡️ Enhanced Security Features

### **NEW: 4 Additional Security-Focused Agents**

1. **🔍 Dependency Security Agent** - Comprehensive vulnerability scanning
   - Checks ALL packages against CVE databases, OSV.dev, GitHub Advisory Database
   - Verifies package authenticity and detects typosquatting
   - Analyzes transitive dependencies and license compatibility
   - Provides specific remediation steps with version recommendations

2. **📊 Change Analyzer Agent** - Intelligent change chunking
   - Automatically divides large PRs (>500 lines) into logical review chunks
   - Maintains context and file relationships across chunks
   - Prioritizes high-risk changes (security, authentication, data handling)
   - Ensures comprehensive coverage without missing critical areas

3. **🔒 Deep Security Agent** - Advanced threat analysis
   - Multi-layer security analysis across 6 domains:
     - Cryptographic security (weak hashing, hardcoded keys)
     - Authentication & Authorization (session management, privilege escalation)
     - Data Protection (exposure in logs, transmission security)
     - Input Validation (SQL injection, XSS, command injection)
     - API & Web Security (CORS, headers, rate limiting)
     - Infrastructure Security (Docker, CI/CD, secrets management)

4. **🎯 Package Integrity Validator** - Supply chain security
   - Validates integrity of dependency and configuration files
   - Checks Docker configurations for security best practices
   - Analyzes CI/CD workflow security
   - Verifies secrets management practices

## 🏗️ Architecture

The enhanced system consists of 8 specialized agents working in a hierarchical process:

1. **🎯 Enhanced Security Supervisor** - Zero-tolerance security orchestration
2. **📁 Git Fetcher Agent** - Retrieves comprehensive PR diff content
3. **🔍 Dependency Security Agent** - Vulnerability scanning specialist
4. **📊 Change Analyzer Agent** - Large PR chunking expert
5. **🔒 Deep Security Agent** - Advanced security researcher
6. **🔍 Heuristic Scanner Agent** - Pattern-based code analysis
7. **🏗️ Architect Agent** - Security-aware design analysis
8. **📝 Report Writer Agent** - Security-focused report synthesis

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -e .
```

This will install all required packages:
- `crewai` - Agent orchestration framework
- `crewai-tools` - Base tools for agents
- `PyGithub` - GitHub API client
- `python-dotenv` - Environment variable management
- `google-generativeai` - Gemini AI integration
- `requests` - HTTP client for security API calls
- `aiohttp` - Async HTTP for performance
- `packaging` - Version parsing for dependency analysis
- `semver` - Semantic version handling

### 2. Set Up Environment Variables

The `.env` file is already configured with your API keys:



### 3. Run PR Analysis

```bash
# Basic usage
python main.py https://github.com/owner/repo/pull/123

# With verbose output
python main.py --verbose https://github.com/owner/repo/pull/123

# Alternative URL specification
python main.py --url https://github.com/owner/repo/pull/123
```

## 📁 Project Structure

```
pr-agent/
├── .env                 # Environment variables (your tokens)
├── main.py             # CLI entry point
├── agents.py           # Agent definitions (5 specialized agents)
├── tasks.py            # Task definitions with clear inputs/outputs
├── tools.py            # Custom GitHub tools (fetch diff, post comment)
├── pyproject.toml      # Project dependencies
└── README.md           # This file
```

## 🔧 Components

### Tools (`tools.py`)
- **`fetch_pr_diff`** - Fetches PR diff content using PyGithub
- **`post_pr_comment`** - Posts analysis results as PR comments

### Agents (`agents.py`)
- **`supervisor_agent`** - Manager with delegation capabilities
- **`diff_fetcher_agent`** - Uses GitHub tools to retrieve PR data
- **`heuristic_scanner_agent`** - Pattern-based code analysis
- **`architect_agent`** - Deep architectural and security analysis  
- **`report_writer_agent`** - Report generation and posting

### Tasks (`tasks.py`)
- **`fetch_diff_task`** - Retrieve PR diff content
- **`heuristic_analysis_task`** - Find simple code issues
- **`architectural_analysis_task`** - Analyze security/performance
- **`generate_report_task`** - Create and post final report

## 📊 Analysis Features

### Heuristic Analysis
- TODO/FIXME comments
- Debug statements (print, console.log)
- Hardcoded secrets detection
- Commented-out code
- Missing error handling
- Magic numbers
- Function length violations
- Deep nesting issues

### Architectural Analysis
- Security vulnerabilities (SQL injection, XSS)
- Performance bottlenecks
- SOLID principle violations
- Design pattern issues
- API breaking changes

### Report Generation
- Executive summary
- Categorized findings by severity
- Specific file/line references
- Actionable recommendations
- Professional markdown formatting

## 🎮 Usage Examples

```bash
# Analyze a public PR
python main.py https://github.com/microsoft/vscode/pull/12345

# Analyze with detailed logging
python main.py --verbose https://github.com/facebook/react/pull/67890

# Get help
python main.py --help
```

## 🛠️ Requirements

- Python 3.10+
- Valid GitHub Personal Access Token with repo access
- Valid Google AI (Gemini) API key
- Internet connection for API calls

## 🔒 Security

- Your API tokens are stored locally in `.env`
- GitHub token needs read access to target repositories
- PR comments are posted using your GitHub identity
- All analysis happens locally with external API calls to AI services

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Make your changes
4. Test with a sample PR
5. Submit a pull request

## 📝 License

This project is open source. Feel free to use and modify as needed.

## 🚨 Troubleshooting

### Common Issues

1. **Import errors**: Make sure dependencies are installed with `pip install -e .`
2. **GitHub API errors**: Verify your `GITHUB_TOKEN` has correct permissions
3. **AI API errors**: Check your `GOOGLE_API_KEY` is valid and has quota
4. **Permission denied**: Ensure token has access to the target repository

### Debug Mode

Run with `--verbose` flag to see detailed execution logs:

```bash
python main.py --verbose https://github.com/owner/repo/pull/123
```

## 🎯 Next Steps

1. Install dependencies: `pip install -e .`
2. Test with a public GitHub PR
3. Customize agent behaviors in `agents.py`
4. Extend analysis rules in `tasks.py`
5. Add custom tools in `tools.py`

Ready to analyze your first PR! 🚀
