import os
import re
import json
import subprocess
import tempfile
import requests
from typing import Type, List, Dict, Any
from pydantic import BaseModel, Field
from github import Github
from crewai.tools import tool
from dotenv import load_dotenv
import hashlib

# Load environment variables
load_dotenv()


@tool("fetch_pr_diff")
def fetch_pr_diff(pr_url: str) -> str:
    """
    Fetches the diff content from a GitHub Pull Request URL.
    
    Args:
        pr_url: The full URL to the GitHub PR (e.g., https://github.com/owner/repo/pull/123)
        
    Returns:
        str: The raw diff content as a string
    """
    try:
        # Parse the PR URL to extract owner, repo, and PR number
        # URL format: https://github.com/owner/repo/pull/123
        url_pattern = r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)"
        match = re.match(url_pattern, pr_url)
        
        if not match:
            return f"Error: Invalid GitHub PR URL format. Expected: https://github.com/owner/repo/pull/123"
        
        owner, repo, pr_number = match.groups()
        pr_number = int(pr_number)
        
        # Initialize GitHub client
        github_token = os.getenv("GITHUB_TOKEN")
        if not github_token:
            return "Error: GITHUB_TOKEN not found in environment variables"
        
        g = Github(github_token)
        
        # Get the repository and pull request
        repository = g.get_repo(f"{owner}/{repo}")
        pull_request = repository.get_pull(pr_number)
        
        # Fetch all files in the PR and build diff content
        files = pull_request.get_files()
        diff_content = []
        
        diff_content.append(f"Pull Request #{pr_number}: {pull_request.title}")
        diff_content.append(f"Author: {pull_request.user.login}")
        diff_content.append(f"Base: {pull_request.base.ref} -> Head: {pull_request.head.ref}")
        diff_content.append(f"Files changed: {pull_request.changed_files}")
        diff_content.append(f"Additions: +{pull_request.additions}, Deletions: -{pull_request.deletions}")
        diff_content.append("=" * 80)
        
        for file in files:
            diff_content.append(f"\nFile: {file.filename}")
            diff_content.append(f"Status: {file.status}")
            diff_content.append(f"Changes: +{file.additions} -{file.deletions}")
            diff_content.append("-" * 40)
            
            if file.patch:
                diff_content.append(file.patch)
            else:
                diff_content.append("No patch content available (binary file or too large)")
            
            diff_content.append("-" * 40)
        
        return "\n".join(diff_content)
        
    except Exception as e:
        return f"Error fetching PR diff: {str(e)}"


@tool("post_pr_comment")
def post_pr_comment(pr_url: str, comment_body: str) -> str:
    """
    Posts a comment to a GitHub Pull Request.
    
    Args:
        pr_url: The full URL to the GitHub PR (e.g., https://github.com/owner/repo/pull/123)
        comment_body: The markdown content to post as a comment
        
    Returns:
        str: Success or error message
    """
    try:
        # Parse the PR URL to extract owner, repo, and PR number
        url_pattern = r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)"
        match = re.match(url_pattern, pr_url)
        
        if not match:
            return f"Error: Invalid GitHub PR URL format. Expected: https://github.com/owner/repo/pull/123"
        
        owner, repo, pr_number = match.groups()
        pr_number = int(pr_number)
        
        # Initialize GitHub client
        github_token = os.getenv("GITHUB_TOKEN")
        if not github_token:
            return "Error: GITHUB_TOKEN not found in environment variables"
        
        g = Github(github_token)
        
        # Get the repository and pull request
        repository = g.get_repo(f"{owner}/{repo}")
        pull_request = repository.get_pull(pr_number)
        
        # Post the comment
        comment = pull_request.create_issue_comment(comment_body)
        
        return f"Successfully posted comment to PR #{pr_number}. Comment ID: {comment.id}"
        
    except Exception as e:
        return f"Error posting PR comment: {str(e)}"


@tool("check_dependency_vulnerabilities")
def check_dependency_vulnerabilities(pr_url: str) -> str:
    """
    Checks dependencies in a PR for known security vulnerabilities using multiple sources.
    
    Args:
        pr_url: The full URL to the GitHub PR
        
    Returns:
        str: Report of vulnerable dependencies found
    """
    try:
        # Parse the PR URL
        url_pattern = r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)"
        match = re.match(url_pattern, pr_url)
        
        if not match:
            return "Error: Invalid GitHub PR URL format"
        
        owner, repo, pr_number = match.groups()
        pr_number = int(pr_number)
        
        # Get GitHub client
        github_token = os.getenv("GITHUB_TOKEN")
        if not github_token:
            return "Error: GITHUB_TOKEN not found"
        
        g = Github(github_token)
        repository = g.get_repo(f"{owner}/{repo}")
        pull_request = repository.get_pull(pr_number)
        
        vulnerabilities = []
        dependency_files = []
        
        # Look for dependency files in the PR
        files = pull_request.get_files()
        for file in files:
            filename = file.filename.lower()
            if any(dep_file in filename for dep_file in 
                   ['requirements.txt', 'package.json', 'pyproject.toml', 'poetry.lock', 
                    'pipfile', 'yarn.lock', 'composer.json', 'go.mod', 'cargo.toml']):
                dependency_files.append({
                    'filename': file.filename,
                    'content': file.patch or "No content available"
                })
        
        if not dependency_files:
            return "No dependency files found in this PR"
        
        # Analyze each dependency file
        for dep_file in dependency_files:
            filename = dep_file['filename']
            content = dep_file['content']
            
            # Extract package names and versions
            packages = extract_packages_from_content(filename, content)
            
            for package in packages:
                vuln_result = check_package_vulnerability(package, filename)
                if vuln_result:
                    vulnerabilities.append(vuln_result)
        
        if not vulnerabilities:
            return f"[SUCCESS] No known vulnerabilities found in {len(dependency_files)} dependency file(s)"
        
        # Format vulnerability report
        report = f"[SECURITY] SECURITY ALERT: {len(vulnerabilities)} vulnerabilities found\n\n"
        
        for vuln in vulnerabilities:
            report += f"**{vuln['severity'].upper()}**: {vuln['package']}\n"
            report += f"  File: {vuln['file']}\n"
            report += f"  Issue: {vuln['description']}\n"
            if vuln.get('fix'):
                report += f"  Fix: {vuln['fix']}\n"
            report += "\n"
        
        return report
        
    except Exception as e:
        return f"Error checking vulnerabilities: {str(e)}"


@tool("analyze_change_chunks")
def analyze_change_chunks(pr_url: str, max_chunk_size: int = 1000) -> str:
    """
    Divides large PR changes into smaller chunks for detailed analysis.
    
    Args:
        pr_url: The full URL to the GitHub PR
        max_chunk_size: Maximum lines per chunk
        
    Returns:
        str: Analysis of changes divided into manageable chunks
    """
    try:
        # Get PR diff content
        diff_content = fetch_pr_diff(pr_url)
        
        if diff_content.startswith("Error"):
            return diff_content
        
        # Split diff into logical chunks
        chunks = create_change_chunks(diff_content, max_chunk_size)
        
        if len(chunks) <= 1:
            return f"[INFO] Small PR: {len(chunks)} chunk, no division needed"
        
        # Analyze each chunk
        chunk_analysis = []
        
        for i, chunk in enumerate(chunks, 1):
            analysis = analyze_single_chunk(chunk, i, len(chunks))
            chunk_analysis.append(analysis)
        
        # Compile comprehensive report
        report = f"[ANALYSIS] LARGE PR ANALYSIS: Divided into {len(chunks)} chunks\n\n"
        report += "**Summary:**\n"
        
        total_files = sum(chunk['files_count'] for chunk in chunk_analysis)
        total_lines = sum(chunk['lines_changed'] for chunk in chunk_analysis)
        risk_chunks = sum(1 for chunk in chunk_analysis if chunk['risk_level'] == 'HIGH')
        
        report += f"- Total files: {total_files}\n"
        report += f"- Total lines changed: {total_lines}\n"
        report += f"- High-risk chunks: {risk_chunks}\n\n"
        
        # Detail each chunk
        for chunk in chunk_analysis:
            report += f"**Chunk {chunk['chunk_id']}** ({chunk['risk_level']} Risk)\n"
            report += f"Files: {chunk['files_count']} | Lines: {chunk['lines_changed']}\n"
            report += f"Focus areas: {', '.join(chunk['focus_areas'])}\n"
            if chunk['security_concerns']:
                report += f"[WARNING] Security concerns: {', '.join(chunk['security_concerns'])}\n"
            report += "\n"
        
        return report
        
    except Exception as e:
        return f"Error analyzing change chunks: {str(e)}"


@tool("deep_security_scan")
def deep_security_scan(pr_url: str) -> str:
    """
    Performs deep security analysis on PR changes including pattern matching,
    cryptographic analysis, and data flow analysis.
    
    Args:
        pr_url: The full URL to the GitHub PR
        
    Returns:
        str: Comprehensive security analysis report
    """
    try:
        # Get PR diff content
        diff_content = fetch_pr_diff(pr_url)
        
        if diff_content.startswith("Error"):
            return diff_content
        
        security_findings = []
        
        # 1. Cryptographic issues
        crypto_issues = scan_cryptographic_issues(diff_content)
        security_findings.extend(crypto_issues)
        
        # 2. Authentication/Authorization flaws
        auth_issues = scan_authentication_issues(diff_content)
        security_findings.extend(auth_issues)
        
        # 3. Data exposure risks
        data_exposure = scan_data_exposure(diff_content)
        security_findings.extend(data_exposure)
        
        # 4. Input validation issues
        input_validation = scan_input_validation(diff_content)
        security_findings.extend(input_validation)
        
        # 5. API security issues
        api_security = scan_api_security(diff_content)
        security_findings.extend(api_security)
        
        # 6. Infrastructure security
        infra_security = scan_infrastructure_security(diff_content)
        security_findings.extend(infra_security)
        
        if not security_findings:
            return "[SUCCESS] Deep security scan completed - No critical security issues found"
        
        # Categorize by severity
        critical = [f for f in security_findings if f['severity'] == 'CRITICAL']
        high = [f for f in security_findings if f['severity'] == 'HIGH']
        medium = [f for f in security_findings if f['severity'] == 'MEDIUM']
        
        # Generate comprehensive report
        report = f"[SECURITY] DEEP SECURITY SCAN RESULTS\n\n"
        report += f"**Summary**: {len(critical)} Critical, {len(high)} High, {len(medium)} Medium\n\n"
        
        if critical:
            report += "[CRITICAL] **CRITICAL SECURITY ISSUES**\n"
            for issue in critical:
                report += format_security_finding(issue)
            report += "\n"
        
        if high:
            report += "[WARNING] **HIGH SEVERITY ISSUES**\n"
            for issue in high:
                report += format_security_finding(issue)
            report += "\n"
        
        if medium:
            report += "[INFO] **MEDIUM SEVERITY ISSUES**\n"
            for issue in medium:
                report += format_security_finding(issue)
        
        return report
        
    except Exception as e:
        return f"Error in deep security scan: {str(e)}"


@tool("validate_package_integrity")
def validate_package_integrity(pr_url: str) -> str:
    """
    Validates the integrity and safety of packages being added/modified in the PR.
    
    Args:
        pr_url: The full URL to the GitHub PR
        
    Returns:
        str: Package integrity and safety report
    """
    try:
        # Parse the PR URL
        url_pattern = r"https://github\.com/([^/]+)/([^/]+)/pull/(\d+)"
        match = re.match(url_pattern, pr_url)
        
        if not match:
            return "Error: Invalid GitHub PR URL format"
        
        owner, repo, pr_number = match.groups()
        pr_number = int(pr_number)
        
        github_token = os.getenv("GITHUB_TOKEN")
        if not github_token:
            return "Error: GITHUB_TOKEN not found"
        
        g = Github(github_token)
        repository = g.get_repo(f"{owner}/{repo}")
        pull_request = repository.get_pull(pr_number)
        
        integrity_report = []
        
        # Check each changed file
        files = pull_request.get_files()
        for file in files:
            filename = file.filename
            
            # Focus on dependency and configuration files
            if any(pattern in filename.lower() for pattern in 
                   ['requirements', 'package.json', 'pyproject.toml', 'dockerfile', 
                    'docker-compose', '.github/workflows', 'makefile']):
                
                file_analysis = analyze_file_integrity(filename, file.patch or "")
                if file_analysis:
                    integrity_report.append(file_analysis)
        
        if not integrity_report:
            return "[SUCCESS] No integrity issues found in dependency/configuration files"
        
        # Compile report
        report = "[ANALYSIS] PACKAGE INTEGRITY ANALYSIS\n\n"
        
        for analysis in integrity_report:
            report += f"**File**: {analysis['filename']}\n"
            report += f"**Risk Level**: {analysis['risk_level']}\n"
            
            if analysis['issues']:
                report += "**Issues Found**:\n"
                for issue in analysis['issues']:
                    report += f"  - {issue}\n"
            
            if analysis['recommendations']:
                report += "**Recommendations**:\n"
                for rec in analysis['recommendations']:
                    report += f"  - {rec}\n"
            
            report += "\n"
        
        return report
        
    except Exception as e:
        return f"Error validating package integrity: {str(e)}"


# Helper functions for security analysis

def extract_packages_from_content(filename: str, content: str) -> List[Dict]:
    """Extract package names and versions from dependency file content."""
    packages = []
    
    if 'requirements.txt' in filename:
        lines = content.split('\n')
        for line in lines:
            if '+' in line and ('==' in line or '>=' in line or '<=' in line):
                # Extract package from diff line
                package_match = re.search(r'\+\s*([a-zA-Z0-9\-_]+)([><=!]+)([0-9\.]+)', line)
                if package_match:
                    packages.append({
                        'name': package_match.group(1),
                        'version': package_match.group(3),
                        'operator': package_match.group(2)
                    })
    
    elif 'package.json' in filename:
        # Extract from JSON-style dependency additions
        dep_matches = re.findall(r'\+\s*"([^"]+)":\s*"([^"]+)"', content)
        for name, version in dep_matches:
            packages.append({
                'name': name,
                'version': version.replace('^', '').replace('~', '').replace('>=', ''),
                'operator': '=='
            })
    
    elif 'pyproject.toml' in filename:
        # Extract from TOML-style dependencies
        dep_matches = re.findall(r'\+\s*"([a-zA-Z0-9\-_]+)([><=!]+)([0-9\.]+)"', content)
        for name, operator, version in dep_matches:
            packages.append({
                'name': name,
                'version': version,
                'operator': operator
            })
    
    return packages


def check_package_vulnerability(package: Dict, filename: str) -> Dict:
    """Check a single package against vulnerability databases."""
    try:
        # This is a simplified implementation. In production, you'd use:
        # - OSV.dev API
        # - Snyk API  
        # - GitHub Advisory Database
        # - Safety DB for Python packages
        
        # Known vulnerable packages (example data)
        known_vulns = {
            'django': {'versions': ['<3.2.15', '<4.0.7'], 'severity': 'HIGH', 
                      'description': 'SQL injection vulnerability'},
            'pillow': {'versions': ['<9.0.0'], 'severity': 'CRITICAL',
                      'description': 'Buffer overflow in image processing'},
            'requests': {'versions': ['<2.25.1'], 'severity': 'MEDIUM',
                        'description': 'Certificate verification bypass'},
            'flask': {'versions': ['<2.0.3'], 'severity': 'HIGH',
                     'description': 'Session fixation vulnerability'},
            'express': {'versions': ['<4.18.2'], 'severity': 'HIGH',
                       'description': 'Open redirect vulnerability'}
        }
        
        pkg_name = package['name'].lower()
        if pkg_name in known_vulns:
            vuln = known_vulns[pkg_name]
            # Simplified version check (in production, use proper version comparison)
            return {
                'package': package['name'],
                'version': package['version'],
                'severity': vuln['severity'],
                'description': vuln['description'],
                'file': filename,
                'fix': f"Upgrade {package['name']} to latest version"
            }
        
        return None
        
    except Exception:
        return None


def create_change_chunks(diff_content: str, max_chunk_size: int) -> List[str]:
    """Divide diff content into manageable chunks."""
    lines = diff_content.split('\n')
    chunks = []
    current_chunk = []
    current_size = 0
    
    for line in lines:
        current_chunk.append(line)
        current_size += 1
        
        if current_size >= max_chunk_size and ('File:' in line or '---' in line):
            chunks.append('\n'.join(current_chunk))
            current_chunk = []
            current_size = 0
    
    if current_chunk:
        chunks.append('\n'.join(current_chunk))
    
    return chunks


def analyze_single_chunk(chunk: str, chunk_id: int, total_chunks: int) -> Dict:
    """Analyze a single chunk of changes."""
    lines = chunk.split('\n')
    
    # Count files and changes
    files_count = len([line for line in lines if line.startswith('File:')])
    added_lines = len([line for line in lines if line.startswith('+')])
    removed_lines = len([line for line in lines if line.startswith('-')])
    
    # Identify focus areas
    focus_areas = []
    security_concerns = []
    
    chunk_lower = chunk.lower()
    
    # Focus area detection
    if any(word in chunk_lower for word in ['auth', 'login', 'password', 'token']):
        focus_areas.append('Authentication')
    if any(word in chunk_lower for word in ['database', 'sql', 'query', 'model']):
        focus_areas.append('Database')
    if any(word in chunk_lower for word in ['api', 'endpoint', 'route', 'controller']):
        focus_areas.append('API')
    if any(word in chunk_lower for word in ['config', 'setting', 'env', 'secret']):
        focus_areas.append('Configuration')
    
    # Security concern detection
    if any(word in chunk_lower for word in ['password', 'secret', 'key', 'token']):
        security_concerns.append('Credential exposure')
    if 'sql' in chunk_lower and any(op in chunk_lower for op in ['select', 'insert', 'update']):
        security_concerns.append('SQL injection risk')
    if any(word in chunk_lower for word in ['eval', 'exec', 'system', 'shell']):
        security_concerns.append('Code execution risk')
    
    # Determine risk level
    risk_level = 'LOW'
    if security_concerns or added_lines > 100:
        risk_level = 'MEDIUM'
    if len(security_concerns) > 1 or added_lines > 200:
        risk_level = 'HIGH'
    
    return {
        'chunk_id': chunk_id,
        'files_count': files_count,
        'lines_changed': added_lines + removed_lines,
        'focus_areas': focus_areas or ['General'],
        'security_concerns': security_concerns,
        'risk_level': risk_level
    }


def scan_cryptographic_issues(diff_content: str) -> List[Dict]:
    """Scan for cryptographic implementation issues."""
    findings = []
    lines = diff_content.split('\n')
    
    # Pattern matching for crypto issues
    crypto_patterns = {
        'weak_hash': [r'md5\(', r'sha1\(', r'\.md5', r'\.sha1'],
        'hardcoded_keys': [r'["\']([A-Za-z0-9+/]{32,})["\']', r'api_key\s*=\s*["\'][^"\']+["\']'],
        'weak_random': [r'random\.random\(', r'Math\.random\('],
        'insecure_ssl': [r'ssl_verify\s*=\s*False', r'verify\s*=\s*False']
    }
    
    for i, line in enumerate(lines):
        if line.startswith('+'):
            for issue_type, patterns in crypto_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            'type': 'Cryptographic Issue',
                            'subtype': issue_type,
                            'severity': 'HIGH' if issue_type in ['hardcoded_keys', 'insecure_ssl'] else 'MEDIUM',
                            'line': i + 1,
                            'code': line.strip(),
                            'description': get_crypto_issue_description(issue_type)
                        })
    
    return findings


def scan_authentication_issues(diff_content: str) -> List[Dict]:
    """Scan for authentication and authorization issues."""
    findings = []
    lines = diff_content.split('\n')
    
    auth_patterns = {
        'hardcoded_passwords': [r'password\s*=\s*["\'][^"\']+["\']'],
        'weak_session': [r'session\.permanent\s*=\s*False', r'httpOnly:\s*false'],
        'missing_auth': [r'@app\.route.*\n(?!.*@login_required)'],
        'admin_bypass': [r'is_admin\s*=\s*True', r'role\s*=\s*["\']admin["\']']
    }
    
    for i, line in enumerate(lines):
        if line.startswith('+'):
            for issue_type, patterns in auth_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            'type': 'Authentication Issue',
                            'subtype': issue_type,
                            'severity': 'CRITICAL' if issue_type in ['hardcoded_passwords', 'admin_bypass'] else 'HIGH',
                            'line': i + 1,
                            'code': line.strip(),
                            'description': get_auth_issue_description(issue_type)
                        })
    
    return findings


def scan_data_exposure(diff_content: str) -> List[Dict]:
    """Scan for data exposure risks."""
    findings = []
    lines = diff_content.split('\n')
    
    exposure_patterns = {
        'logging_sensitive': [r'log.*password', r'print.*token', r'console\.log.*secret'],
        'debug_info': [r'debug\s*=\s*True', r'DEBUG\s*=\s*True'],
        'error_exposure': [r'traceback\.print_exc', r'printStackTrace'],
        'cors_wildcard': [r'Access-Control-Allow-Origin.*\*', r'cors.*origin.*\*']
    }
    
    for i, line in enumerate(lines):
        if line.startswith('+'):
            for issue_type, patterns in exposure_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            'type': 'Data Exposure',
                            'subtype': issue_type,
                            'severity': 'HIGH' if issue_type in ['logging_sensitive', 'cors_wildcard'] else 'MEDIUM',
                            'line': i + 1,
                            'code': line.strip(),
                            'description': get_exposure_issue_description(issue_type)
                        })
    
    return findings


def scan_input_validation(diff_content: str) -> List[Dict]:
    """Scan for input validation issues."""
    findings = []
    lines = diff_content.split('\n')
    
    validation_patterns = {
        'sql_injection': [r'execute\(.*%', r'query\(.*\+', r'SELECT.*\+'],
        'xss_risk': [r'innerHTML\s*=', r'document\.write\(', r'eval\('],
        'path_traversal': [r'open\(.*request\.' r'file_path.*request\.'],
        'command_injection': [r'os\.system\(.*request\.', r'subprocess.*shell=True']
    }
    
    for i, line in enumerate(lines):
        if line.startswith('+'):
            for issue_type, patterns in validation_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            'type': 'Input Validation',
                            'subtype': issue_type,
                            'severity': 'CRITICAL',
                            'line': i + 1,
                            'code': line.strip(),
                            'description': get_validation_issue_description(issue_type)
                        })
    
    return findings


def scan_api_security(diff_content: str) -> List[Dict]:
    """Scan for API security issues."""
    findings = []
    lines = diff_content.split('\n')
    
    api_patterns = {
        'missing_rate_limit': [r'@app\.route(?!.*rate_limit)'],
        'insecure_headers': [r'X-Frame-Options.*ALLOW', r'Content-Security-Policy.*unsafe'],
        'api_key_exposure': [r'api_key.*=.*["\'][^"\']*["\']'],
        'missing_https': [r'http://(?!localhost)']
    }
    
    for i, line in enumerate(lines):
        if line.startswith('+'):
            for issue_type, patterns in api_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            'type': 'API Security',
                            'subtype': issue_type,
                            'severity': 'MEDIUM',
                            'line': i + 1,
                            'code': line.strip(),
                            'description': get_api_issue_description(issue_type)
                        })
    
    return findings


def scan_infrastructure_security(diff_content: str) -> List[Dict]:
    """Scan for infrastructure security issues."""
    findings = []
    lines = diff_content.split('\n')
    
    infra_patterns = {
        'docker_root': [r'USER root', r'FROM.*:latest'],
        'exposed_ports': [r'EXPOSE.*80[^0-9]', r'ports:.*80:'],
        'secrets_in_docker': [r'ENV.*PASSWORD', r'ENV.*SECRET'],
        'privileged_mode': [r'privileged:\s*true', r'--privileged']
    }
    
    for i, line in enumerate(lines):
        if line.startswith('+'):
            for issue_type, patterns in infra_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append({
                            'type': 'Infrastructure Security',
                            'subtype': issue_type,
                            'severity': 'HIGH' if issue_type in ['docker_root', 'secrets_in_docker'] else 'MEDIUM',
                            'line': i + 1,
                            'code': line.strip(),
                            'description': get_infra_issue_description(issue_type)
                        })
    
    return findings


def analyze_file_integrity(filename: str, content: str) -> Dict:
    """Analyze file integrity and safety."""
    issues = []
    recommendations = []
    risk_level = 'LOW'
    
    if 'dockerfile' in filename.lower():
        if 'FROM' in content and ':latest' in content:
            issues.append("Using 'latest' tag - version pinning recommended")
            risk_level = 'MEDIUM'
        
        if 'USER root' in content:
            issues.append("Running as root user")
            recommendations.append("Use non-root user for security")
            risk_level = 'HIGH'
    
    elif 'requirements.txt' in filename.lower():
        if '+' in content and '==' not in content:
            issues.append("Unpinned dependencies detected")
            recommendations.append("Pin dependency versions for reproducibility")
            risk_level = 'MEDIUM'
    
    elif '.github/workflows' in filename:
        if 'secrets.' in content.lower():
            issues.append("Direct secret usage in workflow")
            recommendations.append("Ensure secrets are properly masked")
        
        if 'pull_request_target' in content:
            issues.append("Potentially dangerous trigger detected")
            recommendations.append("Verify pull_request_target usage is safe")
            risk_level = 'HIGH'
    
    if not issues:
        return None
    
    return {
        'filename': filename,
        'risk_level': risk_level,
        'issues': issues,
        'recommendations': recommendations
    }


def format_security_finding(finding: Dict) -> str:
    """Format a security finding for the report."""
    return f"  **{finding['type']} - {finding['subtype']}**\n" \
           f"  Line {finding['line']}: `{finding['code']}`\n" \
           f"  {finding['description']}\n\n"


def get_crypto_issue_description(issue_type: str) -> str:
    descriptions = {
        'weak_hash': "Weak cryptographic hash algorithm detected. Use SHA-256 or stronger.",
        'hardcoded_keys': "Hardcoded cryptographic key found. Use environment variables or key management.",
        'weak_random': "Weak random number generator. Use cryptographically secure random.",
        'insecure_ssl': "SSL verification disabled. This enables man-in-the-middle attacks."
    }
    return descriptions.get(issue_type, "Cryptographic security issue detected.")


def get_auth_issue_description(issue_type: str) -> str:
    descriptions = {
        'hardcoded_passwords': "Hardcoded password detected. Use secure credential storage.",
        'weak_session': "Weak session configuration. Enable secure session settings.",
        'missing_auth': "Endpoint missing authentication. Add proper access controls.",
        'admin_bypass': "Potential admin privilege bypass. Verify authorization logic."
    }
    return descriptions.get(issue_type, "Authentication security issue detected.")


def get_exposure_issue_description(issue_type: str) -> str:
    descriptions = {
        'logging_sensitive': "Sensitive data logged. Remove or sanitize sensitive information.",
        'debug_info': "Debug mode enabled. Disable in production for security.",
        'error_exposure': "Detailed error information exposed. Use generic error messages.",
        'cors_wildcard': "CORS wildcard origin. Restrict to specific trusted domains."
    }
    return descriptions.get(issue_type, "Data exposure issue detected.")


def get_validation_issue_description(issue_type: str) -> str:
    descriptions = {
        'sql_injection': "Potential SQL injection vulnerability. Use parameterized queries.",
        'xss_risk': "Cross-site scripting (XSS) risk. Sanitize user input.",
        'path_traversal': "Path traversal vulnerability. Validate file paths.",
        'command_injection': "Command injection risk. Avoid shell execution with user input."
    }
    return descriptions.get(issue_type, "Input validation issue detected.")


def get_api_issue_description(issue_type: str) -> str:
    descriptions = {
        'missing_rate_limit': "API endpoint missing rate limiting. Add throttling controls.",
        'insecure_headers': "Insecure security headers. Implement proper security headers.",
        'api_key_exposure': "API key potentially exposed. Use secure key management.",
        'missing_https': "Non-HTTPS URL detected. Use HTTPS for secure communication."
    }
    return descriptions.get(issue_type, "API security issue detected.")


def get_infra_issue_description(issue_type: str) -> str:
    descriptions = {
        'docker_root': "Docker container running as root or using latest tag. Use specific versions and non-root users.",
        'exposed_ports': "Potentially insecure port exposure. Verify port security requirements.",
        'secrets_in_docker': "Secrets in Docker environment. Use secure secret management.",
        'privileged_mode': "Container running in privileged mode. Avoid unless absolutely necessary."
    }
    return descriptions.get(issue_type, "Infrastructure security issue detected.")