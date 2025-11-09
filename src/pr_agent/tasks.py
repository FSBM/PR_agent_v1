# Try to import CrewAI Task - handle gracefully if not available
try:
    from crewai import Task
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    # Create dummy Task class if crewai is not available
    class Task:
        def __init__(self, *args, **kwargs):
            pass


class PRTasks:
    """
    Collection of tasks for Pull Request analysis workflow.
    Each task corresponds to a specific agent and defines clear inputs/outputs.
    """
    
    @staticmethod
    def fetch_diff_task(agent, pr_url: str) -> Task:
        """
        Task for fetching PR diff content from GitHub.
        
        Args:
            agent: The diff_fetcher_agent
            pr_url: GitHub PR URL
            
        Returns:
            Task that outputs raw diff content as string
        """
        return Task(
            description=f"""
            Fetch the complete diff content from the GitHub Pull Request at: {pr_url}
            
            Your task is to:
            1. Parse the GitHub PR URL to extract repository and PR number
            2. Use the GitHub API to fetch the pull request data
            3. Retrieve all file changes, additions, and deletions
            4. Format the diff content in a readable structure
            
            Expected Output: A comprehensive string containing:
            - PR metadata (title, author, base/head branches)
            - Summary of changes (files changed, total additions/deletions)
            - Complete diff content for each modified file
            """,
            expected_output="Raw diff content as a structured string with all file changes and metadata",
            agent=agent,
            output_file="pr_diff.txt"
        )
    
    @staticmethod
    def heuristic_analysis_task(agent, diff_content: str = None) -> Task:
        """
        Task for performing heuristic-based code analysis.
        
        Args:
            agent: The heuristic_scanner_agent
            diff_content: Raw diff content to analyze
            
        Returns:
            Task that outputs list of simple issues found
        """
        return Task(
            description=f"""
            Analyze the provided diff content for simple code smells and common issues using pattern matching.
            
            Your task is to scan for:
            1. TODO/FIXME/HACK comments that shouldn't be in production
            2. Debug statements (print(), console.log(), debugger, etc.)
            3. Hardcoded secrets or sensitive data patterns
            4. Commented-out code blocks
            5. Missing error handling (try/catch blocks)
            6. Magic numbers without constants
            7. Long functions (>50 lines)
            8. Deep nesting (>4 levels)
            9. Unused imports or variables
            10. Inconsistent naming conventions
            
            Input: The diff content will be provided from the previous task.
            
            Expected Output: A structured list of findings with:
            - Issue type and severity level
            - File name and line number
            - Description of the issue
            - Suggested fix or improvement
            """,
            expected_output="Structured list of heuristic findings with file locations, issue types, and recommendations",
            agent=agent
        )
    
    @staticmethod
    def architectural_analysis_task(agent, diff_content: str = None) -> Task:
        """
        Task for performing high-level architectural and security analysis.
        
        Args:
            agent: The architect_agent
            diff_content: Raw diff content to analyze
            
        Returns:
            Task that outputs architectural and security concerns
        """
        return Task(
            description=f"""
            Perform a comprehensive architectural and security analysis of the code changes.
            
            Your task is to analyze for:
            
            Security Concerns:
            - SQL injection vulnerabilities
            - Cross-site scripting (XSS) risks
            - Authentication/authorization bypasses
            - Insecure data handling
            - Exposure of sensitive information
            
            Performance Issues:
            - Inefficient database queries
            - Memory leaks or excessive memory usage
            - Blocking operations on main threads
            - Unnecessary API calls or loops
            
            Architectural Concerns:
            - Violation of SOLID principles
            - Tight coupling between components
            - Missing abstraction layers
            - Inconsistent error handling patterns
            - Breaking changes to public APIs
            
            Design Patterns:
            - Improper use of design patterns
            - Missing design patterns where beneficial
            - Code that doesn't follow established project patterns
            
            Input: The diff content will be provided from the previous task.
            
            Expected Output: A detailed analysis report with:
            - Security vulnerability assessment
            - Performance impact evaluation
            - Architectural recommendations
            - Priority levels for each finding
            """,
            expected_output="Comprehensive architectural analysis with security, performance, and design recommendations",
            agent=agent
        )
    
    @staticmethod
    def generate_report_task(agent, pr_url: str, heuristic_findings: str = None, 
                           architectural_findings: str = None) -> Task:
        """
        Task for synthesizing all findings into a final report and posting it.
        
        Args:
            agent: The report_writer_agent
            pr_url: GitHub PR URL where the report should be posted
            heuristic_findings: Results from heuristic analysis
            architectural_findings: Results from architectural analysis
            
        Returns:
            Task that outputs formatted report and posts it to GitHub
        """
        return Task(
            description=f"""
            Synthesize all analysis findings into a comprehensive, well-formatted report and post it to the GitHub PR.
            
            Your task is to:
            1. Collect findings from heuristic and architectural analysis
            2. Organize findings by severity (Critical, High, Medium, Low)
            3. Create a professional markdown report with clear sections
            4. Include actionable recommendations for each finding
            5. Post the final report as a comment on the GitHub PR
            
            Report Structure:
            - Executive Summary
            - Critical Issues (if any)
            - Security Findings
            - Performance Concerns
            - Code Quality Issues
            - Recommendations
            - Summary Statistics
            
            Input: Analysis results from previous tasks will be provided.
            Target PR: {pr_url}
            
            Expected Output: A professional markdown report posted as a GitHub PR comment with:
            - Clear categorization of issues
            - Severity levels and priorities
            - Specific file/line references
            - Actionable recommendations
            - Professional formatting with tables and sections
            """,
            expected_output="Successfully posted comprehensive PR review report to GitHub with all findings and recommendations",
            agent=agent
        )

    @staticmethod
    def dependency_security_task(agent, pr_url: str) -> Task:
        """
        Task for comprehensive dependency security analysis.
        
        Args:
            agent: The dependency_security_agent
            pr_url: GitHub PR URL
            
        Returns:
            Task that outputs vulnerability assessment and package safety report
        """
        return Task(
            description=f"""
            Perform comprehensive dependency security analysis for the GitHub PR at: {pr_url}
            
            Your task is to:
            1. Check ALL dependencies being added, updated, or modified in this PR
            2. Scan each package against multiple vulnerability databases:
               - OSV.dev (Open Source Vulnerability database)
               - CVE database  
               - GitHub Advisory Database
               - Language-specific databases (PyPI, npm, etc.)
            3. Verify package integrity and authenticity
            4. Check for typosquatting or suspicious packages
            5. Analyze dependency chains for transitive vulnerabilities
            6. Assess the overall security posture of dependencies
            
            CRITICAL REQUIREMENTS:
            - Check EVERY package, no matter how small or common
            - Report ALL vulnerabilities, even low-severity ones
            - Verify package names against official registries
            - Check for deprecated or unmaintained packages
            - Assess license compatibility and legal risks
            
            Expected Output: A comprehensive security report with:
            - Complete vulnerability assessment for all dependencies
            - Risk scoring for each package (Critical, High, Medium, Low)
            - Specific CVE numbers and CVSS scores where applicable
            - Remediation steps with version upgrade recommendations
            - Alternative package suggestions for vulnerable dependencies
            - Overall security score for the dependency changes
            """,
            expected_output="Detailed vulnerability report with specific CVEs, risk scores, and remediation steps for all dependencies",
            agent=agent
        )

    @staticmethod
    def change_chunking_task(agent, pr_url: str) -> Task:
        """
        Task for analyzing and chunking large PR changes.
        
        Args:
            agent: The change_analyzer_agent
            pr_url: GitHub PR URL
            
        Returns:
            Task that outputs change analysis and chunking strategy
        """
        return Task(
            description=f"""
            Analyze the scope and complexity of changes in the GitHub PR at: {pr_url}
            
            Your task is to:
            1. Assess the total size and complexity of the PR changes
            2. If the PR is large (>500 lines or >10 files), divide it into logical chunks
            3. Each chunk should be manageable for detailed review (<1000 lines)
            4. Maintain logical cohesion within chunks (related files together)
            5. Identify high-risk areas that need extra attention
            6. Create a review strategy that ensures comprehensive coverage
            
            CHUNKING STRATEGY:
            - Group related files (same feature/module) together
            - Separate high-risk changes (security, authentication, data handling)
            - Keep configuration changes in separate chunks
            - Maintain file dependency context within chunks
            - Prioritize chunks by risk level and impact
            
            For each chunk, provide:
            - Files included and their relationships
            - Primary focus areas (authentication, database, API, etc.)
            - Risk assessment (Low/Medium/High)
            - Estimated review time and complexity
            - Dependencies on other chunks
            
            Expected Output: A structured chunking plan with:
            - Total change summary (files, lines, complexity)
            - Individual chunk definitions with scope and focus
            - Risk assessment for each chunk
            - Recommended review order and priorities
            - Context preservation strategy across chunks
            """,
            expected_output="Comprehensive change analysis with logical chunking strategy for large PRs",
            agent=agent
        )

    @staticmethod
    def deep_security_analysis_task(agent, pr_url: str) -> Task:
        """
        Task for performing deep, comprehensive security analysis.
        
        Args:
            agent: The deep_security_agent
            pr_url: GitHub PR URL
            
        Returns:
            Task that outputs comprehensive security analysis report
        """
        return Task(
            description=f"""
            Perform intensive, multi-layered security analysis of the GitHub PR at: {pr_url}
            
            Your task is to conduct a comprehensive security review covering:
            
            1. CRYPTOGRAPHIC SECURITY:
               - Weak hash algorithms (MD5, SHA1)
               - Hardcoded cryptographic keys or secrets
               - Insecure random number generation
               - SSL/TLS certificate validation issues
               - Improper encryption implementation
            
            2. AUTHENTICATION & AUTHORIZATION:
               - Authentication bypass vulnerabilities
               - Session management flaws
               - Privilege escalation risks
               - Insecure password storage
               - Missing access controls
            
            3. DATA PROTECTION:
               - Sensitive data exposure in logs/errors
               - Insecure data transmission
               - Data validation and sanitization
               - Privacy compliance issues (GDPR, etc.)
               - Database security concerns
            
            4. INPUT VALIDATION & INJECTION:
               - SQL injection vulnerabilities
               - Cross-site scripting (XSS) risks
               - Command injection possibilities
               - Path traversal vulnerabilities
               - LDAP injection, XML injection, etc.
            
            5. API & WEB SECURITY:
               - CORS misconfigurations
               - Insecure HTTP headers
               - Rate limiting gaps
               - API versioning security
               - RESTful security best practices
            
            6. INFRASTRUCTURE SECURITY:
               - Docker/container security issues
               - CI/CD pipeline security
               - Environment configuration flaws
               - Secrets management problems
               - Network security configurations
            
            ANALYSIS DEPTH:
            - Examine ALL code changes line by line
            - Analyze data flow and control flow
            - Check for logic bombs or backdoors
            - Verify error handling security
            - Assess third-party integration security
            
            Expected Output: A detailed security analysis report with:
            - Executive summary of security posture
            - Categorized findings by security domain
            - Severity classification (Critical/High/Medium/Low)
            - Specific line references and code snippets
            - Detailed impact assessment for each finding
            - Step-by-step remediation instructions
            - Security testing recommendations
            """,
            expected_output="Comprehensive security analysis with detailed findings, impact assessment, and remediation steps",
            agent=agent
        )