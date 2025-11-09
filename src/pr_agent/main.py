#!/usr/bin/env python3
"""
PR-Agent: A Multi-Agent System for GitHub Pull Request Review
"""

import sys
import argparse
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def check_dependencies():
    """Check if required dependencies are available and provide helpful error messages."""
    missing_deps = []
    
    try:
        from crewai import Crew, Process
    except ImportError as e:
        missing_deps.append(("crewai", "pip install crewai[google-genai]>=0.36.0"))
    
    try:
        from github import Github
    except ImportError as e:
        missing_deps.append(("PyGithub", "pip install PyGithub>=1.59.1"))
    
    # Check for CrewAI Google GenAI integration
    try:
        from crewai import LLM
        # Try to create a test LLM to ensure Google GenAI is available
        test_llm = LLM(model="gemini/gemini-2.5-flash")
    except ImportError as e:
        missing_deps.append(("crewai[google-genai]", "pip install crewai[google-genai]>=0.36.0"))
    except Exception as e:
        # LLM instantiation failed - likely missing API key or configuration issue
        if "Google Gen AI native provider not available" in str(e):
            missing_deps.append(("crewai[google-genai]", "pip install crewai[google-genai]>=0.36.0"))
    
    if missing_deps:
        print("❌ Missing required dependencies:")
        for dep_name, install_cmd in missing_deps:
            print(f"  - {dep_name}: {install_cmd}")
        print("\nPlease install missing dependencies and try again.")
        return False
    
    return True

def main():
    """
    Main entry point for the PR-Agent CLI.
    """
    # Check dependencies first
    if not check_dependencies():
        print("\n🎭 Running in simulation mode due to missing dependencies...")
        print("📋 Initializing simulated agents...")
        print("Setting up simulated tasks...")
        print("Starting simulated PR analysis...")
        print("Analyzing PR structure...")
        print("Performing simulated change analysis...")
        print("Executing simulated security review...")
        print("Simulated analysis complete")
        print("🎭 Simulation completed - install dependencies for real agent execution")
        print(f"🐛 Debug info: Missing required modules")
        sys.exit(1)
    
    # Import here after dependency check
    from crewai import Crew, Process
    from .agents import PRAgents
    from .tasks import PRTasks


def main():
    """
    Main entry point for the PR-Agent CLI.
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="PR-Agent: AI-powered GitHub Pull Request review system",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://github.com/owner/repo/pull/123
  python main.py --url https://github.com/owner/repo/pull/456
        """
    )
    
    parser.add_argument(
        "pr_url",
        nargs="?",
        help="GitHub Pull Request URL (e.g., https://github.com/owner/repo/pull/123)"
    )
    
    parser.add_argument(
        "--url",
        dest="pr_url_alt",
        help="Alternative way to specify PR URL"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Determine the PR URL
    pr_url = args.pr_url or args.pr_url_alt
    
    if not pr_url:
        print("Error: GitHub PR URL is required")
        parser.print_help()
        sys.exit(1)
    
    # Validate URL format
    if not pr_url.startswith("https://github.com/") or "/pull/" not in pr_url:
        print("Error: Invalid GitHub PR URL format")
        print("Expected format: https://github.com/owner/repo/pull/123")
        sys.exit(1)
    
    print(f"Starting PR-Agent analysis for: {pr_url}")
    print("=" * 80)
    
    try:
        # Import here after dependency check
        from crewai import Crew, Process
        from .agents import PRAgents
        from .tasks import PRTasks
        
        # Initialize agents
        print("📋 Initializing agents...")
        agents = PRAgents()
        supervisor = agents.supervisor_agent()
        diff_fetcher = agents.diff_fetcher_agent()
        heuristic_scanner = agents.heuristic_scanner_agent()
        architect = agents.architect_agent()
        report_writer = agents.report_writer_agent()
        
        # Initialize new security-focused agents
        dependency_security = agents.dependency_security_agent()
        change_analyzer = agents.change_analyzer_agent()
        deep_security = agents.deep_security_agent()
        
        # Initialize tasks
        print("[INFO] Setting up tasks...")
        tasks = PRTasks()
        
        fetch_task = tasks.fetch_diff_task(diff_fetcher, pr_url)
        
        # New security tasks
        dependency_security_task = tasks.dependency_security_task(dependency_security, pr_url)
        change_chunking_task = tasks.change_chunking_task(change_analyzer, pr_url)
        deep_security_task = tasks.deep_security_analysis_task(deep_security, pr_url)
        
        # Existing analysis tasks
        heuristic_task = tasks.heuristic_analysis_task(heuristic_scanner)
        architectural_task = tasks.architectural_analysis_task(architect)
        report_task = tasks.generate_report_task(report_writer, pr_url)
        
        # Create crew with hierarchical process
        print("[SYSTEM] Assembling enhanced security crew...")
        crew = Crew(
            agents=[
                diff_fetcher, 
                dependency_security, 
                change_analyzer, 
                deep_security,
                heuristic_scanner, 
                architect, 
                report_writer
            ],
            tasks=[
                fetch_task,
                dependency_security_task,
                change_chunking_task, 
                deep_security_task,
                heuristic_task, 
                architectural_task, 
                report_task
            ],
            process=Process.hierarchical,
            manager_agent=supervisor,
            verbose=args.verbose
        )
        
        # Execute the crew
        print("[ANALYSIS] Starting enhanced security PR analysis...")
        print("[INFO] Security agents activated:")
        print("  - Dependency Security Scanner")
        print("  - Change Chunk Analyzer")  
        print("  - Deep Security Analyzer")
        print("  - Heuristic Scanner")
        print("  - Architectural Analyzer")
        print("-" * 40)
        
        result = crew.kickoff(inputs={'pr_url': pr_url})
        
        print("-" * 40)
        print("[SUCCESS] Enhanced security PR analysis completed!")
        print("[INFO] Security layers analyzed:")
        print("  • Dependency vulnerabilities")
        print("  • Large change breakdown") 
        print("  • Deep security patterns")
        print("  • Code quality issues")
        print("  • Architectural concerns")
        print("\nFinal Result:")
        print(result)
        
    except KeyboardInterrupt:
        print("\n❌ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during analysis: {str(e)}")
        print("\nPlease check:")
        print("1. Your GITHUB_TOKEN is valid and has necessary permissions")
        print("2. Your GOOGLE_API_KEY is valid")
        print("3. The PR URL is correct and accessible")
        print("4. All required dependencies are installed")
        sys.exit(1)


if __name__ == "__main__":
    main()
