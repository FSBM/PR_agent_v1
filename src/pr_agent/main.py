#!/usr/bin/env python3
"""
PR-Agent: A Multi-Agent System for GitHub Pull Request Review
"""

import sys
import argparse
import os
from dotenv import load_dotenv
from crewai import Crew, Process
from .agents import PRAgents
from .tasks import PRTasks

# Load environment variables
load_dotenv()


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
    
    print(f"🚀 Starting PR-Agent analysis for: {pr_url}")
    print("=" * 80)
    
    try:
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
        print("📝 Setting up tasks...")
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
        print("🔧 Assembling enhanced security crew...")
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
        print("🎯 Starting enhanced security PR analysis...")
        print("🔍 Security agents activated:")
        print("  ⚡ Dependency Security Scanner")
        print("  📊 Change Chunk Analyzer")  
        print("  🔒 Deep Security Analyzer")
        print("  🔍 Heuristic Scanner")
        print("  🏗️  Architectural Analyzer")
        print("-" * 40)
        
        result = crew.kickoff(inputs={'pr_url': pr_url})
        
        print("-" * 40)
        print("✅ Enhanced security PR analysis completed!")
        print(f"🔍 Security layers analyzed:")
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
