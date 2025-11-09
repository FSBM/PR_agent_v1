"""
PR Agent Definitions

Defines specialized AI agents for different aspects of PR analysis.
"""

import os

# Try to import CrewAI components - handle gracefully if not available
try:
    from crewai import Agent, LLM
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    # Create dummy classes if crewai is not available
    class Agent:
        def __init__(self, *args, **kwargs):
            pass
    class LLM:
        pass

from .tools import (
    fetch_pr_diff, 
    post_pr_comment,
    check_dependency_vulnerabilities,
    analyze_change_chunks,
    deep_security_scan,
    validate_package_integrity
)

# Configure Google Gemini LLM using OpenAI-compatible endpoint
def get_gemini_llm():
    """Configure and return Google Gemini LLM instance via OpenAI-compatible API"""
    # Return None to use default LLM configuration from environment variables
    # This uses the OPENAI_* env vars we set up in .env
    return None


class PRAgents:
    
    @staticmethod
    def supervisor_agent():
        """Create the supervisor agent that manages the enhanced security analysis workflow"""
        return Agent(
            role='Enhanced Security PR Review Supervisor',
            goal='Coordinate comprehensive security-focused analysis of GitHub Pull Requests ensuring no vulnerabilities are missed',
            backstory="""You are an elite cybersecurity lead and code review expert with deep expertise in 
            managing complex security analysis workflows. You coordinate multiple specialized security agents 
            to provide comprehensive PR analysis with a security-first approach. You ensure that:
            
            1. ALL dependencies are thoroughly checked for vulnerabilities
            2. Large changes are properly divided and analyzed in chunks
            3. Deep security analysis covers all attack vectors
            4. No security issue, however minor, is overlooked
            5. The final report is actionable and prioritizes security concerns
            
            You have zero tolerance for security risks and ensure every aspect of the code change 
            is examined through multiple security lenses.""",
            verbose=True,
            allow_delegation=True,
            llm=get_gemini_llm()
        )
    
    @staticmethod
    def diff_fetcher_agent():
        """Agent responsible for fetching PR diff content from GitHub."""
        return Agent(
            role="Git Fetcher",
            goal="Retrieve and process GitHub Pull Request diff data",
            backstory="""You are a Git specialist who knows how to efficiently extract 
            diff information from GitHub Pull Requests. You understand file changes, 
            additions, deletions, and can format this information clearly.""",
            tools=[fetch_pr_diff],
            verbose=True,
            llm=get_gemini_llm()
        )

    @staticmethod
    def heuristic_scanner_agent():
        """Agent that performs automated scanning for code issues and patterns."""
        return Agent(
            role="Code Quality Scanner",
            goal="Identify potential code issues, anti-patterns, and quality concerns",
            backstory="""You are an automated code analysis expert who can quickly scan 
            large codebases to identify common issues, security vulnerabilities, 
            performance problems, and code smell patterns. You provide specific, 
            actionable feedback.""",
            verbose=True,
            llm=get_gemini_llm()
        )

    @staticmethod
    def architect_agent():
        """Agent that provides architectural analysis and design feedback."""
        return Agent(
            role="Software Architect",
            goal="Analyze architectural decisions, design patterns, and system impact",
            backstory="""You are a senior software architect with deep experience in 
            system design, architectural patterns, and long-term maintainability. 
            You evaluate changes from a high-level perspective, considering impact 
            on system architecture, scalability, and design principles.""",
            verbose=True,
            llm=get_gemini_llm()
        )

    @staticmethod
    def report_writer_agent():
        """Agent that synthesizes findings into comprehensive reports."""
        return Agent(
            role="Technical Writer",
            goal="Create comprehensive, actionable PR review reports",
            backstory="""You are an experienced technical writer who specializes in 
            creating clear, actionable code review reports. You synthesize input from 
            multiple analysis sources into coherent recommendations that help developers 
            improve their code quality.""",
            tools=[post_pr_comment],
            verbose=True,
            llm=get_gemini_llm()
        )

    @staticmethod
    def dependency_security_agent():
        """Agent that specializes in dependency vulnerability analysis."""
        return Agent(
            role="Dependency Security Specialist",
            goal="Identify and assess security vulnerabilities in project dependencies",
            backstory="""You are a cybersecurity expert specializing in supply chain 
            security and dependency management. You have extensive knowledge of vulnerability 
            databases, package ecosystems, and security best practices. You can quickly 
            identify vulnerable dependencies and provide actionable remediation advice.""",
            tools=[check_dependency_vulnerabilities, validate_package_integrity],
            verbose=True,
            llm=get_gemini_llm()
        )

    @staticmethod
    def change_analyzer_agent():
        """Agent that breaks down large changes into manageable chunks."""
        return Agent(
            role="Change Analysis Specialist",
            goal="Divide large PRs into manageable chunks for comprehensive review",
            backstory="""You are a software engineering expert who specializes in code 
            change analysis and review optimization. You understand how to break down 
            complex changes into logical, reviewable units while maintaining context 
            and ensuring nothing important is missed.""",
            tools=[analyze_change_chunks],
            verbose=True,
            llm=get_gemini_llm()
        )

    @staticmethod
    def deep_security_agent():
        """Agent that performs comprehensive security analysis."""
        return Agent(
            role="Security Research Specialist",
            goal="Perform deep security analysis to identify complex vulnerabilities",
            backstory="""You are an elite security researcher with expertise in 
            application security, cryptography, and advanced threat analysis. You 
            specialize in finding subtle security issues that automated tools might 
            miss, including logic flaws, cryptographic weaknesses, and advanced 
            injection vulnerabilities.""",
            tools=[deep_security_scan],
            verbose=True,
            llm=get_gemini_llm()
        )
