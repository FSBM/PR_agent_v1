import threading
import time
import uuid
import sys
import traceback
import io
import contextlib
import re
import os
from typing import Optional

# Add parent directory to Python path so we can import src modules
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
import json
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Check for dependencies and provide fallback
DEPENDENCIES_AVAILABLE = True
missing_deps = []

try:
    from src.pr_agent.main import main as pr_agent_main
except ImportError as e:
    DEPENDENCIES_AVAILABLE = False
    missing_deps.append(f"pr_agent.main: {str(e)}")

try:
    import google.generativeai
    # Additional check for CrewAI Google GenAI integration
    from crewai import LLM
    # Try to instantiate an LLM to check if Google GenAI is properly configured
    test_llm = LLM(model="gemini/gemini-1.5-flash")
    GENAI_AVAILABLE = True
except ImportError as e:
    DEPENDENCIES_AVAILABLE = False
    missing_deps.append(f"crewai[google-genai]: {str(e)}")
    GENAI_AVAILABLE = False
except Exception as e:
    # This might happen if API key is missing, but the package is installed
    GENAI_AVAILABLE = True  # Package is available, just not configured

try:
    from github import Github
except ImportError as e:
    DEPENDENCIES_AVAILABLE = False
    missing_deps.append(f"PyGithub: {str(e)}")

def simulate_pr_analysis(pr_url: str, job_id: str):
    """Simulate PR analysis when dependencies are not available"""
    jobs[job_id]["status"] = "running"
    jobs[job_id]["output"] = "📋 Initializing simulated agents...\n"
    time.sleep(1)
    
    jobs[job_id]["output"] += "Setting up simulated tasks...\n"
    time.sleep(1)
    
    jobs[job_id]["output"] += "Starting simulated PR analysis...\n"
    time.sleep(1)
    
    jobs[job_id]["output"] += "Analyzing PR structure...\n"
    time.sleep(1)
    
    jobs[job_id]["output"] += "Performing simulated change analysis...\n"
    time.sleep(1)
    
    jobs[job_id]["output"] += "Executing simulated security review...\n"
    time.sleep(1)
    
    jobs[job_id]["output"] += "Simulated analysis complete\n"
    jobs[job_id]["output"] += "🎭 Simulation completed - install dependencies for real agent execution\n"
    jobs[job_id]["output"] += f"🐛 Debug info: Missing dependencies: {', '.join(missing_deps)}\n"
    
    jobs[job_id]["status"] = "completed"

app = FastAPI(title="PR Agent Runner")

# Configure CORS for production and development
origins = [
    "http://localhost:3000",  # Local development
    "http://127.0.0.1:3000",  # Local development
    "https://pr-agent-v1.vercel.app",  # Your Vercel URL
    # preview deployments handled by allow_origin_regex below
]

# In production, you might want to be more restrictive
if os.getenv("ENVIRONMENT") == "production":
    origins = [
        "https://pr-agent-v1.vercel.app",  # Your Vercel URL
        # preview deployments handled by allow_origin_regex below
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    # Allow preview deployments like: https://pr-agent-v1-git-main.fsbm.vercel.app
    allow_origin_regex=r"^https://pr-agent-v1(-.*)?\.vercel\.app$",
    allow_credentials=True,
    # Permit all methods for preflight/OPTIONS handling
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job store
jobs = {}
jobs_lock = threading.Lock()

class StartJobRequest(BaseModel):
    pr_url: Optional[str] = "https://github.com/example/repo/pull/1"

@app.post("/start-job")
def start_job(req: StartJobRequest):
    """
    Start a background job that runs the CrewAI agent (or a simulated fallback).
    Returns a job_id which can be polled via /job-status
    """
    job_id = str(uuid.uuid4())
    job = {
        "id": job_id,
        "status": "queued",
        "progress": 0,
        "result": None,
        "logs": [],
        # outputs stores structured agent output blocks (dicts with ts and message)
        "outputs": [],
        "pr_url": req.pr_url,
        "error": None,
    }
    with jobs_lock:
        jobs[job_id] = job

    thread = threading.Thread(target=_run_agent_job, args=(job_id, req.pr_url), daemon=True)
    thread.start()

    return {"job_id": job_id}

@app.get("/job-status")
def job_status(job_id: str):
    with jobs_lock:
        job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job_id not found")
    # Return a shallow copy to avoid accidental mutation by callers
    with jobs_lock:
        return dict(job)

@app.get("/")
async def index():
    try:
        with open("frontend/index.html", "r", encoding="utf-8") as f:
            html = f.read()
        return HTMLResponse(content=html)
    except Exception:
        return HTMLResponse(content="<html><body><h3>Frontend not found. See frontend/index.html</h3></body></html>")


@app.get("/health")
async def health_check():
    """Health check endpoint that reports dependency status"""
    return {
        "status": "ok",
        "dependencies_available": DEPENDENCIES_AVAILABLE,
        "missing_dependencies": missing_deps if not DEPENDENCIES_AVAILABLE else [],
        "mode": "production" if DEPENDENCIES_AVAILABLE else "simulation"
    }


def _update_job(job_id: str, **kwargs):
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return
        job.update(kwargs)


def _append_log(job_id: str, message: str):
    """Append a timestamped log message to the job's logs list."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    entry = f"{ts} | {message}"
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return
        logs = job.get("logs")
        if logs is None:
            job["logs"] = [entry]
        else:
            logs.append(entry)
        # Also append a structured output block for UI diffing/display
        outputs = job.get("outputs")
        if outputs is None:
            job["outputs"] = [{"ts": ts, "message": message}]
        else:
            outputs.append({"ts": ts, "message": message})


def _append_agent_output(job_id: str, output: str, output_type: str = "general"):
    """Append formatted agent output to the job's outputs list."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return
        outputs = job.get("outputs")
        if outputs is None:
            job["outputs"] = [{"ts": ts, "message": output, "type": output_type}]
        else:
            outputs.append({"ts": ts, "message": output, "type": output_type})


class OutputCapture:
    """Custom output capture for CrewAI agent logging"""
    
    def __init__(self, job_id: str):
        self.job_id = job_id
        self.captured_output = []
        self.current_block = []
        self.in_agent_block = False
        self.agent_block_type = None
        
    def write(self, text):
        """Capture and parse agent output"""
        if not text.strip():
            return
            
        lines = text.split('\n')
        for line in lines:
            if not line.strip():
                continue
                
            # Detect agent block headers (the fancy boxes in your console output)
            if '─────────────────────' in line and ('Agent Started' in line or 'Agent Tool' in line or 'Tool Input' in line or 'Tool Output' in line):
                # End current block if exists
                if self.current_block:
                    self._flush_current_block()
                
                # Start new block
                self.in_agent_block = True
                if 'Agent Started' in line:
                    self.agent_block_type = 'agent_started'
                elif 'Agent Tool' in line:
                    self.agent_block_type = 'tool_execution'
                elif 'Tool Input' in line:
                    self.agent_block_type = 'tool_input'
                elif 'Tool Output' in line:
                    self.agent_block_type = 'tool_output'
                else:
                    self.agent_block_type = 'general'
                    
                self.current_block = [line]
                
            elif '╰─────────────────────────────────────────────────────────────────╯' in line:
                # End of agent block
                if self.current_block:
                    self.current_block.append(line)
                    self._flush_current_block()
                self.in_agent_block = False
                self.agent_block_type = None
                
            elif self.in_agent_block:
                self.current_block.append(line)
                
            else:
                # Regular output - send immediately
                _append_agent_output(self.job_id, line, "console")
    
    def _flush_current_block(self):
        """Send accumulated block to frontend"""
        if self.current_block:
            block_content = '\n'.join(self.current_block)
            _append_agent_output(self.job_id, block_content, self.agent_block_type or "general")
            self.current_block = []
    
    def flush(self):
        """Flush any remaining content"""
        if self.current_block:
            self._flush_current_block()


def _run_agent_job(job_id: str, pr_url: str):
    _update_job(job_id, status="running", progress=0)
    # Add initial agent banner to logs so frontend can display it early
    banner = (
        "╭─────────────────────── 🤖 Agent System Initializing ────────────────────────╮\n"
        "│                                                                             │\n"
        "│  PR-Agent: Enhanced Security Analysis System                             │\n"
        "│                                                                             │\n"
        "│  Target: PR Analysis and Security Review                                    │\n"
        "│  URL: " + pr_url.ljust(60) + "    │\n"
        "│                                                                             │\n"
        "│  Analysis Components:                                                       │\n"
        "│  - Dependency Security Scanner                                             │\n"
        "│  - Change Chunk Analyzer                                                   │\n"
        "│  - Deep Security Analyzer                                                  │\n"
        "│  - Heuristic Scanner                                                       │\n"
        "│  - Architectural Analyzer                                                  │\n"
        "│                                                                             │\n"
        "╰─────────────────────────────────────────────────────────────────────────────╯"
    )
    _append_agent_output(job_id, banner, "system_init")

    # Check if dependencies are available
    if not DEPENDENCIES_AVAILABLE:
        _append_agent_output(job_id, "⚠️ Warning: Missing dependencies - running simulation mode", "warning")
        _append_agent_output(job_id, f"Missing: {', '.join(missing_deps)}", "warning")
        simulate_pr_analysis(pr_url, job_id)
        return

    try:
        # Attempt to import the local agent runner
        from src.pr_agent import main as pr_main

        # Set up output capture to redirect CrewAI output to frontend
        output_capture = OutputCapture(job_id)
        
        # Save original stdout/stderr
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        
        try:
            # Redirect stdout to capture CrewAI output
            sys.stdout = output_capture
            sys.stderr = output_capture
            
            # Run in a safe environment: set argv to include the PR URL
            old_argv = sys.argv[:]
            sys.argv = [old_argv[0], pr_url]

            try:
                # Report progress people can poll and append incremental logs
                _append_agent_output(job_id, "🚀 Initializing CrewAI agent system...", "progress")
                _update_job(job_id, progress=5)
                
                _append_agent_output(job_id, "📋 Loading agent configurations...", "progress")
                _update_job(job_id, progress=15)
                
                _append_agent_output(job_id, "🔧 Assembling security crew...", "progress")
                _update_job(job_id, progress=25)
                
                _append_agent_output(job_id, "🎯 Starting enhanced security PR analysis...", "progress")
                _update_job(job_id, progress=30)

                # Call the real agent main (may be long-running)
                _append_agent_output(job_id, "🔥 CrewAI agents activated - detailed logs will appear below:", "progress")
                pr_main.main()

                # If main returns normally, mark job done
                _update_job(job_id, progress=100, status="completed", result="Agent run completed successfully")
                _append_agent_output(job_id, "[SUCCESS] Security analysis completed successfully!", "completion")
                
            except SystemExit as se:
                # Capture exit code and continue
                _update_job(job_id, progress=100, status="completed", result=f"Agent exited with code {se.code}")
                _append_agent_output(job_id, f"[SUCCESS] Agent completed with exit code {se.code}", "completion")
            finally:
                sys.argv = old_argv
                
        finally:
            # Always restore original stdout/stderr
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            output_capture.flush()

    except Exception as e:
        # If any error occurs importing or running real agent, fallback to simulated run
        tb = traceback.format_exc()
        _update_job(job_id, status="running", progress=0, error=None)
        
        try:
            # Enhanced simulated long-running job with agent-style output
            _append_agent_output(job_id, "[WARNING] Agent import failed - running simulation mode", "warning")
            _append_agent_output(job_id, f"Original error: {str(e)}", "error_info")
            
            simulation_steps = [
                (10, "📋 Initializing simulated agents..."),
                                (25, "[INFO] Setting up simulated tasks..."), 
                (40, "[SYSTEM] Starting simulated PR analysis..."),
                (55, "[ANALYSIS] Analyzing PR structure..."),
                (70, "[ANALYSIS] Performing simulated change analysis..."),
                (85, "[SECURITY] Executing simulated security review..."),
                (100, "[SUCCESS] Simulated analysis complete")
            ]
            
            for progress, message in simulation_steps:
                _update_job(job_id, progress=progress)
                _append_agent_output(job_id, message, "simulation")
                time.sleep(1)  # simulate work
                
            _update_job(job_id, status="completed", result="Simulated agent run complete", progress=100)
            _append_agent_output(job_id, "🎭 Simulation completed - install CrewAI for real agent execution", "completion")
            
        except Exception as e2:
            _update_job(job_id, status="failed", error=str(e2))
            _append_agent_output(job_id, f"❌ Simulation failed: {e2}", "error")
            return
            
        # Also store the original error for debugging 
        _update_job(job_id, error=str(e) + "\n" + tb)
        _append_agent_output(job_id, f"🐛 Debug info: {e}", "debug")


@app.get("/jobs")
def list_jobs():
    with jobs_lock:
        return list(jobs.values())


@app.get("/job-stream")
def job_stream(request: Request, job_id: str):
    """
    Server-Sent Events (SSE) stream for a job. Clients can connect to receive
    incremental updates (progress, status, and logs) in near real-time. This
    is intended as a more efficient alternative to polling.
    """
    def event_generator(job_id: str):
        last_snapshot = None
        while True:
            # If client disconnected, stop generator
            if request.client_disconnected:
                break
            with jobs_lock:
                job = jobs.get(job_id)
                if not job:
                    payload = {"error": "job_id not found"}
                else:
                    # shallow copy
                    payload = dict(job)

            # Only send if changed since last time to reduce noise
            if payload != last_snapshot:
                last_snapshot = payload
                # SSE format: data: <json>\n\n
                yield f"data: {json.dumps(payload)}\n\n"

            # Stop streaming when job reaches terminal state
            if payload.get("status") in ("completed", "failed"):
                break

            # Sleep briefly before next check
            try:
                time.sleep(0.5)
            except GeneratorExit:
                break

    return StreamingResponse(event_generator(job_id), media_type="text/event-stream")
