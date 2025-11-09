import React, { useEffect, useState, useRef } from 'react'
import OutputRenderer from './components/OutputRenderer'
import { 
  Terminal, Activity, Settings, Database, 
  GitPullRequest, Play, Clock, AlertCircle, 
  CheckCircle2, Loader2, Search, ChevronRight, Trash2,
  History as HistoryIcon
} from 'lucide-react'

const BACKEND_BASE = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000'

export default function App() {
  const [jobs, setJobs] = useState([])
  const [activeJob, setActiveJob] = useState(null)
  const [outputs, setOutputs] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [prUrl, setPrUrl] = useState('')
  const [historyJobs, setHistoryJobs] = useState([])
  const [showingHistory, setShowingHistory] = useState(false)
  const pollRef = useRef(null)
  const lastOutputCount = useRef(0)
  const logContainerRef = useRef(null)

  // Auto-scroll to bottom of logs
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight
    }
  }, [outputs])

  // Load history from localStorage on component mount
  useEffect(() => {
    loadHistoryFromStorage()
  }, [])

  function loadHistoryFromStorage() {
    try {
      const storedHistory = localStorage.getItem('pr_analysis_history')
      if (storedHistory) {
        const parsed = JSON.parse(storedHistory)
        setHistoryJobs(parsed)
      }
    } catch (err) {
      console.error('Failed to load history from localStorage:', err)
    }
  }

  function saveJobToHistory(job) {
    try {
      const currentHistory = JSON.parse(localStorage.getItem('pr_analysis_history') || '[]')
      
      // Check if job already exists, update it if so
      const existingIndex = currentHistory.findIndex(h => h.id === job.id)
      const jobToSave = {
        ...job,
        timestamp: job.timestamp || new Date().toISOString(),
        outputs: outputs.length > 0 ? outputs : job.outputs || []
      }

      if (existingIndex >= 0) {
        currentHistory[existingIndex] = jobToSave
      } else {
        currentHistory.unshift(jobToSave) // Add to beginning
      }

      // Keep only last 50 jobs to avoid localStorage bloat
      const limitedHistory = currentHistory.slice(0, 50)
      
      localStorage.setItem('pr_analysis_history', JSON.stringify(limitedHistory))
      setHistoryJobs(limitedHistory)
    } catch (err) {
      console.error('Failed to save job to localStorage:', err)
    }
  }

  function clearHistory() {
    try {
      localStorage.removeItem('pr_analysis_history')
      setHistoryJobs([])
    } catch (err) {
      console.error('Failed to clear history:', err)
    }
  }

  function loadHistoryJob(historyJob) {
    setShowingHistory(true)
    setActiveJob(historyJob)
    setOutputs(historyJob.outputs || [])
    if (pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }

  async function fetchJobs() {
    try {
      const res = await fetch(`${BACKEND_BASE}/jobs`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setJobs(data)
      setError(null)
    } catch (err) {
      setError(err.message)
    }
  }

  async function fetchJobStatus(jobId) {
    try {
      const res = await fetch(`${BACKEND_BASE}/job-status?job_id=${jobId}`)
      if (!res.ok) throw new Error(`job-status HTTP ${res.status}`)
      const data = await res.json()
      const newOutputs = data.outputs || []
      if (newOutputs.length > lastOutputCount.current) {
        const toAdd = newOutputs.slice(lastOutputCount.current)
        setOutputs(prev => [...prev, ...toAdd])
        lastOutputCount.current = newOutputs.length
      }
      setActiveJob(data)
      setShowingHistory(false)
      
      // Save to history when job is completed or failed
      if (data.status === 'completed' || data.status === 'failed') {
        const jobToSave = {
          ...data,
          outputs: newOutputs,
          timestamp: data.timestamp || new Date().toISOString()
        }
        saveJobToHistory(jobToSave)
        if (pollRef.current) {
          clearInterval(pollRef.current)
          pollRef.current = null
        }
      }
    } catch (err) {
      setError(err.message)
    }
  }

  async function startJob() {
    if (!prUrl.trim()) return
    try {
      setLoading(true)
      setError(null)
      setShowingHistory(false)
      const res = await fetch(`${BACKEND_BASE}/start-job`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pr_url: prUrl.trim() })
      })
      if (!res.ok) throw new Error(`Failed: ${res.status}`)
      const data = await res.json()
      
      // Save initial job data to history
      const initialJob = {
        ...data,
        pr_url: prUrl.trim(),
        timestamp: new Date().toISOString(),
        status: 'running',
        progress: 0,
        outputs: []
      }
      saveJobToHistory(initialJob)
      
      lastOutputCount.current = 0
      setOutputs([])
      await fetchJobStatus(data.job_id)
      pollRef.current = setInterval(() => fetchJobStatus(data.job_id), 1000)
      setPrUrl('')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchJobs()
    return () => pollRef.current && clearInterval(pollRef.current)
  }, [])

  return (
    <div className="flex h-screen bg-app-bg text-gray-300 overflow-hidden font-sans">
      {/* SIDEBAR - Static specifically to match the requested professional UI */}
      <aside className="w-64 border-r border-border-dark bg-panel-bg flex-shrink-0 flex flex-col">
        <div className="h-14 flex items-center px-4 border-b border-border-dark">
          <div className="flex items-center gap-2 font-semibold text-white">
            <div className="w-6 h-6 bg-white rounded-md flex items-center justify-center">
              <Terminal size={16} className="text-black" />
            </div>
            <span>Veyor_</span>
          </div>
        </div>
        
        <div className="flex-1 py-4 overflow-y-auto">
          <div className="px-4 mb-2 text-xs font-semibold text-gray-500 uppercase tracking-wider">
            Dashboard
          </div>
          <nav className="space-y-0.5 px-2">
            <SidebarItem icon={Activity} label="Overview" />
            <SidebarItem icon={GitPullRequest} label="PR Analysis" active />
            {/* <SidebarItem icon={Database} label="Vulnerability DB" /> */}
          </nav>
          
          <div className="mt-8 px-4 mb-2 text-xs font-semibold text-gray-500 uppercase tracking-wider flex items-center justify-between">
            <span>Recent Jobs</span>
          </div>
          <div className="px-2 space-y-0.5 overflow-y-auto max-h-32">
            {jobs.slice().reverse().map(job => (
              <button
                key={job.id}
                onClick={() => {
                  if (pollRef.current) clearInterval(pollRef.current);
                  lastOutputCount.current = 0;
                  setOutputs([]);
                  fetchJobStatus(job.id);
                }}
                className={`w-full flex items-center gap-2 px-3 py-2 text-xs rounded-md transition-colors ${
                  activeJob?.id === job.id && !showingHistory
                    ? 'bg-border-dark text-white' 
                    : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
                }`}
              >
                <StatusIcon status={job.status} size={14} />
                <span className="truncate font-mono">{job.id.slice(0, 8)}...</span>
              </button>
            ))}
            {jobs.length === 0 && (
              <div className="px-3 py-2 text-xs text-gray-500 italic">
                No recent jobs
              </div>
            )}
          </div>

          <div className="mt-6 px-4 mb-2 text-xs font-semibold text-gray-500 uppercase tracking-wider flex items-center justify-between">
            <span>Analysis History</span>
            {historyJobs.length > 0 && (
              <button
                onClick={clearHistory}
                className="text-gray-500 hover:text-red-400 transition-colors"
                title="Clear history"
              >
                <Trash2 size={12} />
              </button>
            )}
          </div>
          <div className="px-2 space-y-0.5 overflow-y-auto flex-1">
            {historyJobs.map(job => (
              <button
                key={`history-${job.id}`}
                onClick={() => loadHistoryJob(job)}
                className={`w-full flex flex-col gap-1 px-3 py-2 text-xs rounded-md transition-colors ${
                  activeJob?.id === job.id && showingHistory
                    ? 'bg-border-dark text-white' 
                    : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
                }`}
              >
                <div className="flex items-center gap-2 w-full">
                  <StatusIcon status={job.status} size={14} />
                  <span className="truncate font-mono flex-1">{job.id.slice(0, 8)}...</span>
                  <HistoryIcon size={12} className="text-gray-500" />
                </div>
                {job.timestamp && (
                  <div className="text-xs text-gray-600 text-left">
                    {new Date(job.timestamp).toLocaleDateString()} {new Date(job.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                  </div>
                )}
                {job.pr_url && (
                  <div className="text-xs text-gray-600 text-left truncate">
                    {job.pr_url.split('/').slice(-2).join('/')}
                  </div>
                )}
              </button>
            ))}
            {historyJobs.length === 0 && (
              <div className="px-3 py-2 text-xs text-gray-500 italic">
                No history yet
              </div>
            )}
          </div>
        </div>

        <div className="p-4 border-t border-border-dark">
           <SidebarItem icon={Settings} label="Settings" />
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <main className="flex-1 flex flex-col min-w-0 bg-app-bg">
        {/* HEADER */}
        <header className="h-14 flex items-center justify-between px-6 border-b border-border-dark bg-app-bg flex-shrink-0">
          <div className="flex items-center gap-2 text-sm text-gray-400">
             <span>Dashboard</span>
             <ChevronRight size={14} />
             <span className="text-white">PR Analysis</span>
             {activeJob && (
               <>
                 <ChevronRight size={14} />
                 <span className="font-mono text-xs px-2 py-0.5 bg-border-dark rounded-full text-accent-purple">
                   {activeJob.id}
                 </span>
                 {showingHistory && (
                   <span className="text-xs px-2 py-0.5 bg-amber-500/20 text-amber-400 rounded-full ml-1">
                     History
                   </span>
                 )}
               </>
             )}
          </div>
          
          <div className="flex items-center gap-3">
             <div className="relative">
               <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
               <input 
                 type="text"
                 value={prUrl}
                 onChange={(e) => setPrUrl(e.target.value)}
                 onKeyDown={(e) => e.key === 'Enter' && startJob()}
                 placeholder="Paste GitHub PR URL..."
                 className="bg-panel-bg border border-border-dark rounded-md pl-9 pr-4 py-1.5 text-sm w-80 focus:outline-none focus:border-gray-600 transition-colors font-mono"
               />
             </div>
             <button
                onClick={startJob}
                disabled={loading || !prUrl}
                className="bg-white text-black px-4 py-1.5 rounded-md text-sm font-medium hover:bg-gray-200 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 transition-colors"
             >
               {loading ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
               Run Analysis
             </button>
          </div>
        </header>

        {/* DASHBOARD CONTENT */}
        <div className="flex-1 overflow-hidden flex flex-col">
          {error && (
            <div className="bg-red-500/10 border-l-2 border-status-red p-4 mx-6 mt-6 flex items-center gap-3 text-red-200">
              <AlertCircle size={18} className="text-status-red" />
              {error}
            </div>
          )}

          {activeJob ? (
             <div className="flex-1 flex flex-col min-h-0 p-6">
               {/* Job Status Banner */}
               <div className="bg-panel-bg border border-border-dark rounded-t-lg p-4 flex items-center justify-between flex-shrink-0">
                  <div className="flex items-center gap-4">
                    <div className="flex flex-col">
                       <span className="text-xs text-gray-500 uppercase font-semibold">Status</span>
                       <div className="flex items-center gap-2 mt-1">
                         <StatusIcon status={activeJob.status} />
                         <span className="capitalize text-white font-medium">{activeJob.status}</span>
                         {showingHistory && (
                           <span className="text-xs px-2 py-0.5 bg-amber-500/20 text-amber-400 rounded-full ml-2">
                             From History
                           </span>
                         )}
                       </div>
                    </div>
                    <div className="h-8 w-px bg-border-dark"></div>
                    <div className="flex flex-col">
                       <span className="text-xs text-gray-500 uppercase font-semibold">Progress</span>
                       <div className="flex items-center gap-2 mt-1 w-48">
                         <div className="flex-1 h-2 bg-border-dark rounded-full overflow-hidden">
                           <div 
                             className="h-full bg-accent-purple transition-all duration-500 ease-out"
                             style={{ width: `${activeJob.progress || 0}%` }}
                           />
                         </div>
                         <span className="text-xs font-mono w-10 text-right">{activeJob.progress}%</span>
                       </div>
                    </div>
                    {activeJob.timestamp && (
                      <>
                        <div className="h-8 w-px bg-border-dark"></div>
                        <div className="flex flex-col">
                          <span className="text-xs text-gray-500 uppercase font-semibold">Analyzed</span>
                          <span className="text-xs text-white mt-1">
                            {new Date(activeJob.timestamp).toLocaleDateString()} {new Date(activeJob.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                          </span>
                        </div>
                      </>
                    )}
                  </div>
                  {activeJob.pr_url && (
                    <div className="flex flex-col items-end">
                      <span className="text-xs text-gray-500 uppercase font-semibold">PR URL</span>
                      <a 
                        href={activeJob.pr_url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-xs text-accent-purple hover:text-white transition-colors mt-1 font-mono max-w-xs truncate"
                      >
                        {activeJob.pr_url.split('/').slice(-2).join('/')}
                      </a>
                    </div>
                  )}
               </div>

               {/* Tabs mimicking the screenshot */}
               <div className="flex items-center gap-6 px-4 border-x border-border-dark bg-panel-bg text-sm border-b">
                  <button className="py-3 px-1 border-b-2 border-accent-purple text-white font-medium">
                    {showingHistory ? 'Analysis Results' : 'Live Logs'}
                  </button>
                  <button className="py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-300">
                    Metrics
                  </button>
                  <button className="py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-300">
                    Artifacts
                  </button>
               </div>

               {/* LOG VIEWER - The core of the requested UI */}
               <div 
                 ref={logContainerRef}
                 className="flex-1 bg-[#0A0A0A] border-x border-b border-border-dark rounded-b-lg overflow-y-auto p-4 font-mono text-sm"
               >
                 {outputs.length === 0 ? (
                   <div className="h-full flex items-center justify-center text-gray-600 gap-2">
                     {showingHistory ? (
                       <span>No analysis outputs available for this job</span>
                     ) : (
                       <>
                         <Loader2 className="animate-spin" />
                         <span>Waiting for agent logs...</span>
                       </>
                     )}
                   </div>
                 ) : (
                   <div className="space-y-2">
                     {outputs.map((output, idx) => (
                       <OutputRenderer key={idx} output={output} />
                     ))}
                     {activeJob.status === 'running' && !showingHistory && (
                       <div className="flex items-center gap-2 text-gray-600 pl-2 animate-pulse">
                         <span className="w-2 h-4 bg-accent-purple/50 block"></span>
                       </div>
                     )}
                   </div>
                 )}
               </div>
             </div>
          ) : (
            <EmptyState />
          )}
        </div>
      </main>
    </div>
  )
}

// --- Subcomponents for cleaner main file ---

function SidebarItem({ icon: Icon, label, active }) {
  return (
    <button className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
      active 
        ? 'bg-accent-purple/10 text-accent-purple font-medium' 
        : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
    }`}>
      <Icon size={16} />
      {label}
    </button>
  )
}

function StatusIcon({ status, size = 18 }) {
  switch(status) {
    case 'completed': return <CheckCircle2 size={size} className="text-status-green" />
    case 'failed': return <AlertCircle size={size} className="text-status-red" />
    case 'running': return <Loader2 size={size} className="text-status-blue animate-spin" />
    default: return <Clock size={size} className="text-gray-500" />
  }
}

function EmptyState() {
  return (
    <div className="flex-1 flex items-center justify-center">
      <div className="text-center max-w-md p-6 border border-border-dark border-dashed rounded-xl bg-panel-bg/50">
        <div className="w-16 h-16 bg-border-dark/50 rounded-full flex items-center justify-center mx-auto mb-4">
          <GitPullRequest size={32} className="text-gray-600" />
        </div>
        <h3 className="text-lg font-medium text-white mb-2">No Analysis Running</h3>
        <p className="text-gray-500 text-sm mb-6">
          Paste a GitHub Pull Request URL in the top bar and click "Run Analysis" to start a new security review session.
        </p>
      </div>
    </div>
  )
}