import React from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import AnsiToHtml from 'ansi-to-html'
import { 
  CheckCircle, 
  AlertTriangle, 
  AlertCircle, 
  XCircle, 
  Info, 
  Shield, 
  BarChart3, 
  FileText, 
  Settings, 
  Zap 
} from 'lucide-react'

const ansiConverter = new AnsiToHtml({
  newline: false,
  escapeXML: true,
  colors: {
    0: '#000000', // black
    1: '#d32f2f', // red
    2: '#388e3c', // green
    3: '#f57c00', // yellow/orange
    4: '#1976d2', // blue
    5: '#7b1fa2', // magenta/purple
    6: '#0097a7', // cyan
    7: '#e0e0e0', // white/light gray
  }
})

// Function to get React icon based on text indicators
const getIconFromText = (text) => {
  if (!text) return null
  
  const textLower = text.toLowerCase()
  
  if (text.includes('[SUCCESS]') || textLower.includes('completed') || textLower.includes('✅')) {
    return <CheckCircle className="w-4 h-4" />
  }
  if (text.includes('[WARNING]') || text.includes('[CRITICAL]') || textLower.includes('⚠️') || textLower.includes('🚨')) {
    return <AlertTriangle className="w-4 h-4" />
  }
  if (text.includes('[ERROR]') || textLower.includes('error') || textLower.includes('❌')) {
    return <XCircle className="w-4 h-4" />
  }
  if (text.includes('[SECURITY]') || textLower.includes('security') || textLower.includes('🔒')) {
    return <Shield className="w-4 h-4" />
  }
  if (text.includes('[ANALYSIS]') || textLower.includes('analysis') || textLower.includes('📊')) {
    return <BarChart3 className="w-4 h-4" />
  }
  if (text.includes('[INFO]') || textLower.includes('📝') || textLower.includes('info')) {
    return <FileText className="w-4 h-4" />
  }
  if (text.includes('[SYSTEM]') || textLower.includes('🔧') || textLower.includes('system')) {
    return <Settings className="w-4 h-4" />
  }
  
  return <Info className="w-4 h-4" />
}

const ToolExecutionBox = ({ children, type = 'general', title }) => {
  const getBoxStyle = (type) => {
    switch (type) {
      case 'tool_execution':
        return {
          border: 'border-purple-400',
          bg: 'bg-purple-900/20',
          header: 'bg-purple-800/30',
          text: 'text-purple-100',
          icon: <Settings className="w-4 h-4" />
        }
      case 'tool_input':
        return {
          border: 'border-blue-400',
          bg: 'bg-blue-900/20', 
          header: 'bg-blue-800/30',
          text: 'text-blue-100',
          icon: <Info className="w-4 h-4" />
        }
      case 'tool_output':
        return {
          border: 'border-green-400',
          bg: 'bg-green-900/20',
          header: 'bg-green-800/30', 
          text: 'text-green-100',
          icon: <CheckCircle className="w-4 h-4" />
        }
      case 'completion':
        return {
          border: 'border-green-400',
          bg: 'bg-green-900/20',
          header: 'bg-green-800/30',
          text: 'text-green-100', 
          icon: <CheckCircle className="w-4 h-4" />
        }
      case 'error':
        return {
          border: 'border-red-400',
          bg: 'bg-red-900/20',
          header: 'bg-red-800/30',
          text: 'text-red-100',
          icon: <XCircle className="w-4 h-4" />
        }
      default:
        return {
          border: 'border-gray-400',
          bg: 'bg-gray-900/20',
          header: 'bg-gray-800/30',
          text: 'text-gray-100',
          icon: <FileText className="w-4 h-4" />
        }
    }
  }

  const style = getBoxStyle(type)

  return (
    <div className={`${style.bg} ${style.border} border rounded-lg overflow-hidden font-mono text-sm`}>
      {title && (
        <div className={`${style.header} px-4 py-2 border-b ${style.border}`}>
          <div className="flex items-center space-x-2">
            <span>{style.icon}</span>
            <span className={`font-medium ${style.text}`}>{title}</span>
          </div>
        </div>
      )}
      <div className={`p-4 ${style.text}`}>
        {children}
      </div>
    </div>
  )
}

const CodeBlock = ({ children, className, ...props }) => {
  const match = /language-(\w+)/.exec(className || '')
  const language = match ? match[1] : ''
  
  return language ? (
    <SyntaxHighlighter
      style={vscDarkPlus}
      language={language}
      PreTag="div"
      className="rounded-md text-sm"
      customStyle={{
        margin: 0,
        background: '#1e1e1e',
        padding: '1rem',
      }}
      {...props}
    >
      {String(children).replace(/\n$/, '')}
    </SyntaxHighlighter>
  ) : (
    <code className="bg-gray-800 text-gray-100 px-2 py-1 rounded text-sm font-mono" {...props}>
      {children}
    </code>
  )
}

const parseStructuredContent = (message) => {
  // Check if message is valid
  if (!message || typeof message !== 'string') {
    return [{ type: 'text', content: message || '' }]
  }

  // Check if message contains the structured format with boxes
  const toolExecutionRegex = /╭─.*?🔧 Agent Tool Execution.*?─╮(.*?)╰.*?╯/gs
  const toolInputRegex = /╭─.*?Tool Input.*?─╮(.*?)╰.*?╯/gs
  const toolOutputRegex = /╭─.*?Tool Output.*?─╮(.*?)╰.*?╯/gs
  const finalAnswerRegex = /╭─.*?Agent Final Answer.*?─╮(.*?)╰.*?╯/gs

  const segments = []
  let lastIndex = 0

  // Find all structured segments
  const patterns = [
    { regex: toolExecutionRegex, type: 'tool_execution', title: 'Agent Tool Execution' },
    { regex: toolInputRegex, type: 'tool_input', title: 'Tool Input' },
    { regex: toolOutputRegex, type: 'tool_output', title: 'Tool Output' },
    { regex: finalAnswerRegex, type: 'completion', title: 'Agent Final Answer' }
  ]

  patterns.forEach(({ regex, type, title }) => {
    let match
    while ((match = regex.exec(message)) !== null) {
      // Add any plain text before this match
      if (match.index > lastIndex) {
        const plainText = message.slice(lastIndex, match.index).trim()
        if (plainText) {
          segments.push({ type: 'text', content: plainText })
        }
      }

      // Add the structured content
      const content = match[1].trim()
      segments.push({ type, content, title })
      lastIndex = match.index + match[0].length
    }
    regex.lastIndex = 0 // Reset regex
  })

  // Add any remaining text
  if (lastIndex < message.length) {
    const remainingText = message.slice(lastIndex).trim()
    if (remainingText) {
      segments.push({ type: 'text', content: remainingText })
    }
  }

  return segments.length > 0 ? segments : [{ type: 'text', content: message }]
}

const cleanAnsiText = (text) => {
  // Convert ANSI codes to HTML and then to clean text for markdown
  const htmlContent = ansiConverter.toHtml(text)
  // Remove HTML tags for markdown processing, but preserve the text
  return htmlContent.replace(/<[^>]*>/g, '')
}

// Function to clean text indicators while preserving content
const cleanTextIndicators = (text) => {
  if (!text) return text
  
  return text
    .replace(/\[SUCCESS\]/g, '')
    .replace(/\[WARNING\]/g, '')
    .replace(/\[ERROR\]/g, '')
    .replace(/\[CRITICAL\]/g, '')
    .replace(/\[SECURITY\]/g, '')
    .replace(/\[ANALYSIS\]/g, '')
    .replace(/\[INFO\]/g, '')
    .replace(/\[SYSTEM\]/g, '')
    .trim()
}

const OutputRenderer = ({ output, index }) => {
  const { ts, message, type = 'general' } = output

  const getOutputStyle = (type) => {
    switch (type) {
      case 'system_init':
        return 'bg-blue-900/30 border-blue-400 text-blue-100'
      case 'agent_started':
        return 'bg-green-900/30 border-green-400 text-green-100'
      case 'tool_execution':
        return 'bg-purple-900/30 border-purple-400 text-purple-100'
      case 'tool_input':
        return 'bg-blue-900/30 border-blue-400 text-blue-100'
      case 'tool_output':
        return 'bg-green-900/30 border-green-400 text-green-100'
      case 'progress':
        return 'bg-blue-900/30 border-blue-400 text-blue-100'
      case 'completion':
        return 'bg-green-900/30 border-green-400 text-green-100'
      case 'warning':
        return 'bg-yellow-900/30 border-yellow-400 text-yellow-100'
      case 'error':
        return 'bg-red-900/30 border-red-400 text-red-100'
      case 'error_info':
        return 'bg-red-900/30 border-red-400 text-red-100'
      case 'simulation':
        return 'bg-gray-900/30 border-gray-400 text-gray-100'
      case 'debug':
        return 'bg-gray-900/30 border-gray-500 text-gray-300'
      case 'console':
      default:
        return 'bg-gray-900/30 border-gray-400 text-gray-100'
    }
  }

  const getTypeIcon = (type, message = '') => {
    // First check if the message has text indicators
    const iconFromText = getIconFromText(message)
    if (iconFromText && message && (message.includes('[') || message.includes('🔒') || message.includes('✅') || message.includes('⚠️') || message.includes('📊'))) {
      return iconFromText
    }
    
    // Fallback to type-based icons
    switch (type) {
      case 'system_init': return <Zap className="w-4 h-4" />
      case 'agent_started': return <Settings className="w-4 h-4" />
      case 'tool_execution': return <Settings className="w-4 h-4" />
      case 'tool_input': return <Info className="w-4 h-4" />
      case 'tool_output': return <CheckCircle className="w-4 h-4" />
      case 'progress': return <Zap className="w-4 h-4" />
      case 'completion': return <CheckCircle className="w-4 h-4" />
      case 'warning': return <AlertTriangle className="w-4 h-4" />
      case 'error': return <XCircle className="w-4 h-4" />
      case 'error_info': return <AlertCircle className="w-4 h-4" />
      case 'simulation': return <FileText className="w-4 h-4" />
      case 'debug': return <Info className="w-4 h-4" />
      case 'console': return <FileText className="w-4 h-4" />
      default: return <FileText className="w-4 h-4" />
    }
  }

  // Parse the message for structured content
  const segments = parseStructuredContent(message) || []

  return (
    <div key={index} className={`p-4 rounded-lg border ${getOutputStyle(type)} mb-4`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center space-x-2">
          <span className="text-lg">{getTypeIcon(type, message)}</span>
          <span className="text-sm font-medium capitalize">
            {type.replace('_', ' ')}
          </span>
        </div>
        <div className="text-xs opacity-70 font-mono">{ts}</div>
      </div>
      
      <div className="space-y-4">
        {segments && segments.length > 0 ? segments.map((segment, idx) => {
          if (segment.type === 'text') {
            // Check if it's markdown content
            const rawContent = cleanAnsiText(segment.content)
            const cleanedContent = cleanTextIndicators(rawContent)
            const hasMarkdown = cleanedContent.includes('#') || 
                               cleanedContent.includes('*') || 
                               cleanedContent.includes('`') ||
                               cleanedContent.includes('[') ||
                               cleanedContent.includes('```')

            if (hasMarkdown) {
              return (
                <div key={idx} className="prose prose-invert prose-sm max-w-none">
                  <ReactMarkdown
                    remarkPlugins={[remarkGfm]}
                    components={{
                      code: CodeBlock,
                      pre: ({ children }) => (
                        <div className="bg-gray-800 rounded-lg overflow-hidden">
                          {children}
                        </div>
                      ),
                      h1: ({ children }) => (
                        <h1 className="text-xl font-bold text-white mb-4 pb-2 border-b border-gray-600">
                          {children}
                        </h1>
                      ),
                      h2: ({ children }) => (
                        <h2 className="text-lg font-semibold text-white mb-3 pb-1 border-b border-gray-700">
                          {children}
                        </h2>
                      ),
                      h3: ({ children }) => (
                        <h3 className="text-base font-semibold text-white mb-2">
                          {children}
                        </h3>
                      ),
                      ul: ({ children }) => (
                        <ul className="list-disc list-inside space-y-1 text-gray-200">
                          {children}
                        </ul>
                      ),
                      ol: ({ children }) => (
                        <ol className="list-decimal list-inside space-y-1 text-gray-200">
                          {children}
                        </ol>
                      ),
                      blockquote: ({ children }) => (
                        <blockquote className="border-l-4 border-blue-400 pl-4 py-2 bg-blue-900/20 text-blue-100 italic">
                          {children}
                        </blockquote>
                      ),
                      table: ({ children }) => (
                        <div className="overflow-x-auto">
                          <table className="min-w-full divide-y divide-gray-600">
                            {children}
                          </table>
                        </div>
                      ),
                      th: ({ children }) => (
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-300 uppercase tracking-wider bg-gray-800">
                          {children}
                        </th>
                      ),
                      td: ({ children }) => (
                        <td className="px-3 py-2 whitespace-nowrap text-sm text-gray-200 border-b border-gray-700">
                          {children}
                        </td>
                      )
                    }}
                  >
                    {cleanedContent}
                  </ReactMarkdown>
                </div>
              )
            } else {
              // Plain text or ANSI formatted text
              const cleanedForDisplay = cleanTextIndicators(segment.content)
              const htmlContent = ansiConverter.toHtml(cleanedForDisplay)
              return (
                <pre 
                  key={idx}
                  className="whitespace-pre-wrap text-sm font-mono leading-relaxed text-gray-200"
                  dangerouslySetInnerHTML={{ __html: htmlContent }}
                />
              )
            }
          } else {
            // Structured content (tool execution, input, output, etc.)
            const rawContent = cleanAnsiText(segment.content)
            const cleanedContent = cleanTextIndicators(rawContent)
            const htmlContent = ansiConverter.toHtml(cleanedContent)
            
            return (
              <ToolExecutionBox key={idx} type={segment.type} title={segment.title}>
                <pre 
                  className="whitespace-pre-wrap text-sm leading-relaxed"
                  dangerouslySetInnerHTML={{ __html: htmlContent }}
                />
              </ToolExecutionBox>
            )
          }
        }) : (
          <pre className="whitespace-pre-wrap text-sm font-mono leading-relaxed text-gray-200">
            {message || 'No content available'}
          </pre>
        )}
      </div>
    </div>
  )
}

export default OutputRenderer