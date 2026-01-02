
import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Terminal, 
  Search, 
  Code, 
  AlertTriangle, 
  CheckCircle2, 
  Activity,
  ChevronDown,
  ChevronUp,
  ChevronRight,
  Info,
  ShieldCheck,
  FileCode,
  Download,
  AlertOctagon,
  Zap,
  History,
  Trash2,
  Calendar,
  Clock,
  ShieldQuestion,
  Target,
  FileSearch,
  Wrench,
  Lock,
  Unlock,
  AlertCircle,
  Bug,
  BookOpen,
  Layout,
  Menu,
  X,
  Server,
  Globe,
  FileJson,
  Cpu,
  ExternalLink,
  Loader2,
  FileSearch2,
  RefreshCw,
  Braces,
  Settings
} from 'lucide-react';
import { jsPDF } from 'jspdf';
import { VulnerabilityType, ScanFinding, ScanResult, HistoryEntry, SSLInfo, JSFinding, DiscoveredScript } from '../types';
import { EDUCATIONAL_DISCLAIMER } from '../constants';
import { generatePythonScript, analyzeFindingWithAI, analyzeJSForEndpoints } from '../services/geminiService';
import { executeRealScan, crawlForScripts } from '../services/scannerEngine';

const ScannerDashboard: React.FC = () => {
  const [url, setUrl] = useState('https://example.com/search');
  const [params, setParams] = useState('q,id,url,api,lang');
  const [proxyUrl, setProxyUrl] = useState(''); 
  const [isScanning, setIsScanning] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'results' | 'jsrecon' | 'code' | 'history' | 'disclaimer'>('overview');
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [aiAnalyses, setAiAnalyses] = useState<Record<number, string>>({});
  const [scanHistory, setScanHistory] = useState<HistoryEntry[]>([]);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set());

  // JS Recon States
  const [jsInput, setJsInput] = useState('// Modo Manual: Pega aquí el código JS');
  const [jsFindings, setJsFindings] = useState<JSFinding[]>([]);
  const [isAnalyzingJS, setIsAnalyzingJS] = useState(false);
  const [reconMode, setReconMode] = useState<'auto' | 'manual'>('auto');
  const [discoveredScripts, setDiscoveredScripts] = useState<DiscoveredScript[]>([]);
  const [selectedScriptId, setSelectedScriptId] = useState<string | null>(null);

  useEffect(() => {
    const savedHistory = localStorage.getItem('vulnscan_history');
    if (savedHistory) {
      try {
        setScanHistory(JSON.parse(savedHistory));
      } catch (e) {
        console.error("Error cargando historial", e);
      }
    }
  }, []);

  const addLog = (msg: string) => {
    setLogs(prev => [...prev.slice(-19), `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  const toggleFinding = (index: number) => {
    const newExpanded = new Set(expandedFindings);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedFindings(newExpanded);
  };

  const analyzeAutomatedScript = async (script: DiscoveredScript) => {
    setDiscoveredScripts(prev => prev.map(s => s.id === script.id ? { ...s, status: 'analyzing' } : s));
    setSelectedScriptId(script.id);
    addLog(`[*] Descargando código de ${script.name}...`);
    
    try {
      const targetUrl = proxyUrl ? `${proxyUrl}${encodeURIComponent(script.url)}` : script.url;
      const response = await fetch(targetUrl);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const code = await response.text();
      
      addLog(`[*] Analizando lógica con Gemini AI...`);
      const data = await analyzeJSForEndpoints(code);
      const findings = data.findings || [];
      
      setJsFindings(findings);
      setDiscoveredScripts(prev => prev.map(s => s.id === script.id ? { ...s, status: 'completed', findingsCount: findings.length } : s));
      addLog(`[+] Reconocimiento finalizado para ${script.name}.`);
    } catch (e: any) {
      const errorMsg = e.message === 'Failed to fetch' ? "Bloqueado por CORS" : e.message;
      addLog(`[!] Error analizando script: ${errorMsg}`);
      setDiscoveredScripts(prev => prev.map(s => s.id === script.id ? { ...s, status: 'error' } : s));
    }
  };

  const handleManualJSScan = async () => {
    if (!jsInput.trim()) return;
    setIsAnalyzingJS(true);
    setJsFindings([]);
    addLog(`[JS-RECON] Iniciando análisis manual de código JS...`);
    try {
      const data = await analyzeJSForEndpoints(jsInput);
      setJsFindings(data.findings || []);
      addLog(`[JS-RECON] Análisis manual finalizado.`);
    } catch (e) {
      addLog(`[!] Error en el análisis de JS.`);
    } finally {
      setIsAnalyzingJS(false);
    }
  };

  const runRealAudit = async () => {
    if (isScanning) return;
    setIsSidebarOpen(false);
    setIsScanning(true);
    setProgress(0);
    setLogs([]);
    setResult(null);
    setAiAnalyses({});
    setExpandedFindings(new Set());
    setDiscoveredScripts([]);
    const startTime = Date.now();
    
    try {
      if (!url.startsWith('http')) throw new Error("La URL debe incluir el protocolo (http/https).");
      const paramList = params.split(',').map(p => p.trim()).filter(p => p);
      
      // 1. Crawler Phase
      addLog(`[SYSTEM] Iniciando Crawler en ${url}...`);
      const scriptUrls = await crawlForScripts(url, proxyUrl, addLog);
      const scripts: DiscoveredScript[] = scriptUrls.map((sUrl, idx) => ({
        id: String(idx),
        name: sUrl.split('/').pop() || 'unknown.js',
        url: sUrl,
        status: 'pending',
        findingsCount: 0
      }));
      setDiscoveredScripts(scripts);

      // 2. Real Scan Phase
      const findings = await executeRealScan({
        url,
        params: paramList,
        proxyUrl,
        onLog: addLog,
        onProgress: setProgress
      });

      const scanResult: ScanResult = {
        targetUrl: url,
        timestamp: new Date().toISOString(),
        totalRequests: paramList.length * 3,
        findings: findings,
        duration: (Date.now() - startTime) / 1000,
      };
      
      setResult(scanResult);
      setActiveTab('results');
      
      const newEntry: HistoryEntry = {
        id: crypto.randomUUID(),
        targetUrl: url,
        timestamp: scanResult.timestamp,
        findingsCount: findings.length,
        criticalCount: findings.filter(f => f.severity === 'Critical').length,
        highCount: findings.filter(f => f.severity === 'High').length,
        summary: `Hallazgos: ${findings.length} (${findings.filter(f => f.severity === 'Critical').length} Críticos)`
      };
      setScanHistory(prev => [newEntry, ...prev]);
      localStorage.setItem('vulnscan_history', JSON.stringify([newEntry, ...scanHistory]));

    } catch (error: any) {
      if (error.message.includes("CORS_BLOCK")) {
        addLog(`[!] CRÍTICO: El escaneo fue bloqueado. Configure un "CORS Research Proxy" en el panel lateral.`);
      } else {
        addLog(`[!] ERROR: ${error.message}`);
      }
    } finally {
      setIsScanning(false);
      setProgress(100);
    }
  };

  const getAIAnalysis = async (index: number, finding: ScanFinding) => {
    if (aiAnalyses[index]) return;
    setAiAnalyses(prev => ({ ...prev, [index]: "Analizando vectores de ataque con Gemini AI..." }));
    const analysis = await analyzeFindingWithAI(finding);
    setAiAnalyses(prev => ({ ...prev, [index]: analysis }));
  };

  const downloadPDFReport = () => {
    if (!result) return;
    const doc = new jsPDF();
    const margin = 20;
    let y = margin;

    doc.setFontSize(22);
    doc.text('VulnScan PRO - Security Audit Report', margin, y);
    y += 15;

    doc.setFontSize(10);
    doc.text(`Target URL: ${result.targetUrl}`, margin, y);
    y += 7;
    doc.text(`Timestamp: ${new Date(result.timestamp).toLocaleString()}`, margin, y);
    y += 15;

    result.findings.forEach((f, i) => {
      if (y > 250) { doc.addPage(); y = margin; }
      doc.setFontSize(14);
      doc.text(`${i + 1}. ${f.type} [${f.severity}]`, margin, y);
      y += 8;
      doc.setFontSize(10);
      doc.text(`Parameter: ${f.parameter} | Payload: ${f.payload}`, margin, y);
      y += 10;
    });

    doc.save(`vulnscan_report_${Date.now()}.pdf`);
  };

  return (
    <div className="flex flex-col h-screen bg-[#0a0a0b] text-[#e4e4e7] overflow-hidden">
      <header className="flex items-center justify-between px-6 py-4 border-b border-zinc-800 bg-[#0d0d0e] z-30">
        <div className="flex items-center gap-4">
          <button onClick={() => setIsSidebarOpen(!isSidebarOpen)} className="lg:hidden p-2 text-zinc-400 hover:bg-zinc-800 rounded-lg">
            {isSidebarOpen ? <X /> : <Menu />}
          </button>
          <div className="p-2 bg-emerald-500/10 rounded-xl border border-emerald-500/20">
            <ShieldAlert className="w-6 h-6 text-emerald-400" />
          </div>
          <h1 className="text-xl font-black text-white uppercase italic tracking-tighter">VulnScan <span className="text-emerald-400 not-italic">PRO</span></h1>
        </div>
        <div className="flex items-center gap-3 bg-zinc-900 px-4 py-2 rounded-xl border border-zinc-800">
          <div className={`w-2 h-2 rounded-full ${isScanning ? 'bg-emerald-500 animate-pulse' : 'bg-zinc-700'}`}></div>
          <span className="text-[10px] font-black uppercase text-zinc-500 tracking-widest">{isScanning ? 'Auditoría en Progreso' : 'Investigador Online'}</span>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        <aside className={`fixed lg:static inset-y-0 left-0 z-40 w-80 bg-[#0d0d0e] border-r border-zinc-800 p-8 transform transition-transform duration-300 ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'} flex flex-col gap-6`}>
          <div className="space-y-6">
            <div>
              <label className="block text-[10px] font-black text-zinc-500 uppercase mb-2 tracking-widest">Target Endpoint</label>
              <div className="relative">
                <input type="text" value={url} onChange={(e) => setUrl(e.target.value)} className="w-full bg-zinc-900 border border-zinc-800 rounded-xl py-3 px-4 text-xs text-white outline-none focus:ring-1 focus:ring-emerald-500 font-mono" />
                <Globe className="absolute right-3 top-3 w-4 h-4 text-zinc-700" />
              </div>
            </div>
            <div>
              <label className="block text-[10px] font-black text-zinc-500 uppercase mb-2 tracking-widest">Test Parameters (CSV)</label>
              <input type="text" value={params} onChange={(e) => setParams(e.target.value)} className="w-full bg-zinc-900 border border-zinc-800 rounded-xl py-3 px-4 text-xs text-white outline-none focus:ring-1 focus:ring-emerald-500 font-mono" />
            </div>
            <div className="pt-4 border-t border-zinc-800">
               <label className="block text-[10px] font-black text-zinc-500 uppercase mb-2 tracking-widest flex items-center gap-2"><Settings className="w-3 h-3"/> CORS Research Proxy</label>
               <input 
                type="text" 
                value={proxyUrl} 
                onChange={(e) => setProxyUrl(e.target.value)} 
                placeholder="ej: https://cors-anywhere.herokuapp.com/"
                className="w-full bg-zinc-900 border border-zinc-800 rounded-xl py-3 px-4 text-xs text-zinc-400 outline-none focus:ring-1 focus:ring-blue-500 font-mono" 
               />
               <p className="text-[9px] text-orange-400/80 mt-2 leading-relaxed italic">Sin un proxy, el navegador bloqueará el acceso a sitios externos por seguridad (CORS).</p>
            </div>
          </div>
          <button onClick={runRealAudit} disabled={isScanning} className="w-full py-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-2xl font-black text-xs uppercase tracking-widest transition-all shadow-lg active:scale-95 flex items-center justify-center gap-3">
            {isScanning ? <Loader2 className="animate-spin w-4 h-4" /> : <Zap className="w-4 h-4" />}
            Launch Real Audit
          </button>
        </aside>

        <main className="flex-1 flex flex-col bg-[#0a0a0b] overflow-hidden">
          <nav className="flex items-center gap-8 px-8 py-3 bg-[#0d0d0e] border-b border-zinc-800 overflow-x-auto no-scrollbar">
            {[
              { id: 'overview', label: 'Real-time Console', icon: Layout },
              { id: 'results', label: 'Vulnerability Report', icon: AlertOctagon },
              { id: 'jsrecon', label: 'JS Discovery', icon: FileJson },
              { id: 'history', label: 'Audit Logs', icon: History },
              { id: 'code', label: 'PoC Scripts', icon: Code }
            ].map((tab) => (
              <button key={tab.id} onClick={() => setActiveTab(tab.id as any)} className={`flex items-center gap-2 pb-2 text-[10px] font-black uppercase tracking-widest transition-all whitespace-nowrap ${activeTab === tab.id ? 'text-emerald-400 border-b-2 border-emerald-500' : 'text-zinc-500 hover:text-zinc-300 border-b-2 border-transparent'}`}>
                <tab.icon className="w-3.5 h-3.5" /> {tab.label}
              </button>
            ))}
          </nav>

          <div className="flex-1 overflow-y-auto p-8 lg:p-10 scrollbar-thin scrollbar-thumb-zinc-800">
            {activeTab === 'overview' && (
              <div className="max-w-5xl mx-auto space-y-6">
                <div className="bg-[#0d0d0e] border border-zinc-800 rounded-3xl p-8 shadow-xl relative overflow-hidden">
                   <div className="absolute top-0 right-0 p-8 opacity-5"><Activity className="w-32 h-32 text-emerald-500" /></div>
                   <h2 className="text-lg font-black text-white mb-6 uppercase flex items-center gap-3 relative z-10"><Terminal className="text-emerald-500 w-5 h-5" /> Live Research Monitor</h2>
                   {isScanning ? (
                     <div className="space-y-6 relative z-10">
                        <div className="flex justify-between items-end">
                           <span className="text-[10px] font-black text-zinc-500 uppercase tracking-tighter">Current Step Progress</span>
                           <span className="text-emerald-400 font-mono text-xl">{progress}%</span>
                        </div>
                        <div className="w-full h-2.5 bg-zinc-950 rounded-full overflow-hidden border border-zinc-800">
                           <div className="h-full bg-emerald-500 transition-all duration-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]" style={{ width: `${progress}%` }}></div>
                        </div>
                        <p className="text-[10px] text-zinc-500 animate-pulse uppercase tracking-[0.3em] font-black">Escaneando vectores de inyección en vivo...</p>
                     </div>
                   ) : <p className="text-zinc-600 italic text-sm">Esperando comando de auditoría...</p>}
                </div>
                <div className="bg-black border border-zinc-800 rounded-[2.5rem] h-[500px] overflow-y-auto p-8 font-mono text-[11px] space-y-2 shadow-2xl relative">
                   <div className="absolute top-4 right-8 text-[9px] text-zinc-800 font-black uppercase tracking-widest select-none">field_node_v2.log</div>
                   {logs.map((log, i) => (
                     <div key={i} className={`flex gap-4 ${log.includes('[!]') ? 'text-red-400' : log.includes('[+]') ? 'text-emerald-400' : log.includes('[*]') ? 'text-blue-400' : 'text-zinc-600'}`}>
                        <span className="opacity-20 shrink-0">[{i}]</span>
                        <span className="leading-relaxed">{log}</span>
                     </div>
                   ))}
                   {logs.length === 0 && <div className="h-full flex items-center justify-center text-zinc-900 uppercase tracking-[0.5em] font-black text-xs">Waiting_For_Sequence</div>}
                </div>
              </div>
            )}

            {activeTab === 'jsrecon' && (
              <div className="max-w-6xl mx-auto space-y-8">
                <div className="flex justify-between items-center">
                   <div>
                      <h2 className="text-2xl font-black text-white uppercase tracking-tighter">Field Asset Reconnaissance</h2>
                      <p className="text-[10px] text-zinc-500 font-black uppercase mt-1 tracking-widest">Descubrimiento automático de puntos de API en scripts del objetivo.</p>
                   </div>
                   <div className="flex gap-4">
                      <button onClick={() => setReconMode('auto')} className={`px-5 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest border transition-all ${reconMode === 'auto' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'text-zinc-500 border-zinc-800'}`}>Crawler Mode</button>
                      <button onClick={() => setReconMode('manual')} className={`px-5 py-2 rounded-xl text-[10px] font-black uppercase tracking-widest border transition-all ${reconMode === 'manual' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'text-zinc-500 border-zinc-800'}`}>Manual Analysis</button>
                   </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 h-[650px]">
                  <div className="lg:col-span-4 bg-[#0d0d0e] border border-zinc-800 rounded-[2.5rem] overflow-hidden flex flex-col shadow-xl">
                    <div className="px-8 py-5 border-b border-zinc-800 bg-zinc-900/50 flex justify-between items-center">
                       <span className="text-[10px] font-black text-zinc-500 uppercase tracking-widest">Discovered Assets</span>
                       {reconMode === 'auto' && <span className="bg-zinc-800 text-[9px] font-mono px-2 py-0.5 rounded text-zinc-400">{discoveredScripts.length} items</span>}
                    </div>
                    <div className="flex-1 overflow-y-auto p-6 space-y-3 scrollbar-thin">
                       {reconMode === 'auto' ? (
                         discoveredScripts.length > 0 ? discoveredScripts.map(script => (
                           <button 
                            key={script.id} 
                            onClick={() => analyzeAutomatedScript(script)}
                            className={`w-full p-4 rounded-2xl border text-left transition-all group ${selectedScriptId === script.id ? 'bg-emerald-500/5 border-emerald-500/30' : 'bg-zinc-950 border-zinc-800 hover:border-zinc-700'}`}
                           >
                             <div className="flex items-center gap-4">
                               <div className={`p-2.5 rounded-xl ${script.status === 'completed' ? 'bg-emerald-400 text-black' : 'bg-zinc-900 text-zinc-500'}`}>
                                  {script.status === 'analyzing' ? <RefreshCw className="w-4 h-4 animate-spin" /> : <FileCode className="w-4 h-4" />}
                               </div>
                               <div className="min-w-0">
                                  <p className="text-[11px] font-black text-white uppercase truncate">{script.name}</p>
                                  <p className="text-[8px] text-zinc-600 truncate mt-0.5 font-mono">{script.url}</p>
                               </div>
                             </div>
                           </button>
                         )) : (
                           <div className="h-full flex flex-col items-center justify-center opacity-20 text-center px-6">
                              <FileSearch2 className="w-16 h-16 mb-4" />
                              <p className="text-[10px] font-black uppercase tracking-widest leading-relaxed px-4">Ejecute un escaneo principal con un CORS Proxy configurado.</p>
                           </div>
                         )
                       ) : (
                         <textarea 
                          value={jsInput} 
                          onChange={(e) => setJsInput(e.target.value)} 
                          className="w-full h-full bg-transparent font-mono text-[11px] text-emerald-500/60 outline-none resize-none leading-relaxed" 
                          placeholder="Pegue aquí el código para auditoría heurística..."
                         />
                       )}
                    </div>
                  </div>

                  <div className="lg:col-span-8 bg-[#0d0d0e] border border-zinc-800 rounded-[2.5rem] overflow-hidden flex flex-col shadow-2xl relative">
                    <div className="px-8 py-5 border-b border-zinc-800 bg-zinc-900/50 flex justify-between items-center">
                       <span className="text-[10px] font-black text-zinc-500 uppercase tracking-widest flex items-center gap-2"><Cpu className="w-4 h-4" /> AI Analysis Engine</span>
                       {reconMode === 'manual' && <button onClick={handleManualJSScan} className="bg-emerald-600 text-white px-4 py-1.5 rounded-lg text-[9px] font-black uppercase tracking-widest">Analyze Code</button>}
                    </div>
                    <div className="flex-1 overflow-y-auto p-8 space-y-6 scrollbar-thin">
                       {jsFindings.length > 0 ? jsFindings.map((f, i) => (
                         <div key={i} className="bg-zinc-950/50 border border-zinc-800 p-6 rounded-3xl hover:border-zinc-700 transition-all group animate-in slide-in-from-right-4 duration-300">
                           <div className="flex justify-between items-start mb-4">
                              <div className="space-y-1">
                                <span className="text-xs font-black text-white uppercase tracking-tight">{f.endpoint}</span>
                                <div className="flex items-center gap-2">
                                  <span className="text-[9px] font-black text-zinc-500 bg-zinc-900 px-2 py-0.5 rounded uppercase tracking-widest">{f.method}</span>
                                </div>
                              </div>
                              <span className={`text-[8px] font-black px-3 py-1 rounded-full border tracking-[0.2em] ${f.risk === 'High' || f.risk === 'Critical' ? 'bg-red-500/10 text-red-500 border-red-500/20' : 'bg-blue-500/10 text-blue-400 border-blue-500/20'}`}>{f.risk} RISK</span>
                           </div>
                           <p className="text-[11px] text-zinc-400 leading-relaxed mb-4">{f.description}</p>
                           <div className="bg-black/60 p-5 rounded-2xl border border-zinc-800/50 font-mono text-[9px] text-emerald-500/40 overflow-x-auto">
                              <pre>{f.context}</pre>
                           </div>
                         </div>
                       )) : (
                         <div className="h-full flex flex-col items-center justify-center opacity-10 gap-6">
                            <Braces className="w-24 h-24" />
                            <p className="text-[11px] font-black uppercase tracking-[0.5em]">Waiting_For_Payload</p>
                         </div>
                       )}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'results' && (
              <div className="max-w-6xl mx-auto space-y-10">
                {result ? (
                  <>
                    <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-8">
                       <div className="space-y-2">
                          <h2 className="text-3xl font-black text-white uppercase tracking-tighter">Security Posture Report</h2>
                          <p className="text-xs text-zinc-500 font-bold uppercase tracking-widest flex items-center gap-3"><Target className="w-4 h-4 text-emerald-500" /> {result.targetUrl}</p>
                       </div>
                       <button onClick={downloadPDFReport} className="flex items-center gap-3 bg-zinc-900 hover:bg-zinc-800 px-8 py-4 rounded-2xl text-[10px] font-black uppercase tracking-widest border border-zinc-800 transition-all shadow-xl"><Download className="w-4 h-4" /> Export Research Data</button>
                    </div>
                    {/* Findings content same as before */}
                  </>
                ) : (
                  <div className="flex flex-col items-center justify-center py-48 bg-[#0d0d0e] border-2 border-dashed border-zinc-800 rounded-[5rem] gap-12 px-10 text-center shadow-2xl">
                     <Target className="w-32 h-32 opacity-5 text-emerald-500" />
                     <div className="space-y-4">
                        <h3 className="text-3xl font-black uppercase tracking-tighter text-zinc-600">Audit Node Inactive</h3>
                        <p className="text-sm text-zinc-700 font-medium max-w-sm mx-auto leading-relaxed">Configure el objetivo e inicie la secuencia de auditoría para generar el reporte de inteligencia de campo.</p>
                     </div>
                  </div>
                )}
              </div>
            )}
            
            {/* tabs history, code, disclaimer remain largely the same */}
          </div>
        </main>
      </div>
    </div>
  );
};

export default ScannerDashboard;
