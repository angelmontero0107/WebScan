
import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, Terminal, Code, AlertTriangle, CheckCircle2, Activity,
  ChevronDown, ChevronUp, Download, AlertOctagon, Zap, History,
  Trash2, Calendar, Target, FileSearch, Wrench, Lock, Bug, BookOpen,
  Layout, Menu, X, Globe, FileJson, Cpu, Loader2, Braces, Settings,
  ShieldCheck, FileCode, RefreshCw, FileSearch2, Copy, Terminal as TerminalIcon
} from 'lucide-react';
import { jsPDF } from 'jspdf';
import { VulnerabilityType, ScanFinding, ScanResult, HistoryEntry, JSFinding, DiscoveredScript } from '../types';
import { EDUCATIONAL_DISCLAIMER } from '../constants';
import { generatePythonScript, analyzeFindingWithAI, analyzeJSForEndpoints } from '../services/geminiService';
import { executeRealScan, crawlForScripts } from '../services/scannerEngine';

const ScannerDashboard: React.FC = () => {
  const [url, setUrl] = useState('https://example.com/search');
  const [params, setParams] = useState('q,id,url');
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
  const [jsInput, setJsInput] = useState('// Pega código aquí para análisis de seguridad');
  const [jsFindings, setJsFindings] = useState<JSFinding[]>([]);
  const [isAnalyzingJS, setIsAnalyzingJS] = useState(false);
  const [reconMode, setReconMode] = useState<'auto' | 'manual'>('auto');
  const [discoveredScripts, setDiscoveredScripts] = useState<DiscoveredScript[]>([]);
  const [selectedScriptId, setSelectedScriptId] = useState<string | null>(null);

  useEffect(() => {
    const savedHistory = localStorage.getItem('vulnscan_history');
    if (savedHistory) setScanHistory(JSON.parse(savedHistory));
  }, []);

  const addLog = (msg: string) => {
    setLogs(prev => [...prev.slice(-15), `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  const runRealAudit = async () => {
    if (isScanning) return;
    setIsScanning(true);
    setProgress(0);
    setLogs([]);
    setResult(null);
    setExpandedFindings(new Set());
    
    try {
      if (!url.startsWith('http')) throw new Error("Protocolo faltante.");
      const paramList = params.split(',').map(p => p.trim()).filter(p => p);
      
      addLog(`[SYSTEM] Iniciando Crawler...`);
      const scriptUrls = await crawlForScripts(url, proxyUrl, addLog);
      setDiscoveredScripts(scriptUrls.map((sUrl, idx) => ({
        id: String(idx), name: sUrl.split('/').pop() || 'script.js',
        url: sUrl, status: 'pending', findingsCount: 0
      })));

      const findings = await executeRealScan({
        url, params: paramList, proxyUrl, onLog: addLog, onProgress: setProgress
      });

      const scanResult: ScanResult = {
        targetUrl: url, timestamp: new Date().toISOString(),
        totalRequests: paramList.length * 3, findings: findings,
        duration: 0,
      };
      
      setResult(scanResult);
      setActiveTab('results');
      
      const newEntry: HistoryEntry = {
        id: crypto.randomUUID(), targetUrl: url, timestamp: scanResult.timestamp,
        findingsCount: findings.length, criticalCount: findings.filter(f => f.severity === 'Critical').length,
        highCount: findings.filter(f => f.severity === 'High').length, summary: `${findings.length} Hallazgos`
      };
      setScanHistory(prev => [newEntry, ...prev]);
    } catch (error: any) {
      addLog(`[!] ERROR: ${error.message}`);
    } finally {
      setIsScanning(false);
      setProgress(100);
    }
  };

  const downloadPDFReport = () => {
    if (!result) return;
    const doc = new jsPDF();
    doc.setFontSize(20);
    doc.text('VulnScan PRO - Security Report', 20, 20);
    doc.setFontSize(10);
    doc.text(`Target: ${result.targetUrl}`, 20, 30);
    result.findings.forEach((f, i) => {
      doc.text(`${i+1}. ${f.type} (${f.severity}) - Param: ${f.parameter}`, 20, 40 + (i*10));
    });
    doc.save('report.pdf');
  };

  return (
    <div className="flex flex-col h-screen bg-[#0a0a0b] text-[#e4e4e7] font-sans">
      <header className="flex items-center justify-between px-6 py-4 border-b border-zinc-800 bg-[#0d0d0e]">
        <div className="flex items-center gap-4">
          <ShieldAlert className="w-6 h-6 text-emerald-400" />
          <h1 className="text-xl font-black uppercase italic tracking-tighter">VulnScan <span className="text-emerald-400 not-italic">PRO</span></h1>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1 bg-zinc-900 border border-zinc-800 rounded-lg">
             <div className={`w-2 h-2 rounded-full ${proxyUrl ? 'bg-emerald-500' : 'bg-red-500'}`} />
             <span className="text-[10px] font-black uppercase text-zinc-500 tracking-widest">CORS BYPASS: {proxyUrl ? 'ACTIVE' : 'BLOCKED'}</span>
          </div>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        <aside className="w-80 bg-[#0d0d0e] border-r border-zinc-800 p-8 flex flex-col gap-6">
          <div className="space-y-6">
            <div>
              <label className="block text-[10px] font-black text-zinc-500 uppercase mb-2">Target URL</label>
              <input type="text" value={url} onChange={(e) => setUrl(e.target.value)} className="w-full bg-zinc-900 border border-zinc-800 rounded-xl py-3 px-4 text-xs font-mono outline-none focus:ring-1 focus:ring-emerald-500" />
            </div>
            <div>
              <label className="block text-[10px] font-black text-zinc-500 uppercase mb-2">Test Parameters</label>
              <input type="text" value={params} onChange={(e) => setParams(e.target.value)} className="w-full bg-zinc-900 border border-zinc-800 rounded-xl py-3 px-4 text-xs font-mono" />
            </div>
            <div className="pt-4 border-t border-zinc-800">
               <label className="block text-[10px] font-black text-emerald-500 uppercase mb-2 flex items-center gap-2"><Settings className="w-3 h-3"/> Linux Researcher Proxy</label>
               <input 
                type="text" 
                value={proxyUrl} 
                onChange={(e) => setProxyUrl(e.target.value)} 
                placeholder="http://localhost:8080/"
                className="w-full bg-zinc-950 border border-zinc-800 rounded-xl py-3 px-4 text-xs text-zinc-400 font-mono outline-none focus:ring-1 focus:ring-blue-500" 
               />
               <div className="mt-4 p-4 bg-black rounded-xl border border-zinc-800 space-y-3">
                  <p className="text-[9px] text-zinc-500 font-bold uppercase tracking-widest">Ejecutar en Linux para bypass:</p>
                  <div className="flex items-center justify-between bg-zinc-900 p-2 rounded border border-zinc-800">
                    <code className="text-[9px] text-emerald-500">npx cors-anywhere</code>
                    <Copy className="w-3 h-3 text-zinc-600 cursor-pointer" onClick={() => navigator.clipboard.writeText('npx cors-anywhere')} />
                  </div>
               </div>
            </div>
          </div>
          <button onClick={runRealAudit} disabled={isScanning} className="w-full py-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-2xl font-black text-xs uppercase tracking-widest transition-all shadow-lg flex items-center justify-center gap-3">
            {isScanning ? <Loader2 className="animate-spin w-4 h-4" /> : <Zap className="w-4 h-4" />}
            Launch Research Audit
          </button>
        </aside>

        <main className="flex-1 flex flex-col bg-[#0a0a0b] overflow-hidden">
          <nav className="flex items-center gap-8 px-8 py-3 bg-[#0d0d0e] border-b border-zinc-800">
            {[
              { id: 'overview', label: 'Monitor', icon: Layout },
              { id: 'results', label: 'Audit Findings', icon: AlertOctagon },
              { id: 'jsrecon', label: 'JS Recon', icon: FileJson },
              { id: 'code', label: 'Linux Native Tool', icon: TerminalIcon },
              { id: 'history', label: 'History', icon: History }
            ].map((tab) => (
              <button key={tab.id} onClick={() => setActiveTab(tab.id as any)} className={`flex items-center gap-2 pb-2 text-[10px] font-black uppercase tracking-widest transition-all ${activeTab === tab.id ? 'text-emerald-400 border-b-2 border-emerald-500' : 'text-zinc-500 hover:text-zinc-300'}`}>
                <tab.icon className="w-3.5 h-3.5" /> {tab.label}
              </button>
            ))}
          </nav>

          <div className="flex-1 overflow-y-auto p-8 lg:p-10">
            {activeTab === 'overview' && (
              <div className="max-w-4xl mx-auto space-y-6">
                <div className="bg-[#0d0d0e] border border-zinc-800 rounded-3xl p-8 shadow-xl">
                   <h2 className="text-sm font-black text-white mb-6 uppercase flex items-center gap-3"><Terminal className="text-emerald-500 w-5 h-5" /> Live Research Output</h2>
                   <div className="bg-black border border-zinc-800 rounded-2xl h-[400px] overflow-y-auto p-6 font-mono text-[11px] space-y-2">
                      {logs.map((log, i) => (
                        <div key={i} className={`flex gap-4 ${log.includes('[!]') ? 'text-red-400' : log.includes('[+]') ? 'text-emerald-400' : 'text-zinc-600'}`}>
                           <span className="opacity-20 shrink-0">[{i}]</span>
                           <span>{log}</span>
                        </div>
                      ))}
                      {logs.length === 0 && <div className="text-zinc-800 uppercase tracking-widest h-full flex items-center justify-center font-black">Waiting for Audit...</div>}
                   </div>
                </div>
              </div>
            )}

            {activeTab === 'code' && (
              <div className="max-w-5xl mx-auto space-y-10 animate-in zoom-in-95 duration-500">
                <div className="bg-[#0d0d0e] border border-emerald-500/10 p-10 rounded-[2.5rem] flex flex-col md:flex-row justify-between items-center gap-8 shadow-2xl">
                   <div className="space-y-3">
                      <h3 className="text-xl font-black text-white uppercase tracking-tighter flex items-center gap-3"><TerminalIcon className="text-emerald-500" /> Linux Native DAST Suite</h3>
                      <p className="text-xs text-zinc-600 font-medium leading-relaxed max-w-lg">Copia este script y ejecútalo en tu terminal Linux para realizar pruebas DAST reales sin las restricciones del navegador. Requiere <code className="bg-zinc-900 px-1 py-0.5 rounded text-emerald-400">requests</code>.</p>
                   </div>
                   <button onClick={() => {navigator.clipboard.writeText(generatePythonScript(url, params.split(','))); addLog("Script CLI copiado al portapapeles.");}} className="bg-emerald-600 hover:bg-emerald-500 text-white px-8 py-4 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] transition-all flex items-center gap-3 shadow-lg active:scale-95"><Copy className="w-4 h-4" /> Copy CLI Tool</button>
                </div>
                <div className="bg-black rounded-[2.5rem] border border-zinc-800 p-10 overflow-hidden relative shadow-inner">
                   <div className="absolute top-4 right-10 text-[9px] text-zinc-800 font-black uppercase tracking-widest">scanner_v2.py</div>
                   <pre className="text-[11px] text-emerald-500/60 font-mono leading-relaxed h-[500px] overflow-y-auto scrollbar-thin"><code>{generatePythonScript(url, params.split(','))}</code></pre>
                </div>
              </div>
            )}

            {activeTab === 'results' && (
              <div className="max-w-5xl mx-auto space-y-10">
                {result ? (
                  <>
                    <div className="flex justify-between items-center">
                       <h2 className="text-2xl font-black text-white uppercase tracking-tighter">Field Intelligence Report</h2>
                       <button onClick={downloadPDFReport} className="flex items-center gap-3 bg-zinc-900 hover:bg-zinc-800 px-6 py-3 rounded-xl text-[10px] font-black uppercase tracking-widest border border-zinc-800 transition-all"><Download className="w-4 h-4" /> Export PDF</button>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                       <div className="bg-[#0d0d0e] border border-zinc-800 p-6 rounded-2xl flex items-center gap-4">
                          <div className="p-3 bg-red-500/10 rounded-xl text-red-500"><AlertOctagon className="w-6 h-6" /></div>
                          <div>
                            <span className="block text-[10px] font-black text-zinc-600 uppercase">Critical</span>
                            <span className="text-xl font-black text-white">{result.findings.filter(f => f.severity === 'Critical').length}</span>
                          </div>
                       </div>
                    </div>
                    {/* Render findings... */}
                    <div className="space-y-4">
                      {result.findings.map((f, i) => (
                        <div key={i} className="bg-[#0d0d0e] border border-zinc-800 rounded-3xl p-6">
                          <div className="flex justify-between items-center">
                            <div className="flex items-center gap-4">
                              <Bug className="text-red-500 w-5 h-5" />
                              <span className="text-sm font-black uppercase text-white">{f.type}</span>
                            </div>
                            <span className="text-[9px] font-black px-3 py-1 bg-red-500/10 text-red-500 border border-red-500/20 rounded-full uppercase tracking-widest">{f.severity}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                ) : (
                  <div className="py-40 text-center opacity-20 flex flex-col items-center gap-6">
                     <Target className="w-20 h-20" />
                     <p className="text-xs font-black uppercase tracking-[0.5em]">No Data Collected</p>
                  </div>
                )}
              </div>
            )}

            {/* Other tabs remain similar with the same aesthetic */}
          </div>
        </main>
      </div>
    </div>
  );
};

export default ScannerDashboard;
