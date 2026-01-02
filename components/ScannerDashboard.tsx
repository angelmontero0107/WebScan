
import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Terminal, 
  Search, 
  Code, 
  AlertTriangle, 
  CheckCircle2, 
  Activity,
  ChevronRight,
  Info,
  ExternalLink,
  ShieldCheck,
  FileCode,
  FileText,
  Download
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { VulnerabilityType, ScanFinding, ScanResult } from '../types';
import { SQLI_PAYLOADS, XSS_PAYLOADS, SQL_ERROR_SIGNATURES, EDUCATIONAL_DISCLAIMER } from '../constants';
import { generatePythonScript, analyzeFindingWithAI } from '../services/geminiService';

const ScannerDashboard: React.FC = () => {
  const [url, setUrl] = useState('http://example.com/search');
  const [params, setParams] = useState('q,id,page');
  const [isScanning, setIsScanning] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'results' | 'code' | 'disclaimer'>('overview');
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [aiAnalyses, setAiAnalyses] = useState<Record<number, string>>({});

  const addLog = (msg: string) => {
    setLogs(prev => [...prev.slice(-19), `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  const runMockScan = async () => {
    setIsScanning(true);
    setProgress(0);
    setLogs([]);
    setResult(null);
    setAiAnalyses({});
    
    const paramList = params.split(',').map(p => p.trim()).filter(p => p);
    addLog(`Initiating DAST sequence for ${url}...`);
    addLog(`Parameters identified: ${paramList.join(', ')}`);

    // Simulate multi-step scanning
    let foundFindings: ScanFinding[] = [];
    const totalSteps = paramList.length * (SQLI_PAYLOADS.length + XSS_PAYLOADS.length);
    let currentStep = 0;

    for (const p of paramList) {
      // SQLI
      for (const payload of SQLI_PAYLOADS) {
        currentStep++;
        setProgress(Math.round((currentStep / totalSteps) * 100));
        addLog(`Testing SQLi on parameter [${p}] with payload [${payload.substring(0, 15)}...]`);
        await new Promise(r => setTimeout(r, 100));
        
        // Mock finding for educational purposes on specific test param
        if (p === 'id' && payload.includes("'")) {
          foundFindings.push({
            parameter: p,
            payload,
            type: VulnerabilityType.SQLI,
            severity: 'Critical',
            evidence: 'SQL syntax error: "You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server..."',
            description: 'The application is vulnerable to SQL injection through the ' + p + ' parameter.'
          });
          addLog(`[!] ALERT: High probability SQLi detected on parameter: ${p}`);
        }
      }

      // XSS
      for (const payload of XSS_PAYLOADS) {
        currentStep++;
        setProgress(Math.round((currentStep / totalSteps) * 100));
        addLog(`Testing XSS on parameter [${p}] with payload [${payload.substring(0, 15)}...]`);
        await new Promise(r => setTimeout(r, 80));

        if (p === 'q' && payload.includes('<script>')) {
          foundFindings.push({
            parameter: p,
            payload,
            type: VulnerabilityType.XSS,
            severity: 'High',
            evidence: `Response body reflects injected tag: ${payload}`,
            description: 'The parameter ' + p + ' is reflected in the response without proper encoding, leading to XSS.'
          });
          addLog(`[!] ALERT: Reflected XSS detected on parameter: ${p}`);
        }
      }
    }

    setResult({
      targetUrl: url,
      timestamp: new Date().toISOString(),
      totalRequests: totalSteps,
      findings: foundFindings,
      duration: 5.2
    });
    
    setIsScanning(false);
    setProgress(100);
    addLog(`Scan complete. ${foundFindings.length} potential vulnerabilities identified.`);
    setActiveTab('results');
  };

  const getAIAnalysis = async (index: number, finding: ScanFinding) => {
    if (aiAnalyses[index]) return;
    setAiAnalyses(prev => ({ ...prev, [index]: 'Analyzing with Gemini AI...' }));
    const analysis = await analyzeFindingWithAI(finding);
    setAiAnalyses(prev => ({ ...prev, [index]: analysis }));
  };

  const downloadPDFReport = () => {
    if (!result) return;
    
    const doc = new jsPDF();
    const timestamp = new Date().toLocaleString();
    
    // Title
    doc.setFontSize(22);
    doc.setTextColor(16, 185, 129); // Emerald-500
    doc.text("DAST Security Report", 105, 20, { align: "center" });
    
    // Sub-header
    doc.setFontSize(10);
    doc.setTextColor(100);
    doc.text(`Generated on: ${timestamp}`, 105, 28, { align: "center" });
    
    doc.setDrawColor(200);
    doc.line(20, 35, 190, 35);
    
    // Target Info
    doc.setFontSize(12);
    doc.setTextColor(0);
    doc.setFont("helvetica", "bold");
    doc.text("Scan Summary", 20, 45);
    doc.setFont("helvetica", "normal");
    doc.text(`Target URL: ${result.targetUrl}`, 20, 52);
    doc.text(`Total Tests: ${result.totalRequests}`, 20, 59);
    doc.text(`Findings: ${result.findings.length}`, 20, 66);
    
    if (result.findings.length === 0) {
      doc.setTextColor(0, 128, 0);
      doc.setFont("helvetica", "bold");
      doc.text("No vulnerabilities detected.", 20, 80);
    } else {
      // Table of findings
      const tableData = result.findings.map(f => [
        f.parameter,
        f.type,
        f.severity,
        f.payload.substring(0, 30) + (f.payload.length > 30 ? "..." : "")
      ]);
      
      autoTable(doc, {
        startY: 75,
        head: [['Parameter', 'Type', 'Severity', 'Payload']],
        body: tableData,
        headStyles: { fillColor: [16, 185, 129] },
        theme: 'striped'
      });
      
      // Detailed findings on subsequent pages if necessary
      let currentY = (doc as any).lastAutoTable.finalY + 15;
      doc.setFont("helvetica", "bold");
      doc.text("Detailed Findings", 20, currentY);
      currentY += 10;
      
      result.findings.forEach((f, idx) => {
        if (currentY > 250) {
          doc.addPage();
          currentY = 20;
        }
        doc.setFont("helvetica", "bold");
        doc.setFontSize(11);
        doc.text(`Finding #${idx + 1}: ${f.type}`, 20, currentY);
        currentY += 6;
        doc.setFont("helvetica", "normal");
        doc.setFontSize(10);
        doc.text(`Severity: ${f.severity}`, 25, currentY);
        currentY += 5;
        const payloadText = doc.splitTextToSize(`Payload: ${f.payload}`, 160);
        doc.text(payloadText, 25, currentY);
        currentY += (payloadText.length * 5);
        const evidenceText = doc.splitTextToSize(`Evidence: ${f.evidence}`, 160);
        doc.text(evidenceText, 25, currentY);
        currentY += (evidenceText.length * 5) + 10;
      });
    }
    
    // Disclaimer
    doc.addPage();
    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text("Ethical Disclaimer", 20, 20);
    doc.setFontSize(10);
    doc.setFont("helvetica", "italic");
    const disclaimerLines = doc.splitTextToSize(EDUCATIONAL_DISCLAIMER, 170);
    doc.text(disclaimerLines, 20, 30);
    
    doc.save(`dast_report_${result.targetUrl.replace(/[^a-z0-9]/gi, '_')}.pdf`);
  };

  return (
    <div className="flex flex-col h-screen bg-[#0a0a0b] overflow-hidden">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-zinc-800 bg-[#0d0d0e]">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-500/10 rounded-lg">
            <ShieldAlert className="w-6 h-6 text-emerald-400" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-white">VulnScan <span className="text-emerald-400">Pro</span></h1>
        </div>
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2 px-3 py-1 bg-zinc-900 border border-zinc-800 rounded-full">
            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
            <span className="text-xs font-medium text-zinc-400">Researcher Mode Active</span>
          </div>
        </div>
      </header>

      <main className="flex flex-1 overflow-hidden">
        {/* Sidebar Controls */}
        <div className="w-80 border-r border-zinc-800 bg-[#0d0d0e] p-6 flex flex-col gap-6 overflow-y-auto">
          <div>
            <label className="block text-sm font-medium text-zinc-400 mb-2">Target Base URL</label>
            <div className="relative">
              <input 
                type="text" 
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com/api"
                className="w-full bg-zinc-900 border border-zinc-800 rounded-lg py-2 pl-3 pr-10 text-sm text-white focus:ring-1 focus:ring-emerald-500 transition-all outline-none"
              />
              <Search className="absolute right-3 top-2.5 w-4 h-4 text-zinc-500" />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-zinc-400 mb-2">Query Parameters (CSV)</label>
            <input 
              type="text" 
              value={params}
              onChange={(e) => setParams(e.target.value)}
              placeholder="e.g. id, search, page"
              className="w-full bg-zinc-900 border border-zinc-800 rounded-lg py-2 px-3 text-sm text-white focus:ring-1 focus:ring-emerald-500 transition-all outline-none"
            />
            <p className="mt-2 text-[10px] text-zinc-500 italic">Separate keys with commas. Scanner will inject payloads into each key.</p>
          </div>

          <button 
            onClick={runMockScan}
            disabled={isScanning || !url}
            className={`flex items-center justify-center gap-2 w-full py-3 rounded-lg font-bold transition-all shadow-lg ${isScanning ? 'bg-zinc-800 text-zinc-500 cursor-not-allowed' : 'bg-emerald-600 hover:bg-emerald-500 text-white glow'}`}
          >
            {isScanning ? <Activity className="w-5 h-5 animate-spin" /> : <Terminal className="w-5 h-5" />}
            {isScanning ? 'SCANNING...' : 'EXECUTE SCAN'}
          </button>

          <div className="mt-auto pt-6 border-t border-zinc-800">
            <div className="flex items-center gap-2 mb-4">
              <Info className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-bold text-white">Security Posture</h3>
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-zinc-500">Active Payloads</span>
                <span className="text-xs font-mono text-zinc-300">{SQLI_PAYLOADS.length + XSS_PAYLOADS.length}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-zinc-500">Methodology</span>
                <span className="text-xs font-mono text-zinc-300">DAST / Blackbox</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-zinc-500">Reporting</span>
                <span className="text-xs font-mono text-emerald-400">PDF Supported</span>
              </div>
            </div>
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 flex flex-col bg-[#0a0a0b]">
          {/* Navigation Tabs */}
          <div className="flex items-center gap-8 px-8 py-3 bg-[#0d0d0e] border-b border-zinc-800">
            <button 
              onClick={() => setActiveTab('overview')}
              className={`flex items-center gap-2 pb-2 transition-all border-b-2 text-sm font-medium ${activeTab === 'overview' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-zinc-500 hover:text-zinc-300'}`}
            >
              <Activity className="w-4 h-4" /> Overview
            </button>
            <button 
              onClick={() => setActiveTab('results')}
              className={`flex items-center gap-2 pb-2 transition-all border-b-2 text-sm font-medium ${activeTab === 'results' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-zinc-500 hover:text-zinc-300'}`}
            >
              <AlertTriangle className="w-4 h-4" /> Findings {result && result.findings.length > 0 && <span className="ml-1 px-1.5 py-0.5 bg-red-500/20 text-red-500 rounded text-[10px]">{result.findings.length}</span>}
            </button>
            <button 
              onClick={() => setActiveTab('code')}
              className={`flex items-center gap-2 pb-2 transition-all border-b-2 text-sm font-medium ${activeTab === 'code' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-zinc-500 hover:text-zinc-300'}`}
            >
              <Code className="w-4 h-4" /> Export Script
            </button>
            <button 
              onClick={() => setActiveTab('disclaimer')}
              className={`flex items-center gap-2 pb-2 transition-all border-b-2 text-sm font-medium ${activeTab === 'disclaimer' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-zinc-500 hover:text-zinc-300'}`}
            >
              <ShieldCheck className="w-4 h-4" /> Legal
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-8">
            {activeTab === 'overview' && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div className="col-span-full">
                  <div className="bg-emerald-500/5 border border-emerald-500/10 rounded-xl p-6 flex items-center justify-between">
                    <div>
                      <h2 className="text-xl font-bold text-white mb-1">DAST Scanner Operations</h2>
                      <p className="text-zinc-400 text-sm">Real-time telemetry from the vulnerability discovery engine.</p>
                    </div>
                    {isScanning && (
                      <div className="text-right">
                        <span className="text-emerald-400 font-mono font-bold text-2xl">{progress}%</span>
                        <div className="w-32 h-1.5 bg-zinc-800 rounded-full mt-2 overflow-hidden">
                          <div className="h-full bg-emerald-500 transition-all duration-300" style={{ width: `${progress}%` }}></div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Console Log */}
                <div className="bg-[#0d0d0e] border border-zinc-800 rounded-xl overflow-hidden flex flex-col h-[400px]">
                  <div className="px-4 py-2 bg-zinc-900 border-b border-zinc-800 flex items-center gap-2">
                    <Terminal className="w-3 h-3 text-zinc-500" />
                    <span className="text-[10px] uppercase font-bold text-zinc-500 tracking-wider">Operational Logs</span>
                  </div>
                  <div className="flex-1 p-4 font-mono text-xs overflow-y-auto space-y-1">
                    {logs.length === 0 ? (
                      <span className="text-zinc-600">Waiting for scan execution...</span>
                    ) : (
                      logs.map((log, i) => (
                        <div key={i} className={log.includes('[!]') ? 'text-red-400 font-bold' : 'text-emerald-500/80'}>
                          {log}
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Statistics / Chart */}
                <div className="bg-[#0d0d0e] border border-zinc-800 rounded-xl p-6 flex flex-col h-[400px]">
                   <div className="flex items-center justify-between mb-6">
                      <h3 className="text-sm font-bold text-white uppercase tracking-wider">Payload Impact Distribution</h3>
                      <div className="flex items-center gap-4">
                        <div className="flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                          <span className="text-[10px] text-zinc-400">Requests</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="w-2 h-2 rounded-full bg-red-500"></div>
                          <span className="text-[10px] text-zinc-400">Anomalies</span>
                        </div>
                      </div>
                   </div>
                   <div className="flex-1 w-full">
                     <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={[
                          { name: '0s', req: 0, v: 0 },
                          { name: '1s', req: 10, v: 0 },
                          { name: '2s', req: 25, v: 1 },
                          { name: '3s', req: 45, v: 1 },
                          { name: '4s', req: 70, v: 2 },
                          { name: '5s', req: 95, v: 2 },
                        ]}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#18181b" />
                          <XAxis dataKey="name" hide />
                          <YAxis hide />
                          <Tooltip 
                            contentStyle={{ backgroundColor: '#18181b', border: '1px solid #27272a' }}
                            itemStyle={{ fontSize: '12px' }}
                          />
                          <Line type="monotone" dataKey="req" stroke="#10b981" strokeWidth={2} dot={false} />
                          <Line type="monotone" dataKey="v" stroke="#ef4444" strokeWidth={2} dot={false} />
                        </LineChart>
                     </ResponsiveContainer>
                   </div>
                </div>
              </div>
            )}

            {activeTab === 'results' && (
              <div className="space-y-6">
                {!result ? (
                  <div className="text-center py-20 border-2 border-dashed border-zinc-800 rounded-2xl">
                    <Search className="w-12 h-12 text-zinc-700 mx-auto mb-4" />
                    <h3 className="text-lg font-bold text-white">No active scan results</h3>
                    <p className="text-zinc-500 max-w-sm mx-auto mt-2">Enter a target URL and execute the scan to view identified vulnerabilities.</p>
                  </div>
                ) : (
                  <>
                    <div className="flex items-center justify-between">
                      <h2 className="text-2xl font-bold text-white">Vulnerability Report</h2>
                      <div className="flex items-center gap-4">
                        <button 
                          onClick={downloadPDFReport}
                          className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-bold transition-all text-sm shadow-lg shadow-emerald-500/10"
                        >
                          <Download className="w-4 h-4" /> DOWNLOAD PDF
                        </button>
                        <div className="px-4 py-2 bg-red-500/10 border border-red-500/20 rounded-lg">
                          <span className="text-xs text-red-400 font-bold">{result.findings.length} Issues Identified</span>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 gap-4">
                      {result.findings.length === 0 ? (
                        <div className="bg-[#0d0d0e] border border-zinc-800 rounded-xl p-10 text-center">
                          <CheckCircle2 className="w-12 h-12 text-emerald-500 mx-auto mb-4" />
                          <h3 className="text-white font-bold text-lg">Clean Result</h3>
                          <p className="text-zinc-500 text-sm">No common vulnerabilities were detected with the provided payloads.</p>
                        </div>
                      ) : (
                        result.findings.map((finding, idx) => (
                          <div key={idx} className="bg-[#0d0d0e] border border-zinc-800 rounded-xl overflow-hidden hover:border-zinc-700 transition-all group">
                            <div className="p-6">
                              <div className="flex items-start justify-between mb-4">
                                <div className="flex items-center gap-3">
                                  <div className={`p-2 rounded-lg ${finding.severity === 'Critical' ? 'bg-red-500/10' : 'bg-orange-500/10'}`}>
                                    <AlertTriangle className={`w-5 h-5 ${finding.severity === 'Critical' ? 'text-red-400' : 'text-orange-400'}`} />
                                  </div>
                                  <div>
                                    <h3 className="text-lg font-bold text-white">{finding.type}</h3>
                                    <p className="text-sm text-zinc-500 font-mono">Target: <span className="text-zinc-300">GET /{finding.parameter}=...</span></p>
                                  </div>
                                </div>
                                <span className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${finding.severity === 'Critical' ? 'bg-red-500/20 text-red-400' : 'bg-orange-500/20 text-orange-400'}`}>
                                  {finding.severity}
                                </span>
                              </div>
                              
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
                                <div className="space-y-3">
                                  <div className="p-3 bg-zinc-900/50 rounded-lg border border-zinc-800">
                                    <p className="text-[10px] text-zinc-500 uppercase font-bold mb-1">Injected Payload</p>
                                    <code className="text-sm text-emerald-400 block break-all font-mono">{finding.payload}</code>
                                  </div>
                                  <div className="p-3 bg-zinc-900/50 rounded-lg border border-zinc-800">
                                    <p className="text-[10px] text-zinc-500 uppercase font-bold mb-1">Evidence Captured</p>
                                    <p className="text-xs text-zinc-400 italic font-mono leading-relaxed">{finding.evidence}</p>
                                  </div>
                                </div>

                                <div className="space-y-4">
                                  <div className="flex flex-col h-full">
                                    <div className="flex items-center justify-between mb-2">
                                      <p className="text-[10px] text-zinc-500 uppercase font-bold flex items-center gap-2">
                                        <Terminal className="w-3 h-3" /> AI Remediation Analyst
                                      </p>
                                      {!aiAnalyses[idx] && (
                                        <button 
                                          onClick={() => getAIAnalysis(idx, finding)}
                                          className="text-[10px] text-emerald-400 hover:text-emerald-300 font-bold transition-all"
                                        >
                                          GENERATE REPORT
                                        </button>
                                      )}
                                    </div>
                                    <div className="flex-1 bg-zinc-900/30 rounded-lg border border-zinc-800/50 p-4 relative min-h-[100px]">
                                      {aiAnalyses[idx] ? (
                                        <div className="text-xs text-zinc-300 leading-relaxed whitespace-pre-wrap">
                                          {aiAnalyses[idx]}
                                        </div>
                                      ) : (
                                        <div className="flex items-center justify-center h-full text-zinc-600 text-[10px] text-center italic">
                                          Click 'GENERATE REPORT' to get an AI-powered security deep dive.
                                        </div>
                                      )}
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </>
                )}
              </div>
            )}

            {activeTab === 'code' && (
              <div className="h-full flex flex-col gap-6">
                <div className="bg-emerald-500/10 border border-emerald-500/20 p-4 rounded-xl flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <FileCode className="w-6 h-6 text-emerald-400" />
                    <div>
                      <h3 className="text-sm font-bold text-white">Standalone DAST Script Generator</h3>
                      <p className="text-xs text-zinc-400">Customized Python script with <span className="text-emerald-400 font-mono font-bold italic">fpdf reporting</span> for external testing.</p>
                    </div>
                  </div>
                  <div className="flex gap-2">
                     <button 
                      onClick={() => {
                        navigator.clipboard.writeText(generatePythonScript(url, params.split(',')));
                        alert("Script copied to clipboard!");
                      }}
                      className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold rounded-lg border border-emerald-700 transition-all flex items-center gap-2"
                    >
                      COPY CODE
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                   <div className="lg:col-span-1 space-y-4">
                      <div className="bg-zinc-900/50 border border-zinc-800 p-4 rounded-xl">
                        <div className="flex items-center gap-2 mb-2">
                           <FileText className="w-4 h-4 text-emerald-400" />
                           <h4 className="text-xs font-bold text-white uppercase">New Feature</h4>
                        </div>
                        <p className="text-[10px] text-zinc-400 leading-relaxed">
                          This script now includes an automated PDF generation engine. After the scan completes, it produces a professional security report detailing all identified vulnerabilities.
                        </p>
                        <div className="mt-4 p-2 bg-black rounded border border-zinc-800">
                           <p className="text-[9px] font-mono text-zinc-500">Requirements:</p>
                           <code className="text-[9px] text-emerald-500">pip install fpdf requests</code>
                        </div>
                      </div>
                   </div>

                   <div className="lg:col-span-3">
                      <div className="bg-[#0d0d0e] border border-zinc-800 rounded-xl overflow-hidden shadow-2xl h-[500px] flex flex-col">
                        <div className="px-4 py-2 bg-zinc-900 border-b border-zinc-800 flex items-center justify-between">
                          <div className="flex items-center gap-1.5">
                            <div className="w-2.5 h-2.5 rounded-full bg-red-500"></div>
                            <div className="w-2.5 h-2.5 rounded-full bg-amber-500"></div>
                            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500"></div>
                          </div>
                          <span className="text-[10px] font-mono text-zinc-500">dast_scanner_v2.py</span>
                        </div>
                        <div className="p-6 overflow-y-auto font-mono text-sm text-zinc-300 bg-black/40 flex-1">
                          <pre><code>{generatePythonScript(url, params.split(','))}</code></pre>
                        </div>
                      </div>
                   </div>
                </div>
              </div>
            )}

            {activeTab === 'disclaimer' && (
              <div className="max-w-3xl mx-auto py-12">
                <div className="bg-red-500/5 border border-red-500/10 p-8 rounded-2xl">
                  <div className="flex items-center gap-4 mb-6">
                    <ShieldCheck className="w-10 h-10 text-red-500" />
                    <h2 className="text-3xl font-black text-white tracking-tighter">ETHICAL DISCLOSURE</h2>
                  </div>
                  
                  <div className="prose prose-invert max-w-none text-zinc-400 space-y-4">
                    <p className="text-zinc-200 font-medium text-lg leading-relaxed">
                      Security research is a critical field that requires high ethical standards. Accessing or testing computer systems without authorization is illegal and punishable under laws like the CFAA in the United States and similar regulations worldwide.
                    </p>
                    
                    <div className="bg-black/40 p-6 rounded-xl border border-zinc-800 my-8">
                       <h4 className="text-white font-bold mb-2">Rules of Engagement:</h4>
                       <ul className="list-disc pl-5 space-y-2 text-sm italic">
                          <li>Never test a target without explicit written permission.</li>
                          <li>Respect privacy and data integrity at all times.</li>
                          <li>Report findings responsibly via Bug Bounty or VDP channels.</li>
                          <li>Use this tool strictly for laboratory environments and learning.</li>
                       </ul>
                    </div>

                    <p className="p-4 border-l-4 border-red-500 bg-red-500/10 text-red-200 italic font-mono text-xs">
                      {EDUCATIONAL_DISCLAIMER}
                    </p>
                    
                    <div className="mt-8 flex items-center gap-4">
                      <a href="https://owasp.org" target="_blank" className="flex items-center gap-1 text-emerald-400 hover:underline text-sm font-bold">
                        Learn about OWASP Top 10 <ExternalLink className="w-3 h-3" />
                      </a>
                      <a href="https://hackerone.com" target="_blank" className="flex items-center gap-1 text-emerald-400 hover:underline text-sm font-bold">
                        Start Bug Bounties Responsibly <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>

      {/* Footer Status Bar */}
      <footer className="px-6 py-2 border-t border-zinc-800 bg-[#0d0d0e] flex items-center justify-between text-[10px] text-zinc-500 font-mono">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <span className="text-emerald-500">READY</span>
            <div className="w-1 h-3 bg-zinc-800"></div>
            <span>VULNSCAN-CORE v1.1.0-REPORTING</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-zinc-600">ENGINE:</span>
            <span>HYDRA-PROX-V2</span>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span>LATENCY: 12ms</span>
          <span>UPTIME: 99.9%</span>
          <span className="text-zinc-300">© 2024 VULNSCAN PRO RESEARCHERS</span>
        </div>
      </footer>
    </div>
  );
};

export default ScannerDashboard;