
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
  Download,
  AlertOctagon,
  Zap,
  History,
  Trash2,
  Calendar,
  Clock
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { VulnerabilityType, ScanFinding, ScanResult, HistoryEntry } from '../types';
import { SQLI_PAYLOADS, XSS_PAYLOADS, SQL_ERROR_SIGNATURES, EDUCATIONAL_DISCLAIMER } from '../constants';
import { generatePythonScript, analyzeFindingWithAI } from '../services/geminiService';

const ScannerDashboard: React.FC = () => {
  const [url, setUrl] = useState('http://example.com/search');
  const [params, setParams] = useState('q,id,page');
  const [isScanning, setIsScanning] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'results' | 'code' | 'history' | 'disclaimer'>('overview');
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [aiAnalyses, setAiAnalyses] = useState<Record<number, string>>({});
  const [scanHistory, setScanHistory] = useState<HistoryEntry[]>([]);

  // Cargar historial al montar
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

  const saveToHistory = (scanResult: ScanResult) => {
    const sqliCount = scanResult.findings.filter(f => f.type === VulnerabilityType.SQLI).length;
    const xssCount = scanResult.findings.filter(f => f.type === VulnerabilityType.XSS).length;
    
    const summaryParts = [];
    if (sqliCount > 0) summaryParts.push(`SQLi: ${sqliCount}`);
    if (xssCount > 0) summaryParts.push(`XSS: ${xssCount}`);
    const summary = summaryParts.length > 0 ? summaryParts.join(', ') : 'Sin hallazgos';

    const newEntry: HistoryEntry = {
      id: crypto.randomUUID(),
      targetUrl: scanResult.targetUrl,
      timestamp: scanResult.timestamp,
      findingsCount: scanResult.findings.length,
      criticalCount: scanResult.findings.filter(f => f.severity === 'Critical').length,
      highCount: scanResult.findings.filter(f => f.severity === 'High').length,
      summary: summary
    };

    const updatedHistory = [newEntry, ...scanHistory];
    setScanHistory(updatedHistory);
    localStorage.setItem('vulnscan_history', JSON.stringify(updatedHistory));
  };

  const deleteHistoryEntry = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const updatedHistory = scanHistory.filter(h => h.id !== id);
    setScanHistory(updatedHistory);
    localStorage.setItem('vulnscan_history', JSON.stringify(updatedHistory));
  };

  const clearAllHistory = () => {
    if (window.confirm("¿Seguro que quieres borrar todo el historial?")) {
      setScanHistory([]);
      localStorage.removeItem('vulnscan_history');
    }
  };

  const isValidUrl = (string: string) => {
    try {
      const parsedUrl = new URL(string);
      return parsedUrl.protocol === "http:" || parsedUrl.protocol === "https:";
    } catch (_) {
      return false;
    }
  };

  const runMockScan = async () => {
    if (isScanning) return;
    
    setIsScanning(true);
    setProgress(0);
    setLogs([]);
    setResult(null);
    setAiAnalyses({});
    
    try {
      if (!url) {
        throw new Error("La URL del objetivo no puede estar vacía.");
      }

      if (!isValidUrl(url)) {
        throw new Error("Formato de URL inválido. Asegúrese de incluir el protocolo (http:// o https://).");
      }

      const paramList = params.split(',').map(p => p.trim()).filter(p => p);
      if (paramList.length === 0) {
        throw new Error("Se requiere al menos un parámetro de consulta para realizar el escaneo.");
      }

      addLog(`Iniciando secuencia DAST para ${url}...`);
      await new Promise(r => setTimeout(r, 400)); // Latencia inicial simulada

      let foundFindings: ScanFinding[] = [];
      const totalSteps = paramList.length * (SQLI_PAYLOADS.length + XSS_PAYLOADS.length);
      let currentStep = 0;

      for (const p of paramList) {
        // Simulación SQLI - Solo reportamos una vez por parámetro
        let sqlFoundForThisParam = false;
        for (const payload of SQLI_PAYLOADS) {
          currentStep++;
          setProgress(Math.round((currentStep / totalSteps) * 100));
          addLog(`Auditando SQLi: [${p}]`);
          
          await new Promise(r => setTimeout(r, 60));
          
          if (!sqlFoundForThisParam && p === 'id' && payload.includes("'")) {
            foundFindings.push({
              parameter: p,
              payload,
              type: VulnerabilityType.SQLI,
              severity: 'Critical',
              evidence: 'Error: "You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server..."',
              description: `Se detectó una vulnerabilidad de Inyección SQL en el parámetro '${p}'.`,
              rootCause: "La aplicación concatena directamente la entrada del usuario en una consulta SQL. No se utilizan sentencias preparadas (Prepared Statements) ni validación de tipo, lo que permite al atacante 'romper' la sintaxis original e inyectar comandos arbitrarios.",
              impact: "Compromiso total de la base de datos, extracción masiva de registros (PII), bypass de autenticación y posible ejecución remota de comandos en el servidor."
            });
            addLog(`[!] ALERTA CRÍTICA: SQLi confirmada en '${p}'`);
            sqlFoundForThisParam = true; 
          }
        }

        // Simulación XSS - Solo reportamos una vez por parámetro
        let xssFoundForThisParam = false;
        for (const payload of XSS_PAYLOADS) {
          currentStep++;
          setProgress(Math.round((currentStep / totalSteps) * 100));
          addLog(`Auditando XSS: [${p}]`);
          
          await new Promise(r => setTimeout(r, 50));

          if (!xssFoundForThisParam && p === 'q' && payload.includes('<script>')) {
            foundFindings.push({
              parameter: p,
              payload,
              type: VulnerabilityType.XSS,
              severity: 'High',
              evidence: `Reflejo exacto detectado: ${payload}`,
              description: `Se detectó XSS Reflejado en el parámetro '${p}'.`,
              rootCause: "La aplicación falla al codificar los caracteres especiales (<, >, \", ') antes de renderizar el valor del parámetro en el HTML de la página. Esto permite que el navegador interprete etiquetas de script como código legítimo.",
              impact: "Robo de sesiones de usuario activo, secuestro de cuentas (Account Takeover), redirecciones automáticas a sitios maliciosos y ataques de ingeniería social sobre el cliente."
            });
            addLog(`[!] ALERTA ALTA: XSS detectado en '${p}'`);
            xssFoundForThisParam = true; 
          }
        }
      }

      const scanResult: ScanResult = {
        targetUrl: url,
        timestamp: new Date().toISOString(),
        totalRequests: totalSteps,
        findings: foundFindings,
        duration: 5.2
      };
      
      setResult(scanResult);
      saveToHistory(scanResult);
      setProgress(100);
      addLog(`Auditoría finalizada satisfactoriamente. ${foundFindings.length} vulnerabilidades detectadas.`);
      setActiveTab('results');

    } catch (error: any) {
      console.error("Fallo técnico en la secuencia de escaneo:", error);
      const errorMessage = error instanceof Error ? error.message : "Error desconocido durante la simulación.";
      addLog(`[!] ERROR FATAL: ${errorMessage}`);
      addLog(`[*] El proceso de auditoría se detuvo de forma inesperada.`);
      alert(`Error en el escaneo: ${errorMessage}`);
    } finally {
      setIsScanning(false);
    }
  };

  const getAIAnalysis = async (index: number, finding: ScanFinding) => {
    if (aiAnalyses[index]) return;
    setAiAnalyses(prev => ({ ...prev, [index]: 'Ejecutando motor de análisis profundo Gemini Pro...' }));
    const analysis = await analyzeFindingWithAI(finding);
    setAiAnalyses(prev => ({ ...prev, [index]: analysis }));
  };

  const downloadPDFReport = () => {
    if (!result) return;
    
    const doc = new jsPDF();
    const timestamp = new Date().toLocaleString();
    
    doc.setFillColor(16, 185, 129);
    doc.rect(0, 0, 210, 45, 'F');
    
    doc.setFontSize(26);
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.text("INFORME TÉCNICO DE SEGURIDAD", 105, 25, { align: "center" });
    
    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    doc.text(`Auditoría DAST Automatizada | ${timestamp}`, 105, 35, { align: "center" });
    
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(16);
    doc.setFont("helvetica", "bold");
    doc.text("1. Resumen Ejecutivo", 20, 60);
    
    doc.setFontSize(11);
    doc.setFont("helvetica", "normal");
    doc.text(`Objetivo Auditado: ${result.targetUrl}`, 20, 70);
    doc.text(`Estado Global: ${result.findings.length > 0 ? 'CRÍTICO / VULNERABLE' : 'SEGURO'}`, 20, 77);
    doc.text(`Total de pruebas ejecutadas: ${result.totalRequests}`, 20, 84);
    
    if (result.findings.length > 0) {
      doc.setFontSize(14);
      doc.setFont("helvetica", "bold");
      doc.text("2. Desglose Detallado de Vulnerabilidades", 20, 100);
      
      let yPos = 110;
      
      result.findings.forEach((f, idx) => {
        if (yPos > 240) {
          doc.addPage();
          yPos = 20;
        }
        
        doc.setDrawColor(228, 228, 231);
        doc.setFillColor(250, 250, 250);
        doc.rect(15, yPos, 180, 70, 'FD');
        
        doc.setTextColor(185, 28, 28);
        doc.setFontSize(12);
        doc.setFont("helvetica", "bold");
        doc.text(`${idx + 1}. ${f.type.toUpperCase()}`, 20, yPos + 10);
        
        doc.setTextColor(0, 0, 0);
        doc.setFontSize(10);
        doc.text(`Parámetro: ${f.parameter} | Severidad: ${f.severity}`, 20, yPos + 18);
        
        doc.setFont("helvetica", "bold");
        doc.text("¿Por qué falla la aplicación?:", 20, yPos + 28);
        doc.setFont("helvetica", "normal");
        const rootCauseLines = doc.splitTextToSize(f.rootCause, 170);
        doc.text(rootCauseLines, 20, yPos + 34);
        
        const nextOffset = (rootCauseLines.length * 5) + 42;
        doc.setFont("helvetica", "bold");
        doc.text("Impacto de Negocio:", 20, yPos + nextOffset);
        doc.setFont("helvetica", "normal");
        const impactLines = doc.splitTextToSize(f.impact, 170);
        doc.text(impactLines, 20, yPos + nextOffset + 6);
        
        yPos += nextOffset + (impactLines.length * 5) + 15;
      });
    } else {
      doc.setTextColor(16, 185, 129);
      doc.text("No se detectaron fallos de seguridad en los parámetros analizados.", 20, 100);
    }
    
    doc.addPage();
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text("3. Nota Legal y Ética", 20, 20);
    doc.setFontSize(9);
    doc.setFont("helvetica", "italic");
    const lines = doc.splitTextToSize(EDUCATIONAL_DISCLAIMER, 170);
    doc.text(lines, 20, 30);
    
    doc.save(`auditoria_seguridad_${new Date().getTime()}.pdf`);
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
            <span className="text-xs font-medium text-zinc-400">Auditoría Técnica Activada</span>
          </div>
        </div>
      </header>

      <main className="flex flex-1 overflow-hidden">
        {/* Sidebar Controls */}
        <div className="w-80 border-r border-zinc-800 bg-[#0d0d0e] p-6 flex flex-col gap-6 overflow-y-auto">
          <div>
            <label className="block text-sm font-medium text-zinc-400 mb-2">URL del Objetivo Auditado</label>
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
            <label className="block text-sm font-medium text-zinc-400 mb-2">Variables de Entrada (Query Params)</label>
            <input 
              type="text" 
              value={params}
              onChange={(e) => setParams(e.target.value)}
              placeholder="ej: id, search, page"
              className="w-full bg-zinc-900 border border-zinc-800 rounded-lg py-2 px-3 text-sm text-white focus:ring-1 focus:ring-emerald-500 transition-all outline-none"
            />
          </div>

          <button 
            onClick={runMockScan}
            disabled={isScanning || !url}
            className={`flex items-center justify-center gap-2 w-full py-3 rounded-lg font-bold transition-all shadow-lg ${isScanning ? 'bg-zinc-800 text-zinc-500 cursor-not-allowed' : 'bg-emerald-600 hover:bg-emerald-500 text-white glow'}`}
          >
            {isScanning ? <Activity className="w-5 h-5 animate-spin" /> : <Zap className="w-5 h-5" />}
            {isScanning ? 'EJECUTANDO AUDITORÍA...' : 'INICIAR ANÁLISIS'}
          </button>

          <div className="mt-auto pt-6 border-t border-zinc-800">
            <div className="flex items-center gap-2 mb-4">
              <History className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-bold text-white">Sesión Actual</h3>
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-zinc-500">Alertas Recientes</span>
                <span className="text-xs font-mono text-red-500">{result?.findings.length || 0}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-zinc-500">Historial Total</span>
                <span className="text-xs font-mono text-zinc-300">{scanHistory.length} registros</span>
              </div>
            </div>
          </div>
        </div>

        {/* Content Area */}
        <div className="flex-1 flex flex-col bg-[#0a0a0b]">
          <div className="flex items-center gap-8 px-8 py-3 bg-[#0d0d0e] border-b border-zinc-800">
            <button onClick={() => setActiveTab('overview')} className={`flex items-center gap-2 pb-2 transition-all border-b-2 text-sm font-medium ${activeTab === 'overview' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-zinc-500 hover:text-zinc-300'}`}>
              <Activity className="w-4 h-4" /> Resumen Operativo
            </button>
            <button onClick={() => setActiveTab('results')} className={`flex items-center gap-2 pb-2 transition-all border-b-2 text-sm font-medium ${activeTab === 'results' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-zinc-500 hover:text-zinc-300'}`}>
              <AlertOctagon className="w-4 h-4" /> Hallazgos Técnicos {result && result.findings.length > 0 && <span className="ml-1 px-1.5 py-0.5 bg-red-500/20 text-red-500 rounded text-[10px]">{result.findings.length}</span>}
            </button>
            <button onClick={() => setActiveTab('history')} className={`flex items-center gap-2 pb-2 transition-all border-b-2 text-sm font-medium ${activeTab === 'history' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-zinc-500 hover:text-zinc-300'}`}>
              <History className="w-4 h-4" /> Historial
            </button>
            <button onClick={() => setActiveTab('code')} className={`flex items-center gap-2 pb-2 transition-all border-b-2 text-sm font-medium ${activeTab === 'code' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-zinc-500 hover:text-zinc-300'}`}>
              <Code className="w-4 h-4" /> Script Auditoría
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-8">
            {activeTab === 'overview' && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div className="col-span-full">
                  <div className="bg-[#0d0d0e] border border-zinc-800 rounded-xl p-6">
                    <h2 className="text-xl font-bold text-white mb-4">Estado del Escaneo</h2>
                    {isScanning ? (
                      <div className="space-y-4">
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-zinc-400">Progreso de Auditoría</span>
                          <span className="text-emerald-400 font-mono font-bold">{progress}%</span>
                        </div>
                        <div className="w-full h-2 bg-zinc-900 rounded-full overflow-hidden">
                          <div className="h-full bg-emerald-500 transition-all duration-300 shadow-[0_0_10px_#10b981]" style={{ width: `${progress}%` }}></div>
                        </div>
                      </div>
                    ) : (
                      <div className="text-zinc-500 italic text-sm">Esperando inicio de auditoría...</div>
                    )}
                  </div>
                </div>

                <div className="bg-[#0d0d0e] border border-zinc-800 rounded-xl overflow-hidden flex flex-col h-[400px]">
                  <div className="px-4 py-2 bg-zinc-900 border-b border-zinc-800 flex items-center gap-2">
                    <Terminal className="w-3 h-3 text-zinc-500" />
                    <span className="text-[10px] uppercase font-bold text-zinc-500 tracking-wider">Salida de Consola Realtime</span>
                  </div>
                  <div className="flex-1 p-4 font-mono text-xs overflow-y-auto space-y-1">
                    {logs.map((log, i) => (
                      <div key={i} className={log.includes('[!]') ? 'text-red-400 font-bold bg-red-400/5 px-1 py-0.5 rounded' : 'text-emerald-500/80'}>{log}</div>
                    ))}
                  </div>
                </div>

                <div className="bg-[#0d0d0e] border border-zinc-800 rounded-xl p-6 h-[400px]">
                   <h3 className="text-sm font-bold text-white uppercase tracking-wider mb-6">Métricas de Vulnerabilidad</h3>
                   <div className="h-full pb-10">
                    <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={[
                          { name: 'T1', req: 0, v: 0 },
                          { name: 'T2', req: 15, v: 0 },
                          { name: 'T3', req: 40, v: 1 },
                          { name: 'T4', req: 65, v: 1 },
                          { name: 'T5', req: 90, v: 2 },
                        ]}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#18181b" />
                          <Tooltip contentStyle={{ backgroundColor: '#18181b', border: '1px solid #27272a' }} />
                          <Line type="monotone" dataKey="req" name="Pruebas" stroke="#10b981" strokeWidth={2} dot={false} />
                          <Line type="monotone" dataKey="v" name="Alertas" stroke="#ef4444" strokeWidth={2} dot={false} />
                        </LineChart>
                     </ResponsiveContainer>
                   </div>
                </div>
              </div>
            )}

            {activeTab === 'results' && (
              <div className="space-y-6">
                {!result ? (
                  <div className="text-center py-20 bg-[#0d0d0e] border border-zinc-800 rounded-2xl">
                    <Activity className="w-12 h-12 text-zinc-800 mx-auto mb-4" />
                    <p className="text-zinc-500">Ejecuta un análisis para generar el reporte técnico.</p>
                  </div>
                ) : (
                  <>
                    <div className="flex items-center justify-between">
                      <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                         <AlertOctagon className="text-red-500" /> Resultados de Auditoría
                      </h2>
                      <button onClick={downloadPDFReport} className="flex items-center gap-2 px-6 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-bold transition-all shadow-xl shadow-emerald-500/10">
                        <Download className="w-4 h-4" /> DESCARGAR REPORTE PDF TÉCNICO
                      </button>
                    </div>

                    <div className="space-y-4">
                      {result.findings.length === 0 ? (
                        <div className="bg-[#0d0d0e] border border-zinc-800 rounded-xl p-10 text-center">
                          <CheckCircle2 className="w-12 h-12 text-emerald-500 mx-auto mb-4" />
                          <h3 className="text-white font-bold text-lg">Resultado Limpio</h3>
                          <p className="text-zinc-500 text-sm">No se detectaron vulnerabilidades comunes con los payloads proporcionados.</p>
                        </div>
                      ) : (
                        result.findings.map((f, idx) => (
                          <div key={idx} className="bg-[#0d0d0e] border border-zinc-800 rounded-xl overflow-hidden hover:border-red-500/30 transition-all">
                            <div className="p-6">
                              <div className="flex items-start justify-between mb-6">
                               <div className="flex gap-4">
                                  <div className="p-3 bg-red-500/10 rounded-xl">
                                    <AlertTriangle className="text-red-500 w-6 h-6" />
                                  </div>
                                  <div>
                                    <h3 className="text-lg font-bold text-white uppercase">{f.type}</h3>
                                    <p className="text-sm text-zinc-500">Parámetro: <code className="text-zinc-300 bg-zinc-900 px-1.5 rounded">{f.parameter}</code></p>
                                  </div>
                               </div>
                               <span className="px-3 py-1 bg-red-500/20 text-red-500 rounded-full text-[10px] font-bold uppercase tracking-widest border border-red-500/30">CRÍTICA</span>
                            </div>

                            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                               <div className="lg:col-span-2 space-y-4">
                                  <div className="bg-zinc-900/50 p-4 rounded-xl border border-zinc-800">
                                    <h4 className="text-[10px] font-bold text-emerald-400 uppercase mb-2">¿Por qué falla la aplicación? (Análisis Técnico)</h4>
                                    <p className="text-sm text-zinc-300 leading-relaxed">{f.rootCause}</p>
                                  </div>
                                  <div className="bg-zinc-900/50 p-4 rounded-xl border border-zinc-800">
                                    <h4 className="text-[10px] font-bold text-red-400 uppercase mb-2">Impacto Real de Explotación</h4>
                                    <p className="text-sm text-zinc-300 leading-relaxed">{f.impact}</p>
                                  </div>
                               </div>

                               <div className="space-y-4">
                                  <div className="bg-zinc-900/50 p-4 rounded-xl border border-zinc-800 flex flex-col h-full">
                                    <div className="flex items-center justify-between mb-4">
                                      <h4 className="text-[10px] font-bold text-zinc-500 uppercase">Investigación Profunda (IA)</h4>
                                      {!aiAnalyses[idx] && (
                                        <button onClick={() => getAIAnalysis(idx, f)} className="text-[10px] text-emerald-400 font-bold hover:underline">SOLICITAR ANÁLISIS</button>
                                      )}
                                    </div>
                                    <div className="text-xs text-zinc-400 italic flex-1 overflow-y-auto max-h-[150px] whitespace-pre-wrap">
                                      {aiAnalyses[idx] || "Pendiente de análisis por el motor Gemini."}
                                    </div>
                                  </div>
                               </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>
            )}

            {activeTab === 'history' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                     <History className="text-emerald-400" /> Historial de Auditorías
                  </h2>
                  {scanHistory.length > 0 && (
                    <button 
                      onClick={clearAllHistory}
                      className="flex items-center gap-2 px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-red-400 rounded-lg text-xs font-bold transition-all"
                    >
                      <Trash2 className="w-4 h-4" /> BORRAR TODO EL HISTORIAL
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-1 gap-4">
                  {scanHistory.length === 0 ? (
                    <div className="bg-[#0d0d0e] border border-zinc-800 rounded-xl p-10 text-center">
                      <History className="w-12 h-12 text-zinc-800 mx-auto mb-4" />
                      <h3 className="text-white font-bold text-lg">Historial Vacío</h3>
                      <p className="text-zinc-500 text-sm">Aún no has realizado ninguna auditoría.</p>
                    </div>
                  ) : (
                    scanHistory.map((entry) => (
                      <div 
                        key={entry.id}
                        className="bg-[#0d0d0e] border border-zinc-800 rounded-xl p-5 flex items-center justify-between hover:border-zinc-700 transition-all cursor-default group"
                      >
                        <div className="flex items-center gap-5">
                          <div className={`p-3 rounded-lg ${entry.findingsCount > 0 ? 'bg-red-500/10' : 'bg-emerald-500/10'}`}>
                            <AlertOctagon className={`w-6 h-6 ${entry.findingsCount > 0 ? 'text-red-500' : 'text-emerald-500'}`} />
                          </div>
                          <div>
                            <h4 className="text-white font-bold text-sm truncate max-w-md">{entry.targetUrl}</h4>
                            <div className="flex items-center gap-4 mt-1">
                               <div className="flex items-center gap-1.5 text-[10px] text-zinc-500">
                                 <Calendar className="w-3 h-3" />
                                 {new Date(entry.timestamp).toLocaleDateString()}
                               </div>
                               <div className="flex items-center gap-1.5 text-[10px] text-zinc-500">
                                 <Clock className="w-3 h-3" />
                                 {new Date(entry.timestamp).toLocaleTimeString()}
                               </div>
                               {entry.summary && (
                                 <div className="flex items-center gap-1.5 text-[10px] text-emerald-500 font-mono">
                                   <Zap className="w-3 h-3" />
                                   {entry.summary}
                                 </div>
                               )}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-8">
                           <div className="text-right">
                              <p className="text-[10px] text-zinc-500 uppercase font-bold mb-1">Resultados</p>
                              <div className="flex gap-2">
                                <span className="px-2 py-0.5 bg-red-500/10 text-red-500 text-[10px] font-bold rounded border border-red-500/20">
                                  {entry.criticalCount} Críticas
                                </span>
                                <span className="px-2 py-0.5 bg-zinc-800 text-zinc-400 text-[10px] font-bold rounded border border-zinc-700">
                                  {entry.findingsCount} Total
                                </span>
                              </div>
                           </div>
                           <button 
                             onClick={(e) => deleteHistoryEntry(entry.id, e)}
                             className="p-2 text-zinc-600 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all"
                           >
                             <Trash2 className="w-4 h-4" />
                           </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {activeTab === 'code' && (
              <div className="h-full flex flex-col gap-6">
                <div className="bg-[#0d0d0e] border border-emerald-500/20 p-6 rounded-xl flex items-center justify-between">
                  <div className="flex gap-4 items-center">
                    <FileCode className="text-emerald-400 w-10 h-10" />
                    <div>
                      <h3 className="font-bold text-white">Generador de Payload Técnico</h3>
                      <p className="text-xs text-zinc-500">Este script implementa las pruebas técnicas y genera el PDF de reporte explícito.</p>
                    </div>
                  </div>
                  <button onClick={() => {navigator.clipboard.writeText(generatePythonScript(url, params.split(','))); alert("Copiado!");}} className="bg-emerald-600 text-white px-6 py-2 rounded-lg font-bold text-xs">COPIAR CÓDIGO PYTHON</button>
                </div>
                <div className="flex-1 bg-black rounded-xl border border-zinc-800 p-6 overflow-hidden flex flex-col">
                  <div className="text-[10px] font-mono text-zinc-500 mb-4 uppercase">escanner_tecnico_v2.py</div>
                  <pre className="text-sm text-emerald-500/90 font-mono flex-1 overflow-y-auto"><code>{generatePythonScript(url, params.split(','))}</code></pre>
                </div>
              </div>
            )}

            {activeTab === 'disclaimer' && (
              <div className="max-w-3xl mx-auto py-12">
                <div className="bg-red-500/5 border border-red-500/10 p-8 rounded-2xl">
                  <div className="flex items-center gap-4 mb-6">
                    <ShieldCheck className="w-10 h-10 text-red-500" />
                    <h2 className="text-3xl font-black text-white tracking-tighter">AVISO ÉTICO</h2>
                  </div>
                  
                  <div className="prose prose-invert max-w-none text-zinc-400 space-y-4">
                    <p className="text-zinc-200 font-medium text-lg leading-relaxed">
                      La investigación de seguridad es un campo crítico que requiere altos estándares éticos. Acceder o probar sistemas informáticos sin autorización es ilegal y punible bajo leyes como la CFAA en los Estados Unidos y regulaciones similares en todo el mundo.
                    </p>
                    
                    <div className="bg-black/40 p-6 rounded-xl border border-zinc-800 my-8">
                       <h4 className="text-white font-bold mb-2">Reglas de Compromiso:</h4>
                       <ul className="list-disc pl-5 space-y-2 text-sm italic">
                          <li>Nunca pruebes un objetivo sin permiso explícito por escrito.</li>
                          <li>Respeta la privacidad y la integridad de los datos en todo momento.</li>
                          <li>Reporta los hallazgos de manera responsable a través de programas de Bug Bounty o VDP.</li>
                          <li>Utiliza esta herramienta estrictamente para entornos de laboratorio y aprendizaje.</li>
                       </ul>
                    </div>

                    <p className="p-4 border-l-4 border-red-500 bg-red-500/10 text-red-200 italic font-mono text-xs">
                      {EDUCATIONAL_DISCLAIMER}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
};

export default ScannerDashboard;
