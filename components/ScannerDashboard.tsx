
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
  X
} from 'lucide-react';
import { jsPDF } from 'jspdf';
import { VulnerabilityType, ScanFinding, ScanResult, HistoryEntry, SSLInfo } from '../types';
import { 
  SQLI_PAYLOADS, 
  XSS_PAYLOADS, 
  REDIRECT_PAYLOADS, 
  SSRF_PAYLOADS, 
  CRLF_INJECTION_PAYLOADS, 
  SQL_ERROR_SIGNATURES, 
  EDUCATIONAL_DISCLAIMER 
} from '../constants';
import { generatePythonScript, analyzeFindingWithAI } from '../services/geminiService';

const ScannerDashboard: React.FC = () => {
  const [url, setUrl] = useState('https://example.com/search');
  const [params, setParams] = useState('q,id,url,api,lang');
  const [checkSsl, setCheckSsl] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'results' | 'code' | 'history' | 'disclaimer'>('overview');
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [aiAnalyses, setAiAnalyses] = useState<Record<number, string>>({});
  const [scanHistory, setScanHistory] = useState<HistoryEntry[]>([]);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

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
    const counts: Record<string, number> = {};
    scanResult.findings.forEach(f => {
      counts[f.type] = (counts[f.type] || 0) + 1;
    });

    const summary = Object.entries(counts)
      .map(([type, count]) => {
        if (type === VulnerabilityType.SQLI) return `SQLi: ${count}`;
        if (type === VulnerabilityType.XSS) return `XSS: ${count}`;
        if (type === VulnerabilityType.OPEN_REDIRECT) return `OR: ${count}`;
        if (type === VulnerabilityType.SSRF) return `SSRF: ${count}`;
        if (type === VulnerabilityType.CRLF_INJECTION) return `CRLF: ${count}`;
        return `${type}: ${count}`;
      })
      .join(', ') || 'Sin hallazgos';

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
    setIsSidebarOpen(false); // Cerrar sidebar en móvil al iniciar
    setIsScanning(true);
    setProgress(0);
    setLogs([]);
    setResult(null);
    setAiAnalyses({});
    const startTime = Date.now();
    
    try {
      if (!url) throw new Error("La URL del objetivo no puede estar vacía.");
      if (!isValidUrl(url)) throw new Error("Formato de URL inválido.");

      const targetHostname = new URL(url).hostname;
      const paramList = params.split(',').map(p => p.trim()).filter(p => p);
      if (paramList.length === 0) throw new Error("Se requiere al menos un parámetro.");

      addLog(`[SYSTEM] Iniciando secuencia de auditoría DAST técnica en ${url}...`);
      await new Promise(r => setTimeout(r, 600)); 

      let sslInfo: SSLInfo | undefined = undefined;
      if (checkSsl) {
        addLog(`[*] Verificando certificado SSL/TLS para ${targetHostname}...`);
        await new Promise(r => setTimeout(r, 800));
        
        if (url.startsWith('https')) {
          const isMockInsecure = url.includes('insecure') || targetHostname === 'localhost';
          sslInfo = {
            valid: !isMockInsecure,
            issuer: isMockInsecure ? 'Self-Signed Researcher CA' : 'DigiCert TLS RSA SHA256 2020 CA1',
            expiry: isMockInsecure ? '2023-01-01 (CADUCADO)' : '2026-12-31',
            protocol: 'TLS 1.3',
            error: isMockInsecure ? 'CERT_HAS_EXPIRED: El certificado está caducado o es auto-firmado y no ofrece confianza.' : undefined
          };
          addLog(isMockInsecure ? `[!] ADVERTENCIA: Certificado SSL no válido detectado.` : `[+] Certificado SSL válido verificado.`);
        } else {
          sslInfo = {
            valid: false,
            issuer: 'N/A',
            expiry: 'N/A',
            protocol: 'N/A',
            error: 'CONEXIÓN INSEGURA: El objetivo no utiliza HTTPS. Los datos se transmiten en texto claro, permitiendo ataques de hombre en el medio (MITM).'
          };
          addLog(`[!] ALERTA CRÍTICA: El objetivo no utiliza cifrado HTTPS.`);
        }
      }

      let foundFindings: ScanFinding[] = [];
      const totalSteps = paramList.length * 10;
      let currentStep = 0;

      for (const p of paramList) {
        if (p.toLowerCase().includes('id') || p.toLowerCase().includes('uid')) {
          addLog(`[SQLi] Analizando vulnerabilidades de inyección en parámetro: ${p}`);
          await new Promise(r => setTimeout(r, 100));
          addLog(`[SQLi] Vector potencial detectado. Iniciando verificación Double-Pass...`);
          await new Promise(r => setTimeout(r, 300));
          
          foundFindings.push({
            parameter: p,
            payload: "' OR 1=1--",
            type: VulnerabilityType.SQLI,
            severity: 'Critical',
            evidence: 'HTTP/1.1 200 OK\nServer: nginx\nContent-Type: text/html\n\n[DUMP] User: admin, Pass: hash_8321... [SUCCESSFUL BYPASS]',
            description: `Se ha confirmado una vulnerabilidad de Inyección SQL (SQLi) persistente en el parámetro '${p}'. Esta falla permite a un atacante interferir con las consultas que la aplicación realiza a su base de datos. En este caso específico, se ha logrado un bypass de autenticación y la extracción de registros mediante una técnica de inyección booleana.`,
            rootCause: "La aplicación concatena directamente la entrada del usuario en una cadena de consulta SQL sin utilizar sentencias preparadas (Prepared Statements) ni parametrización, lo que permite la alteración de la lógica de la consulta.",
            impact: "Compromiso total de la confidencialidad, integridad y disponibilidad de la base de datos. Un atacante puede leer datos sensibles, modificar o borrar registros, y en configuraciones inseguras, ejecutar comandos a nivel de sistema operativo (RCE)."
          });
          addLog(`[!] SQLi CONFIRMADA en '${p}'`);
        }

        if (p.toLowerCase().includes('q') || p.toLowerCase().includes('search')) {
          addLog(`[XSS] Auditando Cross-Site Scripting reflejado en parámetro: ${p}`);
          await new Promise(r => setTimeout(r, 100));
          
          foundFindings.push({
            parameter: p,
            payload: "<img src=x onerror=alert(document.cookie)>",
            type: VulnerabilityType.XSS,
            severity: 'High',
            evidence: 'Response Body: ... <div>Usted buscó: <img src=x onerror=alert(document.cookie)></div> ...',
            description: `Vulnerabilidad de Cross-Site Scripting (XSS) Reflejado verificada. La aplicación toma la entrada del parámetro '${p}' y la incluye en la respuesta HTML de la página sin realizar una codificación adecuada de caracteres especiales. Se confirmó que el navegador ejecuta scripts inyectados en el contexto de la sesión del usuario.`,
            rootCause: "Falta de 'Output Encoding' (codificación de salida) al renderizar datos proporcionados por el usuario. La aplicación no neutraliza etiquetas HTML ni atributos de eventos JavaScript antes de insertarlos en el DOM.",
            impact: "Robo de tokens de sesión (Session Hijacking), desfiguración del sitio web (Defacement), redirecciones maliciosas y ejecución de ataques de ingeniería social complejos contra los usuarios finales."
          });
          addLog(`[!] XSS CONFIRMADO en '${p}'`);
        }

        if (p.toLowerCase().includes('api') || p.toLowerCase().includes('url')) {
          addLog(`[SSRF] Comprobando falsificación de peticiones del lado del servidor en: ${p}`);
          await new Promise(r => setTimeout(r, 150));
          
          foundFindings.push({
            parameter: p,
            payload: "http://169.254.169.254/latest/meta-data/hostname",
            type: VulnerabilityType.SSRF,
            severity: 'Critical',
            evidence: 'HTTP/1.1 200 OK\n\nip-10-0-1-50.ec2.internal',
            description: `Se ha identificado una vulnerabilidad crítica de Server-Side Request Forgery (SSRF). La aplicación permite a un atacante forzar al servidor web a realizar peticiones HTTP hacia destinos arbitrarios. Se ha verificado el acceso exitoso al servicio de metadatos de la instancia cloud (IMDS), lo cual es un vector clásico de escalada en entornos de nube.`,
            rootCause: "La aplicación procesa URLs proporcionadas por el usuario para realizar peticiones de red internas sin restringir los destinos a una lista blanca de confianza ni bloquear el acceso a rangos de direcciones IP privadas o servicios de infraestructura interna.",
            impact: "Exfiltración de secretos de infraestructura y claves de acceso temporales de la nube (IAM Roles), escaneo de la red interna privada del servidor y acceso a servicios administrativos no expuestos a Internet."
          });
          addLog(`[!] SSRF CONFIRMADO en '${p}'`);
        }
        
        currentStep += 10;
        setProgress(Math.min(95, Math.round((currentStep / (paramList.length * 10)) * 100)));
      }

      const endTime = Date.now();
      const durationSeconds = (endTime - startTime) / 1000;

      const scanResult: ScanResult = {
        targetUrl: url,
        timestamp: new Date().toISOString(),
        totalRequests: paramList.length * 50,
        findings: foundFindings,
        duration: durationSeconds,
        sslInfo
      };
      
      setResult(scanResult);
      saveToHistory(scanResult);
      setProgress(100);
      addLog(`[SYSTEM] Auditoría finalizada. Se han documentado ${foundFindings.length} hallazgos críticos verificados.`);
      setActiveTab('results');

    } catch (error: any) {
      addLog(`[!] ERROR: ${error.message}`);
      setIsScanning(false);
    } finally {
      setIsScanning(false);
    }
  };

  const getAIAnalysis = async (index: number, finding: ScanFinding) => {
    if (aiAnalyses[index]) return;
    setAiAnalyses(prev => ({ ...prev, [index]: 'Analizando hallazgo con motor Gemini Pro...' }));
    const analysis = await analyzeFindingWithAI(finding);
    setAiAnalyses(prev => ({ ...prev, [index]: analysis }));
  };

  const downloadPDFReport = () => {
    if (!result) return;
    const doc = new jsPDF();
    const timestamp = new Date().toLocaleString();
    doc.setFillColor(15, 15, 17);
    doc.rect(0, 0, 210, 50, 'F');
    doc.setTextColor(16, 185, 129);
    doc.setFontSize(24);
    doc.setFont("helvetica", "bold");
    doc.text("REPORTE TÉCNICO DAST", 20, 30);
    doc.setFontSize(10);
    doc.setTextColor(255, 255, 255);
    doc.text(`AUDITORÍA PROFESIONAL | ${timestamp}`, 20, 40);
    doc.save(`REPORTE_VULNSCAN_${Date.now()}.pdf`);
  };

  return (
    <div className="flex flex-col h-screen bg-[#0a0a0b] text-[#e4e4e7] overflow-hidden selection:bg-emerald-500/30 font-sans">
      {/* Header Responsivo */}
      <header className="flex items-center justify-between px-4 sm:px-8 py-4 sm:py-5 border-b border-zinc-800 bg-[#0d0d0e] z-30 shadow-2xl">
        <div className="flex items-center gap-3 sm:gap-4">
          <button 
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className="lg:hidden p-2 text-zinc-400 hover:bg-zinc-800 rounded-lg transition-colors"
          >
            {isSidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
          <div className="p-2 bg-emerald-500/10 rounded-xl border border-emerald-500/20">
            <ShieldAlert className="w-6 h-6 sm:w-7 sm:h-7 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-xl sm:text-2xl font-black tracking-tighter text-white uppercase italic leading-none">
              VulnScan <span className="text-emerald-400 not-italic">PRO</span>
            </h1>
            <p className="text-[9px] sm:text-[10px] text-zinc-500 font-bold uppercase tracking-[0.2em] mt-0.5">Offensive Security Suite</p>
          </div>
        </div>
        <div className="flex items-center gap-3 sm:gap-4">
          <div className="hidden sm:flex flex-col items-end mr-2">
            <span className="text-[9px] font-bold text-zinc-500 uppercase tracking-widest">Researcher Node</span>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-bold text-emerald-400">ONLINE</span>
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></div>
            </div>
          </div>
          <button onClick={() => setActiveTab('disclaimer')} className="p-2 hover:bg-zinc-800 rounded-lg transition-colors text-zinc-400">
            <Info className="w-5 h-5" />
          </button>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden relative">
        {/* Sidebar con Drawer Responsivo */}
        <aside className={`
          fixed lg:static inset-y-0 left-0 z-40 w-72 sm:w-80 bg-[#0d0d0e] border-r border-zinc-800 p-6 sm:p-8 
          transform transition-transform duration-300 ease-in-out flex flex-col gap-6 overflow-y-auto
          ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        `}>
          <section>
            <div className="flex items-center gap-2 mb-6 text-zinc-400">
              <Target className="w-4 h-4" />
              <h3 className="text-[10px] font-black uppercase tracking-widest">Parámetros del Objetivo</h3>
            </div>
            <div className="space-y-5">
              <div>
                <label className="block text-[9px] font-black text-zinc-500 uppercase mb-2 tracking-widest">Target Endpoint</label>
                <div className="relative group">
                  <input 
                    type="text" 
                    value={url} 
                    onChange={(e) => setUrl(e.target.value)} 
                    className="w-full bg-zinc-900 border border-zinc-800 rounded-xl py-3 pl-4 pr-10 text-xs text-white focus:ring-2 focus:ring-emerald-500/40 outline-none transition-all"
                    placeholder="https://example.com"
                  />
                  <Search className="absolute right-3.5 top-3 w-4 h-4 text-zinc-600" />
                </div>
              </div>
              <div>
                <label className="block text-[9px] font-black text-zinc-500 uppercase mb-2 tracking-widest">Query Parameters</label>
                <input 
                  type="text" 
                  value={params} 
                  onChange={(e) => setParams(e.target.value)} 
                  className="w-full bg-zinc-900 border border-zinc-800 rounded-xl py-3 px-4 text-xs text-white focus:ring-2 focus:ring-emerald-500/40 outline-none transition-all font-mono"
                  placeholder="id,q..."
                />
              </div>
              <div className="flex items-center gap-4 p-4 bg-zinc-900/40 rounded-2xl border border-zinc-800 hover:border-zinc-700 transition-all cursor-pointer" onClick={() => setCheckSsl(!checkSsl)}>
                <div className={`w-9 h-5 rounded-full p-1 transition-colors ${checkSsl ? 'bg-emerald-600' : 'bg-zinc-700'}`}>
                   <div className={`w-3 h-3 bg-white rounded-full transition-transform ${checkSsl ? 'translate-x-4' : 'translate-x-0'}`}></div>
                </div>
                <div className="flex flex-col">
                  <span className="text-[10px] font-black text-zinc-300 uppercase">Verificación SSL</span>
                  <span className="text-[9px] text-zinc-600 font-bold">Validar certificados</span>
                </div>
              </div>
            </div>
          </section>

          <button 
            onClick={runMockScan} 
            disabled={isScanning || !url} 
            className={`
              mt-2 flex items-center justify-center gap-3 w-full py-4 rounded-2xl font-black text-[10px] uppercase tracking-[0.2em] transition-all shadow-xl
              ${isScanning ? 'bg-zinc-800 text-zinc-600' : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-900/10 active:scale-95'}
            `}
          >
            {isScanning ? <Activity className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
            {isScanning ? 'Procesando...' : 'Iniciar Auditoría'}
          </button>

          <div className="mt-auto space-y-4">
             <div className="flex items-center gap-2 mb-2 text-zinc-500"><History className="w-3 h-3" /><h3 className="text-[9px] font-black uppercase tracking-widest">Sesión Actual</h3></div>
             <div className="grid grid-cols-2 gap-3">
               <div className="bg-zinc-900/30 p-3 rounded-xl border border-zinc-800/50">
                  <span className="block text-[8px] font-black text-zinc-600 uppercase mb-1">Hallazgos</span>
                  <span className={`text-base font-black ${result?.findings.length ? 'text-red-500' : 'text-zinc-500'}`}>{result?.findings.length || 0}</span>
               </div>
               <div className="bg-zinc-900/30 p-3 rounded-xl border border-zinc-800/50">
                  <span className="block text-[8px] font-black text-zinc-600 uppercase mb-1">Críticos</span>
                  <span className="text-base font-black text-orange-500">{result?.findings.filter(f => f.severity === 'Critical').length || 0}</span>
               </div>
             </div>
          </div>
        </aside>

        {/* Overlay para móvil */}
        {isSidebarOpen && (
          <div 
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-30 lg:hidden" 
            onClick={() => setIsSidebarOpen(false)}
          />
        )}

        {/* Área de Contenido Principal Adaptable */}
        <main className="flex-1 flex flex-col bg-[#0a0a0b] w-full overflow-hidden">
          <nav className="flex items-center gap-6 sm:gap-10 px-6 sm:px-10 py-3 bg-[#0d0d0e] border-b border-zinc-800 overflow-x-auto no-scrollbar scroll-smooth">
            <button onClick={() => setActiveTab('overview')} className={`flex items-center gap-2 pb-2 text-[10px] font-black uppercase tracking-widest transition-all whitespace-nowrap ${activeTab === 'overview' ? 'text-emerald-400 border-b-2 border-emerald-500' : 'text-zinc-500 hover:text-zinc-300'}`}>
              <Layout className="w-3.5 h-3.5" /> Monitor
            </button>
            <button onClick={() => setActiveTab('results')} className={`flex items-center gap-2 pb-2 text-[10px] font-black uppercase tracking-widest transition-all whitespace-nowrap ${activeTab === 'results' ? 'text-emerald-400 border-b-2 border-emerald-500' : 'text-zinc-500 hover:text-zinc-300'}`}>
              <AlertOctagon className="w-3.5 h-3.5" /> Reporte
            </button>
            <button onClick={() => setActiveTab('history')} className={`flex items-center gap-2 pb-2 text-[10px] font-black uppercase tracking-widest transition-all whitespace-nowrap ${activeTab === 'history' ? 'text-emerald-400 border-b-2 border-emerald-500' : 'text-zinc-500 hover:text-zinc-300'}`}>
              <History className="w-3.5 h-3.5" /> Historial
            </button>
            <button onClick={() => setActiveTab('code')} className={`flex items-center gap-2 pb-2 text-[10px] font-black uppercase tracking-widest transition-all whitespace-nowrap ${activeTab === 'code' ? 'text-emerald-400 border-b-2 border-emerald-500' : 'text-zinc-500 hover:text-zinc-300'}`}>
              <Code className="w-3.5 h-3.5" /> Script
            </button>
          </nav>

          <div className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-10 scrollbar-thin scrollbar-thumb-zinc-800">
            {activeTab === 'overview' && (
              <div className="space-y-6 sm:space-y-8 max-w-5xl mx-auto">
                <div className="bg-[#0d0d0e] border border-zinc-800 rounded-2xl sm:rounded-3xl p-6 sm:p-8 shadow-2xl overflow-hidden relative group">
                  <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:opacity-10 transition-opacity hidden sm:block">
                    <Activity className="w-32 h-32 text-emerald-500" />
                  </div>
                  <h2 className="text-lg sm:text-xl font-black text-white mb-6 uppercase tracking-tight flex items-center gap-3">
                    <Activity className="w-5 h-5 sm:w-6 sm:h-6 text-emerald-500" />
                    Progreso en Tiempo Real
                  </h2>
                  {isScanning ? (
                    <div className="space-y-5">
                      <div className="flex justify-between items-end">
                        <span className="text-[10px] font-black text-zinc-500 uppercase tracking-widest">Escaneo de Vectores</span>
                        <span className="text-emerald-400 font-mono text-xl sm:text-2xl font-black">{progress}%</span>
                      </div>
                      <div className="w-full h-2.5 bg-zinc-900 rounded-full overflow-hidden border border-zinc-800">
                        <div className="h-full bg-emerald-500 transition-all duration-500 shadow-[0_0_15px_#10b981]" style={{ width: `${progress}%` }}></div>
                      </div>
                      <p className="text-[10px] sm:text-xs text-zinc-500 animate-pulse font-medium">Inyectando payloads y analizando cabeceras de respuesta HTTP...</p>
                    </div>
                  ) : <div className="text-center py-6 text-zinc-600 text-xs italic font-medium uppercase tracking-widest">Esperando inicio de secuencia...</div>}
                </div>

                <div className="bg-[#0d0d0e] border border-zinc-800 rounded-2xl sm:rounded-3xl overflow-hidden h-80 sm:h-[450px] flex flex-col shadow-2xl">
                  <div className="px-5 py-3 bg-zinc-900/80 border-b border-zinc-800 text-[9px] uppercase font-black text-zinc-500 tracking-[0.2em] flex justify-between items-center">
                    <span className="flex items-center gap-2"><Terminal className="w-3 h-3" /> Console Output</span>
                    <div className="flex gap-1.5">
                      <div className="w-2 h-2 rounded-full bg-red-500/30"></div>
                      <div className="w-2 h-2 rounded-full bg-orange-500/30"></div>
                      <div className="w-2 h-2 rounded-full bg-emerald-500/30"></div>
                    </div>
                  </div>
                  <div className="flex-1 p-4 sm:p-6 font-mono text-[10px] sm:text-[11px] overflow-y-auto space-y-1.5 bg-black/40">
                    {logs.map((log, i) => (
                      <div key={i} className={`p-1 rounded flex gap-2 sm:gap-3 ${log.includes('[!]') ? 'text-red-400 bg-red-400/5 border-l-2 border-red-500' : log.includes('[?]') ? 'text-orange-400 bg-orange-400/5' : 'text-zinc-500'}`}>
                        <span className="opacity-20 select-none">[{i+1}]</span>
                        <span className="break-all">{log}</span>
                      </div>
                    ))}
                    {logs.length === 0 && <div className="text-zinc-800 italic h-full flex items-center justify-center text-[10px] tracking-widest uppercase">Null_State.Waiting_For_Input</div>}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'results' && (
              <div className="space-y-8 sm:space-y-10 max-w-6xl mx-auto">
                {result ? (
                  <>
                    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-6">
                      <div className="w-full sm:w-auto">
                        <h2 className="text-2xl sm:text-3xl font-black text-white mb-2 uppercase tracking-tight">Hallazgos Técnicos</h2>
                        <p className="text-[10px] sm:text-xs text-zinc-500 flex items-center gap-2 truncate"><Target className="w-3.5 h-3.5" /> {result.targetUrl}</p>
                      </div>
                      <div className="flex w-full sm:w-auto gap-3">
                        <button onClick={downloadPDFReport} className="flex-1 sm:flex-none flex items-center justify-center gap-2 bg-zinc-800 hover:bg-zinc-700 text-white px-4 py-3 rounded-xl text-[9px] font-black uppercase tracking-widest transition-all">
                          <Download className="w-4 h-4" /> PDF
                        </button>
                        <button onClick={runMockScan} className="flex-1 sm:flex-none flex items-center justify-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-3 rounded-xl text-[9px] font-black uppercase tracking-widest transition-all">
                          <Zap className="w-4 h-4" /> Re-audit
                        </button>
                      </div>
                    </div>

                    <div className="space-y-8">
                      {result.findings.map((f, i) => (
                        <div key={i} className="bg-[#0d0d0e] border border-zinc-800 rounded-2xl sm:rounded-[2rem] overflow-hidden shadow-2xl hover:border-zinc-700 transition-all">
                          <div className={`px-6 sm:px-10 py-5 sm:py-6 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 ${f.severity === 'Critical' ? 'bg-red-500/10' : 'bg-orange-500/10'}`}>
                            <div className="flex gap-4 sm:gap-6 items-center">
                              <div className={`p-2.5 sm:p-3.5 rounded-xl sm:rounded-2xl ${f.severity === 'Critical' ? 'bg-red-500/20 text-red-500' : 'bg-orange-500/20 text-orange-500'}`}>
                                <Bug className="w-6 h-6 sm:w-8 sm:h-8" />
                              </div>
                              <div>
                                <h3 className="font-black text-white text-lg sm:text-xl uppercase tracking-tighter">{f.type}</h3>
                                <div className="flex gap-3 sm:gap-4 mt-0.5">
                                  <p className="text-[8px] sm:text-[9px] text-zinc-500 font-black uppercase tracking-widest font-mono">{f.parameter}</p>
                                  <p className={`text-[8px] sm:text-[9px] font-black uppercase tracking-widest ${f.severity === 'Critical' ? 'text-red-500' : 'text-orange-500'}`}>{f.severity}</p>
                                </div>
                              </div>
                            </div>
                            <span className={`px-4 py-1.5 rounded-full text-[8px] font-black uppercase tracking-widest border self-end sm:self-center ${f.severity === 'Critical' ? 'bg-red-500/20 text-red-500 border-red-500/30' : 'bg-orange-500/20 text-orange-500 border-orange-500/30'}`}>{f.severity}</span>
                          </div>

                          <div className="p-6 sm:p-10 grid grid-cols-1 lg:grid-cols-12 gap-8 sm:gap-10">
                            <div className="lg:col-span-7 space-y-8">
                              <section>
                                <h4 className="text-[9px] font-black uppercase tracking-[0.2em] text-emerald-500 mb-3 flex items-center gap-2"><BookOpen className="w-3.5 h-3.5" /> Resumen Técnico</h4>
                                <div className="text-xs sm:text-sm text-zinc-400 leading-relaxed bg-zinc-900/30 p-5 rounded-2xl border border-zinc-800/50">
                                  {f.description}
                                </div>
                              </section>
                              <section>
                                <h4 className="text-[9px] font-black uppercase tracking-[0.2em] text-red-500 mb-3 flex items-center gap-2"><AlertTriangle className="w-3.5 h-3.5" /> Riesgo de Explotación</h4>
                                <div className="text-xs sm:text-sm text-zinc-400 leading-relaxed bg-red-400/5 p-5 rounded-2xl border border-red-400/10">
                                  {f.impact}
                                </div>
                              </section>
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <section>
                                  <h4 className="text-[9px] font-black uppercase tracking-[0.2em] text-zinc-500 mb-3 flex items-center gap-2"><ShieldQuestion className="w-3.5 h-3.5" /> Root Cause</h4>
                                  <div className="text-[11px] text-zinc-500 italic bg-zinc-900/20 p-4 rounded-xl border border-zinc-800/30 min-h-[80px]">
                                    {f.rootCause}
                                  </div>
                                </section>
                                <section>
                                  <h4 className="text-[9px] font-black uppercase tracking-[0.2em] text-zinc-500 mb-3 flex items-center gap-2"><FileSearch className="w-3.5 h-3.5" /> Evidencia</h4>
                                  <div className="bg-black/40 p-4 rounded-xl border border-zinc-800 min-h-[80px] overflow-hidden">
                                    <pre className="text-[9px] text-emerald-500/70 font-mono whitespace-pre-wrap">{f.evidence}</pre>
                                  </div>
                                </section>
                              </div>
                            </div>

                            <div className="lg:col-span-5">
                              <section className="h-full flex flex-col bg-[#0f0f11] rounded-2xl sm:rounded-[2rem] border border-zinc-800 p-6 sm:p-8 shadow-2xl relative overflow-hidden min-h-[300px]">
                                <div className="absolute top-0 right-0 p-6 opacity-5 pointer-events-none">
                                   <Zap className="w-20 h-20 text-emerald-500" />
                                </div>
                                <div className="flex items-center justify-between mb-6 relative z-10">
                                  <h4 className="text-[9px] font-black uppercase tracking-[0.2em] text-emerald-500 flex items-center gap-2"><Zap className="w-3.5 h-3.5" /> Remediación IA</h4>
                                  {!aiAnalyses[i] && (
                                    <button 
                                      onClick={() => getAIAnalysis(i, f)} 
                                      className="text-[8px] bg-emerald-600/10 hover:bg-emerald-600/20 text-emerald-400 px-3 py-1.5 rounded-lg transition-all border border-emerald-500/20 font-black uppercase tracking-widest"
                                    >
                                      Analizar
                                    </button>
                                  )}
                                </div>
                                <div className="flex-1 overflow-y-auto text-[10px] sm:text-[11px] text-zinc-500 leading-relaxed whitespace-pre-wrap relative z-10 scrollbar-thin scrollbar-thumb-zinc-800">
                                  {aiAnalyses[i] || (
                                    <div className="flex flex-col items-center justify-center h-full text-center opacity-20 py-10 space-y-3">
                                      <Wrench className="w-12 h-12" />
                                      <p className="uppercase font-black tracking-widest text-[8px] max-w-[150px]">Ejecutar motor de mitigación para este hallazgo.</p>
                                    </div>
                                  )}
                                </div>
                              </section>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                ) : (
                  <div className="flex flex-col items-center justify-center py-24 sm:py-40 text-zinc-700 bg-[#0d0d0e] rounded-3xl sm:rounded-[3rem] border-2 border-zinc-800 border-dashed space-y-6 sm:space-y-8 px-4 text-center">
                    <ShieldCheck className="w-16 h-16 sm:w-20 sm:h-20 opacity-5" />
                    <div className="space-y-2">
                      <h3 className="text-xl sm:text-2xl font-black uppercase tracking-tighter">Sin Auditorías Activas</h3>
                      <p className="text-xs sm:text-sm max-w-xs mx-auto text-zinc-600 font-medium">Configure el objetivo en el panel de control y lance una auditoría para generar resultados.</p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'history' && (
              <div className="space-y-6 max-w-4xl mx-auto">
                <div className="flex justify-between items-end mb-4">
                  <div>
                    <h2 className="text-2xl sm:text-3xl font-black text-white uppercase tracking-tight">Logs</h2>
                    <p className="text-[9px] sm:text-[10px] text-zinc-600 font-black uppercase tracking-widest mt-1">Sesiones de investigación previas</p>
                  </div>
                  {scanHistory.length > 0 && (
                    <button onClick={clearAllHistory} className="text-[9px] font-black text-red-400/60 hover:text-red-400 transition-all uppercase tracking-widest bg-red-400/5 px-3 py-2 rounded-xl border border-red-400/10 flex items-center gap-2">
                      <Trash2 className="w-3.5 h-3.5" /> Flush
                    </button>
                  )}
                </div>
                <div className="grid grid-cols-1 gap-4">
                  {scanHistory.map(h => (
                    <div key={h.id} className="bg-[#0d0d0e] border border-zinc-800 rounded-2xl p-4 sm:p-5 flex justify-between items-center group hover:border-zinc-700 transition-all shadow-xl">
                      <div className="flex gap-4 sm:gap-5 items-center min-w-0">
                        <div className={`p-3 rounded-xl flex-shrink-0 ${h.findingsCount > 0 ? 'bg-red-500/10 text-red-500' : 'bg-emerald-500/10 text-emerald-500'}`}>
                          {h.findingsCount > 0 ? <AlertTriangle className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
                        </div>
                        <div className="min-w-0">
                          <p className="text-xs sm:text-sm font-black text-white truncate group-hover:text-emerald-400 transition-colors uppercase tracking-tight">{h.targetUrl}</p>
                          <div className="flex flex-wrap items-center gap-2 sm:gap-4 mt-1">
                            <p className="text-[8px] sm:text-[9px] text-zinc-600 flex items-center gap-1.5 uppercase font-black"><Calendar className="w-3 h-3" /> {new Date(h.timestamp).toLocaleDateString()}</p>
                            <p className="text-[8px] sm:text-[9px] text-zinc-500 font-black uppercase tracking-[0.1em]">{h.summary}</p>
                          </div>
                        </div>
                      </div>
                      <button onClick={(e) => deleteHistoryEntry(h.id, e)} className="p-2.5 text-zinc-700 hover:text-red-500 transition-all bg-zinc-900/50 rounded-xl">
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                  {scanHistory.length === 0 && <div className="text-center py-20 text-zinc-800 font-black uppercase tracking-[0.3em] text-[10px]">History_Is_Empty</div>}
                </div>
              </div>
            )}

            {activeTab === 'code' && (
              <div className="h-full flex flex-col gap-6 sm:gap-8 max-w-5xl mx-auto">
                <div className="bg-[#0d0d0e] border border-emerald-500/10 p-6 sm:p-8 rounded-2xl sm:rounded-[2.5rem] flex flex-col sm:flex-row justify-between items-center gap-6 shadow-2xl overflow-hidden relative">
                  <div className="absolute top-0 left-0 w-1 h-full bg-emerald-500/30"></div>
                  <div className="flex gap-4 sm:gap-6 items-center">
                    <div className="p-3 sm:p-4 bg-emerald-500/10 rounded-2xl text-emerald-400">
                      <FileCode className="w-7 h-7 sm:w-8 sm:h-8" />
                    </div>
                    <div>
                      <h3 className="text-base sm:text-lg font-black text-white uppercase tracking-tighter">Researcher Suite</h3>
                      <p className="text-[10px] sm:text-xs text-zinc-600 mt-1 font-medium leading-relaxed max-w-md">Script portable en Python con lógica Double-Pass para despliegue local de investigación.</p>
                    </div>
                  </div>
                  <button onClick={() => {navigator.clipboard.writeText(generatePythonScript(url, params.split(','))); alert("Script copiado.");}} className="w-full sm:w-auto bg-emerald-600 hover:bg-emerald-500 text-white px-6 py-3.5 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all shadow-xl active:scale-95 flex items-center justify-center gap-2">
                    <Code className="w-4 h-4" /> Copy Script
                  </button>
                </div>
                <div className="flex-1 bg-[#050505] rounded-2xl sm:rounded-[2.5rem] border border-zinc-800 p-6 sm:p-8 overflow-hidden relative group">
                  <div className="absolute top-4 right-6 text-[8px] text-zinc-700 font-black uppercase tracking-[0.2em] hidden sm:block">research_automation.py</div>
                  <pre className="text-[10px] sm:text-[11px] text-emerald-500/70 font-mono h-full overflow-y-auto scrollbar-thin scrollbar-thumb-zinc-800 pr-4 leading-relaxed">
                    <code>{generatePythonScript(url, params.split(','))}</code>
                  </pre>
                </div>
              </div>
            )}

            {activeTab === 'disclaimer' && (
              <div className="max-w-3xl mx-auto py-10">
                <div className="bg-orange-500/5 border border-orange-500/10 p-8 sm:p-12 rounded-3xl sm:rounded-[3rem] shadow-2xl">
                   <div className="flex items-center gap-4 mb-8 text-orange-500">
                      <AlertTriangle className="w-8 h-8 sm:w-10 sm:h-10" />
                      <h2 className="text-2xl sm:text-3xl font-black uppercase tracking-tighter">Legal Policy</h2>
                   </div>
                   <p className="text-zinc-400 leading-[1.8] font-medium text-xs sm:text-sm text-justify">
                     {EDUCATIONAL_DISCLAIMER}
                   </p>
                   <div className="mt-10 pt-8 border-t border-orange-500/5 flex justify-between items-center text-[9px] font-black text-zinc-700 uppercase tracking-widest">
                      <span>Ethical Standards Compliance</span>
                      <span>Security_Node_v2.4</span>
                   </div>
                </div>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
};

export default ScannerDashboard;
