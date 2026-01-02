
import { VulnerabilityType, ScanFinding } from '../types';
import { SQL_ERROR_SIGNATURES } from '../constants';

export interface ScanOptions {
  url: string;
  params: string[];
  proxyUrl?: string;
  onLog: (msg: string) => void;
  onProgress: (p: number) => void;
}

export const executeRealScan = async (options: ScanOptions): Promise<ScanFinding[]> => {
  const { url, params, proxyUrl, onLog, onProgress } = options;
  const findings: ScanFinding[] = [];
  
  onLog(`[*] Iniciando Auditoría Técnica...`);
  if (!proxyUrl) {
    onLog(`[!] ADVERTENCIA: Sin Proxy configurado. El navegador podría bloquear peticiones.`);
  }

  for (let i = 0; i < params.length; i++) {
    const param = params[i];
    const testPayloads = [
      { type: VulnerabilityType.SQLI, payload: "' OR '1'='1", severity: 'Critical' },
      { type: VulnerabilityType.XSS, payload: "<script>alert(1)</script>", severity: 'High' },
      { type: VulnerabilityType.OPEN_REDIRECT, payload: "https://evil.com", severity: 'Medium' }
    ];

    for (const test of testPayloads) {
      const testUrl = new URL(url);
      testUrl.searchParams.set(param, test.payload);
      
      const requestUrl = proxyUrl ? `${proxyUrl}${testUrl.toString()}` : testUrl.toString();
      
      try {
        onLog(`[+] Escaneando '${param}' contra ${test.type}...`);
        const startTime = Date.now();
        
        const response = await fetch(requestUrl, { 
          mode: 'cors',
          headers: { 'X-Scanner-Agent': 'VulnScanPro-Linux' }
        });

        const body = await response.text();
        const duration = Date.now() - startTime;

        // SQLi Detection
        if (test.type === VulnerabilityType.SQLI) {
          const found = SQL_ERROR_SIGNATURES.find(sig => body.toLowerCase().includes(sig.toLowerCase()));
          if (found) {
            findings.push({
              parameter: param, payload: test.payload, type: VulnerabilityType.SQLI, severity: 'Critical',
              evidence: `Firma: ${found} | Status: ${response.status} | Time: ${duration}ms`,
              description: "Error de BD expuesto.", impact: "Fuga de datos masiva.", rootCause: "Inyección SQL."
            });
            onLog(`[!] VULNERABILIDAD SQLi DETECTADA en ${param}`);
          }
        }

        // XSS Detection
        if (test.type === VulnerabilityType.XSS && body.includes(test.payload)) {
          findings.push({
            parameter: param, payload: test.payload, type: VulnerabilityType.XSS, severity: 'High',
            evidence: `Payload reflejado en DOM. Status: ${response.status}`,
            description: "Reflected XSS detectado.", impact: "Robo de sesiones.", rootCause: "Falta de saneamiento."
          });
          onLog(`[!] VULNERABILIDAD XSS DETECTADA en ${param}`);
        }

      } catch (err: any) {
        if (err.message.includes('Failed to fetch')) {
          onLog(`[!] CUIDADO: El navegador bloqueó la petición. ¿Está corriendo el Proxy de Linux?`);
        } else {
          onLog(`[!] Error conectando con ${param}: ${err.message}`);
        }
      }
    }
    onProgress(Math.round(((i + 1) / params.length) * 100));
  }

  return findings;
};

export const crawlForScripts = async (targetUrl: string, proxyUrl?: string, onLog?: (msg: string) => void): Promise<string[]> => {
  try {
    const requestUrl = proxyUrl ? `${proxyUrl}${targetUrl}` : targetUrl;
    const response = await fetch(requestUrl);
    const html = await response.text();
    const scriptRegex = /<script\b[^>]*src=["']([^"']+)["'][^>]*>/gi;
    const scripts: string[] = [];
    let match;
    while ((match = scriptRegex.exec(html)) !== null) {
      let sUrl = match[1];
      if (!sUrl.startsWith('http')) sUrl = new URL(sUrl, targetUrl).toString();
      scripts.push(sUrl);
    }
    onLog?.(`[+] Crawler: ${scripts.length} activos identificados.`);
    return scripts;
  } catch (e) {
    onLog?.(`[!] Error en crawler: Ejecute el Proxy Local en Linux.`);
    return [];
  }
};
