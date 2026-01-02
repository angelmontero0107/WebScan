
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
  
  onLog(`[*] Iniciando análisis técnico en ${new URL(url).hostname}...`);

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
      
      const requestUrl = proxyUrl ? `${proxyUrl}${encodeURIComponent(testUrl.toString())}` : testUrl.toString();
      
      try {
        onLog(`[+] Probando ${test.type} en parámetro '${param}'...`);
        const startTime = Date.now();
        
        const response = await fetch(requestUrl, { 
          mode: proxyUrl ? 'cors' : 'no-cors', // 'no-cors' limitará lo que podemos leer pero evita el crash
          cache: 'no-cache'
        });

        // Nota: Si usamos 'no-cors' sin proxy, no podremos leer el body. 
        // El usuario DEBE usar un proxy para una auditoría funcional.
        if (response.type === 'opaque' && !proxyUrl) {
          onLog(`[!] ADVERTENCIA: Respuesta opaca detectada. Instale un CORS Proxy para ver el contenido.`);
          continue;
        }

        const duration = Date.now() - startTime;
        const body = await response.text();

        // 1. Análisis de SQL Injection
        if (test.type === VulnerabilityType.SQLI) {
          const foundSignature = SQL_ERROR_SIGNATURES.find(sig => body.toLowerCase().includes(sig.toLowerCase()));
          if (foundSignature) {
            findings.push({
              parameter: param,
              payload: test.payload,
              type: VulnerabilityType.SQLI,
              severity: 'Critical',
              evidence: `Firma detectada: "${foundSignature}"\nStatus: ${response.status}\nLatencia: ${duration}ms`,
              description: "El servidor devolvió un error de base de datos procesable.",
              impact: "Acceso no autorizado a datos sensibles.",
              rootCause: "Entrada de usuario no saneada en consulta SQL."
            });
            onLog(`[!] VULNERABILIDAD SQLi DETECTADA en ${param}`);
          }
        }

        // 2. Análisis de Reflected XSS
        if (test.type === VulnerabilityType.XSS) {
          if (body.includes(test.payload)) {
            findings.push({
              parameter: param,
              payload: test.payload,
              type: VulnerabilityType.XSS,
              severity: 'High',
              evidence: `Payload reflejado en el cuerpo de respuesta.\nStatus: ${response.status}`,
              description: "El payload del script se refleja sin escape en el DOM.",
              impact: "Ejecución de scripts maliciosos en el contexto del usuario.",
              rootCause: "Falta de codificación de salida (Output Encoding)."
            });
            onLog(`[!] VULNERABILIDAD XSS DETECTADA en ${param}`);
          }
        }

        // 3. Análisis de Open Redirect
        if (test.type === VulnerabilityType.OPEN_REDIRECT) {
          if (response.redirected && response.url.includes("evil.com")) {
            findings.push({
              parameter: param,
              payload: test.payload,
              type: VulnerabilityType.OPEN_REDIRECT,
              severity: 'Medium',
              evidence: `Redirección confirmada a: ${response.url}`,
              description: "La aplicación permite redirecciones arbitrarias.",
              impact: "Ataques de phishing y bypass de seguridad.",
              rootCause: "Redirección basada en parámetros de usuario sin validación."
            });
            onLog(`[!] OPEN REDIRECT DETECTADO en ${param}`);
          }
        }

      } catch (err: any) {
        if (err.message === 'Failed to fetch') {
          onLog(`[!] ERROR DE RED: El navegador bloqueó la petición (CORS). Use un Proxy.`);
          throw new Error("CORS_BLOCK: Se requiere un proxy para auditar este dominio.");
        }
        onLog(`[!] Error conectando con ${param}: ${err.message}`);
      }
    }
    onProgress(Math.round(((i + 1) / params.length) * 100));
  }

  return findings;
};

export const crawlForScripts = async (targetUrl: string, proxyUrl?: string, onLog?: (msg: string) => void): Promise<string[]> => {
  try {
    const requestUrl = proxyUrl ? `${proxyUrl}${encodeURIComponent(targetUrl)}` : targetUrl;
    onLog?.(`[*] Crawler: Intentando acceder a ${targetUrl}...`);
    
    const response = await fetch(requestUrl);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const html = await response.text();
    const scriptRegex = /<script\b[^>]*src=["']([^"']+)["'][^>]*>/gi;
    const scripts: string[] = [];
    let match;
    
    while ((match = scriptRegex.exec(html)) !== null) {
      let scriptUrl = match[1];
      if (!scriptUrl.startsWith('http')) {
        const base = new URL(targetUrl);
        scriptUrl = new URL(scriptUrl, base.origin).toString();
      }
      scripts.push(scriptUrl);
    }
    
    onLog?.(`[+] Crawler: Encontrados ${scripts.length} scripts potenciales.`);
    return scripts;
  } catch (e: any) {
    if (e.message === 'Failed to fetch') {
      onLog?.(`[!] CRAWL ERROR: El navegador bloqueó el acceso (CORS). No se pudieron extraer scripts.`);
    } else {
      onLog?.(`[!] CRAWL ERROR: ${e.message}`);
    }
    return [];
  }
};
