
import { GoogleGenAI, Type } from "@google/genai";
import { ScanFinding } from "../types";

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY || '' });

export const analyzeFindingWithAI = async (finding: ScanFinding) => {
  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: `Como investigador senior de ciberseguridad y auditor experto en pruebas de penetración (Red Team), realiza un análisis TÉCNICO EXHAUSTIVO Y SIN OMISIONES del siguiente hallazgo verificado.
      
      Vulnerabilidad: ${finding.type}
      Nivel de Riesgo: ${finding.severity}
      Parámetro Crítico: ${finding.parameter}
      Payload de Confirmación Ejecutado: ${finding.payload}
      Evidencia Técnica Extraída: ${finding.evidence}
      Descripción del Hallazgo: ${finding.description}
      Impacto Identificado: ${finding.impact}
      Causa Raíz Diagnosticada: ${finding.rootCause}
      
      INSTRUCCIONES PARA EL REPORTE:
      1. ANÁLISIS TÉCNICO PROFUNDO: Desglosa mecánicamente cómo ocurre la falla en el backend. No omitas detalles sobre la falta de sanitización o el flujo de datos.
      2. ESCENARIO DE EXPLOTACIÓN DETALLADO: Describe paso a paso cómo un atacante real podría escalar este hallazgo (ej: de SQLi a RCE, de XSS a Account Takeover).
      3. IMPACTO DETALLADO EN EL NEGOCIO: Consecuencias legales, financieras y de reputación.
      4. GUÍA DE REMEDIACIÓN INTEGRAL: Proporciona código de ejemplo SEGURO (ej: uso de bind parameters, librerías de encoding, configuración de cabeceras de seguridad CSP/HSTS).
      
      IMPORTANTE: Presenta la información de forma profesional, estructurada y extremadamente completa. No resumas; profundiza en cada punto. Escribe en español técnico.`,
      config: {
        temperature: 0.7,
      }
    });

    return response.text || "No se pudo generar el análisis detallado de IA en este momento.";
  } catch (error) {
    console.error("Error de Gemini AI:", error);
    return "Error al conectar con el motor de análisis de IA. Por favor, verifique su configuración.";
  }
};

export const generatePythonScript = (targetUrl: string, params: string[]) => {
  const sqlPayloads = ["' OR '1'='1", "1' AND SLEEP(5)--", "admin'--"];
  const xssPayloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"];
  const redirectPayloads = ["https://evil.com", "//google.com"];
  const ssrfPayloads = ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"];
  const crlfPayloads = ["%0d%0aSet-Cookie: CRLF_Injection=True", "%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK"];
  
  return `import requests
import time
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

# ==============================================================================
# VULNSCAN PRO - PORTABLE RESEARCH SUITE
# REPORTE TÉCNICO Y AUTOMATIZACIÓN DAST
# ==============================================================================
# DESCARGO DE RESPONSABILIDAD: USO EXCLUSIVAMENTE EDUCATIVO Y AUTORIZADO.
# ==============================================================================

TARGET_URL = "${targetUrl}"
PARAMS = ${JSON.stringify(params)}

def verify_ssl(url):
    """Verifica la integridad del certificado SSL/TLS del objetivo."""
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        print("[!] ADVERTENCIA CRÍTICA: Comunicación insegura (HTTP detectado).")
        return False
    
    hostname = parsed.hostname
    port = parsed.port or 443
    print(f"[*] Analizando cadena de confianza para {hostname}...")
    
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if expiry < datetime.now():
                    print(f"  [!] ALERTA: Certificado CADUCADO el {expiry}")
                    return False
                print(f"  [+] Certificado SSL válido (Expira: {expiry})")
                return True
    except ssl.SSLCertVerificationError as e:
        print(f"  [!] ERROR SSL: Fallo en la verificación (Posible auto-firmado): {e.reason}")
    except Exception as e:
        print(f"  [!] ERROR SISTEMA: No se pudo completar la validación SSL: {e}")
    return False

# Vectores de Verificación de Segundo Paso (High Fidelity)
VERIFY_PAYLOADS = {
    "SQLI": "' OR 1=1--",
    "XSS": "<img src=x onerror=alert(1)>",
    "Redirect": "https://bing.com",
    "SSRF": "http://169.254.169.254/latest/meta-data/hostname",
    "CRLF": "%0d%0aInjected-Header: Confirmed"
}

def confirm_vulnerability(vuln_type, param):
    """Ejecuta una validación secundaria para descartar falsos positivos."""
    payload = VERIFY_PAYLOADS.get(vuln_type)
    if not payload: return False
    
    print(f"  [?] Validando hallazgo potential de {vuln_type} en '{param}'...")
    try:
        res = requests.get(TARGET_URL, params={param: payload}, timeout=7, allow_redirects=False)
        if vuln_type == "SQLI" and any(err in res.text.lower() for err in ["sql syntax", "mysql_fetch", "ora-"]): return True
        elif vuln_type == "XSS" and payload in res.text: return True
        elif vuln_type == "Redirect" and "bing.com" in res.headers.get("Location", ""): return True
        elif vuln_type == "SSRF" and any(hit in res.text for hit in ["ami-id", "hostname", "internal"]): return True
        elif vuln_type == "CRLF" and "Injected-Header" in res.headers: return True
    except: pass
    return False

def run_dast_sequence():
    print(f"[SYSTEM] Iniciando Auditoría Técnica en: {TARGET_URL}")
    print("-" * 60)
    verify_ssl(TARGET_URL)
    print(f"[*] Modo de Operación: Doble Paso (Double-Pass)\\n")
    
    findings_count = 0
    
    for param in PARAMS:
        # SQL Injection Sequence
        for payload in ${JSON.stringify(sqlPayloads)}:
            try:
                res = requests.get(TARGET_URL, params={param: payload}, timeout=5)
                if any(err in res.text.lower() for err in ["sql syntax", "mysql_fetch", "ora-", "sqlite"]):
                    if confirm_vulnerability("SQLI", param):
                        print(f"[!] VULNERABILIDAD TÉCNICA CONFIRMADA: SQLi en '{param}'")
                        findings_count += 1
                        break
            except: pass

        # XSS Sequence
        for payload in ${JSON.stringify(xssPayloads)}:
            try:
                res = requests.get(TARGET_URL, params={param: payload}, timeout=5)
                if payload in res.text:
                    if confirm_vulnerability("XSS", param):
                        print(f"[!] VULNERABILIDAD TÉCNICA CONFIRMADA: XSS en '{param}'")
                        findings_count += 1
                        break
            except: pass

    print("-" * 60)
    print(f"[*] Auditoría Finalizada.")
    print(f"[*] Hallazgos Críticos Confirmados: {findings_count}")

if __name__ == "__main__":
    run_dast_sequence()
`;
};
