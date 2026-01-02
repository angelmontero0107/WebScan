
import { GoogleGenAI, Type } from "@google/genai";
import { ScanFinding } from "../types";

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY || '' });

export const analyzeFindingWithAI = async (finding: ScanFinding) => {
  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: `Como investigador senior de ciberseguridad y experto en pruebas de penetración, realiza un análisis exhaustivo del siguiente hallazgo DAST.
      
      Vulnerabilidad: ${finding.type}
      Parámetro Vulnerable: ${finding.parameter}
      Payload Utilizado: ${finding.payload}
      Evidencia Técnica: ${finding.evidence}
      Raíz del Problema Detectada: ${finding.rootCause}
      
      Proporciona un informe detallado que incluya:
      1. Análisis Técnico: Explica EXACTAMENTE por qué falla la aplicación.
      2. Escenario de Explotación: Cómo un atacante podría escalar este problema.
      3. Impacto de Negocio: Consecuencias para la integridad y confidencialidad de los datos.
      4. Guía de Remediación Paso a Paso: Código seguro de ejemplo y configuraciones recomendadas.
      
      Escribe en español profesional y directo.`,
      config: {
        temperature: 0.7,
      }
    });

    return response.text || "No se pudo generar el análisis detallado de IA en este momento.";
  } catch (error) {
    console.error("Error de Gemini AI:", error);
    return "Análisis de IA no disponible.";
  }
};

export const generatePythonScript = (targetUrl: string, params: string[]) => {
  const sqlPayloads = ["' OR '1'='1", "' UNION SELECT 1,2,3--", "admin'--"];
  const xssPayloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"];
  
  return `import requests
import urllib.parse
from datetime import datetime
try:
    from fpdf import FPDF
except ImportError:
    print("[!] Advertencia: No se encontró la librería fpdf. La generación del reporte PDF fallará.")
    print("[*] Instálala usando: pip install fpdf")

# SOLO PARA USO EDUCATIVO - NO UTILIZAR SIN PERMISO
# Herramienta de Investigación de Vulnerabilidades - Reporte Técnico Detallado

TARGET_URL = "${targetUrl}"
PARAMS = ${JSON.stringify(params)}

SQLI_PAYLOADS = ${JSON.stringify(sqlPayloads)}
XSS_PAYLOADS = ${JSON.stringify(xssPayloads)}

SQL_ERRORS = [
    "SQL syntax", "mysql_fetch", "ORA-01756", 
    "SQLite3::query", "PostgreSQL query failed"
]

def generate_pdf_report(findings, target_url):
    """
    Genera un reporte de seguridad PDF técnico y explícito.
    """
    try:
        pdf = FPDF()
        pdf.add_page()
        
        # Encabezado con estilo profesional
        pdf.set_fill_color(16, 185, 129)
        pdf.rect(0, 0, 210, 40, 'F')
        
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Arial", 'B', 24)
        pdf.cell(190, 25, txt="INFORME DE VULNERABILIDAD DAST", ln=True, align='C')
        
        pdf.set_text_color(230, 230, 230)
        pdf.set_font("Arial", size=10)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pdf.cell(190, 5, txt=f"Fecha de Auditoría: {timestamp}", ln=True, align='C')
        pdf.ln(20)
        
        # Información del Objetivo
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(190, 10, txt="1. Resumen Ejecutivo del Objetivo", ln=True)
        pdf.set_font("Arial", size=11)
        pdf.cell(190, 8, txt=f"URL Base: {target_url}", ln=True)
        pdf.ln(5)
        
        if not findings:
            pdf.set_text_color(0, 128, 0)
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(190, 10, txt="ESTADO: SEGURO (No se detectaron fallos comunes)", ln=True)
        else:
            pdf.set_text_color(185, 28, 28)
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(190, 10, txt=f"ESTADO: CRÍTICO - {len(findings)} Hallazgos Detectados", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(5)
            
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(190, 10, txt="2. Detalles Técnicos de los Fallos", ln=True)
            pdf.ln(2)
            
            for i, f in enumerate(findings, 1):
                # Título del Hallazgo
                pdf.set_fill_color(244, 244, 245)
                pdf.set_font("Arial", 'B', 12)
                pdf.cell(190, 10, txt=f"Hallazgo #{i}: {f['type']}", ln=True, fill=True)
                
                pdf.set_font("Arial", 'B', 10)
                pdf.cell(40, 8, txt="Parámetro:", ln=False)
                pdf.set_font("Arial", size=10)
                pdf.cell(150, 8, txt=f['param'], ln=True)
                
                pdf.set_font("Arial", 'B', 10)
                pdf.cell(40, 8, txt="Severidad:", ln=False)
                pdf.set_font("Arial", 'B', 10)
                pdf.set_text_color(185, 28, 28)
                pdf.cell(150, 8, txt="ALTA / CRÍTICA", ln=True)
                pdf.set_text_color(0, 0, 0)
                
                pdf.set_font("Arial", 'B', 10)
                pdf.cell(190, 8, txt="¿Por qué falla la aplicación? (Análisis Técnico):", ln=True)
                pdf.set_font("Arial", size=10)
                pdf.multi_cell(0, 6, txt=f['root_cause'])
                
                pdf.set_font("Arial", 'B', 10)
                pdf.cell(190, 8, txt="Impacto Potencial:", ln=True)
                pdf.set_font("Arial", size=10)
                pdf.multi_cell(0, 6, txt=f['impact'])
                
                pdf.set_font("Arial", 'B', 10)
                pdf.cell(40, 8, txt="Payload Utilizado:", ln=False)
                pdf.set_font("Courier", size=9)
                pdf.cell(150, 8, txt=f['payload'], ln=True)
                
                pdf.set_font("Arial", 'B', 10)
                pdf.cell(190, 8, txt="Evidencia:", ln=True)
                pdf.set_font("Arial", 'I', 9)
                pdf.multi_cell(0, 5, txt=f['evidence'])
                
                pdf.ln(5)
                pdf.line(10, pdf.get_y(), 200, pdf.get_y())
                pdf.ln(5)
        
        report_name = f"reporte_tecnico_dast_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf.output(report_name)
        print(f"[*] Reporte Técnico Detallado guardado: {report_name}")
        
    except Exception as e:
        print(f"[E] Error al generar el reporte PDF: {e}")

def scan():
    print(f"[*] Iniciando Auditoría DAST en {TARGET_URL}")
    findings = []
    
    for param in PARAMS:
        # Pruebas SQLI
        sql_vuln_detected = False
        for payload in SQLI_PAYLOADS:
            if sql_vuln_detected: break # Evitar duplicados para el mismo parámetro
            try:
                response = requests.get(TARGET_URL, params={param: payload}, timeout=5)
                for error in SQL_ERRORS:
                    if error.lower() in response.text.lower():
                        findings.append({
                            "type": "Inyección SQL (SQLi)",
                            "param": param,
                            "payload": payload,
                            "evidence": f"Firma detectada: {error}",
                            "root_cause": "La aplicación concatena entradas del usuario directamente en consultas SQL sin sanitizar ni usar sentencias preparadas. Esto permite alterar la lógica de la base de datos.",
                            "impact": "Acceso no autorizado a datos sensibles, bypass de autenticación y posible compromiso total del servidor de base de datos."
                        })
                        print(f"[!] SQLi detectada en '{param}'")
                        sql_vuln_detected = True
                        break
            except Exception as e: print(f"[E] Error: {e}")

        # Pruebas XSS
        xss_vuln_detected = False
        for payload in XSS_PAYLOADS:
            if xss_vuln_detected: break # Evitar duplicados para el mismo parámetro
            try:
                response = requests.get(TARGET_URL, params={param: payload}, timeout=5)
                if payload in response.text:
                    findings.append({
                        "type": "XSS Reflejado (Cross-Site Scripting)",
                        "param": param,
                        "payload": payload,
                        "evidence": "El payload exacto fue encontrado en el cuerpo de la respuesta HTTP.",
                        "root_cause": "La aplicación devuelve la entrada del usuario al navegador sin realizar codificación de caracteres HTML (HTML Encoding). El navegador interpreta el texto como código ejecutable.",
                        "impact": "Robo de cookies de sesión (Session Hijacking), redirecciones maliciosas y robo de credenciales mediante phishing inyectado."
                    })
                    print(f"[!] XSS detectado en '{param}'")
                    xss_vuln_detected = True
            except Exception as e: print(f"[E] Error: {e}")

    generate_pdf_report(findings, TARGET_URL)

if __name__ == "__main__":
    scan()
`;
};
