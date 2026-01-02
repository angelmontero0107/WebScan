
import { GoogleGenAI, Type } from "@google/genai";
import { ScanFinding } from "../types";

// Fix: Strictly follow the SDK guideline for initialization using process.env.API_KEY directly
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

export const analyzeJSForEndpoints = async (jsCode: string) => {
  try {
    const response = await ai.models.generateContent({
      // Fix: Use 'gemini-3-pro-preview' for complex coding and analysis tasks as per guidelines
      model: "gemini-3-pro-preview",
      contents: `Analiza el siguiente código JavaScript en busca de endpoints de API, rutas ocultas, llaves de API expuestas o parámetros sensibles.
      
      Código JS:
      ${jsCode}
      
      Devuelve un objeto JSON con una lista de hallazgos. Cada hallazgo debe tener:
      - endpoint: la ruta encontrada
      - method: el método HTTP probable (GET, POST, etc.)
      - context: el fragmento de código donde se encontró
      - risk: Low, Medium, High o Critical
      - description: por qué este endpoint es relevante o peligroso.
      
      Responde SOLO el JSON purificado.`,
      config: {
        responseMimeType: "application/json",
        // Fix: Implement responseSchema to ensure reliable and structured JSON output
        responseSchema: {
          type: Type.OBJECT,
          properties: {
            findings: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  endpoint: { type: Type.STRING },
                  method: { type: Type.STRING },
                  context: { type: Type.STRING },
                  risk: { type: Type.STRING },
                  description: { type: Type.STRING },
                },
                required: ["endpoint", "method", "context", "risk", "description"],
              },
            },
          },
          required: ["findings"],
        },
      }
    });

    // Fix: Access .text as a property, not a method call
    return JSON.parse(response.text || '{"findings": []}');
  } catch (error) {
    console.error("Error analizando JS:", error);
    return { findings: [] };
  }
};

export const analyzeFindingWithAI = async (finding: ScanFinding) => {
  try {
    const response = await ai.models.generateContent({
      // Fix: Use 'gemini-3-pro-preview' for advanced security reasoning and detailed reporting
      model: "gemini-3-pro-preview",
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
      1. ANÁLISIS TÉCNICO PROFUNDO: Desglosa mecánicamente cómo ocurre la falla en el backend.
      2. ESCENARIO DE EXPLOTACIÓN DETALLADO: Describe paso a paso cómo un atacante real podría escalar este hallazgo.
      3. IMPACTO DETALLADO EN EL NEGOCIO: Consecuencias legales, financieras y de reputación.
      4. GUÍA DE REMEDIACIÓN INTEGRAL: Proporciona código de ejemplo SEGURO.
      
      Escribe en español técnico.`,
      config: {
        temperature: 0.7,
      }
    });

    // Fix: Access .text as a property according to the latest SDK
    return response.text || "No se pudo generar el análisis detallado de IA en este momento.";
  } catch (error) {
    console.error("Error de Gemini AI:", error);
    return "Error al conectar con el motor de análisis de IA.";
  }
};

export const generatePythonScript = (targetUrl: string, params: string[]) => {
  const sqlPayloads = ["' OR '1'='1", "1' AND SLEEP(5)--", "admin'--"];
  const xssPayloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"];
  
  return `import requests
import time
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

# ==============================================================================
# VULNSCAN PRO - PORTABLE RESEARCH SUITE
# ==============================================================================

TARGET_URL = "${targetUrl}"
PARAMS = ${JSON.stringify(params)}

def verify_ssl(url):
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        print("[!] ADVERTENCIA CRÍTICA: Comunicación insegura.")
        return False
    return True

def run_dast_sequence():
    print(f"[SYSTEM] Iniciando Auditoría Técnica en: {TARGET_URL}")
    for param in PARAMS:
        # Lógica de escaneo simplificada
        pass

if __name__ == "__main__":
    run_dast_sequence()
`;
};
