
import { GoogleGenAI, Type } from "@google/genai";
import { ScanFinding } from "../types";

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

export const analyzeJSForEndpoints = async (jsCode: string) => {
  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-pro-preview",
      contents: `Analiza este código JavaScript buscando vulnerabilidades de seguridad, endpoints de API y secretos.
      Código: ${jsCode}`,
      config: {
        responseMimeType: "application/json",
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
    return JSON.parse(response.text || '{"findings": []}');
  } catch (error) {
    return { findings: [] };
  }
};

export const analyzeFindingWithAI = async (finding: ScanFinding) => {
  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-pro-preview",
      contents: `Analiza técnicamente este hallazgo de seguridad: ${JSON.stringify(finding)}. Proporciona vectores de explotación y guía de remediación para un reporte de pentesting.`,
    });
    return response.text || "Error analizando hallazgo.";
  } catch (error) {
    return "Error de conexión con IA.";
  }
};

export const generatePythonScript = (targetUrl: string, params: string[]) => {
  return `import requests
import argparse
from urllib.parse import urljoin, urlparse

# ==============================================================================
# VULNSCAN PRO - LINUX NATIVE DAST TOOL (CLI)
# ==============================================================================
# Uso: python3 scanner.py --url "${targetUrl}"
# ==============================================================================

class VulnScanner:
    def __init__(self, target_url, params):
        self.target = target_url
        self.params = params
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) VulnScanPro/2.8'
        })
        self.payloads = {
            'sqli': ["' OR '1'='1", "admin'--", "1' AND SLEEP(5)--"],
            'xss': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            'redirect': ["https://evil.com", "//attacker.com"]
        }

    def check_vulnerability(self, param, p_type, payload):
        test_params = {p: 'test' for p in self.params}
        test_params[param] = payload
        
        try:
            resp = self.session.get(self.target, params=test_params, timeout=10)
            
            if p_type == 'sqli':
                errors = ["sql syntax", "mysql_fetch", "ora-01756", "sqlite3"]
                if any(err in resp.text.lower() for err in errors):
                    return True
            
            if p_type == 'xss' and payload in resp.text:
                return True
                
            if p_type == 'redirect' and "evil.com" in resp.url:
                return True
                
        except Exception as e:
            print(f"[!] Error en red: {e}")
        return False

    def run(self):
        print(f"[*] Iniciando Auditoría DAST en: {self.target}")
        for param in self.params:
            for p_type, payloads in self.payloads.items():
                for payload in payloads:
                    print(f"[+] Probando {p_type.upper()} en '{param}'...")
                    if self.check_vulnerability(param, p_type, payload):
                        print(f"\\n[!!!] VULNERABILIDAD DETECTADA [!!!]")
                        print(f"Tipo: {p_type.upper()}")
                        print(f"Parámetro: {param}")
                        print(f"Payload: {payload}\\n")

if __name__ == "__main__":
    scanner = VulnScanner("${targetUrl}", ${JSON.stringify(params)})
    scanner.run()
`;
};
