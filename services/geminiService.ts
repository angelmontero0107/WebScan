
import { GoogleGenAI, Type } from "@google/genai";
import { ScanFinding } from "../types";

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY || '' });

export const analyzeFindingWithAI = async (finding: ScanFinding) => {
  try {
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: `As a senior cybersecurity researcher, analyze the following DAST finding and provide a professional explanation and remediation steps.
      
      Vulnerability: ${finding.type}
      Parameter: ${finding.parameter}
      Payload Used: ${finding.payload}
      Evidence Found: ${finding.evidence}
      
      Format your response as a clear structured report.`,
      config: {
        temperature: 0.7,
      }
    });

    return response.text || "Unable to generate AI analysis at this time.";
  } catch (error) {
    console.error("Gemini AI error:", error);
    return "AI analysis unavailable.";
  }
};

export const generatePythonScript = (targetUrl: string, params: string[]) => {
  const sqlPayloads = ["' OR '1'='1", "' UNION SELECT 1,2,3--", "admin'--"];
  const xssPayloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"];
  
  return `import requests
import urllib.parse

# EDUCATIONAL USE ONLY - DO NOT USE WITHOUT PERMISSION
# Vulnerability Research Tool

TARGET_URL = "${targetUrl}"
PARAMS = ${JSON.stringify(params)}

SQLI_PAYLOADS = ${JSON.stringify(sqlPayloads)}
XSS_PAYLOADS = ${JSON.stringify(xssPayloads)}

SQL_ERRORS = [
    "SQL syntax", "mysql_fetch", "ORA-01756", 
    "SQLite3::query", "PostgreSQL query failed"
]

def scan():
    print(f"[*] Starting DAST scan on {TARGET_URL}")
    print("[*] Testing parameters: " + ", ".join(PARAMS))
    
    for param in PARAMS:
        # Test SQL Injection
        for payload in SQLI_PAYLOADS:
            data = {param: payload}
            try:
                response = requests.get(TARGET_URL, params=data, timeout=5)
                for error in SQL_ERRORS:
                    if error.lower() in response.text.lower():
                        print(f"[!] POSSIBLE SQLI FOUND!")
                        print(f"    Param: {param}")
                        print(f"    Payload: {payload}")
                        print(f"    Evidence: Found '{error}' in response")
            except Exception as e:
                print(f"[E] Request failed: {e}")

        # Test XSS
        for payload in XSS_PAYLOADS:
            data = {param: payload}
            try:
                response = requests.get(TARGET_URL, params=data, timeout=5)
                if payload in response.text:
                    print(f"[!] POSSIBLE XSS FOUND!")
                    print(f"    Param: {param}")
                    print(f"    Payload: {payload}")
                    print(f"    Evidence: Payload reflected in response body")
            except Exception as e:
                print(f"[E] Request failed: {e}")

if __name__ == "__main__":
    scan()
`;
};
