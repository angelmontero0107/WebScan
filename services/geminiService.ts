
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
from datetime import datetime
try:
    from fpdf import FPDF
except ImportError:
    print("[!] Warning: fpdf library not found. PDF report generation will fail.")
    print("[*] Install it using: pip install fpdf")

# EDUCATIONAL USE ONLY - DO NOT USE WITHOUT PERMISSION
# Vulnerability Research Tool with PDF Reporting

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
    Generates a PDF security report using the fpdf library.
    """
    try:
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="DAST Security Report", ln=True, align='C')
        
        pdf.set_font("Arial", size=10)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pdf.cell(200, 10, txt=f"Generated on: {timestamp}", ln=True, align='C')
        pdf.ln(10)
        
        # Target Info
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt=f"Target URL: {target_url}", ln=True)
        pdf.ln(5)
        
        pdf.set_font("Arial", size=11)
        if not findings:
            pdf.set_text_color(0, 128, 0)
            pdf.cell(200, 10, txt="No vulnerabilities detected.", ln=True)
        else:
            pdf.set_text_color(200, 0, 0)
            pdf.cell(200, 10, txt=f"Findings Summary: {len(findings)} issues identified.", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.ln(5)
            
            for i, finding in enumerate(findings, 1):
                pdf.set_font("Arial", 'B', 11)
                pdf.cell(200, 10, txt=f"Finding #{i}: {finding['type']}", ln=True)
                pdf.set_font("Arial", size=10)
                pdf.multi_cell(0, 5, txt=f"Parameter: {finding['param']}\nPayload: {finding['payload']}\nEvidence: {finding['evidence']}\n")
                pdf.ln(2)
        
        report_name = f"dast_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf.output(report_name)
        print(f"[*] Report saved successfully as: {report_name}")
        
    except Exception as e:
        print(f"[E] Failed to generate PDF report: {e}")

def scan():
    print(f"[*] Starting DAST scan on {TARGET_URL}")
    print("[*] Testing parameters: " + ", ".join(PARAMS))
    
    findings = []
    
    for param in PARAMS:
        # Test SQL Injection
        for payload in SQLI_PAYLOADS:
            data = {param: payload}
            try:
                response = requests.get(TARGET_URL, params=data, timeout=5)
                for error in SQL_ERRORS:
                    if error.lower() in response.text.lower():
                        finding = {
                            "type": "SQL Injection",
                            "param": param,
                            "payload": payload,
                            "evidence": f"Found SQL error signature: {error}"
                        }
                        print(f"[!] POSSIBLE SQLI FOUND!")
                        print(f"    Param: {param}")
                        findings.append(finding)
            except Exception as e:
                print(f"[E] Request failed: {e}")

        # Test XSS
        for payload in XSS_PAYLOADS:
            data = {param: payload}
            try:
                response = requests.get(TARGET_URL, params=data, timeout=5)
                if payload in response.text:
                    finding = {
                        "type": "Reflected XSS",
                        "param": param,
                        "payload": payload,
                        "evidence": "Payload reflected in response body"
                    }
                    print(f"[!] POSSIBLE XSS FOUND!")
                    print(f"    Param: {param}")
                    findings.append(finding)
            except Exception as e:
                print(f"[E] Request failed: {e}")

    print("[*] Scan complete.")
    generate_pdf_report(findings, TARGET_URL)

if __name__ == "__main__":
    scan()
`;
};
