
export enum VulnerabilityType {
  SQLI = 'SQL Injection',
  XSS = 'Reflected XSS',
  OPEN_REDIRECT = 'Open Redirect',
  SSRF = 'Server-Side Request Forgery',
  CRLF_INJECTION = 'CRLF Injection',
  NONE = 'None'
}

export interface SSLInfo {
  valid: boolean;
  issuer: string;
  expiry: string;
  protocol: string;
  error?: string;
}

export interface ScanFinding {
  parameter: string;
  payload: string;
  type: VulnerabilityType;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  evidence: string;
  description: string;
  impact: string;
  rootCause: string;
  remediation?: string;
}

export interface ScanResult {
  targetUrl: string;
  timestamp: string;
  totalRequests: number;
  findings: ScanFinding[];
  duration: number;
  sslInfo?: SSLInfo;
}

export interface HistoryEntry {
  id: string;
  targetUrl: string;
  timestamp: string;
  findingsCount: number;
  criticalCount: number;
  highCount: number;
  summary: string;
}

export interface Payload {
  content: string;
  type: VulnerabilityType;
}
