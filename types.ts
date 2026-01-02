
export enum VulnerabilityType {
  SQLI = 'SQL Injection',
  XSS = 'Reflected XSS',
  NONE = 'None'
}

export interface ScanFinding {
  parameter: string;
  payload: string;
  type: VulnerabilityType;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  evidence: string;
  description: string;
  remediation?: string;
}

export interface ScanResult {
  targetUrl: string;
  timestamp: string;
  totalRequests: number;
  findings: ScanFinding[];
  duration: number;
}

export interface Payload {
  content: string;
  type: VulnerabilityType;
}
