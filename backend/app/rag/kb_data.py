from typing import List, Dict, Any

OWASP_CWE_KNOWLEDGE_BASE: List[Dict[str, Any]] = [
    {
        "owasp_id": "A01:2021-Broken Access Control",
        "cwe_id": "CWE-22",
        "title": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "description": "Path traversal vulnerabilities occur when application logic accepts user-controlled inputs in file system calls without normalizing or enforcing directory boundaries.",
        "impact": "Attackers can read, overwrite, or delete arbitrary system files (e.g. /etc/passwd, configuration files, source code, environment credentials).",
        "mitigation": "Sanitize input filenames using os.path.basename(), restrict access using relative root path validation, or use strict whitelist of allowed filenames.",
        "code_example_vulnerable": "path = request.args.get('file')\nwith open('/var/www/uploads/' + path) as f:\n    content = f.read()",
        "code_example_secure": "import os\nfrom werkzeug.utils import secure_filename\nfilename = secure_filename(request.args.get('file'))\nfilepath = os.path.abspath(os.path.join('/var/www/uploads/', filename))\nif not filepath.startswith('/var/www/uploads/'):\n    raise PermissionError('Path Traversal Detected')\nwith open(filepath) as f:\n    content = f.read()"
    },
    {
        "owasp_id": "A01:2021-Broken Access Control",
        "cwe_id": "CWE-639",
        "title": "Insecure Direct Object References (IDOR)",
        "description": "IDOR occurs when an application exposes a reference to an internal implementation object (such as a database record primary key) without proper access control checks.",
        "impact": "Unauthorized users can manipulate parameters (e.g. user_id=102) to view or modify other users' sensitive personal records or financial accounts.",
        "mitigation": "Enforce strict session-based authorization checks for every object access request.",
        "code_example_vulnerable": "@app.route('/user/profile')\ndef profile():\n    uid = request.args.get('id')\n    return db.query(User).get(uid)",
        "code_example_secure": "@app.route('/user/profile')\n@login_required\ndef profile():\n    return current_user.profile"
    },
    {
        "owasp_id": "A02:2021-Cryptographic Failures",
        "cwe_id": "CWE-327",
        "title": "Use of a Broken or Risky Cryptographic Algorithm",
        "description": "Using weak cryptographic algorithms like MD5, SHA-1, DES, or RC4 exposes data to hash collisions and rapid brute-force decryption.",
        "impact": "Attackers can forge cryptographic signatures, reverse password hashes, or decrypt confidential data transmissions.",
        "mitigation": "Use modern cryptographic standards such as SHA-256/SHA-512 for digests, AES-256-GCM for encryption, and bcrypt/Argon2id for passwords.",
        "code_example_vulnerable": "import hashlib\npassword_hash = hashlib.md5(user_pass.encode()).hexdigest()",
        "code_example_secure": "import bcrypt\nsalt = bcrypt.gensalt()\npassword_hash = bcrypt.hashpw(user_pass.encode('utf-8'), salt)"
    },
    {
        "owasp_id": "A03:2021-Injection",
        "cwe_id": "CWE-89",
        "title": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "description": "SQL Injection happens when untrusted user input is directly formatted or concatenated into a raw database query string instead of using parameterized queries.",
        "impact": "Complete database takeover, authentication bypass, data exfiltration, database corruption, and potential OS command execution via DB extensions.",
        "mitigation": "Always use parameterized queries, prepared statements, or ORM object queries.",
        "code_example_vulnerable": "query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"\ncursor.execute(query)",
        "code_example_secure": "query = \"SELECT * FROM users WHERE username = %s AND password = %s\"\ncursor.execute(query, (username, password))"
    },
    {
        "owasp_id": "A03:2021-Injection",
        "cwe_id": "CWE-79",
        "title": "Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting - XSS')",
        "description": "XSS occurs when application scripts process unescaped user inputs directly into HTML documents or DOM manipulation methods.",
        "impact": "Attacker executes arbitrary JavaScript in victim's browser session, stealing cookies, session tokens, or performing actions on behalf of user.",
        "mitigation": "Contextually encode all user inputs before rendering, enforce Content Security Policy (CSP), and use safe DOM methods like textContent.",
        "code_example_vulnerable": "document.getElementById('welcome').innerHTML = 'Hello ' + userInput;",
        "code_example_secure": "document.getElementById('welcome').textContent = 'Hello ' + userInput;"
    },
    {
        "owasp_id": "A03:2021-Injection",
        "cwe_id": "CWE-78",
        "title": "Improper Neutralization of Special Elements used in an OS Command ('Command Injection')",
        "description": "Command injection occurs when untrusted input is passed to system shell execution calls (e.g. os.system, exec, child_process.exec).",
        "impact": "Remote Command Execution (RCE), giving full shell access on the underlying host server.",
        "mitigation": "Avoid invoking shell interpreters. Pass arguments as arrays to subprocess calls without shell=True.",
        "code_example_vulnerable": "import os\nos.system('ping -c 1 ' + user_ip)",
        "code_example_secure": "import subprocess\nsubprocess.run(['ping', '-c', '1', user_ip], shell=False, check=True)"
    },
    {
        "owasp_id": "A03:2021-Injection",
        "cwe_id": "CWE-95",
        "title": "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
        "description": "Eval injection allows an attacker to execute arbitrary code within the running runtime environment by supplying malformed input to eval() or exec().",
        "impact": "Full Remote Code Execution (RCE) inside application memory space.",
        "mitigation": "Never pass dynamic strings to eval() or exec(). Use structured JSON parsers or literal evaluation functions.",
        "code_example_vulnerable": "result = eval(request.form['expression'])",
        "code_example_secure": "import ast\nresult = ast.literal_eval(request.form['expression'])"
    },
    {
        "owasp_id": "A05:2021-Security Misconfiguration",
        "cwe_id": "CWE-942",
        "title": "Overly Permissive Cross-Origin Resource Sharing (CORS) Policy",
        "description": "Wildcard CORS configurations (Access-Control-Allow-Origin: *) combined with credentials allow external untrusted web domains to read sensitive authenticated responses.",
        "impact": "Cross-domain session hijacking and unauthorized API data theft.",
        "mitigation": "Explicitly whitelist allowed origin URLs and do not reflect Origin header dynamically without verification.",
        "code_example_vulnerable": "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)",
        "code_example_secure": "app.add_middleware(CORSMiddleware, allow_origins=['https://app.company.com'], allow_credentials=True)"
    },
    {
        "owasp_id": "A07:2021-Identification and Authentication Failures",
        "cwe_id": "CWE-798",
        "title": "Use of Hard-coded Credentials",
        "description": "Storing plaintext API keys, passwords, or secret signing keys directly inside application source code.",
        "impact": "Compromise of production API services, database infrastructure, or cloud platform resources if repository is leaked.",
        "mitigation": "Load secrets dynamically from secure environment variables or vault secret managers.",
        "code_example_vulnerable": "AWS_SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE'",
        "code_example_secure": "import os\nAWS_SECRET_KEY = os.environ.get('AWS_SECRET_KEY')"
    },
    {
        "owasp_id": "A08:2021-Software and Data Integrity Failures",
        "cwe_id": "CWE-502",
        "title": "Deserialization of Untrusted Data",
        "description": "Deserializing binary or serialized payload streams from untrusted sources via python pickle or PHP unserialize.",
        "impact": "Attacker manipulates object magic methods to achieve remote code execution.",
        "mitigation": "Avoid native serialization formats; use safe language-independent formats like JSON or Protocol Buffers.",
        "code_example_vulnerable": "import pickle\ndata = pickle.loads(user_input_bytes)",
        "code_example_secure": "import json\ndata = json.loads(user_input_string)"
    }
]
