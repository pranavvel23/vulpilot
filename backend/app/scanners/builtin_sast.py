import re
import ast
import os
from typing import List, Dict, Any

class BuiltinSASTScanner:
    """
    Comprehensive multi-language Static Application Security Testing (SAST) engine.
    Supports Python AST analysis + Advanced multi-language regex rule matching.
    """

    RULES = [
        # --- SQL INJECTION ---
        {
            "id": "RULE-SQLI-01",
            "title": "SQL Injection via String Formatting / Concatenation",
            "severity": "Critical",
            "cwe_id": "CWE-89",
            "owasp_category": "A03:2021-Injection",
            "description": "Constructing dynamic SQL queries using string formatting, f-strings, or string concatenation allows an attacker to manipulate SQL syntax and execute unauthorized queries or extract sensitive database contents.",
            "pattern": r"(?i)((execute|query|raw|exec)\s*\(\s*(f[\"']|\".*?%s|\".*?\{\}|\".*?\+\s*\w+|'.*?\+\s*\w+)|(query|sql|stmt|raw_sql)\s*=\s*[\"'].*?(select|insert|update|delete|drop|where|from).*?(\+|\%|\.format|f[\"']))",
            "languages": [".py", ".js", ".ts", ".php", ".java", ".go"],
            "secure_example": "cursor.execute('SELECT * FROM users WHERE username = %s', (username,))"
        },
        {
            "id": "RULE-SQLI-02",
            "title": "Raw SQL Query in ORM / Direct DB Call",
            "severity": "High",
            "cwe_id": "CWE-89",
            "owasp_category": "A03:2021-Injection",
            "description": "Directly passing unsanitized user inputs to database.raw() or raw_query() bypasses ORM parameter binding.",
            "pattern": r"(?i)\.raw_query\s*\(\s*[\"'].*?\$|\.query\s*\(\s*[\"']SELECT.*?\+",
            "languages": [".py", ".js", ".ts", ".php"],
            "secure_example": "db.select(User).where(User.username == username)"
        },

        # --- CROSS-SITE SCRIPTING (XSS) ---
        {
            "id": "RULE-XSS-01",
            "title": "Reflected or Stored XSS via Direct HTML Output / innerHTML",
            "severity": "High",
            "cwe_id": "CWE-79",
            "owasp_category": "A03:2021-Injection",
            "description": "Directly assigning unsanitized input to innerHTML, document.write, or unescaped template rendering allows arbitrary script execution in client browsers.",
            "pattern": r"(?i)(document\.write|innerHTML\s*=|dangerouslySetInnerHTML\s*=|\{\$?\w+\|safe\}|<%=\s*\w+\s*%>)",
            "languages": [".js", ".jsx", ".ts", ".tsx", ".html", ".php", ".py"],
            "secure_example": "element.textContent = sanitizedInput; // or use DOMPurify.sanitize(input)"
        },
        {
            "id": "RULE-XSS-02",
            "title": "Flask / Django Unescaped Markup Output",
            "severity": "High",
            "cwe_id": "CWE-79",
            "owasp_category": "A03:2021-Injection",
            "description": "Using Markup() or safe filter on user-supplied strings disables Jinja2 automatic HTML escaping.",
            "pattern": r"(?i)(Markup\s*\(\s*\w+|render_template_string\s*\(\s*.*?f[\"'])",
            "languages": [".py"],
            "secure_example": "render_template('page.html', user_input=escape(user_input))"
        },

        # --- HARDCODED SECRETS & API KEYS ---
        {
            "id": "RULE-SECRET-01",
            "title": "Hardcoded API Token, AWS Key, or Private Credential",
            "severity": "Critical",
            "cwe_id": "CWE-798",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "description": "Hardcoding API secrets, JWT private keys, AWS access keys, or passwords inside source files exposes them to unauthorized actors in source repositories.",
            "pattern": r"(?i)(aws_access_key_id|aws_secret_access_key|api_key|secret_key|private_key|auth_token|jwt_secret)\s*=\s*[\"'][A-Za-z0-9_\-\.\/]{12,}[\"']",
            "languages": [".py", ".js", ".ts", ".java", ".go", ".json", ".env", ".yaml", ".yml"],
            "secure_example": "api_key = os.getenv('API_KEY')"
        },
        {
            "id": "RULE-SECRET-02",
            "title": "Hardcoded Password in Variable Assignment",
            "severity": "High",
            "cwe_id": "CWE-259",
            "owasp_category": "A07:2021-Identification and Authentication Failures",
            "description": "Assigning a plaintext password constant directly to a variable.",
            "pattern": r"(?i)(db_password|user_password|passwd|pass_phrase)\s*=\s*[\"'][^\"']{4,}[\"']",
            "languages": [".py", ".js", ".ts", ".java", ".php", ".go"],
            "secure_example": "db_password = os.environ.get('DB_PASSWORD')"
        },

        # --- COMMAND INJECTION ---
        {
            "id": "RULE-CMDI-01",
            "title": "OS Command Injection via Shell Execution",
            "severity": "Critical",
            "cwe_id": "CWE-78",
            "owasp_category": "A03:2021-Injection",
            "description": "Passing unvalidated inputs to os.system(), subprocess.call(..., shell=True), or child_process.exec() allows attackers to execute arbitrary system shell commands.",
            "pattern": r"(?i)(os\.system\s*\(|subprocess\.(call|Popen|run)\s*\(.*?shell\s*=\s*True|child_process\.exec\s*\(|exec\s*\(.*?\$|system\s*\(\s*\$)",
            "languages": [".py", ".js", ".ts", ".php", ".java"],
            "secure_example": "subprocess.run(['ls', '-l', sanitized_dir], shell=False)"
        },

        # --- CODE EVALUATION & INSECURE DESERIALIZATION ---
        {
            "id": "RULE-EVAL-01",
            "title": "Dynamic Code Execution via eval() / exec()",
            "severity": "Critical",
            "cwe_id": "CWE-95",
            "owasp_category": "A03:2021-Injection",
            "description": "Evaluating dynamic string input as code allows remote code execution (RCE).",
            "pattern": r"(?i)\b(eval|exec)\s*\(\s*[^\"'].*?\)",
            "languages": [".py", ".js", ".ts", ".php"],
            "secure_example": "Use specific parsing functions like json.loads() or ast.literal_eval() instead of eval()"
        },
        {
            "id": "RULE-DESER-01",
            "title": "Insecure Deserialization via pickle or yaml.load()",
            "severity": "High",
            "cwe_id": "CWE-502",
            "owasp_category": "A08:2021-Software and Data Integrity Failures",
            "description": "Deserializing untrusted data with pickle.loads() or yaml.load() can result in arbitrary object instantiation and RCE.",
            "pattern": r"(?i)(pickle\.loads|yaml\.load\s*\([^,)]*?\)|unserialize\s*\(\s*\$)",
            "languages": [".py", ".php"],
            "secure_example": "yaml.safe_load(user_yaml) # or json.loads()"
        },

        # --- PATH TRAVERSAL / ARBITRARY FILE ACCESS ---
        {
            "id": "RULE-PATH-01",
            "title": "Path Traversal / Arbitrary File Read",
            "severity": "High",
            "cwe_id": "CWE-22",
            "owasp_category": "A01:2021-Broken Access Control",
            "description": "Opening files directly using concatenated request paths without verifying canonical path bounds allows attackers to access restricted system files like /etc/passwd.",
            "pattern": r"(?i)(open\s*\(\s*.*?(\+\s*\w+|f[\"'].*?\{)|send_file\s*\(\s*.*?\+|fs\.readFile\s*\(\s*.*?\+)",
            "languages": [".py", ".js", ".ts", ".php"],
            "secure_example": "safe_path = os.path.abspath(os.path.join(BASE_DIR, secure_filename(filename)))"
        },

        # --- WEAK CRYPTOGRAPHY & HASHING ---
        {
            "id": "RULE-CRYPTO-01",
            "title": "Use of Broken Cryptographic Hash (MD5 / SHA1)",
            "severity": "Medium",
            "cwe_id": "CWE-327",
            "owasp_category": "A02:2021-Cryptographic Failures",
            "description": "Using MD5 or SHA-1 for security hashing or password storage is vulnerable to hash collision attacks.",
            "pattern": r"(?i)(hashlib\.md5\s*\(|hashlib\.sha1\s*\(|crypto\.createHash\s*\(\s*[\"'](md5|sha1)[\"']|md5\s*\()",
            "languages": [".py", ".js", ".ts", ".php", ".java", ".go"],
            "secure_example": "hashlib.sha256(data.encode()).hexdigest() # or bcrypt for passwords"
        },

        # --- INSECURE CORS & PERMISSIONS ---
        {
            "id": "RULE-CORS-01",
            "title": "Overly Permissive CORS Policy (Wildcard Access)",
            "severity": "Medium",
            "cwe_id": "CWE-942",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "description": "Setting Access-Control-Allow-Origin to '*' with credentials allows unauthorized third-party origins to access session data.",
            "pattern": r"(?i)(allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]|Access-Control-Allow-Origin.*?[\"']\*[\"'])",
            "languages": [".py", ".js", ".ts", ".java", ".go"],
            "secure_example": "allow_origins=['https://yourdomain.com']"
        }
    ]

    def scan_code(self, code_text: str, filename: str = "snippet.py") -> List[Dict[str, Any]]:
        results = []
        lines = code_text.splitlines()
        ext = os.path.splitext(filename)[1].lower() if "." in filename else ".py"

        # 1. AST Analysis for Python files
        if ext == ".py":
            ast_vulns = self._scan_python_ast(code_text, filename, lines)
            results.extend(ast_vulns)

        # 2. Regex Rule Scanning across all files
        for rule in self.RULES:
            if rule["languages"] and not any(ext.endswith(l) for l in rule["languages"]):
                continue

            for idx, line in enumerate(lines, start=1):
                if re.search(rule["pattern"], line):
                    # Check if already captured by AST to avoid duplicate reporting
                    if any(r["line_number"] == idx and r["cwe_id"] == rule["cwe_id"] for r in results):
                        continue

                    snippet = self._extract_snippet(lines, idx)
                    results.append({
                        "file_path": filename,
                        "line_number": idx,
                        "end_line_number": idx,
                        "severity": rule["severity"],
                        "title": rule["title"],
                        "cwe_id": rule["cwe_id"],
                        "owasp_category": rule["owasp_category"],
                        "description": rule["description"],
                        "vulnerable_code": snippet,
                        "secure_code_fix": self._generate_secure_fix(rule, snippet),
                        "ai_explanation": f"**Vulnerability Overview:** {rule['description']}\n\n**Risk & Impact:** Exploitation of {rule['cwe_id']} can compromise system integrity, leak confidential data, or grant unauthorized privileges.\n\n**Remediation Guidance:** Replace insecure dynamic construct with parameterized or sanitized alternatives.",
                        "tool_name": "VulnPilot SAST Engine",
                        "status": "OPEN"
                    })

        return results

    def _scan_python_ast(self, code_text: str, filename: str, lines: List[str]) -> List[Dict[str, Any]]:
        results = []
        try:
            tree = ast.parse(code_text)
        except Exception:
            return results # Syntax error, regex will still catch

        SQL_KEYWORDS = {"select", "insert", "update", "delete", "drop", "alter", "create", "truncate", "where", "from", "join"}

        def contains_sql(text: str) -> bool:
            if not isinstance(text, str):
                return False
            words = set(re.findall(r'\b[a-zA-Z]+\b', text.lower()))
            return bool(words & SQL_KEYWORDS)

        def is_dynamic_expr(node: ast.AST) -> bool:
            if isinstance(node, (ast.Name, ast.Attribute, ast.Call, ast.Subscript)):
                return True
            if isinstance(node, ast.JoinedStr):
                return True
            if isinstance(node, ast.BinOp):
                return is_dynamic_expr(node.left) or is_dynamic_expr(node.right)
            return False

        def get_str(n: ast.AST):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                return n.value
            return None

        def check_dynamic_sql(node: ast.AST) -> bool:
            if isinstance(node, ast.JoinedStr):
                for val in node.values:
                    s = get_str(val)
                    if s and contains_sql(s):
                        return True
                return False

            if isinstance(node, ast.BinOp):
                if isinstance(node.op, ast.Add):
                    has_sql = False
                    def walk_binop(n):
                        nonlocal has_sql
                        s = get_str(n)
                        if s and contains_sql(s):
                            has_sql = True
                        elif isinstance(n, ast.BinOp):
                            walk_binop(n.left)
                            walk_binop(n.right)
                    walk_binop(node)
                    return has_sql and is_dynamic_expr(node)

                elif isinstance(node.op, ast.Mod):
                    s = get_str(node.left)
                    return bool(s and contains_sql(s)) and is_dynamic_expr(node.right)

            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                    s = get_str(node.func.value)
                    return bool(s and contains_sql(s)) and bool(node.args or node.keywords)

            return False

        assigned_vars = {}
        reported_assigned_vars = set()

        class ASTVisitor(ast.NodeVisitor):
            def __init__(self, outer):
                self.outer = outer

            def visit_Assign(self, node):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if check_dynamic_sql(node.value):
                            assigned_vars[target.id] = (node, getattr(node, 'lineno', 1))
                self.generic_visit(node)

            def visit_AnnAssign(self, node):
                if isinstance(node.target, ast.Name) and node.value:
                    if check_dynamic_sql(node.value):
                        assigned_vars[node.target.id] = (node, getattr(node, 'lineno', 1))
                self.generic_visit(node)

            def visit_Call(self, node):
                # Check for eval / exec calls
                if isinstance(node.func, ast.Name) and node.func.id in ["eval", "exec"]:
                    line_no = getattr(node, 'lineno', 1)
                    snippet = self.outer._extract_snippet(lines, line_no)
                    results.append({
                        "file_path": filename,
                        "line_number": line_no,
                        "end_line_number": line_no,
                        "severity": "Critical",
                        "title": "Dynamic Code Execution via eval() / exec()",
                        "cwe_id": "CWE-95",
                        "owasp_category": "A03:2021-Injection",
                        "description": f"Use of AST-verified dangerous function {node.func.id}() with dynamic expressions.",
                        "vulnerable_code": snippet,
                        "secure_code_fix": snippet.replace("eval(", "json.loads(").replace("exec(", "# safe logic here"),
                        "ai_explanation": "Evaluating untrusted code directly via Python `eval` or `exec` permits direct Remote Code Execution (RCE). Use `ast.literal_eval()` or structured JSON parsing.",
                        "tool_name": "VulnPilot AST Engine",
                        "status": "OPEN"
                    })

                # Check for cursor/conn/db execute/query calls with dynamic SQL or variable assigned dynamic SQL
                is_exec_call = False
                if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany", "raw", "query", "raw_query", "execute_query"):
                    is_exec_call = True
                elif isinstance(node.func, ast.Name) and node.func.id in ("execute", "raw_query", "query"):
                    is_exec_call = True

                if is_exec_call and node.args:
                    first_arg = node.args[0]
                    is_vuln = False
                    if check_dynamic_sql(first_arg):
                        is_vuln = True
                    elif isinstance(first_arg, ast.Name) and first_arg.id in assigned_vars:
                        is_vuln = True
                        reported_assigned_vars.add(first_arg.id)

                    if is_vuln:
                        line_no = getattr(node, 'lineno', 1)
                        snippet = self.outer._extract_snippet(lines, line_no)
                        results.append({
                            "file_path": filename,
                            "line_number": line_no,
                            "end_line_number": line_no,
                            "severity": "Critical",
                            "title": "SQL Injection via Dynamic Query Construction",
                            "cwe_id": "CWE-89",
                            "owasp_category": "A03:2021-Injection",
                            "description": "SQL statement constructed dynamically using string concatenation, f-strings, or formatting inside database query execution.",
                            "vulnerable_code": snippet,
                            "secure_code_fix": "cursor.execute('SELECT * FROM users WHERE username = ?', (user_input,))",
                            "ai_explanation": "String concatenation or formatting in SQL queries bypasses parameterized query protection. Always pass query parameters as a tuple/list in the second argument.",
                            "tool_name": "VulnPilot AST Engine",
                            "status": "OPEN"
                        })

                self.generic_visit(node)

        visitor = ASTVisitor(self)
        visitor.visit(tree)

        for var_name, (assign_node, line_no) in assigned_vars.items():
            if var_name not in reported_assigned_vars:
                if not any(r["line_number"] == line_no and r["cwe_id"] == "CWE-89" for r in results):
                    snippet = self._extract_snippet(lines, line_no)
                    results.append({
                        "file_path": filename,
                        "line_number": line_no,
                        "end_line_number": line_no,
                        "severity": "Critical",
                        "title": "SQL Injection via Dynamic Query String Construction",
                        "cwe_id": "CWE-89",
                        "owasp_category": "A03:2021-Injection",
                        "description": "Constructing dynamic SQL query string using string concatenation, f-strings, or string formatting.",
                        "vulnerable_code": snippet,
                        "secure_code_fix": "query = 'SELECT * FROM users WHERE username = ?'\ncursor.execute(query, (user_input,))",
                        "ai_explanation": "Building SQL queries by concatenating user inputs allows SQL injection. Use parameterized placeholders instead.",
                        "tool_name": "VulnPilot AST Engine",
                        "status": "OPEN"
                    })

        return results

    def _extract_snippet(self, lines: List[str], line_no: int, context_lines: int = 1) -> str:
        start = max(0, line_no - 1 - context_lines)
        end = min(len(lines), line_no + context_lines)
        return "\n".join(lines[start:end])

    def _generate_secure_fix(self, rule: Dict[str, Any], vulnerable_code: str) -> str:
        if "secure_example" in rule:
            return f"# Secure Remediation Pattern:\n{rule['secure_example']}"
        return "# Replace vulnerable dynamic input with sanitized/parameterized code"

builtin_sast_engine = BuiltinSASTScanner()
