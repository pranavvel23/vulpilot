import os
from typing import Dict, Any, Optional
from app.config import settings
from app.rag.vector_store import rag_vector_store

class LLMProviderManager:
    """
    Manages LLM generation (Gemini / OpenAI) with local rule-based fallback
    when API keys are absent.
    """

    def generate_explanation_and_fix(
        self,
        vulnerability: Dict[str, Any],
        api_key: Optional[str] = None,
        provider: Optional[str] = None
    ) -> Dict[str, str]:
        prov = provider or settings.DEFAULT_LLM_PROVIDER
        key = api_key or (settings.GEMINI_API_KEY if prov == "gemini" else settings.OPENAI_API_KEY)

        # Retrieve OWASP RAG Knowledge
        rag_info = rag_vector_store.get_by_cwe(vulnerability.get("cwe_id", "CWE-79"))

        if key and len(key.strip()) > 5:
            if prov == "gemini":
                try:
                    return self._call_gemini(vulnerability, rag_info, key)
                except Exception as e:
                    print(f"Gemini LLM call failed: {e}. Falling back to rule engine.")
            elif prov == "openai":
                try:
                    return self._call_openai(vulnerability, rag_info, key)
                except Exception as e:
                    print(f"OpenAI LLM call failed: {e}. Falling back to rule engine.")

        # Local Rule-Based Fallback Engine (No API Key required)
        return self._local_rule_fallback(vulnerability, rag_info)

    def _call_gemini(self, vuln: Dict[str, Any], rag_info: Dict[str, Any], api_key: str) -> Dict[str, str]:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.5-flash")

        prompt = f"""You are VulnPilot AI, an expert Application Security Assistant.
Analyze this security vulnerability finding and generate a detailed explanation and a secure code replacement.

Vulnerability Title: {vuln.get('title')}
Severity: {vuln.get('severity')}
CWE ID: {vuln.get('cwe_id')}
OWASP Category: {vuln.get('owasp_category')}
File Path: {vuln.get('file_path')} (Line {vuln.get('line_number')})

Vulnerable Code Snippet:
```
{vuln.get('vulnerable_code')}
```

OWASP Reference Context:
{rag_info.get('description')}
Mitigation Pattern: {rag_info.get('mitigation')}

Instructions:
1. Provide a concise, clear technical explanation of the flaw, attack impact, and root cause under markdown header ## Explanation.
2. Provide ONLY the corrected, secure, drop-in replacement code snippet under markdown header ## Secure Code. Do not execute the code.

Response format:
## Explanation
[Detailed security analysis]

## Secure Code
```
[Secure Code Fix]
```
"""
        response = model.generate_content(prompt)
        text = response.text if response else ""
        return self._parse_llm_output(text, vuln, rag_info)

    def _call_openai(self, vuln: Dict[str, Any], rag_info: Dict[str, Any], api_key: str) -> Dict[str, str]:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)

        prompt = f"""Analyze vulnerability {vuln.get('title')} ({vuln.get('cwe_id')}) in line {vuln.get('line_number')}.
Code:
{vuln.get('vulnerable_code')}

Reference Mitigation: {rag_info.get('mitigation')}

Return output:
## Explanation
...
## Secure Code
...
"""
        res = client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "You are VulnPilot AI, a secure code auditor."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        text = res.choices[0].message.content or ""
        return self._parse_llm_output(text, vuln, rag_info)

    def _parse_llm_output(self, text: str, vuln: Dict[str, Any], rag_info: Dict[str, Any]) -> Dict[str, str]:
        explanation = text
        secure_code = rag_info.get("code_example_secure", "# Secure fix unavailable")

        if "## Explanation" in text and "## Secure Code" in text:
            parts = text.split("## Secure Code")
            explanation = parts[0].replace("## Explanation", "").strip()
            code_part = parts[1].strip()
            if "```" in code_part:
                code_lines = code_part.split("```")[1]
                if "\n" in code_lines:
                    secure_code = "\n".join(code_lines.split("\n")[1:]).strip()
                else:
                    secure_code = code_lines.strip()

        return {
            "ai_explanation": explanation,
            "secure_code_fix": secure_code
        }

    def _local_rule_fallback(self, vuln: Dict[str, Any], rag_info: Dict[str, Any]) -> Dict[str, str]:
        title = vuln.get('title', 'Security Flaw')
        cwe = vuln.get('cwe_id', 'CWE-Unknown')
        sev = vuln.get('severity', 'Medium')
        code = vuln.get('vulnerable_code', '')

        explanation = (
            f"### Vulnerability Analysis: {title} ({cwe})\n"
            f"**Severity Level:** `{sev}` | **OWASP Category:** `{vuln.get('owasp_category')}`\n\n"
            f"**Root Cause:** The code snippet at line {vuln.get('line_number')} contains an unvalidated dynamic construct.\n\n"
            f"**OWASP Security Note:** {rag_info.get('description', 'Insecure design allows potential unauthorized manipulation.')}\n\n"
            f"**Potential Business Impact:** {rag_info.get('impact', 'Data exposure or unauthorized system manipulation.')}\n\n"
            f"**Recommended Action:** {rag_info.get('mitigation', 'Use parameterized values and strict input validation.')}"
        )

        secure_code = vuln.get("secure_code_fix")
        if not secure_code or "Replace vulnerable" in secure_code:
            secure_code = rag_info.get("code_example_secure", "# Use parameterized query / safe API call")

        return {
            "ai_explanation": explanation,
            "secure_code_fix": secure_code
        }

llm_provider = LLMProviderManager()
