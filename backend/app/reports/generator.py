import os
import json
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class SecurityReportGenerator:
    """
    Generates downloadable security reports in PDF, Markdown, HTML, and JSON formats.
    """

    def generate_json_report(self, scan_data: Dict[str, Any]) -> str:
        return json.dumps(scan_data, indent=2, default=str)

    def generate_markdown_report(self, scan_data: Dict[str, Any]) -> str:
        md = []
        md.append(f"# VulnPilot AI - Security Audit Report")
        md.append(f"**Project Name:** {scan_data.get('project_name')}")
        md.append(f"**Scan Date:** {scan_data.get('created_at')}")
        md.append(f"**Security Score:** {scan_data.get('security_score')}/100")
        md.append(f"**Total Vulnerabilities:** {scan_data.get('total_vulnerabilities')}")
        md.append(f"- **Critical:** {scan_data.get('critical_count')}")
        md.append(f"- **High:** {scan_data.get('high_count')}")
        md.append(f"- **Medium:** {scan_data.get('medium_count')}")
        md.append(f"- **Low:** {scan_data.get('low_count')}\n")
        md.append("---")
        md.append("## Vulnerability Findings\n")

        for idx, v in enumerate(scan_data.get('vulnerabilities', []), start=1):
            md.append(f"### {idx}. [{v.get('severity')}] {v.get('title')}")
            md.append(f"- **File:** `{v.get('file_path')}` (Line {v.get('line_number')})")
            md.append(f"- **CWE:** {v.get('cwe_id')} | **OWASP:** {v.get('owasp_category')}")
            md.append(f"\n**Description:**\n{v.get('description')}\n")
            md.append("**Vulnerable Code:**")
            md.append(f"```\n{v.get('vulnerable_code')}\n```\n")
            md.append("**Secure Remediation Fix:**")
            md.append(f"```\n{v.get('secure_code_fix')}\n```\n")
            if v.get('ai_explanation'):
                md.append(f"**AI Security Analysis:**\n{v.get('ai_explanation')}\n")
            md.append("---\n")

        return "\n".join(md)

    def generate_html_report(self, scan_data: Dict[str, Any]) -> str:
        md_content = self.generate_markdown_report(scan_data)
        # Convert to dark theme styled HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>VulnPilot AI - Security Audit Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 40px; line-height: 1.6; }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #0284c7; padding-bottom: 10px; }}
        h2 {{ color: #c084fc; margin-top: 30px; }}
        h3 {{ color: #f43f5e; }}
        .metric-box {{ background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 25px; border-left: 4px solid #38bdf8; }}
        pre {{ background: #0b0f19; padding: 15px; border-radius: 6px; overflow-x: auto; color: #38bdf8; font-family: Consolas, monospace; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; text-transform: uppercase; font-size: 12px; }}
        .Critical {{ background: #ef4444; color: #fff; }}
        .High {{ background: #f97316; color: #fff; }}
        .Medium {{ background: #eab308; color: #000; }}
        .Low {{ background: #3b82f6; color: #fff; }}
    </style>
</head>
<body>
    <pre style="background:transparent; color:#f8fafc; font-family:inherit; white-space:pre-wrap;">{md_content}</pre>
</body>
</html>"""
        return html

    def generate_pdf_report(self, scan_data: Dict[str, Any], output_path: str):
        doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            textColor=colors.HexColor('#0284c7'),
            spaceAfter=12
        )

        sub_style = ParagraphStyle(
            'SubStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=11,
            textColor=colors.HexColor('#475569'),
            spaceAfter=15
        )

        h2_style = ParagraphStyle(
            'H2Style',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=14,
            textColor=colors.HexColor('#7e22ce'),
            spaceBefore=15,
            spaceAfter=10
        )

        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#1e293b'),
            spaceAfter=6
        )

        code_style = ParagraphStyle(
            'CodeStyle',
            parent=styles['Code'],
            fontName='Courier',
            fontSize=9,
            textColor=colors.HexColor('#0f172a'),
            backColor=colors.HexColor('#f1f5f9'),
            borderColor=colors.HexColor('#cbd5e1'),
            borderWidth=1,
            borderPadding=6,
            spaceAfter=8
        )

        story = []
        story.append(Paragraph("VulnPilot AI - Security Audit Report", title_style))
        story.append(Paragraph(f"Project: {scan_data.get('project_name')} | Date: {scan_data.get('created_at')}", sub_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#0284c7'), spaceAfter=15))

        # Metrics Summary Table
        metrics_data = [
            ["Security Score", "Total Findings", "Critical", "High", "Medium", "Low"],
            [
                f"{scan_data.get('security_score')}/100",
                str(scan_data.get('total_vulnerabilities')),
                str(scan_data.get('critical_count')),
                str(scan_data.get('high_count')),
                str(scan_data.get('medium_count')),
                str(scan_data.get('low_count'))
            ]
        ]

        t = Table(metrics_data, colWidths=[90, 85, 65, 65, 65, 65])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 10),
            ('BOTTOMPADDING', (0,0), (-1,0), 8),
            ('BACKGROUND', (0,1), (-1,1), colors.HexColor('#f8fafc')),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1'))
        ]))
        story.append(t)
        story.append(Spacer(1, 15))

        # Vulnerabilities List
        story.append(Paragraph("Vulnerability Findings & AI Remediation", h2_style))

        for idx, v in enumerate(scan_data.get('vulnerabilities', []), start=1):
            sev = v.get('severity', 'Low')
            title_text = f"{idx}. [{sev}] {v.get('title')} ({v.get('cwe_id')})"
            story.append(Paragraph(f"<b>{title_text}</b>", body_style))
            story.append(Paragraph(f"File: <i>{v.get('file_path')}</i> (Line {v.get('line_number')}) | OWASP: {v.get('owasp_category')}", sub_style))
            story.append(Paragraph(f"<b>Description:</b> {v.get('description')}", body_style))
            
            story.append(Paragraph("<b>Vulnerable Code:</b>", body_style))
            vuln_snippet = v.get('vulnerable_code', '').replace('\n', '<br/>').replace(' ', '&nbsp;')
            story.append(Paragraph(vuln_snippet, code_style))
            
            story.append(Paragraph("<b>Secure Code Fix:</b>", body_style))
            fix_snippet = v.get('secure_code_fix', '').replace('\n', '<br/>').replace(' ', '&nbsp;')
            story.append(Paragraph(fix_snippet, code_style))

            story.append(Spacer(1, 10))

        doc.build(story)
        return output_path

report_generator = SecurityReportGenerator()
