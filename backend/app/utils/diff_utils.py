import difflib
from typing import List, Dict, Any

def generate_unified_diff(vulnerable_code: str, secure_code: str) -> List[Dict[str, Any]]:
    """
    Generates structured line-by-line diff items for visual rendering in frontend.
    """
    lines1 = vulnerable_code.splitlines()
    lines2 = secure_code.splitlines()

    differ = difflib.Differ()
    diff = list(differ.compare(lines1, lines2))

    structured_diff = []
    line_no_old = 1
    line_no_new = 1

    for line in diff:
        code = line[2:]
        if line.startswith('  '):
            structured_diff.append({
                "type": "unchanged",
                "old_line": line_no_old,
                "new_line": line_no_new,
                "content": code
            })
            line_no_old += 1
            line_no_new += 1
        elif line.startswith('- '):
            structured_diff.append({
                "type": "removed",
                "old_line": line_no_old,
                "new_line": None,
                "content": code
            })
            line_no_old += 1
        elif line.startswith('+ '):
            structured_diff.append({
                "type": "added",
                "old_line": None,
                "new_line": line_no_new,
                "content": code
            })
            line_no_new += 1

    return structured_diff
