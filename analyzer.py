import sys
import clang.cindex as clang

SEVERITY_LABELS = {
    0: "NOTE",
    1: "WARNING",
    2: "ERROR",
    3: "FATAL"
}

class Analyzer:
    def __init__(self):
        self.index = clang.Index.create()
        self.issues = []
        self.dangerous = {"gets", "scanf", "strcpy", "strcat", "sprintf"}

    def analyze(self, filePath):
        self.issues = []
        nodes = self.index.parse(filePath, args=['-std=c++23'])
        self.diagnostics(nodes)
        self.walkAst(nodes.cursor)
        return self.issues
        
        
    def diagnostics(self, node):
        for diag in node.diagnostics:
            file = diag.location.file
            self.issues.append({
                "file": file.name if file is not None else "<unknown>",
                "line": diag.location.line,
                "column": diag.location.column,
                "severity": SEVERITY_LABELS.get(diag.severity, "UNKNOWN"),
                "message": diag.spelling
            })

    def walkAst(self, node):
        if node.kind == clang.CursorKind.CALL_EXPR:
            if node.spelling in self.dangerous:
                loc = node.location
                file_obj = loc.file
                self.issues.append({
                    "file": file_obj.name if file_obj is not None else "<unknown>",
                    "line": loc.line,
                    "column": loc.column,
                    "severity": "WARNING",
                    "message": f"Unsafe function '{node.spelling}()' — use safer alternative"
                })
                
        for child in node.get_children():
            self.walkAst(child)

if __name__ == "__main__":       
    filePath = sys.argv[1]

    if len(sys.argv) == 2:
        print("Beinning to analyze file: " + filePath)
    else:
        print("Please enter only the name of the file you want to analyze")
        exit(1)
        
    data = Analyzer()
    issues = data.analyze(filePath)
    
    if not issues:
        print("No issues found.")
    else:
        for issue in issues:
            sev = issue['severity']
            print(f"[{sev}] {issue['file']}:{issue['line']}:{issue['column']} — {issue['message']}")
    
    print("Done")