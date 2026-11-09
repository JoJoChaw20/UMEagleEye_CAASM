"""Outline of Python files for the system graph builder (build-system-graph.mjs).

Usage: python -I py_outline.py FILE [FILE ...]
Prints one JSON object: {path: {"doc", "imports", "classes", "functions", "lines", "error"}}.
Standard library only. Reads the files named on the command line and nothing else; it never
runs or imports them, it only parses them with ast.
"""
import ast
import json
import sys


def first_line(doc):
    if not doc:
        return ""
    text = " ".join(doc.strip().split())
    return text[:300]


def arg_names(fn):
    a = fn.args
    names = [x.arg for x in getattr(a, "posonlyargs", [])] + [x.arg for x in a.args]
    if a.vararg:
        names.append("*" + a.vararg.arg)
    names += [x.arg for x in a.kwonlyargs]
    if a.kwarg:
        names.append("**" + a.kwarg.arg)
    return [n for n in names if n not in ("self", "cls")]


def span(node):
    return (getattr(node, "end_lineno", node.lineno) or node.lineno) - node.lineno + 1


def func_info(fn):
    return {
        "name": fn.name,
        "args": arg_names(fn),
        "doc": first_line(ast.get_docstring(fn)),
        "line": fn.lineno,
        "lines": span(fn),
        "async": isinstance(fn, ast.AsyncFunctionDef),
    }


def outline(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        source = fh.read()
    tree = ast.parse(source, filename=path)
    imports, classes, functions = [], [], []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            imports.append("." * node.level + (node.module or ""))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(func_info(node))
        elif isinstance(node, ast.ClassDef):
            classes.append({
                "name": node.name,
                "bases": [ast.unparse(b) for b in node.bases],
                "doc": first_line(ast.get_docstring(node)),
                "line": node.lineno,
                "lines": span(node),
                "methods": [func_info(m) for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))],
            })
    return {
        "doc": first_line(ast.get_docstring(tree)),
        "imports": sorted(set(imports)),
        "classes": classes,
        "functions": functions,
        "lines": source.count("\n") + (0 if source.endswith("\n") or not source else 1),
        "error": None,
    }


def main(paths):
    result = {}
    for path in paths:
        try:
            result[path] = outline(path)
        except Exception as exc:  # a file that does not parse is reported, not fatal
            result[path] = {"doc": "", "imports": [], "classes": [], "functions": [], "lines": 0, "error": type(exc).__name__}
    sys.stdout.write(json.dumps(result))


if __name__ == "__main__":
    main(sys.argv[1:])
