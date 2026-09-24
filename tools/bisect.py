#!/usr/bin/env python3
"""Leave-one-out bisector: find which conjunct of the equivalence query is violated,
   then print a model (concrete counterexample inputs)."""
import subprocess, sys, re

Z3 = "/home/z/bin/z3"

def top_conjuncts(s):
    """Given text of conjuncts `c1 c2 ...`, return list of conjunct strings."""
    i = 0
    out = []
    n = len(s)
    while i < n:
        while i < n and s[i] in " \n\t":
            i += 1
        if i >= n or s[i] == ")":
            break
        start = i
        depth = 0
        while i < n:
            if s[i] == "(":
                depth += 1
            elif s[i] == ")":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
        out.append(s[start:i])
    return out

def main(path):
    text = open(path).read()
    m = re.search(r"\(assert \(not \(and (.*)\)\)\s*\(check-sat\)\s*$", text, re.S)
    if not m:
        print("no match"); sys.exit(1)
    inner = m.group(1)
    # strip final ')' of the and
    inner = inner.rstrip()
    conj = top_conjuncts(inner)
    print(f"{len(conj)} conjuncts")
    prelude = text[:m.start()]
    failing = []
    for c in conj:
        q = prelude + f"(assert (not {c}))\n(check-sat)\n"
        r = subprocess.run([Z3, "-in"], input=q, capture_output=True, text=True, timeout=300)
        verdict = r.stdout.strip()
        print(f"  {c[:60]}... -> {verdict}")
        if verdict == "sat":
            failing.append(c)
    for c in failing:
        q = prelude + f"(assert (not {c}))\n(check-sat)\n(get-model)\n"
        r = subprocess.run([Z3, "-in"], input=q, capture_output=True, text=True, timeout=300)
        print("FAILING CONJUNCT:", c[:200])
        print(r.stdout[:4000])

if __name__ == "__main__":
    main(sys.argv[1])
