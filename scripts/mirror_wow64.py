#!/usr/bin/env python3
import re
import sys

def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)

    reg_path = sys.argv[1]
    prefixes = sys.argv[2:]

    with open(reg_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    # Match a section: [<header>] (optional trailing tokens) + body up to the next [ at start of line.
    section_re = re.compile(
        r"^(\[[^\]\n]+\][^\n]*\n)((?:(?!^\[).*\n?)*)",
        re.MULTILINE
    )

    sections = [(m.group(1), m.group(2)) for m in section_re.finditer(text)]
    existing_64bit_headers = {h.split("]")[0] + "]" for h, _ in sections}

    appended = 0
    chunks = []
    for header, body in sections:
        for p in prefixes:
            if header.startswith(f"[{p}"):
                new_header = header.replace("\\\\Wow6432Node\\\\", "\\\\", 1)
                key_only = new_header.split("]")[0] + "]"
                if key_only in existing_64bit_headers:
                    continue
                existing_64bit_headers.add(key_only)
                chunks.append(new_header + body)
                appended += 1
                break

    if chunks:
        with open(reg_path, "a", encoding="utf-8") as f:
            f.write("\n")
            f.write("".join(chunks))

    print(f"[mirror] appended {appended} 64-bit sections")


if __name__ == "__main__":
    main()
