#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SITE_MODULES = ROOT / "_wac-modules-for-site"
OUT_PATH = ROOT / "data.json"


VERB_MAP = {
    "Get": "Gets",
    "Set": "Sets",
    "New": "Creates",
    "Add": "Adds",
    "Remove": "Removes",
    "Update": "Updates",
    "Install": "Installs",
    "Uninstall": "Uninstalls",
    "Enable": "Enables",
    "Disable": "Disables",
    "Start": "Starts",
    "Stop": "Stops",
    "Restart": "Restarts",
    "Invoke": "Invokes",
    "Test": "Tests",
    "Register": "Registers",
    "Unregister": "Unregisters",
    "Clear": "Clears",
    "Export": "Exports",
    "Import": "Imports",
    "Connect": "Connects",
    "Disconnect": "Disconnects",
    "Resolve": "Resolves",
    "Read": "Reads",
    "Write": "Writes",
    "Initialize": "Initializes",
    "Resume": "Resumes",
    "Suspend": "Suspends",
}


def split_pascal(s: str) -> str:
    s = re.sub(r"_", " ", s)
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", s)
    s = re.sub(r"([A-Za-z])([0-9])", r"\1 \2", s)
    s = re.sub(r"([0-9])([A-Za-z])", r"\1 \2", s)
    return s


def infer_synopsis(name: str) -> str:
    if "-" in name:
        verb, noun = name.split("-", 1)
    else:
        verb, noun = "Invoke", name
    noun = split_pascal(noun).strip()
    verb_phrase = VERB_MAP.get(verb, verb + "s")
    if not noun:
        noun = "information"
    return f"{verb_phrase} {noun}."


def module_keywords(module_name: str) -> list[str]:
    tail = module_name.split(".", 2)[-1]
    parts = [p for p in re.split(r"[-_]+", tail) if p]
    joined = "".join(parts)
    keywords = set(parts + [joined])
    return [k.lower() for k in keywords if k]


def choose_module_icon(module_dir: Path, module_name: str) -> str:
    svgs = list(module_dir.rglob("*.svg"))
    if not svgs:
        return ""

    keywords = module_keywords(module_name)

    def score(path: Path) -> tuple[int, int, int]:
        name = path.stem.lower()
        match_score = sum(1 for k in keywords if k and k in name)
        is_icon = 1 if "icons" in path.parts else 0
        is_image = 1 if "images" in path.parts else 0
        return (match_score, is_icon, is_image)

    chosen = sorted(svgs, key=lambda p: score(p), reverse=True)[0]
    return str(chosen.relative_to(ROOT)).replace("\\", "/")


def map_functions_to_psm1(module_dir: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for psm1 in module_dir.rglob("*.psm1"):
        text = psm1.read_text(errors="ignore")
        for match in re.finditer(r"^\s*function\s+([A-Za-z0-9_-]+)\b", text, re.M):
            name = match.group(1)
            if name not in mapping:
                mapping[name] = str(psm1.relative_to(ROOT)).replace("\\", "/")
    return mapping


def extract_comment_help_synopsis(lines: list[str], function_line_index: int) -> str:
    end_idx = None
    for j in range(function_line_index - 1, -1, -1):
        if "#>" in lines[j]:
            end_idx = j
            break
        if lines[j].strip() and not lines[j].lstrip().startswith("#"):
            break
    if end_idx is None:
        return ""
    start_idx = None
    for k in range(end_idx - 1, -1, -1):
        if "<#" in lines[k]:
            start_idx = k
            break
    if start_idx is None:
        return ""
    block = lines[start_idx + 1 : end_idx]
    synopsis_lines: list[str] = []
    in_synopsis = False
    for bl in block:
        b = bl.strip()
        if b.startswith(".SYNOPSIS"):
            in_synopsis = True
            rest = b[len(".SYNOPSIS") :].strip()
            if rest:
                synopsis_lines.append(rest)
            continue
        if in_synopsis:
            if b.startswith("."):
                break
            if b:
                synopsis_lines.append(b)
    return " ".join(synopsis_lines).strip()


def extract_functions_with_synopsis(psm1_path: Path) -> dict[str, str]:
    text = psm1_path.read_text(errors="ignore")
    lines = text.splitlines()
    found: dict[str, str] = {}
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped.startswith("function "):
            continue
        m = re.match(r"function\s+([A-Za-z0-9_-]+)", stripped)
        if not m:
            continue
        name = m.group(1)
        synopsis = extract_comment_help_synopsis(lines, i)
        if name not in found or (not found[name] and synopsis):
            found[name] = synopsis
    return found


def main() -> None:
    if not SITE_MODULES.exists():
        raise SystemExit(f"Missing {SITE_MODULES}")

    modules: list[dict] = []
    for module_dir in sorted(SITE_MODULES.iterdir(), key=lambda p: p.name.lower()):
        if not module_dir.is_dir():
            continue
        functions: dict[str, str] = {}
        for psm1 in module_dir.rglob("*.psm1"):
            functions.update(extract_functions_with_synopsis(psm1))

        items = []
        func_map = map_functions_to_psm1(module_dir)
        for name in sorted(functions.keys(), key=lambda s: s.lower()):
            synopsis = functions.get(name, "").strip()
            if not synopsis:
                synopsis = infer_synopsis(name)
            items.append({"name": name, "desc": synopsis, "psm1": func_map.get(name, "")})

        modules.append(
            {
                "name": module_dir.name,
                "icon": choose_module_icon(module_dir, module_dir.name),
                "items": items,
            }
        )

    OUT_PATH.write_text(json.dumps(modules, indent=2), encoding="utf-8")
    print(OUT_PATH)


if __name__ == "__main__":
    main()
