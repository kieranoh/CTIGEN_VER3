#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from typing import Iterable, Dict, Any, Set
from dotenv import load_dotenv

load_dotenv()

BENIGN_OUT_DIR=os.getenv("BENIGN_OUT_DIR")
SAMPLE_HASH = os.getenv("SAMPLE_HASH")

FILTERING_OUTPUT_DIR = os.getenv("FILTERING_OUTPUT_DIR")

a_path = os.path.join(BENIGN_OUT_DIR,f"{SAMPLE_HASH}.jsonl")
b_path = os.path.join(FILTERING_OUTPUT_DIR,f"{SAMPLE_HASH}.jsonl")
out_path = os.path.join(FILTERING_OUTPUT_DIR, f"{SAMPLE_HASH}_filtered.json")

# =========================
# JSON 파싱 유틸
# =========================
def iter_concatenated_json(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        buf = f.read()

    objs = []
    depth = 0
    in_str = False
    esc = False
    start = None
    for i, ch in enumerate(buf):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        else:
            if ch == '"':
                in_str = True
                continue
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and start is not None:
                    chunk = buf[start:i+1]
                    try:
                        objs.append(json.loads(chunk))
                    except json.JSONDecodeError:
                        # fallback: line 기반 파싱
                        for line in chunk.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                objs.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
                    start = None
            else:
                continue

    if not objs:
        for line in buf.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    for o in objs:
        if isinstance(o, dict):
            yield o


def extract_funcname_from_a(obj: Dict[str, Any]) -> str | None:
    k = obj.get("key")
    if isinstance(k, str) and "::" in k:
        parts = k.split("::")
        if len(parts) >= 2:
            return parts[1]
    fid = obj.get("func_id")
    if isinstance(fid, str) and "::" in fid:
        parts = fid.split("::")
        if len(parts) >= 1:
            return parts[0]
    return None


def build_funcname_set(a_path: str) -> Set[str]:
    names: Set[str] = set()
    for obj in iter_concatenated_json(a_path):
        fn = extract_funcname_from_a(obj)
        if fn:
            names.add(fn)
    return names


def filter_b_by_names(b_path: str, out_path: str, deny: Set[str]) -> int:
    kept = 0
    with open(out_path, "w", encoding="utf-8") as w:
        for obj in iter_concatenated_json(b_path):
            fn = obj.get("Function Name")
            if isinstance(fn, str) and fn in deny:
                continue
            w.write(json.dumps(obj, ensure_ascii=False))
            w.write("\n")
            kept += 1
    return kept


def main():
    deny_names = build_funcname_set(a_path)
    print(f"[INFO] a.jsonl에서 {len(deny_names)}개 함수명 추출됨")

    kept = filter_b_by_names(b_path, out_path, deny_names)
    print(f"[INFO] 결과 {kept}개 함수 저장됨 → {out_path}")


if __name__ == "__main__":
    main()
