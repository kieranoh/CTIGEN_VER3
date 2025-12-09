#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
해시 기반 정상 함수 제거 스크립트 (TLSH / SSDEEP 공용)

기능 요약
- preprocessed된 함수 JSONL에서 정상과 유사한 함수 제거
- 기준: min_diff < threshold (TLSH/SSDEEP 각각 다름)
- 파일별로 남긴 결과 JSONL 저장
- 제거된 함수 이름은 별도 txt 저장
- resume 지원: 입력 파일 구조 보존
"""
# TLSH → THRESHOLD = 30
# SSDEEP → THRESHOLD = 48
# (악성 함수는 유지하면서 정상 함수만 제거하는 값으로 실험 기반 설정됨). 구축되는 정상 함수 db에 따라 다를수 있움.

import os
import json
from pathlib import Path
from tqdm import tqdm

# =========================
# 환경설정 로드
# =========================
inp = os.getenv("PREPROCESS_OUTPUT_DIR")   # 입력 폴더, preprocessed된 악성 샘플 폴더

mode = os.getenv("FILTERING_MODE")         # "tlsh" | "ssdeep"
if inp is None or mode is None:
    raise RuntimeError("PREPROCESS_OUTPUT_DIR / FILTERING_MODE 환경변수를 설정하세요!")

SAMPLE_DIR = Path(inp)

# ---- 모드별 폴더/임계값 자동 설정 ----
if mode.lower().startswith("tlsh"):
    FILTER_NAME = "TLSH"
    THRESHOLD = 30
    DIFF_DIR = Path("dike_diff_tlsh")
    out = os.getenv("TLSH_FILTERING_OUTPUT_DIR")  # ★ 여기!
    if out is None:
        raise RuntimeError("TLSH_FILTERING_OUTPUT_DIR 환경변수를 설정하세요!")

elif mode.lower().startswith("ssdeep"):
    FILTER_NAME = "SSDEEP"
    THRESHOLD = 48
    DIFF_DIR = Path("dike_diff_ssdeep")
    out = os.getenv("SSDEEP_FILTERING_OUTPUT_DIR")  # ★ 여기!
    if out is None:
        raise RuntimeError("SSDEEP_FILTERING_OUTPUT_DIR 환경변수를 설정하세요!")

else:
    raise RuntimeError("FILTERING_MODE은 'tlsh' 또는 'ssdeep' 이어야 합니다!")

OUTPUT_DIR = Path(out)
REMOVED_DIR = OUTPUT_DIR / "removed_funcs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REMOVED_DIR.mkdir(parents=True, exist_ok=True)

print(f"[i] Filtering Mode: {FILTER_NAME}")
print(f"[i] Input Dir:      {SAMPLE_DIR}")
print(f"[i] Output Dir:     {OUTPUT_DIR}")
print(f"[i] Threshold:      min_diff < {THRESHOLD}")

# =========================
# diff 파일 스캔 → 제거 함수 수집
# =========================
print(f"\n[i] diff < {THRESHOLD} 함수 수집 중...")
remove_funcs_per_file = {}

for diff_file in tqdm(sorted(DIFF_DIR.glob("*.jsonl")), desc="Scanning diff"):
    diff_map = {}

    for line in diff_file.open("r", encoding="utf-8"):
        try:
            entry = json.loads(line)
        except Exception:
            continue

        func = entry.get("Function Name")
        diff = float(entry.get("min_diff", 999))

        if func:
            if func not in diff_map or diff > diff_map[func]:
                diff_map[func] = diff

    funcs_to_remove = {f for f, d in diff_map.items() if d < THRESHOLD}
    if funcs_to_remove:
        remove_funcs_per_file[diff_file.name] = funcs_to_remove

print(f"[i] 제거 대상 diff 파일 수: {len(remove_funcs_per_file)}\n")

# =========================
# 원본 JSONL 필터링
# =========================
for sample_file in tqdm(sorted(SAMPLE_DIR.glob("*.jsonl")), desc="Filtering sample"):
    filename = sample_file.name
    output_path = OUTPUT_DIR / filename.replace(".jsonl", "_filtered.jsonl")
    target_funcs = remove_funcs_per_file.get(filename, set())
    removed_func_list = []
    kept, removed = 0, 0

    if not target_funcs:
        # 스킵 케이스: 전체 복사
        with sample_file.open("r", encoding="utf-8") as fin, output_path.open("w", encoding="utf-8") as fout:
            fout.write(fin.read())
        print(f"[=] {filename}: 제거 없음")
        continue

    with sample_file.open("r", encoding="utf-8") as fin, output_path.open("w", encoding="utf-8") as fout:
        for line in fin:
            try:
                entry = json.loads(line)
            except Exception:
                continue

            func = entry.get("Function Name")

            if func in target_funcs:
                removed += 1
                removed_func_list.append(func)
                continue

            fout.write(json.dumps(entry, ensure_ascii=False) + "\n")
            kept += 1

    print(f"[✓] {filename}: 남김 {kept}, 제거 {removed}")

    if removed_func_list:
        txt_path = REMOVED_DIR / f"{filename.replace('.jsonl', '')}.txt"
        with txt_path.open("w", encoding="utf-8") as ftxt:
            ftxt.write("\n".join(removed_func_list))

# =========================
# 완료 메시지
# =========================
print(f"\n Filtering Complete!")
print(f" - Mode: {FILTER_NAME}")
print(f" - Threshold: min_diff < {THRESHOLD}")
print(f" - Output Dir: {OUTPUT_DIR}")
print(f" - Removed List: {REMOVED_DIR}")
