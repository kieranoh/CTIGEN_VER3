#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
정상 함수 TLSH DB 기반으로,
신규 / 업데이트된 함수(JSONL)와 최소 거리(min_diff)를 비교하여 저장하는 스크립트.

📌 특징
- PREPROCESS_OUTPUT_DIR 내 *.jsonl(함수별 코드) 대상
- (Function Name + Address) 기준으로 resume 지원 (이미 처리된 함수 skip)
- TLSH hash → DB와 diff 비교로 최소 diff 계산
- 실패한 함수들은 error.txt에 기록

출력(jsonl 형식; append, 라인당 한 함수):
{
    "Function Name": "xxx",
    "Address": "0x401000",
    "min_diff": 18.0
}
"""

import os
import json
import tlsh
from pathlib import Path
from tqdm import tqdm

# ===== 경로 설정 =====
DB_PATH = Path("dike_tlsh.json")       # 기준이 되는 정상 코드 TLSH DB
SAMPLE_DIR = Path(os.getenv("PREPROCESS_OUTPUT_DIR") ) #비교할 preprocessed된 악성샘플 디렉토리
OUTPUT_DIR = Path("dike_diff_tlsh")
ERROR_LOG = OUTPUT_DIR / "error.txt"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ===== TLSH 유효성 검사 함수 =====
def is_valid_tlsh(h: str) -> bool:
    """
    TLSH는 다음 조건을 만족해야 유효:
    - 문자열 시작이 'T'
    - 길이가 충분히 길어야 함
    - 'NULL' 포함 → 엔트로피 부족으로 무효 해시
    """
    return (
        isinstance(h, str)
        and h.startswith("T")
        and len(h) > 20
        and "NULL" not in h
    )

# ===== TLSH DB 로드 =====
with open(DB_PATH, "r", encoding="utf-8") as f:
    db = json.load(f)

# DB에서 유효한 TLSH만 추림
db_hashes = [d["hash"] for d in db if is_valid_tlsh(d.get("hash"))]
print(f"[i] 유효한 DB 해시 개수: {len(db_hashes)}개")

# ===== error.txt 초기화 =====
with open(ERROR_LOG, "w", encoding="utf-8") as ferr:
    ferr.write("### Functions that failed to save ###\n")

# ===== PREPROCESS_OUTPUT_DIR 내 모든 jsonl 파일 처리 =====
for jsonl_file in tqdm(sorted(SAMPLE_DIR.glob("*.jsonl")), desc="Processing sample"):
    output_path = OUTPUT_DIR / jsonl_file.name

    # 이미 처리된 결과가 있으면 → (func_name, address) 기준으로 skip
    existing_funcs = set()
    if output_path.exists():
        with open(output_path, "r", encoding="utf-8") as f_existing:
            for line in f_existing:
                try:
                    rec = json.loads(line.strip())
                    fid = (rec.get("Function Name"), rec.get("Address"))
                    if all(fid):
                        existing_funcs.add(fid)
                except json.JSONDecodeError:
                    continue
        print(f"[→] resume: {output_path.name}, 기존 {len(existing_funcs)}개 함수 skip 예정")

    with open(jsonl_file, "r", encoding="utf-8") as f_in, \
         open(output_path, "a", encoding="utf-8") as f_out, \
         open(ERROR_LOG, "a", encoding="utf-8") as ferr:

        for line in f_in:
            try:
                entry = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

            func_name = entry.get("Function Name")
            func_addr = entry.get("Address")
            code = entry.get("Source Code", "")

            # 필수 정보 없거나, 이미 처리한 함수 → skip
            if not func_name or not func_addr or (func_name, func_addr) in existing_funcs:
                continue

            if not code.strip():  # 빈 코드, 난독화 등
                continue

            # TLSH 생성 및 비교
            try:
                h = tlsh.hash(code.encode("utf-8"))
                if not is_valid_tlsh(h):
                    raise ValueError("Invalid TLSH hash")

                # ➜ 최소 diff 계산
                min_diff = float("inf")
                for db_hash in db_hashes:
                    try:
                        diff = tlsh.diff(h, db_hash)
                        if diff < min_diff:
                            min_diff = diff
                    except Exception:
                        continue

                # 결과 저장 (Function Name + Address + min_diff)
                json.dump({
                    "Function Name": func_name,
                    "Address": func_addr,
                    "min_diff": min_diff
                }, f_out, ensure_ascii=False)
                f_out.write("\n")
                f_out.flush()

                print(f"[+] {jsonl_file.name} :: {func_name}@{func_addr} (min_diff={min_diff:.1f}) 추가됨")

            except Exception as e:
                # TLSH 계산 실패, diff 에러 등
                ferr.write(f"{jsonl_file.name} :: {func_name}@{func_addr} - {str(e)}\n")
                print(f"[x] {jsonl_file.name} :: {func_name}@{func_addr} 저장 실패 ({e})")
                continue

    print(f"[✓] {jsonl_file.name} → {output_path.name} 처리 완료")

print(f"\n모든 파일 처리 완료!")
print(f"결과 디렉토리: {OUTPUT_DIR}")
print(f"실패 목록: {ERROR_LOG}")
