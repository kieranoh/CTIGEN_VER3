#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
정상 함수 SSDEEP(pydeep) DB를 기반으로,
새로 추출된 함수(JSONL)들과의 유사도를 비교하여
최소 거리(min_diff = 100 - similarity)를 저장하는 스크립트.

📌 특징
- PREPROCESS_OUTPUT_DIR 내 *.jsonl 파일들 대상
- (Function Name + Address) 기준 resume 지원 → 기존 처리 함수 자동 스킵
- pydeep.compare 기반 fuzzy distance 계산
- 실패한 함수(error)를 별도 로그로 저장
"""

import os
import json
import pydeep
from pathlib import Path
from tqdm import tqdm

# ===== 경로 설정 =====
DB_PATH = Path("dike_ssdeep.json")       # 정상 코드 SSDEEP 해시 DB
SAMPLE_DIR = Path(os.getenv("PREPROCESS_OUTPUT_DIR"))  # 비교할 함수 jsonl 폴더
OUTPUT_DIR = Path("dike_diff_ssdeep")     # 결과 저장 폴더
ERROR_LOG = OUTPUT_DIR / "error.txt"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ===== pydeep 유효성 검사 함수 =====
def is_valid_pydeep(h) -> bool:
    """
    pydeep(SSDEEP) 해시 문자열 유효성:
    - NULL 포함되면 엔트로피 부족으로 무효
    - 길이가 너무 짧으면 무효
    - ':' 구분자가 2개 이상 있어야 정상 SSDEEP
    - 첫 번째 필드(블록 크기)는 숫자여야 함
    """
    if not h:
        return False
    if isinstance(h, bytes):
        h = h.decode("utf-8", errors="ignore").strip()
    if "NULL" in h or len(h) < 10:
        return False
    if h.count(":") < 2:
        return False
    parts = h.split(":")
    if not parts[0].isdigit():
        return False
    return True


# ===== DB 로드 =====
print(f"[i] Loading DB from {DB_PATH} ...")
with open(DB_PATH, "r", encoding="utf-8") as f:
    # SSDEEP 비교는 bytes 기반 → 미리 bytes로 변환
    db_hashes = [h.encode("utf-8") for h in json.load(f)]

# DB 내 유효한 해시만 사용
db_hashes = [h for h in db_hashes if is_valid_pydeep(h)]
print(f"[i] 유효한 DB 해시 개수: {len(db_hashes)}개\n")


# ===== error 로그 초기화 =====
with open(ERROR_LOG, "w", encoding="utf-8") as ferr:
    ferr.write("### Functions that failed to save ###\n")


# ===== PREPROCESS_OUTPUT_DIR 내 모든 jsonl 처리 =====
for jsonl_file in tqdm(sorted(SAMPLE_DIR.glob("*.jsonl")), desc="Processing sample"):
    output_path = OUTPUT_DIR / jsonl_file.name

    # resume 지원: 이미 저장된(이름+주소 동일) 함수는 skip
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

            # 필수 필드 누락 또는 이미 처리한 함수 → skip
            if not func_name or not func_addr or (func_name, func_addr) in existing_funcs:
                continue
            if not code.strip():
                continue

            try:
                # SSDEEP 해시 생성
                h = pydeep.hash_buf(code.encode("utf-8"))
                if not is_valid_pydeep(h):
                    raise ValueError("Invalid pydeep hash")

                # 최소 거리(min_diff = 100 - similarity)
                min_diff = 999
                for db_hash in db_hashes:
                    try:
                        sim = pydeep.compare(h, db_hash)
                        # 결과가 0~100의 int가 아닐 경우 skip
                        if not isinstance(sim, int) or not (0 <= sim <= 100):
                            continue
                        diff = 100 - sim
                        if diff < min_diff:
                            min_diff = diff
                            if min_diff == 0:  # 완전히 동일한 경우 즉시 종료
                                break
                    except Exception:
                        continue

                # 결과 저장(JSONL append)
                json.dump({
                    "Function Name": func_name,
                    "Address": func_addr,
                    "min_diff": min_diff
                }, f_out, ensure_ascii=False)
                f_out.write("\n")
                f_out.flush()

                print(f"[+] {jsonl_file.name} :: {func_name}@{func_addr} (min_diff={min_diff:.1f})")

            except Exception as e:
                # 해싱 실패 또는 compare 오류 → 에러 로그 저장
                ferr.write(f"{jsonl_file.name} :: {func_name}@{func_addr} - {str(e)}\n")
                print(f"[x] {jsonl_file.name} :: {func_name}@{func_addr} 저장 실패 ({e})")
                continue

    print(f"[✓] {jsonl_file.name} → {output_path.name} 처리 완료")

print(f"\n모든 파일 처리 완료!")
print(f"결과 디렉토리: {OUTPUT_DIR}")
print(f"저장 실패 함수 목록: {ERROR_LOG}")
