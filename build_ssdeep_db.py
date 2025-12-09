#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
정상 코드에서 SSDEEP(pydeep) 해시 DB 생성 스크립트
- 여러 base_dir에서 JSONL 파일 재귀 탐색
- 함수별 "Source Code" → pydeep(hash_buf)로 해시 생성
- SSDEEP 형식 검증(비어있음 / NULL / 구분자 ':' 여부)
- 스킵 건수 기록 (길이 부족, 형식 불량 등)

출력 형식 (JSON array; 요소는 문자열 하나)
[
  "12288:bcdefghijklmnopqrstuvwxyz123456:abcdef12",
  "xxxxx:yyyyy:zzzzz",
  ...
]
"""

import os
import json
import pydeep
from pathlib import Path

# ===== 설정 =====
# 분석 대상 정상 함수 폴더 (정상 함수들을 preprocess한 jsonl 파일들이 들어 있음), dike는 예시
BASE_DIRS = [
    # os.path.join(os.path.dirname(__file__), "preprocessed_dike"),
]

# 최종 pydeep 해시 리스트 저장 파일
OUT_FILE = Path(os.path.dirname(__file__)) / "dike_ssdeep.json"


def build_pydeep_db(base_dirs=BASE_DIRS, out_file=OUT_FILE):
    """
    모든 함수의 SSDEEP(pydeep) 해시를 수집하여
    단일 JSON 리스트 형태로 저장합니다.
    """
    hashes = []   # SSDEEP 해시 문자열 리스트
    skipped = 0   # 해시 불가 또는 형식 불량 카운트

    # -------------------------------------------------
    # 1. 전체 .jsonl 파일 목록 수집
    # -------------------------------------------------
    all_files = []
    for base_dir in base_dirs:
        for root, _, files in os.walk(base_dir):
            for fn in files:
                if fn.endswith(".jsonl"):
                    all_files.append(os.path.join(root, fn))

    total_files = len(all_files)
    print(f"[*] 총 {total_files}개 JSONL 파일 발견")

    # -------------------------------------------------
    # 2. 파일별로 ssdeep 해시 생성
    # -------------------------------------------------
    for idx, filepath in enumerate(all_files, start=1):
        fn = os.path.basename(filepath)
        print(f"[{idx}/{total_files}] {fn} 처리 중... ({idx/total_files*100:.2f}%)")

        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                # JSONL → JSON 디코드
                try:
                    func = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # 코드 문자열 확인
                code = func.get("Source Code", "")
                if not code.strip():
                    skipped += 1
                    continue

                # -------------------------------------------------
                # ssdeep 해시 생성
                # -------------------------------------------------
                try:
                    h = pydeep.hash_buf(code.encode("utf-8"))

                    # pydeep.hash_buf()는 bytes 반환 → 문자열 변환
                    if isinstance(h, bytes):
                        h = h.decode("utf-8", errors="ignore").strip()

                    # SSDEEP 해시 유효성 검사
                    #   - 비어있지 않아야 함
                    #   - NULL 문자열 포함하면 무효 (길이/엔트로피 부족)
                    #   - ':' 구분자 2개 이상 포함해야 정상 SSDEEP 형식
                    if h and "NULL" not in h and h.count(":") >= 2:
                        hashes.append(h)
                    else:
                        skipped += 1

                except Exception:
                    # 해싱 과정에서 오류 발생 시 스킵
                    skipped += 1
                    continue

    # -------------------------------------------------
    # 3. 결과 저장 (리스트 그대로)
    # -------------------------------------------------
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(hashes, f, ensure_ascii=False, indent=2)

    print(f"\n ssdeep 해시 리스트 저장 완료: {out_file}")
    print(f"저장된 해시: {len(hashes)}개")
    print(f"스킵된 코드: {skipped}개 (빈 코드 / 형식 불량)")


# 단독 실행 시 자동 수행
if __name__ == "__main__":
    build_pydeep_db()
