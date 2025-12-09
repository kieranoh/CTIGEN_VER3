#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
정상 코드에서 TLSH 해시 DB 생성 스크립트
- 여러 base_dir에서 *.jsonl 재귀 탐색
- 함수 단위 JSON(한 줄) 그대로 로드
- "Source Code" 길이 부족(TNULL 등)한 경우 스킵
- 진행률 출력
- 결과를 하나의 JSON 리스트로 out_file에 저장

출력 형식 (JSON array; 요소당)
{
  "hash": "<tlsh_hash>",
  "function": "<Function Name>",
  "address": "<Address>",
  "file": "<input_filename>"
}
"""

import os
import json
import tlsh

# 분석 대상 정상 함수 폴더 (정상 함수들을 preprocess한 jsonl 파일들이 들어 있음), dike는 예시
BASE_DIRS = [
    # os.path.join(os.path.dirname(__file__), "preprocessed_dike"),
]

# 최종 TLSH DB 저장 경로
HASH_DB = os.path.join(os.path.dirname(__file__), "dike_tlsh.json")


def build_tlsh_db(base_dirs=BASE_DIRS, out_file=HASH_DB):
    """
    여러 디렉토리(base_dirs)에서 JSONL 파일들을 찾고,
    함수별 TLSH 해시를 계산하여 out_file(JSON)로 저장합니다.
    """
    hashes = []   # {"hash", "function", "address", "file"} 리스트
    skipped = 0   # TLSH 생성 불가(짧은 코드 등) 건수

    # ----------------------------
    # 1. 전체 JSONL 파일 목록 수집
    # ----------------------------
    all_files = []
    for base_dir in base_dirs:
        for root, _, files in os.walk(base_dir):
            for fn in files:
                if fn.endswith(".jsonl"):
                    all_files.append(os.path.join(root, fn))

    total_files = len(all_files)
    print(f"[*] 총 {total_files}개 .jsonl 파일 발견")

    # ----------------------------
    # 2. 파일 순회하면서 TLSH 생성
    # ----------------------------
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

                code = func.get("Source Code", "")
                # 빈 코드 또는 매우 짧은 코드는 TLSH 특징 부족 → 스킵
                # ※ TLSH는 최소 50바이트 이상 + 충분한 랜덤성 필요
                if not code.strip():
                    skipped += 1
                    continue

                # -----------------------
                # TLSH 해시 계산
                # -----------------------
                h = tlsh.hash(code.encode("utf-8"))

                # TNULL = 해싱 불가 상태(길이/엔트로피 부족)
                if h and not h.startswith("TNULL"):
                    hashes.append({
                        "hash": h,
                        "function": func.get("Function Name"),
                        "address": func.get("Address"),
                        "file": fn,
                    })
                else:
                    skipped += 1

    # ----------------------------
    # 3. 결과 JSON으로 저장
    # ----------------------------
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(hashes, f, ensure_ascii=False, indent=2)

    print(f"\nTLSH DB 생성 완료: {out_file}")
    print(f"저장된 해시: {len(hashes)}개")
    print(f"스킵된 코드: {skipped}개 (길이/랜덤성 부족)")

    return hashes


# 단독 실행 시 자동 수행
if __name__ == "__main__":
    build_tlsh_db()
