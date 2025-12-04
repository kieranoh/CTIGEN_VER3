import json
import os
from typing import Dict, Any, Tuple, List


INPUT_DIR = r"mapping_py_result\w_DeGPT\wo_filter\wo_top"           # 원본 JSON 들이 있는 디렉터리
OUTPUT_DIR_BASE = r"mapping_py_result\w_DeGPT\wo_filter\top_"  # 결과를 저장할 디렉터리 prefix (뒤에 TOP_K 붙음)
TOP_K = 1                       # 여기만 1 / 3 / 5 등으로 바꿔서 사용하세요


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(obj: Dict[str, Any], path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def dedup_indicators_by_top_k_similarity(
    data: Dict[str, Any],
    top_k: int = 1
) -> Dict[str, Any]:
    """
    같은 (ATT&CK ID, Indicator) 쌍이 여러 함수에 걸쳐 있을 때,
    Similarity 기준 상위 top_k 개 함수에만 남기고,
    나머지 함수에서는 제거한다.

    또한, 같은 함수 안에서 동일 (ATT&CK ID, Indicator)가 여러 번 있을 경우
    그 함수 내에서 Similarity가 최대인 엔트리만 유지한다.
    """

    # (ATT&CK ID, Indicator) → [(sim, func_name), ...]  (모든 엔트리 수집용)
    global_scores: Dict[Tuple[str, str], List[Tuple[float, str]]] = {}

    # (function_name, (ATT&CK ID, Indicator)) → best_similarity (함수 단위로 최대값 기록)
    per_func_best: Dict[Tuple[str, Tuple[str, str]], float] = {}

    # 1차 패스: 전역 점수 목록 + 함수별 최고 Similarity 계산
    for func_name, entries in data.items():
        if not isinstance(entries, list):
            continue

        for e in entries:
            attck_id = e.get("ATT&CK ID")
            indicator = e.get("Indicator")
            sim_raw = e.get("Similarity", 0.0)

            try:
                sim = float(sim_raw)
            except (TypeError, ValueError):
                sim = 0.0

            key = (attck_id, indicator)

            # 전역 목록에 추가
            global_scores.setdefault(key, []).append((sim, func_name))

            # 함수별 최고값 갱신
            fk = (func_name, key)
            if fk not in per_func_best or sim > per_func_best[fk]:
                per_func_best[fk] = sim

    # (ATT&CK ID, Indicator) → top_k 안에 들어가는 함수들의 집합
    global_top_funcs: Dict[Tuple[str, str], set] = {}

    for key, score_list in global_scores.items():
        # Similarity 기준 내림차순 정렬
        score_list_sorted = sorted(score_list, key=lambda x: x[0], reverse=True)
        # 상위 top_k 엔트리만
        top_entries = score_list_sorted[:top_k]
        # 그 안에 포함된 함수 이름 집합
        funcs = {fn for _, fn in top_entries}
        global_top_funcs[key] = funcs

    # 2차 패스: 조건에 맞는 엔트리만 남겨서 새 dict 구성
    new_data: Dict[str, Any] = {}

    for func_name, entries in data.items():
        if not isinstance(entries, list):
            new_data[func_name] = entries
            continue

        filtered_entries = []
        for e in entries:
            attck_id = e.get("ATT&CK ID")
            indicator = e.get("Indicator")
            sim_raw = e.get("Similarity", 0.0)

            try:
                sim = float(sim_raw)
            except (TypeError, ValueError):
                sim = 0.0

            key = (attck_id, indicator)

            # 이 Indicator의 "전역 top_k" 함수에 속하지 않으면 버림
            top_funcs = global_top_funcs.get(key, set())
            if func_name not in top_funcs:
                continue

            # 같은 함수 안에서도 동일 Indicator는 최고 Similarity 엔트리만 남김
            fk = (func_name, key)
            func_best_sim = per_func_best.get(fk, None)
            if func_best_sim is None:
                continue

            # 최대값과 같은 엔트리만 채택
            if sim == func_best_sim:
                filtered_entries.append(e)

        new_data[func_name] = filtered_entries

    return new_data


def main():
    # TOP_K에 맞춰 출력 디렉터리 이름 결정 (예: result_dedup_top3)
    output_dir = f"{OUTPUT_DIR_BASE}{TOP_K}"
    os.makedirs(output_dir, exist_ok=True)

    # 입력 디렉터리의 모든 .json 파일 순회
    for filename in os.listdir(INPUT_DIR):
        if not filename.lower().endswith(".json"):
            continue

        input_path = os.path.join(INPUT_DIR, filename)
        output_path = os.path.join(output_dir, filename)

        print(f"[+] Processing: {input_path}")

        data = load_json(input_path)
        deduped = dedup_indicators_by_top_k_similarity(data, top_k=TOP_K)
        save_json(deduped, output_path)

        print(f"    → Saved to: {output_path}")

    print(f"Done. All JSON files processed with top_k = {TOP_K}.")


if __name__ == "__main__":
    main()
