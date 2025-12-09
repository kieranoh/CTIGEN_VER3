import json
import re
from pathlib import Path

# =========================================
# 하드코딩 설정
# =========================================


target = ["ssdeep"]   # ← 여기만 바꿔서 사용하시면 됩니다.

# 2) 알고리즘별 TXT 디렉터리 (디렉터리까지만 하드코딩)
#    각 디렉터리 안에 hash.txt 파일들이 있다고 가정:
#      ex) filtered_functions/palmtree/0123abcd.txt
#          filtered_functions/tlsh/89ef0123.txt
TXT_DIRS = {
    "palmtree": Path("filtered_functions/palmtree"),
    "tlsh": Path("filtered_functions/tlsh"),
    "ssdeep": Path("filtered_functions/ssdeep"),
}

# 3) baseline JSON들이 있는 디렉터리
#    이 안에 hash.json 형식의 파일들이 있다고 가정:
#      ex) mapping_py_result/baseline/0123abcd.json
BASELINE_DIR = Path("mapping_py_result/baseline")

# 4) 필터링 결과를 저장할 디렉터리
OUT_DIR = Path("mapping_py_result/wo_DeGPT/ssdeep/wo_top")
OUT_DIR.mkdir(parents=True, exist_ok=True)


# =========================================
# 제거 로직 (기존 로직 유지)
# =========================================

def strip_suffix(name: str) -> str:
    name = name.strip()
    parts = name.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return name


def load_remove_base_set_from_txt(txt_path: Path):
    """
    hash.txt 하나에서 제거할 base 함수 이름 집합을 만든다.
    (줄 단위로 함수 이름이 들어 있다고 가정)
    """
    remove_bases = set()

    if not txt_path.exists():
        # 해당 hash에 대한 txt가 없을 수도 있으니 조용히 리턴
        return remove_bases

    with open(txt_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            base = line
            remove_bases.add(base)

    return remove_bases


def filter_json_mapping(input_json: Path, remove_base_set: set):
    """
    mapping_py_result JSON에서
    strip_suffix(key)가 remove_base_set에 포함되면 제거한다.
    반환값: 필터링된 dict
    """
    try:
        with open(input_json, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] JSON 로드 실패: {input_json} / {e}")
        return {}

    new_data = {}

    for key, val in data.items():
        base = strip_suffix(key)

        # 제거 대상이면 skip
        if base in remove_base_set:
            continue

        # 원래 key를 그대로 유지 (suffix 포함)
        new_data[key] = val

    return new_data


# =========================================
# Main
# =========================================

def process():
    print("=== 사용 target 알고리즘 ===")
    for algo in target:
        print(f"  - {algo}")
    print()

    if not BASELINE_DIR.exists():
        print(f"[!] BASELINE_DIR 없음: {BASELINE_DIR}")
        return

    # baseline 디렉터리 안의 모든 hash.json 순회
    for json_file in BASELINE_DIR.glob("*.json"):
        hash_name = json_file.stem  # 예: 0123abcd (확장자 제거)
        print(f"\n[hash] {hash_name}")

        # 이 hash에 대해, target에 지정된 알고리즘들의 txt를 전부 모은다.
        remove_base_set = set()

        for algo in target:
            txt_dir = TXT_DIRS.get(algo)
            if txt_dir is None:
                print(f"  [!] 지원되지 않는 알고리즘 이름: {algo} (무시)")
                continue

            # ex) filtered_functions/palmtree/0123abcd.txt
            txt_path = txt_dir / f"{hash_name}.txt"

            bases = load_remove_base_set_from_txt(txt_path)
            if bases:
                print(f"  - {algo}: {txt_path.name} → 제거 {len(bases)}개")
            else:
                print(f"  - {algo}: {txt_path.name} 없음 또는 비어 있음")

            remove_base_set |= bases  # 합집합

        print(f"  [총 제거 base 함수 수] {len(remove_base_set)}")

        # JSON 필터링 수행
        filtered_data = filter_json_mapping(json_file, remove_base_set)

        # 결과 저장
        out_path = OUT_DIR / json_file.name  # 같은 hash.json 이름으로 저장
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(filtered_data, f, indent=4, ensure_ascii=False)

        print(f"  → 저장 완료: {out_path} (keys: {len(filtered_data)})")


if __name__ == "__main__":
    process()
