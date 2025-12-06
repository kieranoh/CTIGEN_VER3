import os

BASE_DIR = r"filtered_functions"  # 필요하면 절대경로로 수정
SUB_DIRS = ["palmtree", "ssdeep", "tlsh"]


def count_unique_functions_in_file(file_path):
    """파일 한 개당 유일한 함수 이름 갯수 세기"""
    funcs = set()
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            funcs.add(line)
    return len(funcs)


print("\n===== Filtered Function Count (by folder & file) =====")

total_all = 0
folder_results = {}

for sub in SUB_DIRS:
    sub_dir = os.path.join(BASE_DIR, sub)
    if not os.path.isdir(sub_dir):
        print(f"[WARN] No folder: {sub_dir}")
        continue

    print(f"\n[ {sub} ]")
    folder_total = 0

    for file in sorted(os.listdir(sub_dir)):
        if not file.endswith(".txt"):
            continue

        file_path = os.path.join(sub_dir, file)
        file_count = count_unique_functions_in_file(file_path)
        folder_total += file_count

        print(f"  {file:<40} {file_count:6d} funcs")

    folder_results[sub] = folder_total
    total_all += folder_total

    print(f"Folder Total ({sub}): {folder_total} funcs")