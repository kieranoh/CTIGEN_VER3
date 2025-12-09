import re
import json
import sys
import os
from dotenv import load_dotenv

# ─────────────────────────────────────────────────────────────────────────────────
load_dotenv()
SAMPLE_HASH = os.getenv("SAMPLE_HASH")
FILTERING_OUTPUT_DIR = os.getenv("FILTERING_OUTPUT_DIR")
INPUT_FILE  = os.path.join(FILTERING_OUTPUT_DIR, f"{SAMPLE_HASH}_degpt_result.json")
OUTPUT_FILE = os.path.join(FILTERING_OUTPUT_DIR, f"{SAMPLE_HASH}_degpt_remove.json")

# 너무 큰 함수는 처리하지 않기 위한 최대 길이
MAX_SOURCE_LENGTH = 8000
# ─────────────────────────────────────────────────────────────────────────────────

def remove_comments_and_newlines(code: str) -> str:
    # 주석 제거
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)

    # 연속된 개행 문자(\n\n\n...)을 하나로 줄이기
    code = re.sub(r'\n{2,}', '\n', code)

    # 문자열 앞뒤의 불필요한 개행 제거
    code = code.strip('\n')

    return code


def process_json_file(input_path: str, output_path: str):
    with open(input_path, 'r', encoding='utf-8') as f:
        text = f.read().strip()

    data = None
    try:
        # 전체가 하나의 JSON 객체/배열일 수도 있으니 먼저 시도
        data = json.loads(text)
    except json.JSONDecodeError:
        # 아니면 JSONL로 가정하고 라인별로 파싱
        data = []
        for lineno, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                data.append(obj)
            except json.JSONDecodeError as e:
                # 깨진 JSON 라인은 건너뛰고 에러만 stderr로 알려줌
                print(
                    f"[WARN] Skip invalid JSON at line {lineno}: {e}",
                    file=sys.stderr
                )
                continue

    def recurse(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "Source Code" and isinstance(v, str):

                    # 크기가 너무 크면 스킵하고 원본 그대로 저장
                    if len(v) > MAX_SOURCE_LENGTH:
                        obj[k] = v
                    else:
                        obj[k] = remove_comments_and_newlines(v)

                else:
                    recurse(v)

        elif isinstance(obj, list):
            for item in obj:
                recurse(item)

    recurse(data)

    with open(output_path, 'w', encoding='utf-8') as f_out:
        if isinstance(data, list):
            for obj in data:
                f_out.write(json.dumps(obj, ensure_ascii=False) + '\n')
        else:
            f_out.write(json.dumps(data, ensure_ascii=False) + '\n')

    print(f"JSON cleaned and saved to: {output_path}")


if __name__ == "__main__":
    process_json_file(INPUT_FILE, OUTPUT_FILE)
