import json
import re
import os
from dotenv import load_dotenv
load_dotenv()
preprocess_output_dir = os.getenv("PREPROCESS_OUTPUT_DIR")
filtering_output_dir = os.getenv("FILTERING_OUTPUT_DIR")
sample_hash = os.getenv("SAMPLE_HASH")

def remove_comments_and_trailing_vars(code: str) -> str:
    # C 스타일 블록/라인 주석 제거
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'//.*$', '', code, flags=re.MULTILINE)

    # 함수 끝난 뒤에 붙는 Local Variable: ... 블록 통째로 제거
    # 예:
    #   }
    #   Local Variable: local_10 : undefined8
    #   Local Variable: local_18 : undefined8
    code = re.sub(r'\n*Local Variable:.*', '', code, flags=re.DOTALL)

    return code

def clean_blank_lines(source: str) -> str:
    # 연속 빈 줄 정리: \n + (공백들) + \n... → \n
    source = re.sub(r'\n[ \t]*\n+', '\n', source)
    # 앞뒤 불필요한 개행 제거
    return source.strip('\n')

def extract_function_name(source: str) -> str:
    # 함수 시그니처가 있는 첫 줄에서 함수 이름 추출
    first_line = source.strip().split('\n', 1)[0]
    m = re.search(r'\b([A-Za-z_]\w*)\s*\(', first_line)
    return m.group(1) if m else ''

def is_self_trivial_wrapper(func_name: str, source: str) -> bool:
    # { … } 내부만 추출
    m = re.search(r'\{([\s\S]*?)\}', source)
    if not m:
        return False

    # 내용 라인만 추림 (공백 줄 제거)
    body = m.group(1)
    lines = [ln.strip() for ln in body.splitlines() if ln.strip()]

    # 패턴들
    call_only     = re.compile(rf'^{re.escape(func_name)}\s*\(.*\)\s*;\s*$')
    return_call   = re.compile(rf'^return\s+{re.escape(func_name)}\s*\(.*\)\s*;\s*$')
    # 숫자/16진수 등 "상수만 반환"
    return_const  = re.compile(r'^return\s+([+-]?\d+|0x[0-9A-Fa-f]+)\s*;\s*(?:\/\/.*|/\*.*\*/)?$')
    # 아무 내용 없이 return; 만 있는 void 빈 함수
    return_void   = re.compile(r'^return\s*;\s*(?:\/\/.*|/\*.*\*/)?$')

    # --- 1라인 함수 ---
    if len(lines) == 1:
        if (call_only.match(lines[0])
            or return_call.match(lines[0])
            or return_const.match(lines[0])
            or return_void.match(lines[0])):
            return True

    # --- 2라인 함수: 자기자신 호출 + return; 조합 ---
    if len(lines) == 2:
        if call_only.match(lines[0]) and return_void.match(lines[1]):
            return True
        if return_call.match(lines[0]) and return_void.match(lines[1]):
            return True

    return False

def transform_code(code: str) -> str:
    code = remove_comments_and_trailing_vars(code)
    code = clean_blank_lines(code)
    return code

def process_json_file(input_path: str, output_path: str):
    with open(input_path, 'r', encoding='utf-8') as f:
        text = f.read().strip()

    # JSON 전체가 하나의 배열/객체일 수도 있고,
    # jsonl 형식(한 줄당 하나의 JSON)일 수도 있음
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            data.append(json.loads(line))

    cnt_removed = 0  # trivial wrapper 제거 개수

    def recurse(obj):
        # 중첩된 구조 안의 "Source Code"도 정리만 해줌 (삭제는 top-level에서만)
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "Source Code" and isinstance(v, str):
                    obj[k] = transform_code(v)
                else:
                    recurse(v)
        elif isinstance(obj, list):
            for item in obj:
                recurse(item)

    # top-level 이 리스트이면 각 함수 엔트리에 대해 trivial wrapper 필터 적용
    if isinstance(data, list):
        kept = []
        for obj in data:
            if isinstance(obj, dict) and isinstance(obj.get("Source Code"), str):
                src_clean = transform_code(obj["Source Code"])
                func_name = extract_function_name(src_clean)

                # self-trivial wrapper / 상수만 return / 빈 return 등 걸러내기
                if func_name and is_self_trivial_wrapper(func_name, src_clean):
                    cnt_removed += 1
                    continue

                obj["Source Code"] = src_clean

            # 그 밖의 nested "Source Code"도 정리
            recurse(obj)
            kept.append(obj)

        data = kept
    else:
        # 리스트가 아니면 그냥 재귀적으로 정리만
        recurse(data)

    with open(output_path, 'w', encoding='utf-8') as f_out:
        if isinstance(data, list):
            for obj in data:
                f_out.write(json.dumps(obj, ensure_ascii=False) + '\n')
        else:
            f_out.write(json.dumps(data, ensure_ascii=False) + '\n')

    print(f"JSON cleaned and saved to: {output_path}")
    print(f"Trivial/self-wrapper functions removed: {cnt_removed}")

if __name__ == '__main__':
    
    input_file = f"{preprocess_output_dir}/{sample_hash}.jsonl"
    output_file = f"{filtering_output_dir}/{sample_hash}.jsonl"
    process_json_file(input_file,output_file)
