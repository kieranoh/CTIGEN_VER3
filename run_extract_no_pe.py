#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, shlex, struct, subprocess, shutil
from pathlib import Path
from datetime import datetime
from tqdm import tqdm
import pefile
from multiprocessing import Pool, cpu_count
from concurrent.futures import ProcessPoolExecutor, as_completed


GHIDRA_HEADLESS = os.getenv("GHIDRA_HEADLESS_PATH")
SCRIPT_DIR        = Path(__file__).parent           # dump_instructions.py 위치
BENIGN_DIR        = os.getenv("SAMPLE_EXE_PATH")
OUT_DIR           = os.getenv("ASM_OUTPUT_DIR")
GHIDRA_PROJ_ROOT  = r"./temp/ghidra_projects"  # ★ 절대경로 권장

BINARY_EXTS = {".exe", ".dll", ".bin", ".so", ".elf"}
TIMEOUT_SEC = 0  # 0=무제한
assert Path(GHIDRA_HEADLESS).exists(), GHIDRA_HEADLESS

def work_one(bin_path: Path):
    rel = bin_path.relative_to(Path(BENIGN_DIR))
    proj_dir = Path(GHIDRA_PROJ_ROOT) / rel.parent
    proj_dir.mkdir(parents=True, exist_ok=True)
    proj_name = rel.stem

    out_dir = Path(OUT_DIR) / rel.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    out_jsonl = out_dir / f"{rel.stem}.jsonl"

    rc = run_headless(
        ghidra_headless=GHIDRA_HEADLESS,
        proj_dir=proj_dir,
        proj_name=proj_name,
        binary_path=bin_path,
        script_dir=SCRIPT_DIR,
        out_jsonl=out_jsonl,
        timeout=TIMEOUT_SEC
    )
    cleanup_project(proj_dir=proj_dir, proj_name=proj_name, stop_at=Path(GHIDRA_PROJ_ROOT))
    return (bin_path, rc, out_jsonl.exists() and out_jsonl.stat().st_size > 0)

def is_binary_file(p: Path) -> bool:
    return p.is_file() and p.suffix.lower() in BINARY_EXTS

def iter_binaries(root: Path):
    for p in root.rglob("*"):
        if is_binary_file(p):
            yield p

def should_skip_stub(path: Path) -> bool:
    """
    PE 전용 깊은 검사를 일반 파일에 적용하지 않도록 완화.
    - 이름/폴더 기반 휴리스틱은 그대로 유지
    - .exe/.dll 에 한해서만 pefile 기반의 '실코드 없음/전량 forwarder' 검사를 수행
    """
    n = path.name.lower()
    # ① 리소스 위성 DLL / 리소스 폴더
    if n.endswith(".resources.dll") or "resources" in str(path.parent).lower():
        return True
    # ② API set / ext-ms 스텁
    if n.startswith("api-ms-win-") or n.startswith("ext-ms-"):
        return True
    # ③ .NET 위성/문화권 폴더 (예: en-US, ko-KR 등)
    parts = {p.lower() for p in path.parts}
    if any(len(p) == 5 and "-" in p for p in parts):  # en-US, zh-CN 등 휴리스틱
        if n.endswith(".dll") and ".resources" in n:
            return True

    # ④ (완화) .exe/.dll 에 대해서만 pefile 기반 추가 검사
    if path.suffix.lower() in {".exe", ".dll"}:
        try:
            pe = pefile.PE(str(path), fast_load=True)
            if not has_real_code(pe):
                return True
            if is_all_forwarders(pe):
                return True
        except Exception:
            # 이전에는 예외 시 True(스킵)였으나, 일반/비정형 파일을 살리기 위해 False로 완화
            return False

    return False

def has_real_code(pe: pefile.PE) -> bool:
    try:
        if getattr(pe.OPTIONAL_HEADER, "SizeOfCode", 0) == 0:
            return False
        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode(errors="ignore").lower()
            if name in (".text", "text") and s.SizeOfRawData > 0:
                return True
    except Exception:
        pass
    return False

def is_all_forwarders(pe: pefile.PE) -> bool:
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return False
        entries = pe.DIRECTORY_ENTRY_EXPORT.symbols
        if not entries:
            return False
        return all(getattr(e, "forwarder", None) for e in entries)
    except Exception:
        return False

# (보존) 필요 시 다른 데서 쓸 수 있지만, 이제 호출하지 않습니다.
def is_pe_magic(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                return False
            f.seek(0x3C)
            off = struct.unpack("<I", f.read(4))[0]
            if off <= 0 or off > 10_000_000:
                return False
            f.seek(off)
            return f.read(4) == b"PE\x00\x00"
    except Exception:
        return False

def run_headless(ghidra_headless: str, proj_dir: Path, proj_name: str,
                 binary_path: Path, script_dir: Path, out_jsonl: Path,
                 timeout: int = 0) -> int:
    """Ghidra headless 실행. 표준출력 로그 파일 기록 제거(완전 무시)."""
    proj_dir   = Path(proj_dir).resolve()
    binary_path= Path(binary_path).resolve()
    script_dir = Path(script_dir).resolve()
    out_jsonl  = Path(out_jsonl).resolve()

    cmdline = (
        f'"{ghidra_headless}" '
        f'"{proj_dir}" "{proj_name}" '
        f'-import "{binary_path}" '
        f'-scriptPath "{script_dir}" '
        f'-postScript dump_instructions.py "{out_jsonl}" '
        f'-max-cpu 3'
    )

    env = os.environ.copy()
    env.setdefault("MSYS2_ARG_CONV_EXCL", "*")
    env.setdefault("MAXMEM", "8G")

    proc = subprocess.Popen(
        cmdline,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env
    )
    try:
        proc.wait(timeout=None if timeout == 0 else timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        return -9

    return proc.returncode

def cleanup_project(proj_dir: Path, proj_name: str, stop_at: Path):
    proj_dir = Path(proj_dir)
    stop_at = Path(stop_at).resolve()

    candidates = [
        proj_dir / f"{proj_name}.gpr",
        proj_dir / f"{proj_name}.rep",
        proj_dir / f"{proj_name}.crt",
        proj_dir / f"{proj_name}.lock",
    ]
    for p in candidates:
        try:
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            elif p.exists():
                p.unlink(missing_ok=True)
        except Exception:
            pass

    cur = proj_dir
    try:
        while True:
            if not cur.exists():
                break
            if cur.resolve() == stop_at:
                break
            if not any(cur.iterdir()):
                cur.rmdir()
                cur = cur.parent
            else:
                break
    except Exception:
        pass

def _parallel_worker(bin_path_str: str) -> tuple:
    """
    반환값:
      ("skip", bin_path_str) |
      ("ok",   bin_path_str) |
      ("fail", bin_path_str, rc)
    """
    bin_path = Path(bin_path_str)
    try:
        # (변경) PE 매직 검사 제거. 이름 기반 휴리스틱만 적용.
        if should_skip_stub(bin_path):
            return ("skip", bin_path_str)

        rel = bin_path.relative_to(Path(BENIGN_DIR))
        proj_dir = Path(GHIDRA_PROJ_ROOT) / rel.parent
        proj_dir.mkdir(parents=True, exist_ok=True)
        proj_name = rel.stem

        out_dir = Path(OUT_DIR) / rel.parent
        out_dir.mkdir(parents=True, exist_ok=True)
        out_jsonl = out_dir / f"{rel.stem}.jsonl"

        rc = run_headless(
            ghidra_headless=GHIDRA_HEADLESS,
            proj_dir=proj_dir,
            proj_name=proj_name,
            binary_path=bin_path,
            script_dir=SCRIPT_DIR,
            out_jsonl=out_jsonl,
            timeout=TIMEOUT_SEC
        )

        ok = (rc == 0 and out_jsonl.exists() and out_jsonl.stat().st_size > 0)
        return ("ok", bin_path_str) if ok else ("fail", bin_path_str, rc)

    except Exception:
        return ("fail", bin_path_str, -99)

    finally:
        try:
            rel = bin_path.relative_to(Path(BENIGN_DIR))
            proj_dir = Path(GHIDRA_PROJ_ROOT) / rel.parent
            cleanup_project(proj_dir=proj_dir, proj_name=rel.stem, stop_at=Path(GHIDRA_PROJ_ROOT))
        except Exception:
            pass


def main():
    gh = Path(GHIDRA_HEADLESS)
    sd = Path(SCRIPT_DIR)
    benign_root = Path(BENIGN_DIR)
    out_root = Path(OUT_DIR)
    proj_root = Path(GHIDRA_PROJ_ROOT)

    targets = list(iter_binaries(benign_root))
    if not targets:
        print("[!] 처리할 바이너리가 없습니다."); sys.exit(0)

    print(f"[i] 총 대상 파일: {len(targets)}개")

    # ★ 추가: 병렬 스위치
    USE_PARALLEL = True  # ← 병렬 켜기(프로세스 2개 × -max-cpu 3)

    ok = 0
    skipped = 0

    try:
        if not USE_PARALLEL:
            # ===== 기존 순차 로직 =====
            for bin_path in tqdm(targets, desc="Processing binaries", unit="file"):
                # (변경) PE 매직 검사 제거
                if should_skip_stub(bin_path):
                    skipped += 1
                    continue

                rel = bin_path.relative_to(benign_root)
                proj_dir = Path(GHIDRA_PROJ_ROOT) / rel.parent
                proj_dir.mkdir(parents=True, exist_ok=True)
                proj_name = rel.stem

                out_dir = Path(OUT_DIR) / rel.parent
                out_dir.mkdir(parents=True, exist_ok=True)
                out_jsonl = out_dir / f"{rel.stem}.jsonl"

                rc = run_headless(
                    ghidra_headless=str(gh),
                    proj_dir=proj_dir,
                    proj_name=proj_name,
                    binary_path=bin_path,
                    script_dir=sd,
                    out_jsonl=out_jsonl,
                    timeout=TIMEOUT_SEC
                )

                if rc == 0 and out_jsonl.exists() and out_jsonl.stat().st_size > 0:
                    ok += 1
                elif rc != 0:
                    print(f"[!] Ghidra 실패(code={rc}) {bin_path}")

                cleanup_project(proj_dir=proj_dir, proj_name=proj_name, stop_at=Path(GHIDRA_PROJ_ROOT))

        else:
            # ===== 병렬 분기: 프로세스 2개, 각 프로세스는 -max-cpu 3 =====
            PROCS = 2
            with ProcessPoolExecutor(max_workers=PROCS) as ex:
                futs = [ex.submit(_parallel_worker, str(p)) for p in targets]
                for fut in tqdm(as_completed(futs), total=len(futs), desc="Parallel Ghidra", unit="file"):
                    res = fut.result()
                    tag = res[0]
                    if tag == "skip":
                        skipped += 1
                    elif tag == "ok":
                        ok += 1
                    else:
                        _, path_str, rc = res
                        if rc != 0:
                            print(f"[!] Ghidra 실패(code={rc}) {path_str}")

        print(f"\n=== 완료 ===\n성공(비어있지 않은 결과): {ok}/{len(targets)}  |  스킵: {skipped}\n결과: {OUT_DIR}\n프로젝트 루트(잔여 유지): {GHIDRA_PROJ_ROOT}")

    except KeyboardInterrupt:
        print(f"\n[!] 사용자 중단(Ctrl+C)\n지금까지 성공: {ok}/{len(targets)}  |  스킵: {skipped}")


if __name__ == "__main__":
    main()
