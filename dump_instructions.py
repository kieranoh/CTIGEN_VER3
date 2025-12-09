# -*- coding: utf-8 -*-
# dump_instructions.py
# Silent Ghidra Headless Jython script (single JSONL per binary, flat output)

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.lang import Register
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import Symbol
from java.io import File, FileWriter, BufferedWriter
import os

# ---------- output path setup ----------
args = getScriptArgs()
OUT_PATH = None
if args and len(args) >= 1:
    OUT_PATH = str(args[0]).strip()
if not OUT_PATH:
    OUT_PATH = "."

# derive output filename (no subdir)
prog = currentProgram
prog_path = prog.getExecutablePath()
if prog_path is None:
    prog_path = prog.getName()
binary_name = os.path.basename(prog_path)
base_name = os.path.splitext(binary_name)[0]

# If OUT_PATH is directory-like, flatten to one file (ignore subdirs)
base_dir, tail = os.path.split(OUT_PATH)
if tail == "":
    out_file_path = os.path.join(OUT_PATH, base_name + ".jsonl")
else:
    # ignore intermediate folders, flatten filename
    tail_name = os.path.basename(tail)
    out_file_path = os.path.join(base_dir, tail_name + ".jsonl")

fw = FileWriter(out_file_path, True)
bw = BufferedWriter(fw)

monitor = ConsoleTaskMonitor()
fapi = FlatProgramAPI(prog)
bb_model = BasicBlockModel(prog)
use_json = True
try:
    import json
except:
    use_json = False

# ---------- tokenizer ----------
def palm_normalize_opobj(obj):
    try:
        if isinstance(obj, Register):
            return "<REG>"
        if isinstance(obj, Scalar):
            return "<IMM>"
        if isinstance(obj, Address):
            return "<ADDR>"
        if isinstance(obj, Symbol):
            return "<SYM>"
        s = str(obj).lower()
        if s.startswith("0x"):
            return "<ADDR>"
        if s.isdigit():
            return "<IMM>"
        if "[" in s or "]" in s or "(" in s or ")" in s:
            return "<MEM>"
        return s
    except:
        return "<UNK>"

def palm_tokenize_instruction(ins):
    try:
        mnem = ins.getMnemonicString().lower()
        parts = [mnem]
        op_count = ins.getNumOperands()
        for i in range(op_count):
            objs = ins.getOpObjects(i)
            if objs is None:
                continue
            toks = []
            for obj in objs:
                toks.append(palm_normalize_opobj(obj))
            parts.append(",".join(toks))
        return " ".join([p for p in parts if p])
    except:
        return ins.toString().lower()

def emit_jsonl(obj):
    try:
        if use_json:
            s = json.dumps(obj, ensure_ascii=False)
        else:
            s = str(obj)
        bw.write(s + "\n")
    except:
        pass

try:
    fapi.analyzeAll(monitor)
except:
    pass

# ---------- helpers ----------
def get_blocks_sorted(fn):
    it = bb_model.getCodeBlocksContaining(fn.getBody(), monitor)
    blocks = []
    while it.hasNext():
        cb = it.next()
        if fn.getBody().contains(cb.getFirstStartAddress()):
            blocks.append(cb)
    blocks.sort(key=lambda b: int(b.getFirstStartAddress().getOffset()))
    return blocks

def addr_to_bbidx_by_lookup(addr, bb_start_to_idx):
    try:
        cb = bb_model.getCodeBlockAt(addr, monitor)
        if cb is None:
            return None
        start = cb.getFirstStartAddress()
        return bb_start_to_idx.get(start, None)
    except:
        return None

def build_bb_instr_tokens_and_reindex(fn, blocks):
    listing = prog.getListing()
    kept = []
    for cb in blocks:
        toks = []
        ins_iter = listing.getInstructions(cb, True)
        for ins in ins_iter:
            toks.append(palm_tokenize_instruction(ins))
        if len(toks) > 0:
            kept.append((cb, toks))
    bb_instrs = []
    bb_start_to_idx = {}
    kept_blocks = []
    for idx, (cb, toks) in enumerate(kept):
        bb_instrs.append(toks)
        bb_start_to_idx[cb.getFirstStartAddress()] = idx
        kept_blocks.append(cb)
    return bb_instrs, bb_start_to_idx, kept_blocks

def build_cfg_edges(fn, kept_blocks, bb_start_to_idx):
    listing = prog.getListing()
    edges = []
    seen = set()
    for cb in kept_blocks:
        src_idx = bb_start_to_idx.get(cb.getFirstStartAddress(), None)
        if src_idx is None:
            continue
        last_ins = None
        ins_iter = listing.getInstructions(cb, True)
        for ins in ins_iter:
            last_ins = ins
        if last_ins is None:
            continue
        ft = last_ins.getFallThrough()
        if ft and fn.getBody().contains(ft):
            dst_idx = addr_to_bbidx_by_lookup(ft, bb_start_to_idx)
            if dst_idx is not None and (src_idx, dst_idx) not in seen:
                edges.append([src_idx, dst_idx]); seen.add((src_idx, dst_idx))
        for ref in last_ins.getReferencesFrom():
            tgt = ref.getToAddress()
            if tgt and fn.getBody().contains(tgt):
                dst_idx = addr_to_bbidx_by_lookup(tgt, bb_start_to_idx)
                if dst_idx is not None and (src_idx, dst_idx) not in seen:
                    edges.append([src_idx, dst_idx]); seen.add((src_idx, dst_idx))
    return edges

def is_signal_varnode(v):
    try:
        addr = v.getAddress()
        if addr is None:
            return False
        sp = addr.getAddressSpace()
        if sp is None:
            return False
        name = sp.getName().lower()
        if "unique" in name or "const" in name:
            return False
        return True
    except:
        return False

def build_dfg_edges(fn, bb_start_to_idx):
    dfg_edges = []
    seen = set()
    try:
        ifc = DecompInterface()
        ifc.setOptions(DecompileOptions())
        ifc.openProgram(prog)
        res = ifc.decompileFunction(fn, 60.0, monitor)
        if not res or not res.getHighFunction():
            return dfg_edges
        hf = res.getHighFunction()
        all_ops = [op for op in hf.getPcodeOps()]
        uses = {}
        for op in all_ops:
            insv = op.getInputs()
            if insv:
                for v in insv:
                    if is_signal_varnode(v):
                        uses.setdefault(id(v), []).append(op)
        def bbidx_of_op(op):
            addr = op.getSeqnum().getTarget()
            return addr_to_bbidx_by_lookup(addr, bb_start_to_idx)
        for defop in all_ops:
            v = defop.getOutput()
            if v is None or not is_signal_varnode(v):
                continue
            src = bbidx_of_op(defop)
            if src is None:
                continue
            use_ops = uses.get(id(v), [])
            for uop in use_ops:
                dst = bbidx_of_op(uop)
                if dst is None or dst == src:
                    continue
                key = (src, dst)
                if key not in seen:
                    seen.add(key)
                    dfg_edges.append([src, dst])
    except:
        pass
    return dfg_edges

# ---------- main ----------
funcman = prog.getFunctionManager()
funcs = list(funcman.getFunctions(True))

for fn in funcs:
    try:
        modname = os.path.basename(prog_path)
        func_id = "%s!%s@0x%X" % (modname, fn.getName(), fn.getEntryPoint().getOffset())
        blocks = get_blocks_sorted(fn)
        bb_instrs, bb_start_to_idx, kept_blocks = build_bb_instr_tokens_and_reindex(fn, blocks)
        if len(bb_instrs) == 0:
            continue
        cfg_edges = build_cfg_edges(fn, kept_blocks, bb_start_to_idx)
        dfg_edges = build_dfg_edges(fn, bb_start_to_idx)
        out = {
            "func_id": func_id,
            "bb_instrs": bb_instrs,
            "cfg_edges": cfg_edges,
            "dfg_edges": dfg_edges
        }
        emit_jsonl(out)
    except:
        pass

try:
    bw.flush()
    bw.close()
except:
    pass

try:
    if os.path.exists(out_file_path):
        if os.path.getsize(out_file_path) == 0:
            os.remove(out_file_path)
except:
    pass
