import pandas as pd
import json
#------ Function precision / recall to CSV ------#
thresholds = [i / 100 for i in range(80, 81)]

malware_to_hash = {
    "Babuk": "8203c2f00ecd3ae960cb3247a7d7bfb35e55c38939607c85dbdb5c92f0495fa9",
    "AbbadonRAT": "74f58ab637713ca0463c3842cd71176a887b132d13d32f9841c03f59c359c6d7",
    "BPFDoor" : "afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7",
    "Emotet" : "76816ba1a506eba7151bce38b3e6d673362355063c8fd92444b6bec5ad106c21",
    "Emotet2" : "249269aae1e8a9c52f7f6ae93eb0466a5069870b14bf50ac22dc14099c2655db",
    "IISerpent" : "aa34ecb2922ce8a8066358a1d0ce0ff632297037f8b528e3a37cd53477877e47",
    "RaccoonStealer" : "0123b26df3c79bac0a3fda79072e36c159cfd1824ae3fd4b7f9dea9bda9c7909",
    "new_sample" : "1bc5621a4818f2124ac085da21f607ca"

}


test_code = {
"BPFDoor" : {
    "baseline" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\wo_filter\wo_top\afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7.json",
    "palmtree" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree\wo_top\afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7.json",
    "ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\ssdeep\wo_top\afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7.json",
    "tlsh" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh\wo_top\afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7.json",
    "palmtree_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_ssdeep\wo_top\afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7.json",
    "tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh_ssdeep\wo_top\afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7.json",
    "palmtree_tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_tlsh_ssdeep\wo_top\afa8a32ec29a31f152ba20a30eb483520fe50f2dce6c9aa9135d88f7c9c511d7.json",
    },

"AbbadonRAT" : {
    "baseline" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\wo_filter\wo_top\74f58ab637713ca0463c3842cd71176a887b132d13d32f9841c03f59c359c6d7.json",
    "palmtree" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree\wo_top\74f58ab637713ca0463c3842cd71176a887b132d13d32f9841c03f59c359c6d7.json",
    "ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\ssdeep\wo_top\74f58ab637713ca0463c3842cd71176a887b132d13d32f9841c03f59c359c6d7.json",
    "tlsh" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh\wo_top\74f58ab637713ca0463c3842cd71176a887b132d13d32f9841c03f59c359c6d7.json",
    "palmtree_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_ssdeep\wo_top\74f58ab637713ca0463c3842cd71176a887b132d13d32f9841c03f59c359c6d7.json",
    "tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh_ssdeep\wo_top\74f58ab637713ca0463c3842cd71176a887b132d13d32f9841c03f59c359c6d7.json",
    "palmtree_tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_tlsh_ssdeep\wo_top\74f58ab637713ca0463c3842cd71176a887b132d13d32f9841c03f59c359c6d7.json",
    },

"Babuk" : {
    "baseline" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\wo_filter\wo_top\8203c2f00ecd3ae960cb3247a7d7bfb35e55c38939607c85dbdb5c92f0495fa9.json",
    "palmtree" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree\wo_top\8203c2f00ecd3ae960cb3247a7d7bfb35e55c38939607c85dbdb5c92f0495fa9.json",
    "ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\ssdeep\wo_top\8203c2f00ecd3ae960cb3247a7d7bfb35e55c38939607c85dbdb5c92f0495fa9.json",
    "tlsh" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh\wo_top\8203c2f00ecd3ae960cb3247a7d7bfb35e55c38939607c85dbdb5c92f0495fa9.json",
    "palmtree_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_ssdeep\wo_top\8203c2f00ecd3ae960cb3247a7d7bfb35e55c38939607c85dbdb5c92f0495fa9.json",
    "tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh_ssdeep\wo_top\8203c2f00ecd3ae960cb3247a7d7bfb35e55c38939607c85dbdb5c92f0495fa9.json",
    "palmtree_tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_tlsh_ssdeep\wo_top\8203c2f00ecd3ae960cb3247a7d7bfb35e55c38939607c85dbdb5c92f0495fa9.json",
    },

"Emotet" : {
    "baseline" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\wo_filter\wo_top\76816ba1a506eba7151bce38b3e6d673362355063c8fd92444b6bec5ad106c21.json",
    "palmtree" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree\wo_top\76816ba1a506eba7151bce38b3e6d673362355063c8fd92444b6bec5ad106c21.json",
    "ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\ssdeep\wo_top\76816ba1a506eba7151bce38b3e6d673362355063c8fd92444b6bec5ad106c21.json",
    "tlsh" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh\wo_top\76816ba1a506eba7151bce38b3e6d673362355063c8fd92444b6bec5ad106c21.json",
    "palmtree_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_ssdeep\wo_top\76816ba1a506eba7151bce38b3e6d673362355063c8fd92444b6bec5ad106c21.json",
    "tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh_ssdeep\wo_top\76816ba1a506eba7151bce38b3e6d673362355063c8fd92444b6bec5ad106c21.json",
    "palmtree_tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_tlsh_ssdeep\wo_top\76816ba1a506eba7151bce38b3e6d673362355063c8fd92444b6bec5ad106c21.json",
  } ,

"Emotet2" : {      
    "baseline" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\wo_filter\wo_top\249269aae1e8a9c52f7f6ae93eb0466a5069870b14bf50ac22dc14099c2655db.json",
    "palmtree" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree\wo_top\249269aae1e8a9c52f7f6ae93eb0466a5069870b14bf50ac22dc14099c2655db.json",
    "ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\ssdeep\wo_top\249269aae1e8a9c52f7f6ae93eb0466a5069870b14bf50ac22dc14099c2655db.json",
    "tlsh" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh\wo_top\249269aae1e8a9c52f7f6ae93eb0466a5069870b14bf50ac22dc14099c2655db.json",
    "palmtree_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_ssdeep\wo_top\249269aae1e8a9c52f7f6ae93eb0466a5069870b14bf50ac22dc14099c2655db.json",
    "tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh_ssdeep\wo_top\249269aae1e8a9c52f7f6ae93eb0466a5069870b14bf50ac22dc14099c2655db.json",
    "palmtree_tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_tlsh_ssdeep\wo_top\249269aae1e8a9c52f7f6ae93eb0466a5069870b14bf50ac22dc14099c2655db.json",
 },

"IISerpent" : {
    "baseline" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\wo_filter\wo_top\aa34ecb2922ce8a8066358a1d0ce0ff632297037f8b528e3a37cd53477877e47.json",
    "palmtree" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree\wo_top\aa34ecb2922ce8a8066358a1d0ce0ff632297037f8b528e3a37cd53477877e47.json",
    "ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\ssdeep\wo_top\aa34ecb2922ce8a8066358a1d0ce0ff632297037f8b528e3a37cd53477877e47.json",
    "tlsh" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh\wo_top\aa34ecb2922ce8a8066358a1d0ce0ff632297037f8b528e3a37cd53477877e47.json",
    "palmtree_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_ssdeep\wo_top\aa34ecb2922ce8a8066358a1d0ce0ff632297037f8b528e3a37cd53477877e47.json",
    "tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh_ssdeep\wo_top\aa34ecb2922ce8a8066358a1d0ce0ff632297037f8b528e3a37cd53477877e47.json",
    "palmtree_tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_tlsh_ssdeep\wo_top\aa34ecb2922ce8a8066358a1d0ce0ff632297037f8b528e3a37cd53477877e47.json",
  },

"RaccoonStealer" : {
    "baseline" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\wo_filter\wo_top\0123b26df3c79bac0a3fda79072e36c159cfd1824ae3fd4b7f9dea9bda9c7909.json",
    "palmtree" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree\wo_top\0123b26df3c79bac0a3fda79072e36c159cfd1824ae3fd4b7f9dea9bda9c7909.json",
    "ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\ssdeep\wo_top\0123b26df3c79bac0a3fda79072e36c159cfd1824ae3fd4b7f9dea9bda9c7909.json",
    "tlsh" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh\wo_top\0123b26df3c79bac0a3fda79072e36c159cfd1824ae3fd4b7f9dea9bda9c7909.json",
    "palmtree_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_ssdeep\wo_top\0123b26df3c79bac0a3fda79072e36c159cfd1824ae3fd4b7f9dea9bda9c7909.json",
    "tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh_ssdeep\wo_top\0123b26df3c79bac0a3fda79072e36c159cfd1824ae3fd4b7f9dea9bda9c7909.json",
    "palmtree_tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_tlsh_ssdeep\wo_top\0123b26df3c79bac0a3fda79072e36c159cfd1824ae3fd4b7f9dea9bda9c7909.json",
  },

"new_sample" : {
    "baseline" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\wo_filter\wo_top\1bc5621a4818f2124ac085da21f607ca.json",
    "palmtree" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree\wo_top\1bc5621a4818f2124ac085da21f607ca.json",
    "ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\ssdeep\wo_top\1bc5621a4818f2124ac085da21f607ca.json",
    "tlsh" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh\wo_top\1bc5621a4818f2124ac085da21f607ca.json",
    "palmtree_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_ssdeep\wo_top\1bc5621a4818f2124ac085da21f607ca.json",
    "tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\tlsh_ssdeep\wo_top\1bc5621a4818f2124ac085da21f607ca.json",
    "palmtree_tlsh_ssdeep" :  r"C:\Users\kiera\Desktop\workspace\65_CTIGEN_ver3\mapping_py_result\w_DeGPT\palmtree_tlsh_ssdeep\wo_top\1bc5621a4818f2124ac085da21f607ca.json",
 }
}

# 네 가지 실험 설정 정의
exp_settings = {
    "wo_DeGPT_top_1":   {"use_degpt": False, "use_top1": True},
    "wo_DeGPT_wo_top":  {"use_degpt": False, "use_top1": False},
    "w_DeGPT_top_1":    {"use_degpt": True,  "use_top1": True},
    "w_DeGPT_wo_top":   {"use_degpt": True,  "use_top1": False},
}

def make_path(base_path: str, use_degpt: bool, use_top1: bool) -> str:
    """기존 경로(wo_DeGPT + top_1 기준)를 네 가지 설정에 맞게 바꿔주는 함수"""
    path = base_path
    path = path.replace("w_DeGPT", "w_DeGPT" if use_degpt else "wo_DeGPT")
    path = path.replace("wo_top", "top_1" if use_top1 else "wo_top")
    return path

rows = []  # CSV로 만들 기록들

for exp_name, cfg in exp_settings.items():
    use_degpt = cfg["use_degpt"]
    use_top1 = cfg["use_top1"]

    # mode 이름: baseline, palmtree, ssdeep ...
    mode_names = list(next(iter(test_code.values())).keys())

    for t in thresholds:
        for mode in mode_names:
            # 총합 계산용
            total_tp = 0
            total_pred = 0
            total_gt = 0

            for malware, hashval in malware_to_hash.items():
                base_path = test_code[malware][mode]
                path = make_path(base_path, use_degpt, use_top1)

                # 결과/정답 로드
                with open(path, encoding="utf8") as f:
                    res = json.load(f)
                with open(f"eval/function-report/{malware}.json", encoding="utf8") as f:
                    gt = set(json.load(f).keys())

                # threshold 이상인 함수들만 수집
                f_ctigen = {}
                for k, v in res.items():
                    for _v in v:
                        if _v["Similarity"] > t:
                            fn = k[:k.rindex("_")]
                            f_ctigen.setdefault(fn, []).append(_v)

                pred_funcs = set(f_ctigen.keys())
                tp = len(pred_funcs & gt)
                pred = len(pred_funcs)
                gt_cnt = len(gt)

                # 개별 샘플 metric
                prec = tp / pred if pred > 0 else 0.0
                recall = tp / gt_cnt if gt_cnt > 0 else 0.0
                f1 = (2 * prec * recall / (prec + recall)) if (prec + recall) > 0 else 0.0

                rows.append({
                    "exp": exp_name,        # wo_DeGPT_top_1 등
                    "threshold": t,
                    "mode": mode,           # baseline / palmtree / ...
                    "malware": malware,
                    "precision": prec,
                    "recall": recall,
                    "f1": f1,
                    "tp": tp,
                    "predicted": pred,
                    "gt": gt_cnt,
                })

                # 총합용 누적
                total_tp += tp
                total_pred += pred
                total_gt += gt_cnt

            # 설정+모드별 Total(마이크로 평균) 한 줄 추가
            total_prec = total_tp / total_pred if total_pred > 0 else 0.0
            total_recall = total_tp / total_gt if total_gt > 0 else 0.0
            total_f1 = (
                2 * total_prec * total_recall / (total_prec + total_recall)
                if (total_prec + total_recall) > 0 else 0.0
            )

            rows.append({
                "exp": exp_name,
                "threshold": t,
                "mode": mode,
                "malware": "Total",
                "precision": total_prec,
                "recall": total_recall,
                "f1": total_f1,
                "tp": total_tp,
                "predicted": total_pred,
                "gt": total_gt,
            })

# DataFrame으로 만들고 CSV 저장
df = pd.DataFrame(rows)
df.to_csv("function_precision_recall_all_experiments.csv", index=False)
print("Saved to function_precision_recall_all_experiments.csv")
