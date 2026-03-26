
import argparse
import subprocess
import json
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import pandas as pd
import datetime as dt

def run_cmd(cmd: List[str], timeout: int = 300) -> Tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        errors="replace",
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""

def extract_first_json(text: str) -> Optional[object]:
    m = re.search(r"(\{[\s\S]*\}|\[[\s\S]*\])", text)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except Exception:
        return None

class VolExecutor:
    def __init__(self, vol_cmd: str, mem: str, outdir: Path, timeout: int = 300):
        self.vol_cmd = vol_cmd
        self.mem = mem
        self.outdir = outdir
        self.timeout = timeout
        outdir.mkdir(parents=True, exist_ok=True)

    def _base(self) -> List[str]:
        # vol_cmd is a string like: "python C:\\path\\to\\vol.py"
        return self.vol_cmd.split() + ["-f", self.mem]

    def run_plugin_json(self, plugin: str, args: Dict[str, object], tag: str):
        ts = dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        outfile = self.outdir / f"{ts}__{tag}.txt"

        cmd = self._base() + ["-r", "json", plugin]
        for k, v in args.items():
            if v is None:
                continue
            flag = f"--{k}"
            if isinstance(v, list):
                for item in v:
                    cmd += [flag, str(item)]
            else:
                cmd += [flag, str(v)]

        rc, out, err = run_cmd(cmd, self.timeout)

        outfile.write_text(
            "COMMAND:\n"
            + " ".join(cmd)
            + "\n\nSTDOUT:\n"
            + out
            + "\n\nSTDERR:\n"
            + err,
            encoding="utf-8",
            errors="replace",
        )

        return rc, extract_first_json(out), outfile

    def resolve_pids(self, exe_names: List[str]) -> List[int]:
        exe_names = [e.strip().lower() for e in exe_names if isinstance(e, str)]
        exe_names = [e for e in exe_names if e.endswith(".exe")]
        if not exe_names:
            return []

        rc, data, _ = self.run_plugin_json("windows.pslist", {}, "pslist_pid_resolve")
        if not data or not isinstance(data, list):
            return []

        pids: List[int] = []
        for row in data:
            img = str(row.get("ImageFileName", "")).strip().lower()
            pid = row.get("PID")
            if img in exe_names and isinstance(pid, int):
                pids.append(pid)
        return sorted(set(pids))

# ===== Technique Implementations (extendable) =====

def T1055_002(ctx: dict, exe: VolExecutor) -> List[str]:
    outputs = []
    for pid in ctx["TARGET_PIDS"]:
        for plugin in ["windows.malfind", "windows.vadinfo", "windows.threads"]:
            _, _, out = exe.run_plugin_json(plugin, {"pid": pid}, f"T1055.002_pid{pid}_{plugin}")
            outputs.append(str(out))
    return outputs

def T1055_013(ctx: dict, exe: VolExecutor) -> List[str]:
    outputs = []
    for pid in ctx["TARGET_PIDS"]:
        for plugin in ["windows.handles", "windows.threads", "windows.malfind"]:
            _, _, out = exe.run_plugin_json(plugin, {"pid": pid}, f"T1055.013_pid{pid}_{plugin}")
            outputs.append(str(out))
    return outputs

TECHNIQUE_FUNCS = {
    "T1055.002": T1055_002,
    "T1055.013": T1055_013,
}

# ===== Excel Parsing for your StuxnetResults format =====

def _find_row_col(raw: pd.DataFrame, needle: str) -> Optional[Tuple[int, int]]:
    needle_low = needle.strip().lower()
    for r in range(raw.shape[0]):
        for c in range(raw.shape[1]):
            v = raw.iat[r, c]
            if isinstance(v, str) and v.strip().lower() == needle_low:
                return r, c
    return None

def _read_table(raw: pd.DataFrame, header_row: int, header_col: int) -> pd.DataFrame:
    # Build headers from the header_row to the right until blanks
    headers = []
    c = header_col
    while c < raw.shape[1]:
        v = raw.iat[header_row, c]
        if v is None or (isinstance(v, float) and pd.isna(v)):
            break
        if isinstance(v, str) and v.strip() == "":
            break
        headers.append(str(v).strip())
        c += 1

    if not headers:
        return pd.DataFrame()

    start_col = header_col
    end_col = header_col + len(headers)

    # Collect rows until a fully blank row in that span
    rows = []
    r = header_row + 1
    while r < raw.shape[0]:
        span = raw.iloc[r, start_col:end_col].tolist()
        if all((x is None) or (isinstance(x, float) and pd.isna(x)) or (isinstance(x, str) and x.strip() == "") for x in span):
            break
        rows.append(span)
        r += 1

    df = pd.DataFrame(rows, columns=headers)
    return df

def load_stuxnet_results(path: str) -> Tuple[List[str], dict]:
    """
    Parses the combined-sheet StuxnetResults.xlsx where:
    - Mapping table header contains 'Sub-Technique'
    - NER table header contains 'sentence_id'
    """
    raw = pd.read_excel(path, header=None)

    # Mapping results table
    loc_map = _find_row_col(raw, "Sub-Technique")
    if not loc_map:
        raise ValueError("Could not find 'Sub-Technique' header in the Excel.")
    map_df = _read_table(raw, loc_map[0], loc_map[1])

    # NER entities table
    loc_ner = _find_row_col(raw, "sentence_id")
    if not loc_ner:
        raise ValueError("Could not find 'sentence_id' header in the Excel.")
    ner_df = _read_table(raw, loc_ner[0], loc_ner[1])

    # Techniques from mapping table
    techs = []
    if "Sub-Technique" in map_df.columns:
        techs = sorted(set(map_df["Sub-Technique"].dropna().astype(str).str.strip()))
    else:
        # Fallback: first column
        techs = sorted(set(map_df.iloc[:, 0].dropna().astype(str).str.strip()))

    # Build NER context
    ctx = {
        "TARGET_EXES": [],
        "TARGET_PIDS": [],
        "MAL_DLLS": [],
        "TARGET_DLLS": [],
        "STRINGS": [],
        "extras": {},
    }

    if not ner_df.empty:
        # normalize column names
        cols = {c.lower(): c for c in ner_df.columns}
        text_col = cols.get("entity_text")
        label_col = cols.get("entity_label")
        if text_col and label_col:
            for _, r in ner_df.iterrows():
                label = str(r.get(label_col, "")).strip()
                text = str(r.get(text_col, "")).strip()

                if not label:
                    continue

                lab_up = label.upper()
                # Keep this aligned with your NER labels
                if lab_up in ("TARGETPROCESS", "PROCESS", "TARGET_PROCESS"):
                    ctx["TARGET_EXES"].append(text)
                elif lab_up in ("PID", "PROCESSID", "PROCESS_ID"):
                    if text.isdigit():
                        ctx["TARGET_PIDS"].append(int(text))
                elif lab_up in ("MALLIBRARY", "DLL", "MAL_DLL"):
                    ctx["MAL_DLLS"].append(text)
                elif lab_up in ("TARGETDLL", "TARGET_DLL"):
                    ctx["TARGET_DLLS"].append(text)
                elif lab_up in ("STRING", "IOC", "INDICATOR"):
                    ctx["STRINGS"].append(text)
                else:
                    ctx["extras"].setdefault(label, []).append(text)

    # Deduplicate
    ctx["TARGET_EXES"] = sorted(set([x for x in ctx["TARGET_EXES"] if x]))
    ctx["TARGET_PIDS"] = sorted(set(ctx["TARGET_PIDS"]))
    ctx["MAL_DLLS"] = sorted(set([x for x in ctx["MAL_DLLS"] if x]))
    ctx["TARGET_DLLS"] = sorted(set([x for x in ctx["TARGET_DLLS"] if x]))
    ctx["STRINGS"] = sorted(set([x for x in ctx["STRINGS"] if x]))

    return techs, ctx

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stuxnet-results", required=True)
    ap.add_argument("--mem", required=True)
    ap.add_argument("--vol", required=True)
    ap.add_argument("--out", default="vol_output")
    ap.add_argument("--prefix", default="T1055.")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    outdir = Path(args.out)
    techniques, ctx = load_stuxnet_results(args.stuxnet_results)

    selected = [t for t in techniques if isinstance(t, str) and t.startswith(args.prefix)]
    exe = VolExecutor(args.vol, args.mem, outdir, timeout=args.timeout)

    # Resolve PIDs once if not provided by NER
    if not ctx["TARGET_PIDS"] and ctx["TARGET_EXES"]:
        ctx["TARGET_PIDS"] = exe.resolve_pids(ctx["TARGET_EXES"])

    executed: List[str] = []
    skipped: List[Tuple[str, str]] = []

    for tech in selected:
        func = TECHNIQUE_FUNCS.get(tech)
        if not func:
            skipped.append((tech, "No function implemented"))
            continue
        if not ctx["TARGET_PIDS"]:
            skipped.append((tech, "Could not resolve PIDs for TARGET_EXES / TARGET_PIDS."))
            continue
        func(ctx, exe)
        executed.append(tech)

    summary = {
        "mapping_results_techniques": techniques,
        "selected_prefix": args.prefix,
        "selected_techniques": selected,
        "executed": executed,
        "skipped": skipped,
        "ner_context": ctx,
        "output_dir": str(outdir),
    }

    (outdir / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"\nSummary written to: {outdir / 'run_summary.json'}")

if __name__ == "__main__":
    main()
