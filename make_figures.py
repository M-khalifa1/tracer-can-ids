#!/usr/bin/env python3
"""
make_figures.py — regenerate the paper figures ENTIRELY from measured data
(results/metrics.json, results/sweeps.json, results/hmac_bench*.json).

Unlike the previous plot_ids.py, nothing here is hand-set or simulated:
  * no fixed detect_rates/fp_rates arrays,
  * no synthetic alert log,
  * the HMAC-vs-CAN-period reference line is 20 ms = 20000 us (the earlier
    figure drew it at 20 us, a 1000x error).
If an input file is missing the corresponding figure is skipped with a notice,
so the same script runs on the real lab data once it is collected.
"""
import os, json, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "results")
CH = os.path.join(OUT, "charts"); os.makedirs(CH, exist_ok=True)

plt.rcParams.update({
    "font.family":"serif", "font.size":9, "axes.titlesize":10,
    "axes.labelsize":9, "xtick.labelsize":8, "ytick.labelsize":8,
    "legend.fontsize":8, "figure.dpi":150, "axes.grid":True,
    "grid.alpha":0.25, "savefig.bbox":"tight", "savefig.dpi":300,
})
# colourblind-safe (Okabe-Ito)
OK = dict(blue="#0072B2", orange="#E69F00", green="#009E73",
          red="#D55E00", grey="#999999", purple="#CC79A7", black="#000000")

def load(name):
    p=os.path.join(OUT,name)
    return json.load(open(p)) if os.path.exists(p) else None

def save(fig, name):
    for ext in ("png","pdf"):
        fig.savefig(os.path.join(CH,f"{name}.{ext}"))
    plt.close(fig); print(f"  wrote charts/{name}.png/.pdf")

# ── Fig A: per-attack detection with 95% Wilson CI ───────────────────
def fig_detection(m):
    if not m: print("  [skip] metrics.json (detection)"); return
    ks=list(m["attacks"].keys())
    labels=[f"{k}" for k in ks]
    det=[m["attacks"][k]["detection_rate"] for k in ks]
    lo=[m["attacks"][k]["ci95"][0] for k in ks]
    hi=[m["attacks"][k]["ci95"][1] for k in ks]
    err=[[d-l for d,l in zip(det,lo)],[h-d for d,h in zip(det,hi)]]
    fig,ax=plt.subplots(figsize=(7.0,3.0))
    x=np.arange(len(ks))
    ax.bar(x,det,color=OK["green"],edgecolor="white",width=0.62,zorder=2)
    ax.errorbar(x,det,yerr=err,fmt="none",ecolor=OK["black"],capsize=3,lw=1,zorder=3)
    for xi,d in zip(x,det):
        ax.text(xi,min(d+2,101),f"{d:.0f}",ha="center",fontsize=7)
    ax.set_xticks(x); ax.set_xticklabels(labels)
    ax.set_ylim(0,112); ax.set_ylabel("Detection rate (%)")
    b=m.get("benign",{})
    ax.set_title(f"Per-attack detection (n={m['attacks'][ks[0]]['events']} each, "
                 f"95% Wilson CI) — benign FPR={b.get('fpr_percent','?')}%")
    save(fig,"fig_detection_ci")

# ── Fig B: threshold sensitivity (2x2) ───────────────────────────────
def fig_sensitivity(s):
    if not s: print("  [skip] sweeps.json (sensitivity)"); return
    order=["flood_hz","vel_jump","burst_idle_ms","auth_win_us"]
    titles={"flood_hz":"R1 FLOOD rate threshold (Hz)",
            "vel_jump":"R3 VEL_JUMP threshold (mm/s)",
            "burst_idle_ms":"R8 BURST idle threshold (ms)",
            "auth_win_us":"R6 auth window (us)"}
    defaults={"flood_hz":200,"vel_jump":600,"burst_idle_ms":300,"auth_win_us":8000}
    fig,axs=plt.subplots(2,2,figsize=(7.2,5.0))
    for ax,key in zip(axs.flat,order):
        if key not in s: ax.set_visible(False); continue
        rows=s[key]["rows"]; v=[r[0] for r in rows]; d=[r[1] for r in rows]; fp=[r[2] for r in rows]
        ax.plot(v,d,"o-",color=OK["green"],label="Detection %",zorder=3)
        ax2=ax.twinx()
        ax2.plot(v,fp,"s--",color=OK["red"],label="Benign FPR %",zorder=3)
        ax.axvline(defaults[key],color=OK["grey"],lw=1,ls=":",zorder=1)
        ax.set_title(titles[key]); ax.set_ylabel("Detection %",color=OK["green"])
        ax2.set_ylabel("FPR %",color=OK["red"])
        ax.set_ylim(-5,108)
        ax.tick_params(axis="y",colors=OK["green"]); ax2.tick_params(axis="y",colors=OK["red"])
    fig.suptitle("IDS threshold sensitivity (dotted line = chosen operating point)",fontsize=10)
    fig.tight_layout(rect=[0,0,1,0.96])
    save(fig,"fig_sensitivity")

# ── Fig C: HMAC cost vs CAN control period (CORRECT 20 ms line) ──────
def fig_hmac():
    cand=[f for f in os.listdir(OUT) if f.startswith("hmac_bench") and f.endswith(".json")]
    if not cand: print("  [skip] hmac_bench*.json"); return
    b=json.load(open(os.path.join(OUT,sorted(cand)[-1])))
    s=b["sign_us"]
    fig,ax=plt.subplots(figsize=(5.2,3.2))
    xs=["min","median","mean","p99","max"]
    vals=[s[k] for k in xs]
    ax.bar(xs,vals,color=OK["blue"],edgecolor="white",width=0.6,zorder=2)
    for i,val in enumerate(vals):
        ax.text(i,val,f"{val:.2f}",ha="center",va="bottom",fontsize=7)
    ax.axhline(20000,color=OK["red"],ls="--",lw=1.2,
               label="CAN control period = 20 ms (20000 us)")
    ax.set_yscale("log"); ax.set_ylabel("Time per authenticator (us, log)")
    ax.set_title(f"HMAC-SHA-256 companion cost vs CAN period\n"
                 f"({b.get('platform','platform')}, N={b['iterations']})")
    ax.legend(loc="upper left")
    save(fig,"fig_hmac_overhead")

if __name__=="__main__":
    print("Generating figures from measured data:")
    fig_detection(load("metrics.json"))
    fig_sensitivity(load("sweeps.json"))
    fig_hmac()
    print("Done ->", CH)
