#!/usr/bin/env python3
# generate_full_report.py
# Advanced visualization + forensic report generator
# Expects: http_requests.tsv, auth_headers.tsv, dns_queries.tsv, timeline.tsv
# Produces: forensics_output/forensics_report.md and plots in forensics_output/plots/

import os
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import base64
import numpy as np

# --- Config / filenames ---
HTTP_F = "http_requests.tsv"
AUTH_F = "auth_headers.tsv"
DNS_F = "dns_queries.tsv"
TL_F = "timeline.tsv"
PCAP_F = "case_study_large.pcap"  # optional

OUT_DIR = "forensics_output"
PLOTS_DIR = os.path.join(OUT_DIR, "plots")
REPORT_MD = os.path.join(OUT_DIR, "forensics_report.md")

os.makedirs(PLOTS_DIR, exist_ok=True)

# --- Helpers ---
def epoch_to_dt(epoch):
    try:
        return datetime.fromtimestamp(float(epoch))
    except:
        return None

def load_tsv_safe(path, cols):
    if os.path.exists(path) and os.path.getsize(path) > 0:
        try:
            df = pd.read_csv(path, sep='\t', header=None, names=cols, dtype=str, na_filter=False)
            return df
        except Exception as e:
            print(f"Warning: failed to load {path}: {e}")
    return pd.DataFrame(columns=cols)

# --- Load data ---
http = load_tsv_safe(HTTP_F, ["time","src","dst","host","uri"])
auth = load_tsv_safe(AUTH_F, ["time","src","dst","host","authorization"])
dns = load_tsv_safe(DNS_F, ["time","src","query"])
tl = load_tsv_safe(TL_F, ["time","src","dst","length"])

# convert types
for df in (http, auth, dns, tl):
    if "time" in df.columns:
        df["time_dt"] = df["time"].apply(epoch_to_dt)

if "length" in tl.columns:
    tl["length"] = pd.to_numeric(tl["length"], errors='coerce').fillna(0).astype(int)

# --- Basic stats ---
num_http = len(http)
num_dns = len(dns)
num_auth = len(auth)
num_packets = len(tl)

# Protocol distribution (estimate): use counts from TSVs and remaining as "other"
proto_counts = {
    "HTTP": num_http,
    "DNS": num_dns,
    "AuthHeaders": num_auth
}
# Estimate others as remainder (timeline contains total packets)
remaining = max(0, num_packets - (num_http + num_dns))
proto_counts["Other"] = remaining

# --- Plot 1: Timeline (packet length over time) ---
timeline_png = os.path.join(PLOTS_DIR, "timeline.png")
if not tl.empty:
    fig, ax = plt.subplots(figsize=(12,4))
    ax.plot(tl["time_dt"], tl["length"], marker='.', linestyle='None')
    ax.set_title("Packet timeline (packet length vs time)")
    ax.set_xlabel("Time")
    ax.set_ylabel("Frame length (bytes)")
    plt.tight_layout()
    plt.savefig(timeline_png)
    plt.close()
else:
    timeline_png = None

# --- Plot 2: Packet size distribution histogram ---
packet_size_png = os.path.join(PLOTS_DIR, "packet_size_hist.png")
if not tl.empty:
    fig, ax = plt.subplots(figsize=(8,4))
    ax.hist(tl["length"], bins=50)
    ax.set_title("Packet size distribution")
    ax.set_xlabel("Frame length (bytes)")
    ax.set_ylabel("Count")
    plt.tight_layout()
    plt.savefig(packet_size_png)
    plt.close()
else:
    packet_size_png = None

# --- Plot 3: Protocol distribution pie (estimated) ---
protocol_png = os.path.join(PLOTS_DIR, "protocol_dist.png")
labels = list(proto_counts.keys())
values = [proto_counts[k] for k in labels]
fig, ax = plt.subplots(figsize=(6,6))
ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90)
ax.set_title("Estimated protocol distribution (from exported TSVs)")
plt.tight_layout()
plt.savefig(protocol_png)
plt.close()

# --- Plot 4: Top DNS queries (frequency) ---
dns_png = os.path.join(PLOTS_DIR, "dns_freq.png")
if not dns.empty:
    dns_sample = dns["query"].value_counts().head(25)
    fig, ax = plt.subplots(figsize=(10,5))
    dns_sample.plot(kind="bar", ax=ax)
    ax.set_title("Top DNS queries")
    ax.set_xlabel("Domain")
    ax.set_ylabel("Count")
    plt.tight_layout()
    plt.savefig(dns_png)
    plt.close()
else:
    dns_png = None

# --- Plot 5: Top HTTP hosts ---
http_hosts_png = os.path.join(PLOTS_DIR, "http_hosts.png")
if not http.empty:
    hosts = http["host"].fillna("unknown").value_counts().head(25)
    fig, ax = plt.subplots(figsize=(10,5))
    hosts.plot(kind="bar", ax=ax)
    ax.set_title("Top HTTP hosts contacted")
    ax.set_xlabel("Host")
    ax.set_ylabel("Requests")
    plt.tight_layout()
    plt.savefig(http_hosts_png)
    plt.close()
else:
    http_hosts_png = None

# --- Analyze and decode Authorization headers (Basic) ---
auth_decoded = []
if not auth.empty:
    for idx, row in auth.iterrows():
        raw = str(row.get("authorization",""))
        if raw and raw.lower().startswith("basic "):
            b64 = raw.split(None,1)[1].strip()
            try:
                decoded = base64.b64decode(b64).decode(errors='replace')
            except:
                decoded = "<decode-failed>"
            auth_decoded.append({
                "time": row.get("time_dt"),
                "src": row.get("src"),
                "dst": row.get("dst"),
                "host": row.get("host"),
                "raw": raw,
                "decoded": decoded
            })

# --- Plot 6: Auth decoded summary (if many) ---
auth_png = os.path.join(PLOTS_DIR, "auth_decoded.png")
if auth_decoded:
    # Create dataframe and save a small bar of top usernames if many
    auth_df = pd.DataFrame(auth_decoded)
    # extract username portion before :
    auth_df["user"] = auth_df["decoded"].apply(lambda x: str(x).split(":",1)[0] if ":" in str(x) else str(x))
    top_users = auth_df["user"].value_counts().head(15)
    fig, ax = plt.subplots(figsize=(8,4))
    top_users.plot(kind="bar", ax=ax)
    ax.set_title("Top decoded Basic Auth usernames (from captured Authorization headers)")
    ax.set_xlabel("Username")
    ax.set_ylabel("Occurrences")
    plt.tight_layout()
    plt.savefig(auth_png)
    plt.close()
else:
    auth_png = None

# --- Plot 7: Top talkers by bytes (from timeline) ---
top_talkers_png = os.path.join(PLOTS_DIR, "top_talkers.png")
if not tl.empty:
    top_src = tl.groupby("src")["length"].sum().sort_values(ascending=False).head(20)
    fig, ax = plt.subplots(figsize=(10,5))
    top_src.plot(kind="bar", ax=ax)
    ax.set_title("Top source IPs by total bytes (from timeline)")
    ax.set_xlabel("Source IP")
    ax.set_ylabel("Total bytes")
    plt.tight_layout()
    plt.savefig(top_talkers_png)
    plt.close()
else:
    top_talkers_png = None

# --- Plot 8: Source->Destination matrix (heatmap-like) ---
flows_png = os.path.join(PLOTS_DIR, "flows_matrix.png")
if not tl.empty:
    # keep only top N src and top N dst
    top_srcs = tl["src"].value_counts().head(10).index.tolist()
    top_dsts = tl["dst"].value_counts().head(10).index.tolist()
    small = tl[tl["src"].isin(top_srcs) & tl["dst"].isin(top_dsts)]
    if not small.empty:
        mat = pd.pivot_table(small, index="src", columns="dst", values="length", aggfunc="sum", fill_value=0)
        fig, ax = plt.subplots(figsize=(10,6))
        im = ax.imshow(mat.values)
        ax.set_xticks(range(len(mat.columns)))
        ax.set_xticklabels(mat.columns, rotation=45, ha="right")
        ax.set_yticks(range(len(mat.index)))
        ax.set_yticklabels(mat.index)
        ax.set_title("Top source -> dest bytes matrix (subset)")
        plt.colorbar(im, ax=ax, label="Total bytes")
        plt.tight_layout()
        plt.savefig(flows_png)
        plt.close()
    else:
        flows_png = None
else:
    flows_png = None

# --- C2 detection (DNS) ---
c2_domains = ["c2bad.net","evilserver.org","darkc2.io","stealthc2.io"]
c2_dns_png = os.path.join(PLOTS_DIR, "c2_dns.png")
if not dns.empty:
    dns_lower = dns["query"].str.lower()
    c2_hits = dns[dns_lower.str.contains("|".join([d.lower() for d in c2_domains]))]
    if not c2_hits.empty:
        c2_counts = c2_hits["query"].value_counts().head(25)
        fig, ax = plt.subplots(figsize=(10,5))
        c2_counts.plot(kind="bar", ax=ax)
        ax.set_title("C2-like DNS query hits (suspicious domains)")
        ax.set_xlabel("Domain")
        ax.set_ylabel("Count")
        plt.tight_layout()
        plt.savefig(c2_dns_png)
        plt.close()
    else:
        c2_dns_png = None
else:
    c2_dns_png = None

# --- C2 detection (HTTP callbacks) ---
c2_http_png = os.path.join(PLOTS_DIR, "c2_http.png")
if not http.empty:
    http_lower_host = http["host"].fillna("").str.lower()
    c2_http_hits = http[http_lower_host.str.contains("c2.example|c2bad|evilserver|darkc2", na=False)]
    if not c2_http_hits.empty:
        cb_counts = c2_http_hits["host"].value_counts().head(25)
        fig, ax = plt.subplots(figsize=(10,5))
        cb_counts.plot(kind="bar", ax=ax)
        ax.set_title("C2-like HTTP callback hosts")
        ax.set_xlabel("Host")
        ax.set_ylabel("Count")
        plt.tight_layout()
        plt.savefig(c2_http_png)
        plt.close()
    else:
        c2_http_png = None
else:
    c2_http_png = None

# --- Build the Markdown report ---
def fmt_dt(dt):
    if pd.isnull(dt):
        return ""
    if isinstance(dt, (float,int)):
        return datetime.fromtimestamp(dt).isoformat()
    try:
        return dt.isoformat()
    except:
        return str(dt)

with open(REPORT_MD, "w", encoding="utf-8") as f:
    f.write("# Digital Forensics Report — Combined Case Study (TShark Analysis)\n\n")
    f.write("## Executive Summary\n")
    f.write("An automated analysis was performed on captured network traffic exported from the supplied PCAP using TShark. The goals were to identify credential leakage, suspicious DNS activity (possible C2/beaconing), and to profile network traffic for anomalies.\n\n")

    f.write("## Evidence & Files Analyzed\n")
    f.write(f"- PCAP file: `{PCAP_F}` (if available)\n")
    f.write(f"- HTTP export: `{HTTP_F}` — {num_http} records\n")
    f.write(f"- Authorization headers export: `{AUTH_F}` — {num_auth} records\n")
    f.write(f"- DNS export: `{DNS_F}` — {num_dns} records\n")
    f.write(f"- Timeline export: `{TL_F}` — {num_packets} records\n\n")

    f.write("## Key Findings (high level)\n")
    f.write(f"- Total HTTP requests: **{num_http}**\n")
    f.write(f"- Total DNS queries: **{num_dns}**\n")
    f.write(f"- Total captured packets (timeline records): **{num_packets}**\n")
    if auth_decoded:
        f.write(f"- Found **{len(auth_decoded)}** HTTP Authorization headers. Several decode to plaintext credentials. See details below.\n")
    else:
        f.write("- No HTTP Authorization headers were found in the dataset.\n")
    if c2_dns_png or c2_http_png:
        f.write("- Evidence of C2-like activity was detected (DNS beaconing and/or HTTP callbacks). See C2 section.\n")
    else:
        f.write("- No obvious C2 hosts matched the known suspicious domain names in our detection list.\n")
    f.write("\n")

    f.write("## Visualizations\n")
    if timeline_png:
        f.write("### Packet timeline\n")
        f.write(f"![Timeline]({os.path.basename(timeline_png)})\n\n")
    if packet_size_png:
        f.write("### Packet size distribution\n")
        f.write(f"![Packet size histogram]({os.path.basename(packet_size_png)})\n\n")
    f.write("### Protocol distribution (estimated)\n")
    f.write(f"![Protocol distribution]({os.path.basename(protocol_png)})\n\n")
    if dns_png:
        f.write("### Top DNS queries\n")
        f.write(f"![DNS frequency]({os.path.basename(dns_png)})\n\n")
    if http_hosts_png:
        f.write("### Top HTTP hosts\n")
        f.write(f"![HTTP hosts]({os.path.basename(http_hosts_png)})\n\n")
    if auth_png:
        f.write("### Decoded Authorization summary\n")
        f.write(f"![Auth decoded]({os.path.basename(auth_png)})\n\n")
    if top_talkers_png:
        f.write("### Top talkers by bytes\n")
        f.write(f"![Top talkers]({os.path.basename(top_talkers_png)})\n\n")
    if flows_png:
        f.write("### Top source->destination flows (subset)\n")
        f.write(f"![Flows matrix]({os.path.basename(flows_png)})\n\n")
    if c2_dns_png:
        f.write("### Suspicious DNS (C2-like) hits\n")
        f.write(f"![C2 DNS]({os.path.basename(c2_dns_png)})\n\n")
    if c2_http_png:
        f.write("### Suspicious HTTP callback hosts\n")
        f.write(f"![C2 HTTP]({os.path.basename(c2_http_png)})\n\n")

    f.write("## Detailed Findings\n")
    # Credential details
    if auth_decoded:
        f.write("### Credentials extracted from HTTP Authorization headers\n\n")
        f.write("| Time | Source IP | Destination IP | Host | Decoded credentials |\n")
        f.write("| --- | --- | --- | --- | --- |\n")
        for row in auth_decoded[:200]:  # limit to 200 entries for report size
            f.write(f"| {fmt_dt(row['time'])} | {row['src']} | {row['dst']} | {row['host']} | `{row['decoded']}` |\n")
        if len(auth_decoded) > 200:
            f.write(f"\n- (Only first 200 of {len(auth_decoded)} shown.)\n")
    else:
        f.write("No credentials were decoded from Authorization headers.\n")

    # C2 DNS
    if c2_dns_png and not c2_hits.empty:
        f.write("\n### Suspicious DNS queries (C2 indicators)\n\n")
        f.write(f"- Number of suspicious DNS queries matched: **{len(c2_hits)}**\n")
        sample = c2_hits["query"].value_counts().head(20)
        f.write("\nTop matched suspicious domains:\n\n")
        for dom, cnt in sample.items():
            f.write(f"- {dom} ({cnt})\n")
    else:
        f.write("\nNo suspicious C2-like DNS domains from our matcher were found.\n")

    # C2 HTTP
    if c2_http_png and not c2_http_hits.empty:
        f.write("\n### Suspicious HTTP callback hosts\n\n")
        f.write(f"- Number of HTTP requests to C2-like hosts: **{len(c2_http_hits)}**\n")
        for host, cnt in c2_http_hits["host"].value_counts().head(20).items():
            f.write(f"- {host}: {cnt}\n")
    else:
        f.write("\nNo suspicious HTTP callback hosts were detected by simple host matching.\n")

    f.write("\n## Conclusion & Recommendations\n")
    f.write("- Use end-to-end TLS for all authentication; avoid sending credentials in plaintext.\n")
    f.write("- Block or monitor DNS queries to suspicious domains (create IDS/suricata rules for matched patterns).\n")
    f.write("- Investigate the top source IPs identified in the Top Talkers chart; correlate with endpoint logs.\n")
    f.write("- If C2 activity is suspected, isolate affected hosts and perform host-based forensics (memory, disk imaging).\n\n")

    f.write("## Appendix: TShark extraction commands\n")
    f.write("```\n")
    f.write("tshark -r case_study_large.pcap -Y \"http.request\" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.uri > http_requests.tsv\n")
    f.write("tshark -r case_study_large.pcap -Y \"http.authorization\" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.authorization > auth_headers.tsv\n")
    f.write("tshark -r case_study_large.pcap -Y dns -T fields -e frame.time_epoch -e ip.src -e dns.qry.name > dns_queries.tsv\n")
    f.write("tshark -r case_study_large.pcap -T fields -e frame.time_epoch -e ip.src -e ip.dst -e frame.len > timeline.tsv\n")
    f.write("```\n")

print("Report generation completed. Output folder:", OUT_DIR)

