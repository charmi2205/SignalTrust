"""
SignalTrust Trust Engine v3
Two-tier scoring: Local (PageRank graph) + Global (reputation fallback)
Phones stored as SHA-256 hashes — plaintext never touches the DB.
"""

import math
import time
import networkx as nx
from database import get_conn, hash_phone

SEVERITY_MAP = {
    "otp_scam":        1.0,
    "financial_fraud": 1.0,
    "impersonation":   0.9,
    "robocall":        0.6,
    "telemarketing":   0.4,
    "unknown":         0.5,
}
HALF_LIFE_DAYS = 30


# ── Graph ────────────────────────────────────────────────────────

def build_graph() -> nx.Graph:
    G = nx.Graph()
    conn = get_conn()
    for u in conn.execute("SELECT id, name, cluster FROM users").fetchall():
        G.add_node(u["id"], name=u["name"], cluster=u["cluster"])
    for e in conn.execute("SELECT user_a, user_b FROM contacts").fetchall():
        G.add_edge(e["user_a"], e["user_b"])
    conn.close()
    return G


def pagerank_scores(G: nx.Graph) -> dict:
    if len(G.nodes) == 0:
        return {}
    return nx.pagerank(G, alpha=0.85)


def path_exists(G, source, target):
    if source == target:
        return True
    if source not in G or target not in G:
        return False
    return nx.has_path(G, source, target)


def get_path(G, source, target):
    try:
        return nx.shortest_path(G, source, target)
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []


# ── Reputation ───────────────────────────────────────────────────

def global_reputation_score(reporter_id: str) -> float:
    conn = get_conn()
    row = conn.execute(
        "SELECT COUNT(*) as total, SUM(confirmed) as correct "
        "FROM reports WHERE reporter_id=?",
        (reporter_id,)
    ).fetchone()
    conn.close()
    total   = row["total"]   or 0
    correct = row["correct"] or 0
    if total == 0:
        return 0.3
    return (correct + 1) / (total + 2)   # Laplace smoothing


# ── Decay ────────────────────────────────────────────────────────

def recency_weight(timestamp: float) -> float:
    age_days = (time.time() - timestamp) / 86400
    return math.exp(-0.693 * age_days / HALF_LIFE_DAYS)


# ── Cluster diversity ────────────────────────────────────────────

def cluster_diversity_multiplier(reporter_ids: list, G: nx.Graph) -> float:
    clusters = set()
    for rid in reporter_ids:
        if rid in G.nodes:
            clusters.add(G.nodes[rid].get("cluster", rid))
    n = len(clusters)
    if n >= 3: return 1.5
    if n == 2: return 1.2
    return 1.0


# ── Main scorer ──────────────────────────────────────────────────

def calculate_risk_score(phone: str, current_user: str) -> dict:
    """
    Accepts plaintext phone — hashes it internally for the DB query.
    Returns full verdict with per-reporter breakdown.
    """
    phone_hash = hash_phone(phone)
    conn = get_conn()
    raw_reports = conn.execute(
        "SELECT r.*, u.name as reporter_name "
        "FROM reports r JOIN users u ON r.reporter_id=u.id "
        "WHERE r.phone=?",
        (phone_hash,)
    ).fetchall()
    conn.close()

    if not raw_reports:
        return {
            "risk_level":        "SAFE",
            "score":             0.0,
            "reporters":         [],
            "cluster_diversity": 1.0,
            "explanation":       "No reports found for this number.",
            "phone_mask":        "XXXXX",
        }

    G        = build_graph()
    pr       = pagerank_scores(G)
    details  = []
    total    = 0.0

    for rep in raw_reports:
        rid      = rep["reporter_id"]
        category = rep["category"]
        ts       = rep["timestamp"]
        note     = rep["note"] or ""

        if path_exists(G, rid, current_user):
            trust       = pr.get(rid, 0.1)
            trust_type  = "local (graph)"
            hop_path    = get_path(G, current_user, rid)
            trust_norm  = min(1.0, trust / 0.11)
        else:
            trust       = global_reputation_score(rid)
            trust_type  = "global (reputation)"
            hop_path    = []
            trust_norm  = trust * 0.55

        rec  = recency_weight(ts)
        sev  = SEVERITY_MAP.get(category, 0.5)
        contrib = trust_norm * rec * sev

        details.append({
            "id":          rid,
            "name":        rep["reporter_name"],
            "trust_type":  trust_type,
            "trust":       round(trust, 4),
            "trust_norm":  round(trust_norm, 4),
            "recency":     round(rec, 4),
            "severity":    sev,
            "category":    category,
            "note":        note,
            "contribution": round(contrib, 4),
            "path":        " -> ".join(
                G.nodes[n]["name"] if n in G.nodes else n for n in hop_path
            ) if hop_path else None,
        })
        total += contrib

    reporter_ids = [r["reporter_id"] for r in raw_reports]
    diversity    = cluster_diversity_multiplier(reporter_ids, G)
    total       *= diversity
    normalized   = min(100.0, total * 100)

    if normalized >= 70:   risk_level = "HIGH RISK"
    elif normalized >= 30: risk_level = "CAUTION"
    else:                  risk_level = "SAFE"

    top = sorted(details, key=lambda x: x["contribution"], reverse=True)
    if top:
        t = top[0]
        if t["path"]:
            expl = (f"Flagged by {len(raw_reports)} reporter(s). "
                    f"Strongest signal from {t['name']} via {t['path']} "
                    f"for {t['category'].replace('_',' ')}.")
        else:
            expl = (f"Flagged by {len(raw_reports)} reporter(s). "
                    f"Strongest signal from {t['name']} (global reputation) "
                    f"for {t['category'].replace('_',' ')}.")
    else:
        expl = "No active signals."

    phone_mask = raw_reports[0]["phone_mask"] if raw_reports else "XXXXX"

    return {
        "risk_level":        risk_level,
        "score":             round(normalized, 2),
        "reporters":         details,
        "cluster_diversity": diversity,
        "explanation":       expl,
        "phone_mask":        phone_mask,
    }


# ── Graph export ─────────────────────────────────────────────────

def get_graph_data(current_user: str) -> dict:
    G  = build_graph()
    pr = pagerank_scores(G)
    nodes = [
        {
            "id":              nid,
            "name":            d.get("name", nid),
            "cluster":         d.get("cluster", "unknown"),
            "pagerank":        round(pr.get(nid, 0), 4),
            "is_current_user": nid == current_user,
        }
        for nid, d in G.nodes(data=True)
    ]
    edges = [{"source": u, "target": v} for u, v in G.edges()]
    return {"nodes": nodes, "edges": edges}


# ── Dashboard stats ──────────────────────────────────────────────

def get_dashboard_stats() -> dict:
    conn = get_conn()
    total_reports  = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    total_users    = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_gates    = conn.execute("SELECT COUNT(*) FROM call_gates").fetchone()[0]
    blocked        = conn.execute(
        "SELECT COUNT(*) FROM call_gates WHERE status='declined'"
    ).fetchone()[0]
    allowed        = conn.execute(
        "SELECT COUNT(*) FROM call_gates WHERE status='accepted'"
    ).fetchone()[0]

    # spam velocity: reports in last 24 h
    since = time.time() - 86400
    recent = conn.execute(
        "SELECT COUNT(*) FROM reports WHERE timestamp > ?", (since,)
    ).fetchone()[0]

    # category breakdown
    cats = conn.execute(
        "SELECT category, COUNT(*) as cnt FROM reports GROUP BY category ORDER BY cnt DESC"
    ).fetchall()

    # avg trust score across all gated calls
    avg_score_row = conn.execute(
        "SELECT AVG(score) FROM call_gates"
    ).fetchone()[0]
    avg_score = round(avg_score_row or 0, 1)

    conn.close()
    return {
        "total_reports":  total_reports,
        "total_users":    total_users,
        "total_gates":    total_gates,
        "calls_blocked":  blocked,
        "calls_allowed":  allowed,
        "reports_24h":    recent,
        "avg_gate_score": avg_score,
        "top_categories": [{"category": r["category"], "count": r["cnt"]} for r in cats],
    }
