"""
SignalTrust — FastAPI backend v3
New in this version:
  - Phone numbers hashed (SHA-256) before storage
  - Report notes (free-text human detail)
  - Rate-limited /confirm (one user = one confirmation per report)
  - GET  /dashboard        → network health stats
  - POST /sybil-demo       → live Sybil attack simulation data
  - GET  /explain/{phone}/{user_id} → LLM-style natural-language verdict
"""

import asyncio, json, time, uuid
from typing import Optional, Dict, List

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import os

from database import init_db, get_conn, hash_phone, mask_phone
from trust_engine import (
    calculate_risk_score, get_graph_data,
    get_dashboard_stats, cluster_diversity_multiplier,
    build_graph, pagerank_scores, global_reputation_score,
    recency_weight, SEVERITY_MAP,
)

init_db()

app = FastAPI(title="SignalTrust", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

# SSE subscriber registry
_subscribers: Dict[str, List[asyncio.Queue]] = {}

async def _publish(user_id: str, event: dict):
    for q in _subscribers.get(user_id, []):
        await q.put(event)


# ── Models ────────────────────────────────────────────────────────

class ReportIn(BaseModel):
    reporter_id: str
    phone:       str
    category:    str
    note:        Optional[str] = ""
    timestamp:   Optional[float] = None

class GateIn(BaseModel):
    caller_phone: str
    caller_name:  Optional[str] = None
    callee_id:    str

class RespondIn(BaseModel):
    decision: str   # "accept" | "decline"
    user_id:  str

class SybilDemoIn(BaseModel):
    """
    Drive the Sybil demo from the frontend.
    phase: 1 = add 5 same-cluster fakes, 2 = add 2 cross-cluster real reporters
    """
    phase:      int    # 1 or 2
    callee_id:  str = "you"


# ── Standard endpoints ────────────────────────────────────────────

@app.get("/")
def health():
    return {"status": "ok", "service": "SignalTrust v3"}

@app.get("/users")
def list_users():
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, name, cluster FROM users ORDER BY cluster, name"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/graph/{user_id}")
def graph(user_id: str):
    _require_user(user_id)
    return get_graph_data(user_id)

@app.get("/score/{phone}/{user_id}")
def score(phone: str, user_id: str):
    _require_user(user_id)
    return calculate_risk_score(phone, user_id)

@app.post("/report", status_code=201)
def submit_report(body: ReportIn):
    _require_user(body.reporter_id)
    conn = get_conn()
    ts         = body.timestamp or time.time()
    ph_hash    = hash_phone(body.phone)
    ph_mask    = mask_phone(body.phone)
    note       = (body.note or "")[:280]   # cap at 280 chars

    conn.execute(
        "INSERT INTO reports "
        "(reporter_id, phone, phone_mask, category, note, timestamp) "
        "VALUES (?,?,?,?,?,?)",
        (body.reporter_id, ph_hash, ph_mask, body.category, note, ts),
    )
    conn.commit()
    report_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return {"status": "created", "report_id": report_id}

@app.get("/reports/{phone}")
def list_reports(phone: str):
    ph_hash = hash_phone(phone)
    conn    = get_conn()
    rows    = conn.execute(
        "SELECT r.id, r.reporter_id, u.name as reporter_name, "
        "r.category, r.note, r.phone_mask, r.timestamp, r.confirmed "
        "FROM reports r JOIN users u ON r.reporter_id=u.id "
        "WHERE r.phone=? ORDER BY r.timestamp DESC",
        (ph_hash,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/confirm/{report_id}")
def confirm_report(report_id: int, user_id: str = Query(...)):
    """
    Rate-limited: a given user can only confirm a given report once.
    Prevents a single Sybil account from inflating reporter reputation.
    """
    conn = get_conn()
    row = conn.execute(
        "SELECT reporter_id FROM reports WHERE id=?", (report_id,)
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Report not found")

    # Block self-confirmation
    if row["reporter_id"] == user_id:
        conn.close()
        raise HTTPException(403, "Cannot confirm your own report")

    # Block duplicate confirmation
    dup = conn.execute(
        "SELECT 1 FROM confirm_log WHERE report_id=? AND user_id=?",
        (report_id, user_id)
    ).fetchone()
    if dup:
        conn.close()
        raise HTTPException(429, "Already confirmed this report")

    conn.execute("UPDATE reports SET confirmed=1 WHERE id=?", (report_id,))
    conn.execute(
        "INSERT INTO confirm_log (report_id, user_id, confirmed_at) VALUES (?,?,?)",
        (report_id, user_id, time.time())
    )
    conn.commit()
    conn.close()
    return {"status": "confirmed", "report_id": report_id}

@app.get("/scenarios")
def scenarios():
    return [
        {"id":1,"phone":"+91-90000-00001","label":"Friend-of-a-friend report",
         "description":"Reported by Farah via Aisha → Chen → Elin → Farah"},
        {"id":2,"phone":"+91-90000-00002","label":"Trusted stranger (fallback)",
         "description":"No graph path but strong accuracy track record"},
        {"id":3,"phone":"+91-90000-00003","label":"Unreliable stranger (fallback)",
         "description":"No path and poor accuracy history — low weight"},
        {"id":4,"phone":"+91-90000-00004","label":"3 reports, one friend group",
         "description":"Same cluster reporters — weaker signal"},
        {"id":5,"phone":"+91-90000-00005","label":"3 reports, 3 independent circles",
         "description":"College + work + family clusters — strong signal"},
    ]


# ── Dashboard ─────────────────────────────────────────────────────

@app.get("/dashboard")
def dashboard():
    return get_dashboard_stats()


# ── Sybil attack demo ─────────────────────────────────────────────

SYBIL_PHONE   = "+91-99999-SYBIL"
SYBIL_PHONE_2 = "+91-99999-REAL"

@app.post("/sybil-demo")
def sybil_demo(body: SybilDemoIn):
    """
    Phase 1: insert 5 fake same-cluster reporters + their reports.
             Score barely moves — cluster diversity = 1.0.
    Phase 2: add 2 real reporters from different clusters.
             Score jumps — diversity multiplier kicks in.
    Returns the score snapshot after each phase.
    """
    conn = get_conn()

    if body.phase == 1:
        # Create 5 fake accounts all in 'sybil_cluster'
        # Give them a poor reputation history (1 correct out of 8 reports each)
        # so global_reputation_score ≈ (1+1)/(8+2) = 0.2
        fakes = [
            ("sybil_1","Fake #1","sybil_cluster"),
            ("sybil_2","Fake #2","sybil_cluster"),
            ("sybil_3","Fake #3","sybil_cluster"),
            ("sybil_4","Fake #4","sybil_cluster"),
            ("sybil_5","Fake #5","sybil_cluster"),
        ]
        ts_now = time.time()
        day    = 86400
        for uid, name, cluster in fakes:
            conn.execute(
                "INSERT OR IGNORE INTO users (id,name,cluster) VALUES (?,?,?)",
                (uid, name, cluster)
            )
            # 8 unconfirmed previous reports — poor track record
            for k in range(8):
                dummy_hash = hash_phone(f"+91-00000-{uid}-{k}")
                dummy_mask = mask_phone(f"+91-00000-{uid}-{k}")
                conn.execute(
                    "INSERT INTO reports "
                    "(reporter_id,phone,phone_mask,category,note,timestamp,confirmed) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (uid, dummy_hash, dummy_mask, "otp_scam",
                     "prior report", ts_now - 40*day, 0)
                )

        # Now each fake reports the target number
        ph_hash = hash_phone(SYBIL_PHONE)
        ph_mask = mask_phone(SYBIL_PHONE)
        for uid, name, _ in fakes:
            conn.execute(
                "INSERT INTO reports "
                "(reporter_id,phone,phone_mask,category,note,timestamp) "
                "VALUES (?,?,?,?,?,?)",
                (uid, ph_hash, ph_mask, "otp_scam",
                 f"{name}: flagging this number", ts_now)
            )
        conn.commit()
        conn.close()

        verdict = calculate_risk_score(SYBIL_PHONE, body.callee_id)
        return {
            "phase":           1,
            "description":     "5 fake accounts from ONE cluster all reported the same number.",
            "reporters_added": [f[1] for f in fakes],
            "cluster_diversity": verdict["cluster_diversity"],
            "score":           verdict["score"],
            "risk_level":      verdict["risk_level"],
            "insight": (
                f"5 reports — but cluster diversity = 1.0× (all same isolated cluster) "
                f"and each fake account has a poor accuracy track record. "
                f"Score: {verdict['score']}/100 ({verdict['risk_level']}). "
                "A naive count-based system would scream HIGH RISK. "
                "SignalTrust discounts coordinated same-cluster noise correctly."
            ),
        }

    elif body.phase == 2:
        # Add 2 real reporters from different clusters
        reals = [
            ("real_worker","Maya (colleague)","colleagues"),
            ("real_family","Raj (family)",   "family"),
        ]
        ph_hash = hash_phone(SYBIL_PHONE)
        ph_mask = mask_phone(SYBIL_PHONE)
        ts_now  = time.time()
        for uid, name, cluster in reals:
            conn.execute(
                "INSERT OR IGNORE INTO users (id,name,cluster) VALUES (?,?,?)",
                (uid, name, cluster)
            )
            conn.execute(
                "INSERT INTO reports "
                "(reporter_id,phone,phone_mask,category,note,timestamp) "
                "VALUES (?,?,?,?,?,?)",
                (uid, ph_hash, ph_mask, "financial_fraud",
                 f"{name} flagged this as suspicious", ts_now)
            )
        conn.commit()
        conn.close()

        verdict = calculate_risk_score(SYBIL_PHONE, body.callee_id)
        return {
            "phase":           2,
            "description":     "2 real reporters from DIFFERENT clusters added.",
            "reporters_added": [r[1] for r in reals],
            "cluster_diversity": verdict["cluster_diversity"],
            "score":           verdict["score"],
            "risk_level":      verdict["risk_level"],
            "insight":         f"Cluster diversity jumped to {verdict['cluster_diversity']}×. Score rose sharply — independent agreement across social circles is the signal that matters.",
        }

    else:
        # Reset — delete reports first (FK child), then users (FK parent)
        ph_hash = hash_phone(SYBIL_PHONE)
        conn.execute("DELETE FROM reports WHERE phone=?", (ph_hash,))
        # also delete dummy history reports from fake accounts
        for uid in ["sybil_1","sybil_2","sybil_3","sybil_4","sybil_5",
                    "real_worker","real_family"]:
            conn.execute("DELETE FROM reports WHERE reporter_id=?", (uid,))
        conn.execute(
            "DELETE FROM users WHERE id LIKE 'sybil_%' OR id LIKE 'real_%'"
        )
        conn.commit()
        conn.close()
        return {"phase": 0, "description": "Sybil demo reset.", "score": 0}


# ── LLM-style explanation ─────────────────────────────────────────

@app.get("/explain/{phone}/{user_id}")
def explain(phone: str, user_id: str):
    """
    Generates a natural-language verdict.
    Uses a local template engine that reads the score breakdown and
    writes a 2-sentence human-readable explanation.
    Structured to be a drop-in for a real LLM call
    (just swap _generate_explanation for an OpenAI/Claude call).
    """
    _require_user(user_id)
    verdict = calculate_risk_score(phone, user_id)
    verdict["natural_language"] = _generate_explanation(verdict)
    return verdict


def _generate_explanation(v: dict) -> str:
    """
    Template-driven NL explanation.
    Reads score, risk_level, cluster_diversity, top reporter.
    Designed to be replaced with a real LLM call without changing any
    other endpoint — just swap this function body.
    """
    level    = v["risk_level"]
    score    = v["score"]
    reps     = v["reporters"]
    div      = v["cluster_diversity"]
    n        = len(reps)

    if n == 0:
        return ("This number has no reports in the SignalTrust network. "
                "Treat it with normal caution for an unknown caller.")

    top      = sorted(reps, key=lambda x: x["contribution"], reverse=True)[0]
    is_local = top["trust_type"].startswith("local")
    clusters_word = (
        "three completely separate social circles" if div >= 1.5 else
        "two different social circles"             if div >= 1.2 else
        "a single social circle"
    )
    trust_word = (
        "someone in your extended network"  if is_local else
        "an independent reporter with a strong accuracy track record"
    )

    opening = {
        "HIGH RISK": f"⚠️ This number carries a high risk score of {score}/100 — our trust network is strongly flagging it.",
        "CAUTION":   f"This number has a caution score of {score}/100 — some signals of concern, but not conclusive.",
        "SAFE":      f"This number looks safe with a score of {score}/100 — very little trust-weighted concern.",
    }[level]

    detail = (
        f"The strongest signal came from {trust_word}, flagging it for "
        f"{top['category'].replace('_', ' ')}. "
    )

    if n > 1:
        detail += (
            f"In total, {n} reporters across {clusters_word} flagged this number"
            + (f", amplified by a {div}× cluster diversity bonus" if div > 1.0 else "")
            + "."
        )
    else:
        detail += "Only one report exists — treat this with moderate caution."

    return opening + " " + detail


# ── Call gating ───────────────────────────────────────────────────

@app.post("/gate", status_code=201)
async def create_gate(body: GateIn):
    _require_user(body.callee_id)
    verdict = calculate_risk_score(body.caller_phone, body.callee_id)
    gate_id = str(uuid.uuid4())[:8]

    conn = get_conn()
    conn.execute(
        "INSERT INTO call_gates "
        "(gate_id,caller_phone,caller_name,callee_id,"
        " risk_level,score,explanation,status,created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (gate_id, body.caller_phone, body.caller_name or "",
         body.callee_id, verdict["risk_level"], verdict["score"],
         verdict["explanation"], "pending", time.time()),
    )
    conn.commit()
    conn.close()

    await _publish(body.callee_id, {
        "type":              "incoming_call",
        "gate_id":           gate_id,
        "caller_phone":      body.caller_phone,
        "caller_name":       body.caller_name or "Unknown",
        "risk_level":        verdict["risk_level"],
        "score":             verdict["score"],
        "explanation":       verdict["explanation"],
        "reporters":         verdict["reporters"],
        "cluster_diversity": verdict["cluster_diversity"],
    })
    return {"gate_id": gate_id, "verdict": verdict,
            "status": "pending", "message": "Callee notified."}

@app.post("/gate/{gate_id}/respond")
async def respond_gate(gate_id: str, body: RespondIn):
    if body.decision not in ("accept", "decline"):
        raise HTTPException(400, "decision must be 'accept' or 'decline'")
    conn = get_conn()
    row = conn.execute(
        "SELECT * FROM call_gates WHERE gate_id=?", (gate_id,)
    ).fetchone()
    if not row:
        conn.close(); raise HTTPException(404, f"Gate '{gate_id}' not found")
    if row["status"] != "pending":
        conn.close(); raise HTTPException(409, f"Gate already {row['status']}")
    if row["callee_id"] != body.user_id:
        conn.close(); raise HTTPException(403, "Not your call")

    new_status = "accepted" if body.decision == "accept" else "declined"
    conn.execute(
        "UPDATE call_gates SET status=?, decided_at=? WHERE gate_id=?",
        (new_status, time.time(), gate_id),
    )
    conn.commit()
    conn.close()

    await _publish(body.user_id, {
        "type":         "call_resolved",
        "gate_id":      gate_id,
        "decision":     body.decision,
        "caller_phone": row["caller_phone"],
        "caller_name":  row["caller_name"],
    })
    action = "Phone is now ringing." if body.decision == "accept" \
             else "Call silently disconnected."
    return {"status": new_status, "action": action, "gate_id": gate_id}

@app.get("/gate/{gate_id}")
def get_gate(gate_id: str):
    conn = get_conn()
    row  = conn.execute(
        "SELECT * FROM call_gates WHERE gate_id=?", (gate_id,)
    ).fetchone()
    conn.close()
    if not row: raise HTTPException(404, f"Gate '{gate_id}' not found")
    return dict(row)

@app.get("/gates/{user_id}")
def list_gates(user_id: str, limit: int = 20):
    _require_user(user_id)
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM call_gates WHERE callee_id=? "
        "ORDER BY created_at DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── SSE ───────────────────────────────────────────────────────────

@app.get("/stream/{user_id}")
async def stream(user_id: str):
    _require_user(user_id)
    q: asyncio.Queue = asyncio.Queue()
    _subscribers.setdefault(user_id, []).append(q)

    async def gen():
        yield _sse({"type": "connected", "user_id": user_id})
        try:
            while True:
                try:
                    evt = await asyncio.wait_for(q.get(), timeout=20)
                    yield _sse(evt)
                except asyncio.TimeoutError:
                    yield _sse({"type": "heartbeat"})
        except asyncio.CancelledError:
            pass
        finally:
            _subscribers[user_id].remove(q)
            if not _subscribers[user_id]:
                del _subscribers[user_id]

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache",
                                      "X-Accel-Buffering":"no"})

def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


# ── Helpers ───────────────────────────────────────────────────────

def _require_user(user_id: str):
    conn = get_conn()
    row  = conn.execute("SELECT id FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if not row: raise HTTPException(404, f"User '{user_id}' not found")


# ── Static frontend ───────────────────────────────────────────────

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/app")
    def serve_frontend():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
