"""
SignalTrust v3 — seed script
Phones stored as SHA-256 hashes. Notes added to every report.
"""

import time, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from database import init_db, get_conn, hash_phone, mask_phone

def seed():
    init_db()
    conn = get_conn()
    conn.execute("DELETE FROM confirm_log")
    conn.execute("DELETE FROM call_gates")
    conn.execute("DELETE FROM reports")
    conn.execute("DELETE FROM contacts")
    conn.execute("DELETE FROM users")

    # ── Users ──────────────────────────────────────────────────────
    users = [
        ("you",          "You",               "college_friends"),
        ("aisha",        "Aisha",             "college_friends"),
        ("chen",         "Chen",              "college_friends"),
        ("elin",         "Elin",              "college_friends"),
        ("farah",        "Farah",             "college_friends"),
        ("nisha",        "Nisha",             "college_friends"),
        ("omkar",        "Omkar",             "college_friends"),
        ("meeza",        "Meeza",             "college_friends"),
        ("dev",          "Dev",               "college_friends"),
        ("ben",          "Ben",               "college_friends"),
        ("priya",        "Priya",             "colleagues"),
        ("laela",        "Laela",             "colleagues"),
        ("omar",         "Omar",              "colleagues"),
        ("tara",         "Tara",              "family"),
        ("sana",         "Sana",              "family"),
        ("rohan",        "Rohan",             "family"),
        ("shady_sam",    "Shady Sam",         "unknown"),
        ("trusted_ext",  "Trusted External",  "unknown"),
    ]
    conn.executemany("INSERT INTO users VALUES (?,?,?)", users)

    # ── Edges ──────────────────────────────────────────────────────
    edges = [
        ("you","aisha"), ("aisha","chen"), ("chen","elin"), ("elin","farah"),
        ("you","tara"),  ("tara","sana"),  ("sana","rohan"),
        ("you","priya"), ("priya","laela"),("laela","omar"),
        ("you","ben"),   ("ben","dev"),    ("dev","farah"),
        ("aisha","nisha"),("nisha","omkar"),("nisha","meeza"),
    ]
    both = [(a,b) for a,b in edges] + [(b,a) for a,b in edges]
    conn.executemany("INSERT OR IGNORE INTO contacts VALUES (?,?)", both)

    # ── Reports ────────────────────────────────────────────────────
    now = time.time()
    day = 86400

    def r(reporter, phone, cat, note, age_days=2, confirmed=1):
        return (reporter, hash_phone(phone), mask_phone(phone),
                cat, note, now - age_days*day, confirmed)

    # trusted_ext history — 10 accurate reports
    ext_history = [
        r("trusted_ext", f"+91-99999-0{i:04d}", "otp_scam",
          "Reported by external monitor — confirmed fraud", 60, 1)
        for i in range(10)
    ]
    # shady_sam history — 1 of 8 correct
    shady_history = [
        r("shady_sam", f"+91-88888-0{i:04d}", "robocall",
          "Reported as suspicious", 20, 1 if i == 0 else 0)
        for i in range(8)
    ]

    scenario_reports = [
        # SC1 — friend of a friend
        r("farah",      "+91-90000-00001", "otp_scam",
          "Called claiming to be from my bank, asked for OTP — I hung up immediately."),

        # SC2 — trusted stranger
        r("trusted_ext","+91-90000-00002", "financial_fraud",
          "Number appears in known fraud database. Multiple victims reported wire transfer requests.",
          5, 1),

        # SC3 — unreliable stranger
        r("shady_sam",  "+91-90000-00003", "otp_scam",
          "Seemed suspicious but could be wrong.", 1, 0),

        # SC4 — same cluster (3 college friends)
        r("aisha",  "+91-90000-00004","telemarketing","Kept calling during class hours. Very persistent.",3,1),
        r("chen",   "+91-90000-00004","telemarketing","Same number, same script about a fake prize.",4,1),
        r("elin",   "+91-90000-00004","telemarketing","Robocall about car warranty.",6,0),

        # SC5 — 3 independent clusters (HIGH RISK)
        r("farah",  "+91-90000-00005","financial_fraud","Claimed to be a tax officer, asked me to transfer money urgently.",1,1),
        r("priya",  "+91-90000-00005","financial_fraud","Said my account would be frozen unless I paid a fine over the phone.",2,1),
        r("tara",   "+91-90000-00005","financial_fraud","My elderly mother almost got scammed by this number. Impersonating police.",3,1),
    ]

    all_reports = scenario_reports + ext_history + shady_history
    conn.executemany(
        "INSERT INTO reports "
        "(reporter_id,phone,phone_mask,category,note,timestamp,confirmed) "
        "VALUES (?,?,?,?,?,?,?)",
        all_reports,
    )

    conn.commit()
    conn.close()
    print(f"✓ Seeded: {len(users)} users | {len(both)} edges | {len(all_reports)} reports")

if __name__ == "__main__":
    seed()
