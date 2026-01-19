from datetime import datetime, timedelta
from functools import wraps
import random
import geocoder

from flask import (
    Flask, flash, jsonify, redirect, render_template,
    request, session, url_for
)
from flask_cors import CORS
from werkzeug.security import check_password_hash
from db import connect_db

app = Flask(__name__)
app.secret_key = "super-secret-change-me"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# ───────────────────────── helpers ─────────────────────────
def protect(key):
    """Decorator that redirects to /login unless session[key] is set."""
    def deco(fn):
        @wraps(fn)
        def inner(*a, **kw):
            if not session.get(key):
                return redirect(url_for("login_page"))
            return fn(*a, **kw)
        return inner
    return deco


def safe_match(stored: str, raw: str) -> bool:
    """Handle both plain text & werkzeug‑hashed passwords."""
    if stored and stored.startswith(("pbkdf2:", "sha", "bcrypt")):
        return check_password_hash(stored, raw)
    return stored == raw


def fmt_time(t):
    if not t:
        return None
    if isinstance(t, timedelta):
        h, m = divmod(int(t.total_seconds()) // 60, 60)
        return f"{h:02}:{m:02}"
    return t.strftime("%I:%M %p")


def get_emp_by_pin(pin):
    db = connect_db()
    cur = db.cursor()
    cur.execute("SELECT id, name, emp_code FROM employee WHERE pin=%s", (pin,))
    row = cur.fetchone()
    cur.close()
    db.close()
    return row


# ───────────────────── dashboards (HTML) ───────────────────
def dashboard_stats(cur):
    # 7‑day graph - ONLY count actual punch-ins (exclude absences)
    cur.execute("""
        SELECT date, COUNT(*) FROM attendance
        WHERE absent = false AND time_in IS NOT NULL
        GROUP BY date ORDER BY date DESC LIMIT 7
    """)
    rows = cur.fetchall()
    labels = [r[0].strftime("%b %d") for r in rows[::-1]]
    counts = [r[1] for r in rows[::-1]]

    # today's roster with separate locations
    cur.execute("""
        SELECT e.id, e.name, e.emp_code, e.pin,
               a.time_in, a.time_out,
               a.location_in, a.location_out,
               a.absent, a.reason
          FROM employee e
     LEFT JOIN attendance a
            ON a.emp_id = e.id AND a.date = CURRENT_DATE
      ORDER BY e.name
    """)
    today_rows = cur.fetchall()
    return labels, counts, today_rows


# ─────────────────────── health ping ───────────────────────
@app.get("/ping")
def ping():
    return "pong"


@app.get("/ping_json")
def ping_json():
    return jsonify(pong=True, time=datetime.utcnow().isoformat())


# ────────────────────── HTML login form ────────────────────
@app.route("/")
@app.route("/login")
def login_page():
    return render_template("login.html")


@app.post("/login")
def login_credentials():
    role = request.form.get("role")
    user = request.form.get("username")
    pwd = request.form.get("password")

    db = connect_db()
    cur = db.cursor()
    try:
        if role == "admin":
            cur.execute("SELECT id, password FROM admin WHERE username=%s", (user,))
            row = cur.fetchone()
            if row and safe_match(row[1], pwd):
                session.clear()
                session["admin"] = row[0]
                return redirect("/admin")
        else:
            cur.execute("SELECT id, password FROM employee WHERE emp_code=%s", (user,))
            row = cur.fetchone()
            if row and safe_match(row[1], pwd):
                session.clear()
                session["emp_id"] = row[0]
                return redirect("/employee")
    finally:
        cur.close()
        db.close()

    flash("Invalid credentials", "danger")
    return redirect("/login")


# ───────── PIN‑based JSON login (mobile & web) ─────────
@app.route("/login_pin", methods=["POST", "OPTIONS"])
def login_pin():
    if request.method == "OPTIONS":
        return "", 200, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
        }

    data = request.get_json(force=True, silent=True) or {}
    pin = str(data.get("pin", "")).strip()

    db = connect_db()
    cur = db.cursor()

    # ───────── EMPLOYEE LOGIN ─────────
    cur.execute("SELECT id, name, emp_code FROM employee WHERE pin=%s", (pin,))
    row = cur.fetchone()

    if row:
        cur.close()
        db.close()
        return jsonify(
            success=True,
            role="employee",
            user={
                "id": row[0],
                "name": row[1],
                "emp_code": row[2]
            }
        )

    # ───────── ADMIN LOGIN ─────────
    cur.execute("SELECT id, username FROM admin WHERE pin=%s", (pin,))
    row = cur.fetchone()
    cur.close()
    db.close()

    if row:
        return jsonify(
            success=True,
            role="admin",
            user={
                "id": row[0],
                "name": row[1]
            }
        )

    return jsonify(success=False), 401


# ───────────────────── Admin dashboard ────────────────────
@app.route("/admin")
@protect("admin")
def admin_dashboard():
    db = connect_db()
    cur = db.cursor()

    try:
        labels, counts, today_rows = dashboard_stats(cur)
        cur.execute("SELECT id, name, emp_code FROM employee ORDER BY name")
        employees = cur.fetchall()
    finally:
        cur.close()
        db.close()

    # --------- ABSENT HISTORY ---------
    db1 = connect_db()
    cur1 = db1.cursor()

    cur1.execute("""
        SELECT e.name, a.date, a.reason
        FROM attendance a
        JOIN employee e ON e.id = a.emp_id
        WHERE a.absent = true
        ORDER BY a.date DESC
    """)
    absent_history = cur1.fetchall()
    cur1.close()
    db1.close()

    # --------- LEAVE REQUESTS ---------
    db2 = connect_db()
    cur2 = db2.cursor()

    cur2.execute("""
        SELECT 
            l.emp_id,
            e.name,
            l.from_date,
            l.to_date,
            l.reason,
            l.id
        FROM leaves l
        JOIN employee e ON e.id = l.emp_id
        ORDER BY l.id DESC
        LIMIT 10
    """)
    leave_rows = cur2.fetchall()

    cur2.close()
    db2.close()

    return render_template(
        "admin_dashboard.html",
        labels=labels,
        counts=counts,
        attendance=today_rows,
        employees=employees,
        absent_history=absent_history,
        leave_requests=leave_rows
    )


@app.get("/search")
@protect("admin")
def search_employee():
    q = request.args.get("query", "")
    like = f"%{q}%"
    db = connect_db()
    cur = db.cursor()
    try:
        labels, counts, today_rows = dashboard_stats(cur)
        cur.execute("SELECT id, name, emp_code FROM employee "
                    "WHERE name ILIKE %s OR emp_code ILIKE %s", (like, like))
        employees = cur.fetchall()
    finally:
        cur.close()
        db.close()
    return render_template("admin_dashboard.html",
                           labels=labels, counts=counts,
                           attendance=today_rows, employees=employees,
                           query=q)


# ─────────────── add / delete employee ───────────────
@app.post("/add_employee")
@protect("admin")
def add_employee():
    name = request.form["name"]
    emp_code = request.form["emp_code"]
    raw_pass = request.form["password"]
    pin = f"{random.randint(0, 9999):04}"

    db = connect_db()
    cur = db.cursor()
    try:
        cur.execute("""INSERT INTO employee(name, emp_code, password, pin)
                       VALUES(%s, %s, %s, %s)""",
                    (name, emp_code, raw_pass, pin))
        db.commit()
        flash(f"Employee added! Quick PIN = {pin}", "success")
    except Exception as e:
        db.rollback()
        flash(str(e), "danger")
    finally:
        cur.close()
        db.close()
    return redirect("/admin")


@app.post("/delete_employee/<int:emp_id>")
@protect("admin")
def delete_employee(emp_id):
    db = connect_db()
    cur = db.cursor()
    try:
        cur.execute("DELETE FROM employee WHERE id=%s", (emp_id,))
        db.commit()
        flash("Employee deleted", "success")
    except Exception as e:
        db.rollback()
        flash(f"Error: {e}", "danger")
    finally:
        cur.close()
        db.close()
    return redirect("/admin")


# ─────────────── mark absent (employee & admin) ───────────────
@app.post("/absent")
@protect("emp_id")
def mark_absent():
    emp_id = session["emp_id"]
    today = datetime.today().date()
    reason = request.form.get("reason", "").strip() or "No reason given"

    db = connect_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO attendance (emp_id, date, absent, reason)
        VALUES (%s, %s, true, %s)
        ON CONFLICT (emp_id, date) DO UPDATE SET
          absent = true,
          reason = EXCLUDED.reason,
          time_in = NULL,
          time_out = NULL
    """, (emp_id, today, reason))
    db.commit()
    cur.close()
    db.close()
    flash("Absent recorded.", "warning")
    return redirect("/employee")


@app.post("/admin/absent/<int:emp_id>")
@protect("admin")
def admin_mark_absent(emp_id):
    today = datetime.today().date()
    reason = request.form.get("reason", "").strip() or "Not specified"

    db = connect_db()
    cur = db.cursor()
    cur.execute("""
        INSERT INTO attendance (emp_id, date, absent, reason)
        VALUES (%s, %s, true, %s)
        ON CONFLICT (emp_id, date) DO UPDATE SET
          absent = true,
          reason = EXCLUDED.reason,
          time_in = NULL,
          time_out = NULL
    """, (emp_id, today, reason))
    db.commit()
    cur.close()
    db.close()
    flash("Employee marked absent.", "info")
    return redirect("/admin")


@app.post("/api/leave")
def apply_leave():
    data = request.get_json(force=True, silent=True) or {}

    print("📌 Incoming Leave Request:", data)

    emp_id = data.get("emp_id")
    leave_type = data.get("type")
    reason = data.get("reason")

    from_date = data.get("from_date")
    to_date = data.get("to_date")

    if not emp_id:
        return jsonify({"success": False, "message": "emp_id required"}), 400

    if leave_type not in ("quick", "custom"):
        return jsonify({"success": False, "message": "type must be quick or custom"}), 400

    db = connect_db()
    cur = db.cursor()

    # ----- QUICK LEAVE (today only) -----
    if leave_type == "quick":
        today = datetime.today().date()

        cur.execute("""
            INSERT INTO attendance (emp_id, date, absent, reason)
            VALUES (%s, %s, true, %s)
            ON CONFLICT (emp_id, date) DO UPDATE SET
              absent = true,
              reason = EXCLUDED.reason,
              time_in = NULL,
              time_out = NULL
        """, (emp_id, today, reason or "No reason"))

        cur.execute("""
            INSERT INTO leaves (emp_id, from_date, to_date, reason)
            VALUES (%s, %s, %s, %s)
        """, (emp_id, today, today, reason or "No reason"))

        db.commit()
        cur.close()
        db.close()
        return jsonify({"success": True, "message": "Quick leave applied"})

    # ----- CUSTOM LEAVE -----
    if leave_type == "custom":
        if not from_date or not to_date or not reason:
            return jsonify({
                "success": False,
                "message": "from_date, to_date and reason required"
            }), 400

        cur.execute("""
            INSERT INTO leaves (emp_id, from_date, to_date, reason)
            VALUES (%s, %s, %s, %s)
        """, (emp_id, from_date, to_date, reason))

        try:
            from_dt = datetime.strptime(from_date, "%Y-%m-%d").date()
            to_dt = datetime.strptime(to_date, "%Y-%m-%d").date()

            current = from_dt
            while current <= to_dt:
                cur.execute("""
                    INSERT INTO attendance (emp_id, date, absent, reason)
                    VALUES (%s, %s, true, %s)
                    ON CONFLICT (emp_id, date) DO UPDATE SET
                      absent = true,
                      reason = EXCLUDED.reason,
                      time_in = NULL,
                      time_out = NULL
                """, (emp_id, current, reason))
                current += timedelta(days=1)

        except Exception as e:
            db.rollback()
            cur.close()
            db.close()
            return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

        db.commit()
        cur.close()
        db.close()
        return jsonify({"success": True, "message": "Custom leave applied"})


# ─────────────── employee dashboard (HTML) ───────────────
@app.route("/employee")
@protect("emp_id")
def employee_dashboard():
    emp_id = session["emp_id"]
    today = datetime.today().date()
    db = connect_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT time_in, time_out FROM attendance "
                    "WHERE emp_id=%s AND date=%s", (emp_id, today))
        result = cur.fetchone()
        time_in, time_out = map(fmt_time, result or (None, None))

        cur.execute("SELECT date, COUNT(*) FROM attendance "
                    "WHERE emp_id=%s AND date >= CURRENT_DATE - INTERVAL '6 days' "
                    "GROUP BY date ORDER BY date", (emp_id,))
        w = cur.fetchall()
        p_labels = [r[0].strftime("%a") for r in w]
        p_counts = [r[1] for r in w]

        cur.execute("SELECT name FROM employee WHERE id=%s", (emp_id,))
        emp_name = cur.fetchone()[0]
    finally:
        cur.close()
        db.close()

    return render_template("employee_dashboard.html",
                           name=emp_name,
                           time_in=time_in, time_out=time_out,
                           p_labels=p_labels, p_counts=p_counts)


# ───────────────────── punch helper ─────────────────────
def _record_punch(emp_id: int, punch_type: str, gps_location: dict = None):
    now = datetime.now()
    date = now.date()
    t = now.time()

    if gps_location:
        city = gps_location.get('city', 'Unknown')
        lat = gps_location.get('latitude', 0.0)
        lng = gps_location.get('longitude', 0.0)
        address = gps_location.get('address', 'Unknown')
        location = f"{address}|{lat:.6f}|{lng:.6f}"
    else:
        geo = geocoder.ip("me")
        city = geo.city or "Unknown"
        lat, lng = (geo.latlng or [0.0, 0.0])
        location = f"{city}|{lat:.4f}|{lng:.4f}"

    nice_time = now.strftime("%I:%M %p")

    db = connect_db()
    cur = db.cursor()
    ok, message = False, ""
    try:
        cur.execute("""
            SELECT id, time_in, time_out
              FROM attendance
             WHERE emp_id=%s AND date=%s
        """, (emp_id, date))
        row = cur.fetchone()

        if punch_type == "in":
            if row:
                raise ValueError("Already punched in")
            cur.execute("""
                INSERT INTO attendance (emp_id, date, time_in, location_in)
                VALUES (%s, %s, %s, %s)
            """, (emp_id, date, t, location))
        else:
            if not row or row[2]:
                raise ValueError("Not punched in yet / already out")
            cur.execute("""
                UPDATE attendance 
                SET time_out=%s, location_out=%s 
                WHERE id=%s
            """, (t, location, row[0]))
        db.commit()
        ok, message = True, "Saved"
    except ValueError as e:
        db.rollback()
        message = str(e)
    finally:
        cur.close()
        db.close()

    return ok, message, nice_time, location


def get_today_leave(cur, emp_id):
    cur.execute("""
        SELECT reason
        FROM leaves
        WHERE emp_id = %s
        AND CURRENT_DATE BETWEEN from_date AND to_date
        LIMIT 1
    """, (emp_id,))
    row = cur.fetchone()
    return row[0] if row else None


# ─────────────── web punch (HTML form) ───────────────
@app.post("/punch")
@protect("emp_id")
def punch_web():
    ok, msg, _, _ = _record_punch(session["emp_id"], request.form.get("type"))
    flash(msg, "success" if ok else "danger")
    return redirect("/employee")


# ─────────────── mobile punch (JSON) ───────────────
@app.post("/mobile/punch")
def punch_mobile():
    data = request.get_json(force=True) or {}
    pin = str(data.get("pin", "")).strip()
    ptype = data.get("type", "").lower()

    gps_location = data.get("location")

    if ptype not in ("in", "out"):
        return jsonify(success=False, msg="type?"), 400

    emp = get_emp_by_pin(pin)
    if not emp:
        return jsonify(success=False, msg="bad pin"), 400

    ok, msg, nice_time, loc = _record_punch(
        emp_id=emp[0],
        punch_type=ptype,
        gps_location=gps_location
    )
    return jsonify(success=ok, msg=msg, time=nice_time, location=loc), (200 if ok else 400)


# ─────────────── mobile helpers (history, whoami) ───────────────
@app.get("/mobile/history/<int:emp_id>")
def mobile_history(emp_id):
    db = connect_db()
    cur = db.cursor()

    cur.execute("""
        SELECT date, time_in, time_out, absent, reason
        FROM attendance
        WHERE emp_id=%s
        ORDER BY date DESC
    """, (emp_id,))
    attendance = cur.fetchall()

    cur.execute("""
        SELECT from_date, to_date, reason
        FROM leaves
        WHERE emp_id=%s
        ORDER BY id DESC
    """, (emp_id,))
    leave = cur.fetchall()

    cur.close()
    db.close()

    return jsonify({
        "attendance": [{
            "date": r[0].strftime("%Y-%m-%d"),
            "time_in": fmt_time(r[1]),
            "time_out": fmt_time(r[2]),
            "absent": bool(r[3]),
            "reason": r[4]
        } for r in attendance],

        "leave": [{
            "from_date": str(r[0]),
            "to_date": str(r[1]),
            "reason": r[2]
        } for r in leave]
    })


@app.get("/mobile/whoami/<pin>")
def mobile_whoami(pin):
    emp = get_emp_by_pin(pin)
    if not emp:
        return jsonify(success=False), 404

    return jsonify(
        success=True,
        id=emp[0],
        name=emp[1],
        emp_code=emp[2] if len(emp) > 2 else None
    )


# ─────────────── Profile endpoint for mobile ───────────────
@app.route("/profile", methods=["POST", "OPTIONS"])
def get_profile():
    if request.method == "OPTIONS":
        return "", 200, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
        }

    data = request.get_json(force=True, silent=True) or {}
    emp_code = data.get("emp_code", "").strip()

    if not emp_code:
        return jsonify({"success": False, "message": "emp_code required"}), 400

    db = connect_db()
    cur = db.cursor()

    try:
        cur.execute("""
            SELECT id, name, emp_code, email, phone, department, designation
            FROM employee
            WHERE emp_code = %s
        """, (emp_code,))

        row = cur.fetchone()

        if not row:
            return jsonify({"success": False, "message": "Employee not found"}), 404

        return jsonify({
            "success": True,
            "user": {
                "id": row[0],
                "name": row[1],
                "emp_code": row[2],
                "email": row[3] if row[3] else "N/A",
                "phone": row[4] if row[4] else "N/A",
                "department": row[5] if row[5] else "N/A",
                "designation": row[6] if row[6] else "N/A"
            }
        })

    except Exception as e:
        print(f"🔥 Profile error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

    finally:
        cur.close()
        db.close()


# ───────────────────── reports & monthly report (HTML) ─────────────────────
@app.route("/reports")
@protect("admin")
def reports():
    db = connect_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT date, COUNT(*) FROM attendance "
                    "GROUP BY date ORDER BY date DESC LIMIT 7")
        rows = cur.fetchall()
        labels = [r[0].strftime("%b %d") for r in rows[::-1]]
        counts = [r[1] for r in rows[::-1]]

        cur.execute("SELECT COUNT(*) FROM employee")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT emp_id) FROM attendance "
                    "WHERE date = CURRENT_DATE AND absent = false")
        present = cur.fetchone()[0]
        absent = total - present

        return render_template("reports.html",
                               labels=labels, counts=counts,
                               present=present, absent=absent)
    finally:
        cur.close()
        db.close()


# ───────────────────── monthly report ─────────────────────
@app.route("/monthly_report")
@protect("admin")
def monthly_report():
    today = datetime.today()
    first_day = today.replace(day=1).date()
    
    # PostgreSQL way to get last day of month
    db = connect_db()
    cur = db.cursor()
    cur.execute("""
        SELECT (DATE_TRUNC('month', %s::date) + INTERVAL '1 month - 1 day')::date
    """, (today,))
    last_day = cur.fetchone()[0]

    cur.execute("""
        SELECT e.id, e.name,
               a.date, a.time_in, a.time_out,
               a.location_in, a.location_out,
               a.absent, a.reason
          FROM employee e
     LEFT JOIN attendance a
            ON e.id = a.emp_id
           AND a.date BETWEEN %s AND %s
      ORDER BY e.id, a.date
    """, (first_day, last_day))
    rows = cur.fetchall()
    cur.close()
    db.close()

    records = [{
        "emp_id": r[0],
        "name": r[1],
        "date": r[2].strftime("%Y-%m-%d") if r[2] else "—",
        "time_in": fmt_time(r[3]) if r[3] else "—",
        "time_out": fmt_time(r[4]) if r[4] else "—",
        "location_in": r[5] or "—",
        "location_out": r[6] or "—",
        "absent": "Yes" if r[7] else "No",
        "reason": r[8] or "—",
    } for r in rows]

    return render_template("monthly_report.html",
                           records=records,
                           month=first_day.strftime("%B %Y"))


# ───────────────────── BIOMETRIC ─────────────────────
@app.post("/punch/biometric")
def punch_biometric():
    data = request.get_json(force=True, silent=True) or {}
    emp_id = data.get("emp_id")
    punch_type = data.get("type")

    ok, msg, nice_time, loc = _record_punch(emp_id=emp_id, punch_type=punch_type)

    # Log biometric usage
    db = connect_db()
    cur = db.cursor()
    cur.execute("""
        UPDATE attendance 
        SET auth_method = 'biometric'
        WHERE emp_id = %s AND date = CURRENT_DATE
    """, (emp_id,))
    db.commit()
    cur.close()
    db.close()

    return jsonify(success=ok, msg=msg, time=nice_time, location=loc)


# ───────────────────── logout ─────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ───────────────────── run app ─────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)