import os
import json
from datetime import timedelta

from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from flask_cors import CORS
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
CORS(app)

app.secret_key = os.environ.get("SECRET_KEY", "super-secret-key-change-this")

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True

# MySQL config — resolves Railway's auto-injected vars first, falls back to DB_ vars
MYSQL_HOST     = os.environ.get("MYSQLHOST")     or os.environ.get("DB_HOST",     "localhost")
MYSQL_PORT     = int(os.environ.get("MYSQLPORT") or os.environ.get("DB_PORT",     3306))
MYSQL_USER     = os.environ.get("MYSQLUSER")     or os.environ.get("DB_USER",     "root")
MYSQL_PASSWORD = os.environ.get("MYSQLPASSWORD") or os.environ.get("DB_PASSWORD", "")
MYSQL_DATABASE = os.environ.get("MYSQLDATABASE") or os.environ.get("DB_NAME",     "calculator_app")

# Print to Railway deploy logs so you can verify vars resolved correctly
print(f"[DB] host={MYSQL_HOST} port={MYSQL_PORT} user={MYSQL_USER} db={MYSQL_DATABASE}", flush=True)

db_config = {
    "host":     MYSQL_HOST,
    "port":     MYSQL_PORT,
    "user":     MYSQL_USER,
    "password": MYSQL_PASSWORD,
    "database": MYSQL_DATABASE,
}


def get_db_connection():
    return mysql.connector.connect(**db_config)


def parse_history_json(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return []
    return []


# ── Health check — Railway uses this to confirm the app is alive ──

@app.route("/health")
def health():
    return "OK", 200


# ── Page routes ──

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/signup")
def signup_page():
    return render_template("signup.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("index"))
    return render_template("dashboard.html", email=session.get("email"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ── Auth API ──

@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json(silent=True) or {}
    email    = (data.get("email")    or "").strip().lower()
    password =  data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = cursor = None
    try:
        conn   = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, email, password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "No account found with that email.", "redirect": "/signup"}), 404

        if not check_password_hash(user["password"], password):
            return jsonify({"error": "Incorrect password."}), 401

        session.permanent  = True
        session["user_id"] = user["id"]
        session["email"]   = user["email"]

        return jsonify({"message": "Login successful!", "user_id": user["id"], "email": user["email"]})

    except Exception as e:
        print(f"[LOGIN ERROR] {e}", flush=True)
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        if cursor: cursor.close()
        if conn:   conn.close()


@app.route("/register", methods=["POST"])
def register():
    data     = request.get_json(silent=True) or {}
    email    = (data.get("email")    or "").strip().lower()
    password =  data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    hashed_password = generate_password_hash(password)

    conn = cursor = None
    try:
        conn   = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "That email is already registered. Try logging in."}), 409

        cursor.close()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed_password))
        conn.commit()
        return jsonify({"message": "User registered successfully"}), 201

    except Exception as e:
        print(f"[REGISTER ERROR] {e}", flush=True)
        return jsonify({"error": f"Database error: {str(e)}"}), 500
    finally:
        if cursor: cursor.close()
        if conn:   conn.close()


# ── Saved histories API ──

@app.route("/api/saved_histories", methods=["GET"])
def get_saved_histories():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = cursor = None
    try:
        conn   = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, title, history_json, created_at, updated_at
            FROM saved_histories
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (session["user_id"],))

        rows = cursor.fetchall()
        histories = []
        for row in rows:
            histories.append({
                "id":         row["id"],
                "title":      row["title"],
                "history":    parse_history_json(row["history_json"]),
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
            })
        return jsonify(histories)

    except Exception as e:
        print(f"[GET HISTORIES ERROR] {e}", flush=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn:   conn.close()


@app.route("/api/saved_histories", methods=["POST"])
def save_history():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data    = request.get_json(silent=True) or {}
    title   = (data.get("title") or "").strip()
    history = data.get("history", [])

    if not title:
        return jsonify({"error": "Title is required"}), 400
    if not isinstance(history, list):
        return jsonify({"error": "History must be an array"}), 400

    conn = cursor = None
    try:
        conn   = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO saved_histories (user_id, title, history_json)
            VALUES (%s, %s, %s)
        """, (session["user_id"], title, json.dumps(history)))
        conn.commit()
        return jsonify({"message": "Saved successfully", "id": cursor.lastrowid}), 201

    except Exception as e:
        print(f"[SAVE HISTORY ERROR] {e}", flush=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn:   conn.close()


@app.route("/api/saved_histories/<int:history_id>", methods=["GET"])
def get_saved_history(history_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = cursor = None
    try:
        conn   = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, title, history_json, created_at, updated_at
            FROM saved_histories
            WHERE id = %s AND user_id = %s
        """, (history_id, session["user_id"]))

        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "History not found"}), 404

        return jsonify({
            "id":         row["id"],
            "title":      row["title"],
            "history":    parse_history_json(row["history_json"]),
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        })

    except Exception as e:
        print(f"[GET HISTORY ERROR] {e}", flush=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn:   conn.close()


@app.route("/api/saved_histories/<int:history_id>", methods=["PUT"])
def update_saved_history(history_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data  = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()

    if not title:
        return jsonify({"error": "Title is required"}), 400

    conn = cursor = None
    try:
        conn   = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE saved_histories SET title = %s
            WHERE id = %s AND user_id = %s
        """, (title, history_id, session["user_id"]))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({"error": "History not found"}), 404
        return jsonify({"message": "Updated successfully"})

    except Exception as e:
        print(f"[UPDATE HISTORY ERROR] {e}", flush=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn:   conn.close()


@app.route("/api/saved_histories/<int:history_id>", methods=["DELETE"])
def delete_saved_history(history_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = cursor = None
    try:
        conn   = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM saved_histories
            WHERE id = %s AND user_id = %s
        """, (history_id, session["user_id"]))
        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({"error": "History not found"}), 404
        return jsonify({"message": "Deleted successfully"})

    except Exception as e:
        print(f"[DELETE HISTORY ERROR] {e}", flush=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if cursor: cursor.close()
        if conn:   conn.close()


# ── Entry point ──

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)