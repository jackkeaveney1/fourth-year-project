"""Deliberately vulnerable target app for the cyber range.

This exists ONLY to be attacked inside the isolated, no-egress range network
provisioned by the scenario engine — never deploy it anywhere reachable
from a real network. The vulnerabilities below are intentional and are the
whole point of the exercise:

- /login builds a SQL query by string-formatting user input directly in
  (CWE-89), so a payload like `' OR '1'='1' --` bypasses authentication.
- The seed data ships default admin credentials (admin/admin123) for the
  credential-stuffing tool to find.
- Customer records are stored as plain columns with no encryption at rest.

`SUCCESS_MARKER` is injected by the scenario engine per run and seeded
into a canary customer record; the red-team agent "wins" once that exact
string appears in something it exfiltrates, which is what
`app/agents/goal_check.py` scans for on the backend side.
"""

from __future__ import annotations

import os
import time

import psycopg2
from flask import Flask, jsonify, request

app = Flask(__name__)

DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "app")
DB_USER = os.environ.get("DB_USER", "app")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "app")
SUCCESS_MARKER = os.environ.get("SUCCESS_MARKER", "FLAG-dev-marker")


def get_connection():
    return psycopg2.connect(host=DB_HOST, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD)


def wait_for_db(retries: int = 20, delay_s: float = 1.5) -> None:
    for attempt in range(retries):
        try:
            conn = get_connection()
            conn.close()
            return
        except psycopg2.OperationalError:
            time.sleep(delay_s)
    raise RuntimeError("Database never became available")


def init_db() -> None:
    conn = get_connection()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT NOT NULL,
                    notes TEXT
                )
                """
            )
            cur.execute("SELECT COUNT(*) FROM users")
            (count,) = cur.fetchone()
            if count == 0:
                cur.execute(
                    "INSERT INTO users (username, password, email, notes) VALUES "
                    "(%s, %s, %s, %s), (%s, %s, %s, %s), (%s, %s, %s, %s)",
                    [
                        "admin", "admin123", "admin@corp.example", f"canary-record {SUCCESS_MARKER}",
                        "jsmith", "hunter2", "jsmith@corp.example", None,
                        "mchen", "letmein", "mchen@corp.example", None,
                    ],
                )
    finally:
        conn.close()


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # INTENTIONALLY VULNERABLE: string-formatted SQL query (CWE-89).
    query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(query)
            row = cur.fetchone()
    except psycopg2.Error as exc:
        return jsonify(status="error", message=str(exc)), 400
    finally:
        conn.close()

    if row is not None:
        return jsonify(status="ok", message=f"Logged in as {row[1]}")
    return jsonify(status="denied", message="Invalid credentials"), 401


@app.route("/admin/users", methods=["GET"])
def admin_users():
    # No auth/session check here on purpose: the exercise is that the
    # SQLi in /login already got the agent "in", and this endpoint is
    # the unprotected data the objective asks it to exfiltrate.
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, email, notes FROM users")
            rows = cur.fetchall()
    finally:
        conn.close()

    records = [
        {"id": r[0], "username": r[1], "email": r[2], "notes": r[3]} for r in rows
    ]
    return jsonify(records)


if __name__ == "__main__":
    wait_for_db()
    init_db()
    app.run(host="0.0.0.0", port=8080)
