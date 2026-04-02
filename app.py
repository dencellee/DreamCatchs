import logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(asctime)s %(message)s')
logger = logging.getLogger(__name__)
import os
import json
import logging
import traceback
from functools import wraps
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

def require_admin_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-Admin-Key', '')

        if not api_key or api_key != ADMIN_API_KEY:
            logger.warning(f"[SECURITY] Unauthorized admin access attempt from {request.remote_addr}")
            return jsonify({"error": "Unauthorized. Invalid or missing admin key."}), 401

        return f(*args, **kwargs)
    return decorated_function

# --- Admin: Edit User ---
@app.route('/admin/edit_user', methods=['POST'])
@require_admin_key
def edit_user():
    try:
        logger.info("/admin/edit_user called")
        data = request.get_json(force=True, silent=True)
        logger.info(f"Request data: {data}")
        if not data:
            return jsonify({'status': 'error', 'message': 'No JSON body received'}), 400
        license_key = str(data.get('license_key', '')).strip()
        username = str(data.get('username', '')).strip()
        full_name = str(data.get('full_name', '')).strip()
        if not license_key or not username or not full_name:
            logger.warning(f"Missing fields: license_key={license_key}, username={username}, full_name={full_name}")
            return jsonify({'status': 'error', 'message': 'Missing fields'}), 400
        conn = get_db()
        if not conn:
            logger.error("DB connection failed")
            return jsonify({'status': 'error', 'message': 'DB error'}), 500
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET username = %s, full_name = %s WHERE license_key = %s
        """, (username, full_name, license_key))
        conn.commit()
        cursor.close()
        conn.close()
        logger.info(f"User updated: {license_key} -> {username}, {full_name}")
        return jsonify({'status': 'success'}), 200
    except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            logger.error(f"[ERROR] edit_user: {e}\n{traceback.format_exc()}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

# --- Admin: Extend License ---
@app.route('/admin/extend_license', methods=['POST'])
@require_admin_key
def extend_license():
    try:
        data = request.get_json(force=True, silent=True)
        license_key = str(data.get('license_key', '')).strip()
        expiry_days = data.get('expiry_days', None)
        if expiry_days is not None:
            try:
                expiry_days = int(str(expiry_days).strip())
            except Exception:
                return jsonify({'status': 'error', 'message': 'expiry_days must be an integer'}), 400
        if not license_key or not expiry_days:
            return jsonify({'status': 'error', 'message': 'Missing fields'}), 400
        conn = get_db()
        if not conn:
            return jsonify({'status': 'error', 'message': 'DB error'}), 500
        cursor = conn.cursor()
        # Get current expires_at
        cursor.execute("SELECT expires_at FROM users WHERE license_key = %s", (license_key,))
        row = cursor.fetchone()
        if row and row[0]:
            current_expiry = row[0]
            if isinstance(current_expiry, str):
                current_expiry = datetime.fromisoformat(current_expiry)
        else:
            current_expiry = datetime.now()
        new_expiry = current_expiry + timedelta(days=expiry_days)
        cursor.execute("""
            UPDATE users SET expires_at = %s WHERE license_key = %s
        """, (new_expiry, license_key))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'status': 'success', 'new_expiry': new_expiry.isoformat()}), 200
    except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            logger.error(f"[ERROR] extend_license: {e}\n{traceback.format_exc()}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
# --- Admin: Delete User ---
@app.route('/admin/delete_user', methods=['POST'])
@require_admin_key
def delete_user():
    try:
        data = request.get_json(force=True, silent=True)
        license_key = str(data.get('license_key', '')).strip()
        if not license_key:
            return jsonify({'status': 'error', 'message': 'Missing license_key'}), 400
        conn = get_db()
        if not conn:
            return jsonify({'status': 'error', 'message': 'DB error'}), 500
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE license_key = %s", (license_key,))
        conn.commit()
        cursor.close()
        conn.close()
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        logger.error(f"[ERROR] delete_user: {e}\n{traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Database Configuration - Railway auto-provides DATABASE_URL
DATABASE_URL = os.environ.get('DATABASE_URL')

# Security Configuration
ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY')
ALLOWED_HWID = None
MAX_LOGIN_ATTEMPTS = 10
FAILED_ATTEMPTS = {}
# Track last login time per user+ip to avoid log spam
LAST_LOGIN_LOG = {}

def init_db():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            full_name VARCHAR(255) NOT NULL,
            license_key VARCHAR(255) UNIQUE NOT NULL,
            hwid VARCHAR(255),
            active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NULL
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS strategies (
            id SERIAL PRIMARY KEY,
            license_key VARCHAR(255) UNIQUE NOT NULL,
            strategy_data JSON NOT NULL,
            strategy_name VARCHAR(100) DEFAULT 'Custom',
            max_goal INTEGER DEFAULT 20,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(license_key) REFERENCES users(license_key) ON DELETE CASCADE
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS betting_history (
            id SERIAL PRIMARY KEY,
            license_key VARCHAR(255) NOT NULL,
            action VARCHAR(50),
            amount DECIMAL(10,2),
            side VARCHAR(16),
            live_balance DECIMAL(10,2),
            profit DECIMAL(10,2),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(license_key) REFERENCES users(license_key) ON DELETE CASCADE
        )''')

        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_license ON betting_history (license_key)''')
        cursor.execute('''CREATE INDEX IF NOT EXISTS idx_timestamp ON betting_history (timestamp)''')

        conn.commit()
        cursor.close()
        conn.close()
        logger.info("[DB] All tables created successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}\n{traceback.format_exc()}")
        raise

def get_db():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        return conn
    except Exception as e:
        logger.error(f"[ERROR] Failed to connect to database: {e}\n{traceback.format_exc()}")
        return None

def get_user_by_key(license_key):
    conn = get_db()
    if not conn:
        return None

    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT * FROM users WHERE license_key = %s", (license_key,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return user
    except Exception as e:
        logger.error(f"[ERROR] Query failed: {e}\n{traceback.format_exc()}")
        conn.close()
        return None

def get_strategy(license_key):
    conn = get_db()
    if not conn:
        return None

    try:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT strategy_data, max_goal FROM strategies WHERE license_key = %s", (license_key,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return result
    except Exception as e:
        logger.error(f"[ERROR] Query failed: {e}\n{traceback.format_exc()}")
        conn.close()
        return None

def require_admin_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-Admin-Key', '')

        if not api_key or api_key != ADMIN_API_KEY:
            logger.warning(f"[SECURITY] Unauthorized admin access attempt from {request.remote_addr}")
            return jsonify({"error": "Unauthorized. Invalid or missing admin key."}), 401

        return f(*args, **kwargs)
    return decorated_function

def check_rate_limit(key):
    if key not in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[key] = {'count': 0, 'last_attempt': datetime.now()}

    attempt_data = FAILED_ATTEMPTS[key]

    if (datetime.now() - attempt_data['last_attempt']).seconds > 900:
        FAILED_ATTEMPTS[key] = {'count': 0, 'last_attempt': datetime.now()}
        return True

    if attempt_data['count'] >= MAX_LOGIN_ATTEMPTS:
        logger.warning(f"[SECURITY] Rate limit exceeded for key: {key[:10]}...")
        return False

    return True

def log_failed_attempt(key):
    if key not in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[key] = {'count': 0, 'last_attempt': datetime.now()}

    FAILED_ATTEMPTS[key]['count'] += 1
    FAILED_ATTEMPTS[key]['last_attempt'] = datetime.now()

    logger.warning(f"[SECURITY] Failed login attempt #{FAILED_ATTEMPTS[key]['count']} for key: {key[:10]}...")

    if FAILED_ATTEMPTS[key]['count'] >= MAX_LOGIN_ATTEMPTS:
        logger.warning(f"[SECURITY] Account locked due to too many attempts: {key[:10]}...")

@app.route('/verify.php', methods=['POST'])
def verify_license():
    try:
        key = request.form.get('key', '').strip()
        hwid = request.form.get('hwid', '').strip()

        if not key:
            return jsonify({"status": "error", "message": "Invalid request"}), 400

        if not check_rate_limit(key):
            logger.warning(f"[SECURITY] Rate limit exceeded for key: {key[:10]}...")
            return jsonify({"status": "error", "message": "Too many login attempts. Try again later."}), 429

        user = get_user_by_key(key)

        if not user:
            log_failed_attempt(key)
            logger.warning(f"[SECURITY] Invalid license key attempt: {key[:10]}...")
            return jsonify({"status": "error", "message": "Authentication failed"}), 401

        if not user['active']:
            log_failed_attempt(key)
            logger.warning(f"[SECURITY] Attempt to use deactivated license: {key[:10]}...")
            return jsonify({"status": "error", "message": "Authentication failed"}), 401

        if user['expires_at']:
            expires = user['expires_at']
            if isinstance(expires, str):
                expires = datetime.fromisoformat(expires)
            if datetime.now() > expires:
                log_failed_attempt(key)
                logger.warning(f"[SECURITY] Attempt to use expired license: {key[:10]}...")
                return jsonify({"status": "error", "message": "Authentication failed"}), 401

        # Enforce HWID binding: once set, cannot be changed
        if user['hwid']:
            if user['hwid'] != hwid:
                log_failed_attempt(key)
                logger.warning(f"[SECURITY] HWID mismatch for license: {key[:10]}... (Expected: {user['hwid']}, Got: {hwid})")
                return jsonify({"status": "error", "message": "Authentication failed: HWID mismatch"}), 401
        else:
            # If HWID is not set, bind it to the first PC that logs in
            if hwid:
                try:
                    conn = get_db()
                    if conn:
                        cursor = conn.cursor()
                        cursor.execute("UPDATE users SET hwid = %s WHERE license_key = %s AND hwid IS NULL", (hwid, key))
                        conn.commit()
                        cursor.close()
                        conn.close()
                        logger.info(f"[SECURITY] HWID {hwid} bound to license: {key[:10]}...")
                except Exception as e:
                    logger.warning(f"[ERROR] Failed to bind HWID: {e}")

        if key in FAILED_ATTEMPTS:
            FAILED_ATTEMPTS[key] = {'count': 0, 'last_attempt': datetime.now()}

            # Only log if last login for this user+ip was > 60 seconds ago
            login_key = f"{user['username']}:{request.remote_addr}"
            now = datetime.now()
            last_time = LAST_LOGIN_LOG.get(login_key)
            if not last_time or (now - last_time).total_seconds() > 60:
                logger.info(f"[AUTH] Successful login: {user['username']} from {request.remote_addr}")
                LAST_LOGIN_LOG[login_key] = now

        strategy_result = get_strategy(key)
        if not strategy_result:
            default_strategy = {str(i): {"amount": 100 * (2 ** (i-1)), "side": "2"} for i in range(1, 12)}
            strategy_data = default_strategy
            max_goal = 20
        else:
            strategy_data = strategy_result['strategy_data']
            if isinstance(strategy_data, str):
                strategy_data = json.loads(strategy_data)
            max_goal = strategy_result['max_goal']

        return jsonify({
            "status": "success",
            "user_info": {
                "id": user['id'],
                "username": user['username'],
                "full_name": user['full_name'],
                "license_key": user['license_key']
            },
            "config": {
                "strategy": strategy_data,
                "max_goal": max_goal
            }
        }), 200

    except Exception as e:
        logger.error(f"[ERROR] verify_license: {e}\n{traceback.format_exc()}")
        return jsonify({"status": "error", "message": "Server error", "debug": str(e)}), 500

@app.route('/sync_action.php', methods=['POST'])
def sync_action():
    try:
        key = request.form.get('key', '').strip()
        hwid = request.form.get('hwid', '').strip()
        action = request.form.get('action', '').strip()
        amount = request.form.get('amount', 0)
        live_balance = request.form.get('live_balance', 0)
        profit = request.form.get('profit', 0)
        start_balance = request.form.get('start_balance', None)
        max_goal = request.form.get('max_goal', None)

        user = get_user_by_key(key)
        if not user:
            return jsonify({"status": "error", "message": "Invalid license"}), 401

        conn = get_db()
        if not conn:
            return jsonify({"status": "error", "message": "Database connection failed"}), 500

        try:
            cursor = conn.cursor()
            if action == 'UPDATE_GOAL' and max_goal is not None:
                try:
                    max_goal_val = float(max_goal)
                except:
                    conn.close()
                    return jsonify({"status": "error", "message": "Invalid max_goal"}), 400

                cursor.execute(
                    "UPDATE strategies SET max_goal = %s WHERE license_key = %s",
                    (max_goal_val, key)
                )
                if cursor.rowcount == 0:
                    conn.close()
                    return jsonify({"status": "error", "message": "Strategy not found for license"}), 404

                amount = max_goal_val

            if action == 'RESET_CYCLE':
                # Save only the total net profit for the user
                cursor.execute("""
                    INSERT INTO betting_history (license_key, action, amount, live_balance, profit)
                    VALUES (%s, %s, %s, %s, %s)
                """, (key, action, 0, live_balance, profit))
                conn.commit()
                cursor.close()
                conn.close()
                return jsonify({"status": "success", "message": "Net profit recorded for RESET_CYCLE"}), 200

            # For other actions, save full bet history
            side = request.form.get('side', None)
            cursor.execute("""
                INSERT INTO betting_history (license_key, action, amount, side, live_balance, profit)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (key, action, amount, side, live_balance, profit))
            conn.commit()
            cursor.close()
            conn.close()

            return jsonify({"status": "success", "message": "Action recorded"}), 200
        except Exception as e:
            conn.close()
            print(f"[ERROR] sync_action: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

    except Exception as e:
        logger.error(f"[ERROR] sync_action: {e}\n{traceback.format_exc()}")
        return jsonify({"status": "error", "message": str(e), "debug": traceback.format_exc()}), 500

@app.route('/admin/add_user', methods=['POST'])
@require_admin_key
def add_user():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        full_name = data.get('full_name', '').strip()
        license_key = data.get('license_key', '').strip()
        hwid = data.get('hwid', '')
        expires_at = data.get('expires_at', None)

        if not all([username, full_name, license_key]):
            return jsonify({"status": "error", "message": "Missing required fields"}), 400

        conn = get_db()
        if not conn:
            return jsonify({"status": "error", "message": "Database connection failed"}), 500

        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, full_name, license_key, hwid, expires_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (username, full_name, license_key, hwid if hwid else None, expires_at))
            # Insert default strategy for new account (Strategy 1)
            default_amounts = [4, 12, 28, 60, 124, 252, 508, 1020, 2044, 4092, 8188]
            default_strategy = {
                str(i+1): {
                    "amount": default_amounts[i],
                    "side": "2"
                }
                for i in range(len(default_amounts))
            }
            try:
                cursor.execute("""
                    INSERT INTO strategies (license_key, strategy_data, max_goal, strategy_name)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (license_key) DO NOTHING
                """, (license_key, json.dumps(default_strategy), 20, 'Strategy 1'))
            except Exception:
                # If strategies table doesn't exist or insert fails, ignore; user still created
                pass
            conn.commit()
            cursor.close()
            conn.close()

            return jsonify({"status": "success", "message": "User created"}), 201
        except psycopg2.IntegrityError:
            conn.rollback()
            conn.close()
            return jsonify({"status": "error", "message": "Username or license key already exists"}), 400
        except Exception as e:
            conn.close()
            return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        logger.error(f"[ERROR] add_user: {e}\n{traceback.format_exc()}")
        return jsonify({"status": "error", "message": str(e), "debug": traceback.format_exc()}), 500

@app.route('/admin/set_strategy', methods=['POST'])
@require_admin_key
def set_strategy():
    try:
        data = request.get_json()
        license_key = data.get('license_key', '').strip()
        strategy = data.get('strategy', {})
        strategy_name = data.get('strategy_name', '').strip() or None
        max_goal = data.get('max_goal', 20)

        if not license_key:
            return jsonify({"error": "Missing license_key"}), 400

        user = get_user_by_key(license_key)
        if not user:
            return jsonify({"error": "User not found"}), 404

        conn = get_db()
        if not conn:
            return jsonify({"error": "Database connection failed"}), 500

        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO strategies (license_key, strategy_data, max_goal, strategy_name)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (license_key) DO UPDATE SET
                strategy_data = EXCLUDED.strategy_data,
                max_goal = EXCLUDED.max_goal,
                strategy_name = EXCLUDED.strategy_name
            """, (license_key, json.dumps(strategy), max_goal, strategy_name))
            conn.commit()
            cursor.close()
            conn.close()

            return jsonify({"status": "success", "message": "Strategy updated"}), 200
        except Exception as e:
            conn.close()
            print(f"[ERROR] set_strategy: {e}")
            traceback.print_exc()
            return jsonify({"error": str(e)}), 400

    except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            logger.error(f"[ERROR] set_strategy: {e}\n{traceback.format_exc()}")
            return jsonify({"status": "error", "message": str(e), "debug": traceback.format_exc()}), 500

@app.route('/admin/list_users', methods=['GET'])
@require_admin_key
def list_users():
    try:
        conn = get_db()
        if not conn:
            return jsonify({"status": "error", "message": "Database connection failed"}), 500

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        # Try to select strategy_name (newer DB schema). If the column doesn't exist, fall back.
        try:
            cursor.execute("""
                SELECT u.id, u.username, u.full_name, u.license_key, u.hwid, u.active, u.created_at, u.expires_at,
                       s.strategy_data, s.max_goal, s.strategy_name
                FROM users u
                LEFT JOIN strategies s ON u.license_key = s.license_key
            """)
        except Exception as e:
            try:
                conn.rollback()
            except Exception:
                pass
            try:
                cursor.execute("""
                    SELECT u.id, u.username, u.full_name, u.license_key, u.hwid, u.active, u.created_at, u.expires_at,
                           s.strategy_data, s.max_goal
                    FROM users u
                    LEFT JOIN strategies s ON u.license_key = s.license_key
                """)
            except Exception as e2:
                conn.close()
                print(f"[ERROR] list_users query failed: {e2}")
                traceback.print_exc()
                return jsonify({"status": "error", "message": "Database query failed", "error": str(e2)}), 500
        users = cursor.fetchall()
        cursor.close()
        conn.close()

        for user in users:
            # Normalize datetime fields for JSON
            if user.get('created_at'):
                user['created_at'] = user['created_at'].isoformat()
            if user.get('expires_at'):
                user['expires_at'] = user['expires_at'].isoformat()

            # If strategy_data exists, try to parse it so the admin UI can display it without extra requests
            strat = user.get('strategy_data')
            if strat:
                try:
                    if isinstance(strat, str):
                        user['strategy'] = json.loads(strat)
                    else:
                        user['strategy'] = strat
                except Exception:
                    user['strategy'] = {}
            else:
                user['strategy'] = {}
            # Expose max_goal if available
            user['max_goal'] = user.get('max_goal', None)

        return jsonify({"status": "success", "users": users}), 200

    except Exception as e:
        logger.error(f"[ERROR] list_users: {e}\n{traceback.format_exc()}")
        return jsonify({"status": "error", "message": "Internal server error: see server logs", "error": str(e), "debug": traceback.format_exc()}), 500

@app.route('/admin/user_stats/<license_key>', methods=['GET'])
@require_admin_key
def user_stats(license_key):
    conn = get_db()
    if not conn:
        return jsonify({"status": "error", "message": "Database connection failed"}), 500

    cursor = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cursor.execute("""
            SELECT action, COUNT(*) as count, SUM(amount) as total_amount, SUM(profit) as total_profit
            FROM betting_history
            WHERE license_key = %s
            GROUP BY action
        """, (license_key,))
        stats = cursor.fetchall()
    except Exception as e:
        logger.error(f"[user_stats] ERROR in stats query: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': f'stats query failed: {e}'}), 500

    # Calculate daily profit and profit history
    daily_profit = None
    profit_history = []
    total_net_profit = None
    full_history = []

    logger.info("[user_stats] Querying betting_history for daily profit and history...")
    try:
        # Use Asia/Manila timezone for daily profit calculation
        cursor.execute("""
            SELECT profit, timestamp FROM betting_history
            WHERE license_key = %s
              AND (timestamp AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Manila')::date = (CURRENT_DATE AT TIME ZONE 'Asia/Manila')
              AND action IN ('WIN', 'LOSS')
            ORDER BY timestamp ASC
        """, (license_key,))
        rows = cursor.fetchall()
        if rows:
            daily_profit = sum([float(r['profit']) for r in rows if r['profit'] is not None])
            profit_history = [{"profit": float(r['profit']), "timestamp": r['timestamp'].isoformat()} for r in rows]
        else:
            daily_profit = None
            profit_history = []
    except Exception as e:
        logger.error(f"[user_stats] ERROR in daily profit/history query: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': f'daily profit/history query failed: {e}'}), 500

    logger.info("[user_stats] Querying betting_history for total profit...")
    try:
        cursor.execute("SELECT SUM(profit) as total_profit FROM betting_history WHERE license_key = %s AND action IN ('WIN', 'LOSS')", (license_key,))
        net_row = cursor.fetchone()
        total_net_profit = float(net_row['total_profit']) if net_row and net_row['total_profit'] is not None else 0.0
    except Exception as e:
        logger.error(f"[user_stats] ERROR in total profit query: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': f'total profit query failed: {e}'}), 500

    logger.info("[user_stats] Querying betting_history for full history...")
    try:
        cursor.execute("""
            SELECT action, amount, profit, timestamp FROM betting_history
            WHERE license_key = %s
            ORDER BY timestamp ASC
        """, (license_key,))
        full_rows = cursor.fetchall()
        for r in full_rows:
            full_history.append({
                "action": r["action"],
                "amount": float(r["amount"]),
                "profit": float(r["profit"]),
                "timestamp": r["timestamp"].isoformat()
            })
    except Exception as e:
        logger.error(f"[user_stats] ERROR in full history query: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': f'full history query failed: {e}'}), 500

    logger.info("[user_stats] Querying strategies for strategy_data and max_goal...")
    try:
        cursor.execute("SELECT strategy_data, max_goal FROM strategies WHERE license_key = %s", (license_key,))
        strat_row = cursor.fetchone()
        strategy_data = strat_row["strategy_data"] if strat_row and "strategy_data" in strat_row else None
        max_goal = strat_row["max_goal"] if strat_row and "max_goal" in strat_row else None
    except Exception as e:
        logger.error(f"[user_stats] ERROR in strategies query: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': f'strategies query failed: {e}'}), 500

    return jsonify({
        "status": "success",
        "stats": {
            "stats": stats,
            "daily_profit": daily_profit,
            "net_profit": total_net_profit,
            "profit_history": profit_history,
            "full_history": full_history,
            "strategy_data": strategy_data,
            "max_goal": max_goal
        }
    }), 200

@app.route('/status', methods=['GET'])
def status():
    return jsonify({"status": "online", "timestamp": datetime.now().isoformat()}), 200

# Initialize database when app starts (works with both local dev and Gunicorn in production)

logger.info("\n" + "="*60)
logger.info("[SERVER] BacBot Auth Server with PostgreSQL")
logger.info("="*60)
logger.info(f"[DEBUG] DATABASE_URL set: {'Yes' if DATABASE_URL else 'NO - MISSING!'}")
logger.info(f"[DEBUG] ADMIN_API_KEY set: {'Yes' if ADMIN_API_KEY else 'NO'}")
logger.info("="*60)

if not DATABASE_URL:
    logger.critical("[CRITICAL] DATABASE_URL not set! Railway PostgreSQL not linked properly.")
    logger.warning("[FIX] Go to Railway dashboard and link PostgreSQL service to web service.")
else:
    try:
        init_db()
        logger.info("[SUCCESS] Database initialized successfully")
    except Exception as e:
        logger.warning(f"Database initialization failed: {e}")
        logger.info("[INFO] App will still start - database will retry on first request")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
