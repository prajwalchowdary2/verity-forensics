#!/usr/bin/env python3
import os
import sys
import re
import json
import sqlite3
import shutil
import time
import argparse
import hashlib
import subprocess
import hmac
import secrets
import threading
import base64
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, HTTPServer
import socketserver

# Professional log colors
CYAN = '\033[96m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Globals for HTTP Loopback APIs
BOOTSTRAP_TOKEN = ""
session_hmac_key = b""
key_version = 1
DECRYPTED_PRIVATE_KEY = None

def print_banner():
    banner = fr"""{CYAN}
======================================================================
 __     __        _ _         
 \ \   / /__ _ __(_) |_ _   _ 
  \ \ / / _ \ '__| | __| | | |
   \ V /  __/ |  | | |_| |_| |
    \_/ \___|_|  |_|\__|\__, |
                        |___/ 

               AI FORENSICS LAB — LIVE CARVING DAEMON
               Digital Evidence. Verified Truth.
======================================================================{RESET}"""
    print(banner)

def get_file_sha256(path):
    """Calculate the cryptographic SHA-256 hash of a file for Chain of Custody verification."""
    if not os.path.exists(path):
        return "N/A"
    sha = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()
    except Exception:
        return "ERROR_HASH_FAILED"

def get_system_clipboard():
    """Retrieve clipboard contents without GUI dependencies using subprocess wrappers."""
    try:
        if sys.platform == "darwin":  # macOS
            return subprocess.check_output('pbpaste', shell=True).decode('utf-8', errors='ignore')
        elif sys.platform == "win32":  # Windows
            cmd = ['powershell', '-NoProfile', '-Command', 'Get-Clipboard']
            return subprocess.check_output(cmd).decode('utf-8', errors='ignore')
        else:  # Linux
            return subprocess.check_output('xclip -selection clipboard -o', shell=True).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def get_firefox_profile_dir(base_path):
    """Find the active Firefox profile directory containing places.sqlite."""
    if not os.path.exists(base_path):
        return None
    try:
        for item in os.listdir(base_path):
            profile_path = os.path.join(base_path, item)
            if os.path.isdir(profile_path) and os.path.exists(os.path.join(profile_path, "places.sqlite")):
                return profile_path
    except Exception:
        pass
    return None

def get_forensic_paths():
    """Detect Safari, Firefox, Edge, Chrome and Native Desktop App paths."""
    home = os.path.expanduser("~")
    paths = {
        "chrome_history": "",
        "chrome_cookies": "",
        "edge_history": "",
        "edge_cookies": "",
        "firefox_history": "",
        "firefox_cookies": "",
        "safari_history": "",
        "indexeddb": {}
    }
    
    # 1. Resolve pathways based on OS
    if sys.platform == "darwin":
        # Google Chrome
        chrome_base = os.path.join(home, "Library/Application Support/Google/Chrome/Default")
        paths["chrome_history"] = os.path.join(chrome_base, "History")
        cookie_path = os.path.join(chrome_base, "Network", "Cookies")
        if not os.path.exists(cookie_path):
            cookie_path = os.path.join(chrome_base, "Cookies")
        paths["chrome_cookies"] = cookie_path
        
        # Microsoft Edge
        edge_base = os.path.join(home, "Library/Application Support/Microsoft Edge/Default")
        paths["edge_history"] = os.path.join(edge_base, "History")
        edge_cookie = os.path.join(edge_base, "Network", "Cookies")
        if not os.path.exists(edge_cookie):
            edge_cookie = os.path.join(edge_base, "Cookies")
        paths["edge_cookies"] = edge_cookie
        
        # Safari
        paths["safari_history"] = os.path.join(home, "Library/Safari/History.db")
        
        # Firefox
        ff_base = os.path.join(home, "Library/Application Support/Firefox/Profiles")
        ff_profile = get_firefox_profile_dir(ff_base)
        if ff_profile:
            paths["firefox_history"] = os.path.join(ff_profile, "places.sqlite")
            paths["firefox_cookies"] = os.path.join(ff_profile, "cookies.sqlite")
            
        # Dynamic Chrome & Edge profiles on macOS
        chrome_user_data_mac = os.path.join(home, "Library/Application Support/Google/Chrome")
        if os.path.exists(chrome_user_data_mac):
            for item in os.listdir(chrome_user_data_mac):
                profile_path = os.path.join(chrome_user_data_mac, item)
                if os.path.isdir(profile_path) and (item == "Default" or item.startswith("Profile ")):
                    c_idb = os.path.join(profile_path, "IndexedDB")
                    if os.path.exists(c_idb):
                        for bot, host in [("chatgpt", "https_chatgpt.com_0"), ("claude", "https_claude.ai_0"), ("gemini", "https_gemini.google.com_0")]:
                            db_p = os.path.join(c_idb, f"{host}.indexeddb.leveldb")
                            if os.path.exists(db_p):
                                paths["indexeddb"][f"{bot}_browser_chrome_{item}"] = db_p

        edge_user_data_mac = os.path.join(home, "Library/Application Support/Microsoft Edge")
        if os.path.exists(edge_user_data_mac):
            for item in os.listdir(edge_user_data_mac):
                profile_path = os.path.join(edge_user_data_mac, item)
                if os.path.isdir(profile_path) and (item == "Default" or item.startswith("Profile ")):
                    e_idb = os.path.join(profile_path, "IndexedDB")
                    if os.path.exists(e_idb):
                        for bot, host in [("chatgpt", "https_chatgpt.com_0"), ("claude", "https_claude.ai_0"), ("gemini", "https_gemini.google.com_0")]:
                            db_p = os.path.join(e_idb, f"{host}.indexeddb.leveldb")
                            if os.path.exists(db_p):
                                paths["indexeddb"][f"{bot}_browser_edge_{item}"] = db_p
                                
        # Native Desktop Apps LevelDB locations
        paths["indexeddb"]["chatgpt_desktop"] = os.path.join(home, "Library/Application Support/com.openai.chat/IndexedDB/https_chatgpt.com_0.indexeddb.leveldb")
        paths["indexeddb"]["claude_desktop"] = os.path.join(home, "Library/Application Support/Claude/IndexedDB/https_claude.ai_0.indexeddb.leveldb")
        
    elif sys.platform == "win32":
        local_app = os.environ.get("LOCALAPPDATA", "")
        app_data = os.environ.get("APPDATA", "")
        
        # Chrome
        chrome_base = os.path.join(local_app, "Google/Chrome/User Data/Default")
        paths["chrome_history"] = os.path.join(chrome_base, "History")
        cookie_path = os.path.join(chrome_base, "Network", "Cookies")
        if not os.path.exists(cookie_path):
            cookie_path = os.path.join(chrome_base, "Cookies")
        paths["chrome_cookies"] = cookie_path
        
        # Edge
        edge_base = os.path.join(local_app, "Microsoft/Edge/User Data/Default")
        paths["edge_history"] = os.path.join(edge_base, "History")
        edge_cookie = os.path.join(edge_base, "Network", "Cookies")
        if not os.path.exists(edge_cookie):
            edge_cookie = os.path.join(edge_base, "Cookies")
        paths["edge_cookies"] = edge_cookie
        
        # Firefox
        ff_base = os.path.join(app_data, "Mozilla/Firefox/Profiles")
        ff_profile = get_firefox_profile_dir(ff_base)
        if ff_profile:
            paths["firefox_history"] = os.path.join(ff_profile, "places.sqlite")
            paths["firefox_cookies"] = os.path.join(ff_profile, "cookies.sqlite")
        
        # Dynamic Chrome & Edge profiles on Windows
        chrome_user_data_win = os.path.join(local_app, "Google/Chrome/User Data")
        if os.path.exists(chrome_user_data_win):
            for item in os.listdir(chrome_user_data_win):
                profile_path = os.path.join(chrome_user_data_win, item)
                if os.path.isdir(profile_path) and (item == "Default" or item.startswith("Profile ")):
                    c_idb = os.path.join(profile_path, "IndexedDB")
                    if os.path.exists(c_idb):
                        for bot, host in [("chatgpt", "https_chatgpt.com_0"), ("claude", "https_claude.ai_0"), ("gemini", "https_gemini.google.com_0")]:
                            db_p = os.path.join(c_idb, f"{host}.indexeddb.leveldb")
                            if os.path.exists(db_p):
                                paths["indexeddb"][f"{bot}_browser_chrome_{item}"] = db_p

        edge_user_data_win = os.path.join(local_app, "Microsoft/Edge/User Data")
        if os.path.exists(edge_user_data_win):
            for item in os.listdir(edge_user_data_win):
                profile_path = os.path.join(edge_user_data_win, item)
                if os.path.isdir(profile_path) and (item == "Default" or item.startswith("Profile ")):
                    e_idb = os.path.join(profile_path, "IndexedDB")
                    if os.path.exists(e_idb):
                        for bot, host in [("chatgpt", "https_chatgpt.com_0"), ("claude", "https_claude.ai_0"), ("gemini", "https_gemini.google.com_0")]:
                            db_p = os.path.join(e_idb, f"{host}.indexeddb.leveldb")
                            if os.path.exists(db_p):
                                paths["indexeddb"][f"{bot}_browser_edge_{item}"] = db_p
                                
        paths["indexeddb"]["chatgpt_desktop"] = os.path.join(app_data, "com.openai.chat/IndexedDB/https_chatgpt.com_0.indexeddb.leveldb")
        paths["indexeddb"]["claude_desktop"] = os.path.join(app_data, "Claude/IndexedDB/https_claude.ai_0.indexeddb.leveldb")
        
    return paths

db_copy_failures = set()

def safe_copy_db(src_path, dest_name, temp_dir, warnings_list=None):
    """Copy database file using direct copy (with WAL files) first to prevent backup hangs on Windows, falling back to SQLite Online Backup API."""
    global db_copy_failures
    if not src_path or not os.path.exists(src_path):
        return None
    
    os.makedirs(temp_dir, exist_ok=True)
    dest_path = os.path.join(temp_dir, dest_name)
    
    # Try direct copy first (extremely fast and avoids locking/backup API hangs on Windows)
    try:
        shutil.copy2(src_path, dest_path)
        wal_path = src_path + "-wal"
        shms_path = src_path + "-shm"
        if os.path.exists(wal_path):
            shutil.copy2(wal_path, dest_path + "-wal")
        if os.path.exists(shms_path):
            shutil.copy2(shms_path, dest_path + "-shm")
        if src_path in db_copy_failures:
            db_copy_failures.remove(src_path)
            print(f"[+] Access restored to {src_path} (copied successfully).")
        return dest_path
    except PermissionError as pe:
        if src_path not in db_copy_failures:
            print(f"[!] Copy failed with permission error (file locked) for {src_path}. Falling back to SQLite Backup API.")
    except Exception as e:
        if src_path not in db_copy_failures:
            print(f"[!] Copy exception for {src_path}: {e}. Falling back to SQLite Backup API.")
        
    # Fallback to SQLite Online Backup API
    try:
        src_conn = sqlite3.connect(src_path)
        dest_conn = sqlite3.connect(dest_path)
        with dest_conn:
            src_conn.backup(dest_conn)
        dest_conn.close()
        src_conn.close()
        if src_path in db_copy_failures:
            db_copy_failures.remove(src_path)
            print(f"[+] Access restored to {src_path} (replicated via SQLite Backup API).")
        return dest_path
    except PermissionError as pe:
        if src_path not in db_copy_failures:
            print(f"[!] TCC Permission Error accessing {src_path}: {pe}")
            db_copy_failures.add(src_path)
        if warnings_list is not None and "tcc_permission_denied" not in warnings_list:
            warnings_list.append("tcc_permission_denied")
        return None
    except Exception as e:
        if src_path not in db_copy_failures:
            print(f"[!] Warning: Could not replicate {src_path} using SQLite Backup API: {e}")
            db_copy_failures.add(src_path)
        return None

def parse_chrome_history(db_path):
    """Extract visits to AI platforms from history database copy."""
    results = []
    if not db_path or not os.path.exists(db_path):
        return results
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        query = """
        SELECT id, url, title, visit_count, 
               datetime(last_visit_time/1000000-11644473600, 'unixepoch', 'localtime') AS last_visited
        FROM urls 
        WHERE url LIKE '%chatgpt.com%' OR url LIKE '%claude.ai%' OR url LIKE '%gemini.google.com%'
        ORDER BY last_visit_time DESC;
        """
        cursor.execute(query)
        for row in cursor.fetchall():
            url = row[1]
            bot = "chatgpt" if "chatgpt.com" in url else "claude" if "claude.ai" in url else "gemini"
            results.append({
                "id": row[0],
                "url": url,
                "title": row[2],
                "visit_count": row[3],
                "last_visited": row[4],
                "bot": bot
            })
    except Exception as e:
        print(f"[!] History query exception: {e}")
    finally:
        if conn:
            conn.close()
    return results

def parse_chrome_cookies(db_path):
    """Extract active session cookies from cookies database copy."""
    results = []
    if not db_path or not os.path.exists(db_path):
        return results
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        query = """
        SELECT host_key, name, value, 
               datetime(expires_utc/1000000-11644473600, 'unixepoch', 'localtime') AS expires,
               is_secure 
        FROM cookies 
        WHERE (host_key LIKE '%chatgpt%' OR host_key LIKE '%claude%' OR host_key LIKE '%gemini%') 
          AND (name LIKE '%session%' OR name = '__Secure-next-auth.session-token' OR name = 'sessionKey' OR name = '__Secure-1PSID' OR name = '__Secure-3PSID');
        """
        cursor.execute(query)
        for row in cursor.fetchall():
            host = row[0]
            name = row[1]
            bot = "chatgpt" if "chatgpt" in host else "claude" if "claude" in host else "gemini"
            results.append({
                "host": host,
                "name": name,
                "value": row[2][:35] + "..." if row[2] else "N/A (Encrypted)",
                "expires": row[3],
                "secure": bool(row[4]),
                "bot": bot
            })
    except Exception as e:
        print(f"[!] Cookies query exception: {e}")
    finally:
        if conn:
            conn.close()
    return results

def parse_chrome_downloads(db_path):
    """Carve downloaded file details with AI referrals."""
    results = []
    if not db_path or not os.path.exists(db_path):
        return results
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        query = """
        SELECT d.id, d.target_path, d.received_bytes, 
               datetime(d.start_time/1000000-11644473600, 'unixepoch', 'localtime') AS download_time,
               d.state, d.tab_url, d.site_url, duc.url AS download_url
        FROM downloads d
        LEFT JOIN downloads_url_chains duc ON d.id = duc.id AND duc.chain_index = 0
        WHERE d.tab_url LIKE '%chatgpt.com%' OR d.tab_url LIKE '%claude.ai%' OR d.tab_url LIKE '%gemini.google.com%'
           OR d.site_url LIKE '%chatgpt.com%' OR d.site_url LIKE '%claude.ai%' OR d.site_url LIKE '%gemini.google.com%'
           OR duc.url LIKE '%chatgpt.com%' OR duc.url LIKE '%claude.ai%' OR duc.url LIKE '%gemini.google.com%'
        ORDER BY d.start_time DESC;
        """
        cursor.execute(query)
        for row in cursor.fetchall():
            path = row[1]
            size = row[2]
            time_str = row[3]
            state = row[4]
            tab_url = row[5]
            site_url = row[6]
            download_url = row[7] or ""
            
            bot = "chatgpt" if ("chatgpt" in tab_url or "chatgpt" in download_url) else "claude" if ("claude" in tab_url or "claude" in download_url) else "gemini"
            filename = os.path.basename(path) if path else "unknown"
            state_str = "COMPLETED" if state == 1 else "INTERRUPTED"
            
            # Live calculate hash of downloaded script/file if found
            file_hash = "N/A"
            if path and os.path.exists(path):
                file_hash = get_file_sha256(path)
                
            results.append({
                "bot": bot,
                "filename": filename,
                "target_path": path,
                "received_bytes": size,
                "download_time": time_str,
                "state": state_str,
                "hash": file_hash,
                "download_url": download_url
            })
    except Exception as e:
        print(f"[!] Downloads carve exception: {e}")
    finally:
        if conn:
            conn.close()
    return results

def parse_safari_history(db_path):
    """Extract visits to AI platforms from Safari History.db."""
    results = []
    if not db_path or not os.path.exists(db_path):
        return results
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        query = """
        SELECT i.id, i.url, v.title, v.visit_time
        FROM history_items i
        JOIN history_visits v ON i.id = v.history_item
        WHERE i.url LIKE '%chatgpt.com%' OR i.url LIKE '%claude.ai%' OR i.url LIKE '%gemini.google.com%'
        ORDER BY v.visit_time DESC;
        """
        cursor.execute(query)
        for row in cursor.fetchall():
            url = row[1]
            raw_time = row[3]
            
            if raw_time > 10000000000:
                raw_time = raw_time / 1000000.0
                
            unix_time = raw_time + 978307200
            dt = datetime.fromtimestamp(unix_time, tz=timezone.utc)
            last_visited = dt.strftime("%Y-%m-%d %H:%M:%S")
            
            bot = "chatgpt" if "chatgpt.com" in url else "claude" if "claude.ai" in url else "gemini"
            results.append({
                "id": row[0],
                "url": url,
                "title": row[2] or "Safari Visit",
                "visit_count": 1,
                "last_visited": last_visited,
                "bot": bot
            })
    except Exception as e:
        print(f"[!] Safari history query exception: {e}")
    finally:
        if conn:
            conn.close()
    return results

def parse_firefox_history(db_path):
    """Extract visits to AI platforms from Firefox places.sqlite."""
    results = []
    if not db_path or not os.path.exists(db_path):
        return results
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        query = """
        SELECT p.id, p.url, p.title, p.visit_count,
               datetime(v.visit_date/1000000, 'unixepoch', 'localtime') AS last_visited
        FROM moz_places p
        JOIN moz_historyvisits v ON p.id = v.place_id
        WHERE p.url LIKE '%chatgpt.com%' OR p.url LIKE '%claude.ai%' OR p.url LIKE '%gemini.google.com%'
        ORDER BY v.visit_date DESC;
        """
        cursor.execute(query)
        for row in cursor.fetchall():
            url = row[1]
            bot = "chatgpt" if "chatgpt.com" in url else "claude" if "claude.ai" in url else "gemini"
            results.append({
                "id": row[0],
                "url": url,
                "title": row[2] or "Firefox Visit",
                "visit_count": row[3],
                "last_visited": row[4],
                "bot": bot
            })
    except Exception as e:
        print(f"[!] Firefox history exception: {e}")
    finally:
        if conn:
            conn.close()
    return results

def parse_firefox_cookies(db_path):
    """Extract cookies from Firefox cookies.sqlite."""
    results = []
    if not db_path or not os.path.exists(db_path):
        return results
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        query = """
        SELECT host, name, value, datetime(expiry, 'unixepoch', 'localtime') AS expires, isSecure
        FROM moz_cookies
        WHERE (host LIKE '%chatgpt%' OR host LIKE '%claude%' OR host LIKE '%gemini%')
          AND (name LIKE '%session%' OR name = '__Secure-next-auth.session-token' OR name = 'sessionKey' OR name = '__Secure-1PSID' OR name = '__Secure-3PSID');
        """
        cursor.execute(query)
        for row in cursor.fetchall():
            host = row[0]
            name = row[1]
            value = row[2]
            expires = row[3]
            secure = bool(row[4])
            bot = "chatgpt" if "chatgpt" in host else "claude" if "claude" in host else "gemini"
            results.append({
                "host": host,
                "name": name,
                "value": value[:35] + "..." if value else "N/A",
                "expires": expires,
                "secure": secure,
                "bot": bot
            })
    except Exception as e:
        print(f"[!] Firefox cookies exception: {e}")
    finally:
        if conn:
            conn.close()
    return results

def scan_claude_cli_sessions(warnings_list=None):
    """Scan local ~/.claude/projects/ directory for Claude CLI session records."""
    results = []
    home = os.path.expanduser("~")
    projects_dir = os.path.join(home, ".claude", "projects")
    if not os.path.exists(projects_dir):
        return results
    try:
        for filename in os.listdir(projects_dir):
            if filename.endswith(".json"):
                file_path = os.path.join(projects_dir, filename)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        if "project_name" in data and "events" in data:
                            results.append(data)
                except PermissionError:
                    if warnings_list is not None and "tcc_permission_denied" not in warnings_list:
                        warnings_list.append("tcc_permission_denied")
                except Exception:
                    continue
    except PermissionError:
        if warnings_list is not None and "tcc_permission_denied" not in warnings_list:
            warnings_list.append("tcc_permission_denied")
    except Exception:
        pass
    return results

# --- PURE-PYTHON LEVELDB DECOMPRESSOR & SSTABLE PARSER ---
def snappy_decompress(src: bytes) -> bytes:
    """Pure-Python Snappy block decompression algorithm."""
    try:
        pos = 0
        dec_len = 0
        shift = 0
        while True:
            if pos >= len(src):
                return b""
            b = src[pos]
            pos += 1
            dec_len |= (b & 0x7f) << shift
            if not (b & 0x80):
                break
            shift += 7
            if shift >= 35:
                return b""
                
        out = bytearray()
        src_len = len(src)
        
        while pos < src_len:
            tag = src[pos]
            pos += 1
            tag_type = tag & 0x03
            
            if tag_type == 0x00:
                # Literal
                len_bits = tag >> 2
                if len_bits < 60:
                    lit_len = len_bits + 1
                elif len_bits == 60:
                    if pos + 1 > src_len: break
                    lit_len = src[pos] + 1
                    pos += 1
                elif len_bits == 61:
                    if pos + 2 > src_len: break
                    lit_len = int.from_bytes(src[pos:pos+2], 'little') + 1
                    pos += 2
                elif len_bits == 62:
                    if pos + 3 > src_len: break
                    lit_len = int.from_bytes(src[pos:pos+3], 'little') + 1
                    pos += 3
                else: # 63
                    if pos + 4 > src_len: break
                    lit_len = int.from_bytes(src[pos:pos+4], 'little') + 1
                    pos += 4
                    
                if pos + lit_len > src_len:
                    break
                out.extend(src[pos:pos+lit_len])
                pos += lit_len
            else:
                # Copy
                if tag_type == 0x01:
                    # Copy with 1-byte offset
                    lit_len = 4 + ((tag >> 2) & 0x07)
                    if pos >= src_len: break
                    offset = ((tag & 0xe0) << 3) | src[pos]
                    pos += 1
                elif tag_type == 0x02:
                    # Copy with 2-byte offset
                    lit_len = 1 + (tag >> 2)
                    if pos + 2 > src_len: break
                    offset = int.from_bytes(src[pos:pos+2], 'little')
                    pos += 2
                else: # 0x03
                    # Copy with 4-byte offset
                    lit_len = 1 + (tag >> 2)
                    if pos + 4 > src_len: break
                    offset = int.from_bytes(src[pos:pos+4], 'little')
                    pos += 4
                    
                if offset == 0 or offset > len(out):
                    break
                
                for _ in range(lit_len):
                    out.append(out[-offset])
                    
        return bytes(out)
    except Exception:
        return b""

def read_varint(data: bytes, pos: int) -> tuple:
    """Read a varint from bytes starting at position pos."""
    val = 0
    shift = 0
    while True:
        if pos >= len(data):
            break
        b = data[pos]
        pos += 1
        val |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return val, pos

def parse_block_entries(block_data: bytes) -> list:
    """Parse key-value entries in a LevelDB block."""
    entries = []
    if len(block_data) < 4:
        return entries
    try:
        num_restarts = int.from_bytes(block_data[-4:], 'little')
        restarts_offset = len(block_data) - 4 - num_restarts * 4
        if restarts_offset < 0:
            return entries
            
        pos = 0
        last_key = b""
        while pos < restarts_offset:
            shared, pos = read_varint(block_data, pos)
            unshared, pos = read_varint(block_data, pos)
            value_len, pos = read_varint(block_data, pos)
            
            key_delta = block_data[pos : pos + unshared]
            pos += unshared
            
            value = block_data[pos : pos + value_len]
            pos += value_len
            
            key = last_key[:shared] + key_delta
            last_key = key
            
            entries.append((key, value))
    except Exception:
        pass
    return entries

def parse_sstable_blocks(file_path: str) -> list:
    """Parse a LevelDB SSTable file, extracting all key-value entries."""
    entries = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            
        if len(content) < 48:
            return entries
            
        # Read footer (last 48 bytes)
        footer = content[-48:]
        magic = footer[-8:]
        if magic != b'\x57\xfb\x80\x8b\x24\x75\x47\xdb':
            return entries
            
        pos = 0
        metaindex_offset, pos = read_varint(footer, pos)
        metaindex_size, pos = read_varint(footer, pos)
        index_offset, pos = read_varint(footer, pos)
        index_size, pos = read_varint(footer, pos)
        
        index_block_data = content[index_offset : index_offset + index_size]
        
        # Check if index block itself is compressed
        if index_offset + index_size < len(content):
            index_compression_type = content[index_offset + index_size]
            if index_compression_type == 1:
                index_block_data = snappy_decompress(index_block_data)
                
        index_entries = parse_block_entries(index_block_data)
        
        for key, val in index_entries:
            block_offset, v_pos = read_varint(val, 0)
            block_size, v_pos = read_varint(val, v_pos)
            
            data_block_raw = content[block_offset : block_offset + block_size]
            if block_offset + block_size < len(content):
                compression_type = content[block_offset + block_size]
                if compression_type == 1:
                    decompressed = snappy_decompress(data_block_raw)
                    if decompressed:
                        entries.extend(parse_block_entries(decompressed))
                else:
                    entries.extend(parse_block_entries(data_block_raw))
    except Exception:
        pass
    return entries

def robust_carve_value_chats(value: bytes, bot_name: str, mtime: float = None):
    prompts = []
    conversations = []
    
    # 1. Try structured V8 array carving first
    v8_pattern = b"\x22\x08messages\x61"
    pos = 0
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    while True:
        pos = value.find(v8_pattern, pos)
        if pos == -1:
            break
            
        try:
            val_pos = pos + len(v8_pattern)
            array_len, next_pos = read_varint(value, val_pos)
            
            # Find title
            title = "Unknown Chat"
            title_pattern = b"\x22\x05title\x22"
            title_pos = value.rfind(title_pattern, max(0, pos - 600), pos)
            if title_pos != -1:
                t_val_pos = title_pos + len(title_pattern)
                t_len, t_next_pos = read_varint(value, t_val_pos)
                title = value[t_next_pos : t_next_pos + t_len].decode('utf-8', errors='ignore')
                
            # Find ID
            conv_id = "Unknown ID"
            id_pattern = b"\x22\x02id\x22"
            id_pos = value.rfind(id_pattern, max(0, pos - 1000), pos)
            if id_pos != -1:
                id_val_pos = id_pos + len(id_pattern)
                id_len, id_next_pos = read_varint(value, id_val_pos)
                conv_id = value[id_next_pos : id_next_pos + id_len].decode('utf-8', errors='ignore')
                
            messages = []
            curr_pos = next_pos
            
            for _ in range(array_len):
                # Skip to next element
                while curr_pos < len(value) and value[curr_pos] != 0x49:
                    curr_pos += 1
                if curr_pos >= len(value):
                    break
                curr_pos += 1
                idx, curr_pos = read_varint(value, curr_pos)
                
                if curr_pos >= len(value) or value[curr_pos] != 0x6f:
                    break
                curr_pos += 1
                
                msg_id = ""
                msg_text = ""
                
                depth = 0
                for _ in range(1000):
                    if curr_pos >= len(value):
                        break
                    b = value[curr_pos]
                    
                    if b == 0x7b: # Object End
                        curr_pos += 1
                        if depth == 0:
                            break
                        else:
                            depth -= 1
                        continue
                        
                    if b in (0x6f, 0x61): # Object or Array
                        depth += 1
                        curr_pos += 1
                        continue
                        
                    if b in (0x22, 0x63): # String (OneByte or TwoByte)
                        tag = b
                        curr_pos += 1
                        s_len, curr_pos = read_varint(value, curr_pos)
                        
                        if tag == 0x22:
                            val_bytes = value[curr_pos : curr_pos + s_len]
                            curr_pos += s_len
                            if depth == 0:
                                val = val_bytes.decode('utf-8', errors='ignore')
                        else:
                            val_bytes = value[curr_pos : curr_pos + s_len]
                            curr_pos += s_len
                            if depth == 0:
                                val = val_bytes.decode('utf-16le', errors='ignore')
                                
                        if depth == 0:
                            key = val
                            
                            # Parse value
                            if curr_pos < len(value):
                                while curr_pos < len(value) and value[curr_pos] == 0:
                                    curr_pos += 1
                                    
                            if curr_pos < len(value):
                                v_tag = value[curr_pos]
                                if v_tag in (0x22, 0x63):
                                    curr_pos += 1
                                    v_len, curr_pos = read_varint(value, curr_pos)
                                    if v_tag == 0x22:
                                        v_val = value[curr_pos : curr_pos + v_len].decode('utf-8', errors='ignore')
                                        curr_pos += v_len
                                    else:
                                        v_val = value[curr_pos : curr_pos + v_len].decode('utf-16le', errors='ignore')
                                        curr_pos += v_len
                                        
                                    if key == "id":
                                        msg_id = v_val
                                    elif key == "text":
                                        msg_text = v_val
                                elif v_tag in (0x6f, 0x61):
                                    # Nested object or array. Let outer loop handle it
                                    pass
                                elif v_tag == 0x4e:
                                    curr_pos += 9
                                elif v_tag in (0x49, 0x55):
                                    curr_pos += 1
                                    _, curr_pos = read_varint(value, curr_pos)
                                else:
                                    curr_pos += 1
                        continue
                        
                    if b == 0x4e:
                        curr_pos += 9
                        continue
                    if b in (0x49, 0x55):
                        curr_pos += 1
                        _, curr_pos = read_varint(value, curr_pos)
                        continue
                    curr_pos += 1
                    
                if msg_text.strip():
                    role = "user" if (idx // 2) % 2 == 1 else "assistant"
                    messages.append({
                        "id": msg_id or f"node-{conv_id}-{idx}",
                        "text": msg_text,
                        "index": idx,
                        "role": role
                    })
                    
                    prompts.append({
                        "bot": bot_name,
                        "role": role,
                        "parts": [msg_text],
                        "deleted": True,
                        "offset": pos,
                        "timestamp": timestamp
                    })
            
            if messages:
                conversations.append({
                    "id": conv_id,
                    "title": title,
                    "bot": bot_name,
                    "messages": messages,
                    "offset": pos,
                    "mtime": mtime or time.time()
                })
        except:
            pass
            
        pos += len(v8_pattern)
        
    # 2. If no structured V8 conversations were found, fall back to simple keyword carving
    if not conversations:
        title_pattern = b"\x22\x05title\x22"
        text_pattern = b"\x22\x04text\x22"
        id_pattern = b"\x22\x02id\x22"
        
        # Scan for all titles
        titles = []
        pos = 0
        while True:
            pos = value.find(title_pattern, pos)
            if pos == -1:
                break
            val_pos = pos + len(title_pattern)
            try:
                length, next_pos = read_varint(value, val_pos)
                title_str = value[next_pos : next_pos + length].decode('utf-8', errors='ignore')
                titles.append((pos, title_str))
            except:
                pass
            pos += len(title_pattern)
            
        # Scan for all messages (texts)
        messages = []
        pos = 0
        while True:
            pos = value.find(text_pattern, pos)
            if pos == -1:
                break
            val_pos = pos + len(text_pattern)
            try:
                length, next_pos = read_varint(value, val_pos)
                msg_str = value[next_pos : next_pos + length].decode('utf-8', errors='ignore')
                
                # Find message ID by scanning backward
                msg_id = "client-created-root"
                id_pos = value.rfind(id_pattern, max(0, pos - 150), pos)
                if id_pos != -1:
                    id_val_pos = id_pos + len(id_pattern)
                    id_len, id_next_pos = read_varint(value, id_val_pos)
                    msg_id = value[id_next_pos : id_next_pos + id_len].decode('utf-8', errors='ignore')
                    
                messages.append((pos, msg_id, msg_str))
            except:
                pass
            pos += len(text_pattern)
            
        if messages:
            # Group messages by preceding title
            conv_groups = {}
            for m_pos, m_id, m_text in messages:
                if not m_text.strip():
                    continue
                    
                # Find preceding title
                preceding_title = None
                for t_pos, t_str in reversed(titles):
                    if t_pos < m_pos:
                        # Find conversation ID
                        conv_id = "Unknown ID"
                        id_pos = value.rfind(id_pattern, max(0, t_pos - 150), t_pos)
                        if id_pos != -1:
                            id_val_pos = id_pos + len(id_pattern)
                            id_len, id_next_pos = read_varint(value, id_val_pos)
                            conv_id = value[id_next_pos : id_next_pos + id_len].decode('utf-8', errors='ignore')
                        preceding_title = (t_str, conv_id, t_pos)
                        break
                        
                if preceding_title:
                    t_str, conv_id, t_pos = preceding_title
                    block_key = (conv_id, t_str, t_pos)
                else:
                    block_key = ("Unknown ID", "Active Live Session", 0)
                    
                if block_key not in conv_groups:
                    conv_groups[block_key] = []
                conv_groups[block_key].append((m_id, m_text))
                
                role = "user"
                if len(conv_groups[block_key]) % 2 == 0:
                    role = "assistant"
                    
                prompts.append({
                    "bot": bot_name,
                    "role": role,
                    "parts": [m_text],
                    "deleted": True,
                    "offset": m_pos,
                    "timestamp": timestamp
                })
                
            for (conv_id, t_str, t_pos), msgs in conv_groups.items():
                if conv_id == "Unknown ID" and len(msgs) <= 1:
                    continue
                msg_list = []
                for idx, (m_id, m_text) in enumerate(msgs):
                    msg_list.append({
                        "id": m_id,
                        "text": m_text,
                        "index": idx + 1
                    })
                conversations.append({
                    "id": conv_id,
                    "title": t_str,
                    "bot": bot_name,
                    "messages": msg_list,
                    "offset": t_pos,
                    "mtime": mtime or time.time()
                })
                
    return prompts, conversations

def carve_leveldb_deleted_data(leveldb_dir, bot_name, warnings_list=None):
    """Scan LevelDB directories directly, parsing SSTables and logs to extract prompts and trace deletions."""
    prompts = []
    conversations = []
    if not leveldb_dir or not os.path.exists(leveldb_dir):
        return prompts, conversations
        
    all_convs = []
    try:
        for file in os.listdir(leveldb_dir):
            if file.endswith(('.log', '.ldb', '.sst')):
                file_path = os.path.join(leveldb_dir, file)
                try:
                    entries = []
                    if file.endswith(('.ldb', '.sst')):
                        entries = parse_sstable_blocks(file_path)
                    else:
                        with open(file_path, 'rb') as f:
                            log_content = f.read()
                        entries = [(b"log_dummy_key_seq_type_01", log_content)]
                        
                    mtime = os.path.getmtime(file_path)
                    for key, value in entries:
                        if len(value) < 100:
                            continue
                        v_prompts, v_convs = robust_carve_value_chats(value, bot_name, mtime)
                        prompts.extend(v_prompts)
                        all_convs.extend(v_convs)
                except PermissionError:
                    if warnings_list is not None and "tcc_permission_denied" not in warnings_list:
                        warnings_list.append("tcc_permission_denied")
                except Exception:
                    continue
                    
        # Deduplicate conversations
        deduped = {}
        for c in all_convs:
            conv_key = (c["id"], c["title"])
            if conv_key not in deduped or len(c["messages"]) > len(deduped[conv_key]["messages"]):
                deduped[conv_key] = c
        conversations = list(deduped.values())
        
    except PermissionError:
        if warnings_list is not None and "tcc_permission_denied" not in warnings_list:
            warnings_list.append("tcc_permission_denied")
    except Exception:
        pass
        
    return prompts, conversations

def sign_payload_raw(payload, key):
    """HMAC signature computation with canonical sorting."""
    serialized = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    signature = hmac.new(key, serialized.encode('utf-8'), hashlib.sha256).hexdigest()
    return signature

def sign_evidence(payload, key):
    """Wrapper that returns the anti-tamper evidence envelope."""
    serialized = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    mac = hmac.new(key, serialized, hashlib.sha256).hexdigest()
    return {
        "payload": payload,
        "hmac_sha256": mac,
        "key_version": key_version,
        "timestamp": time.time()
    }

def clean_temp(temp_dir):
    """Clean workspace."""
    if os.path.exists(temp_dir):
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass

def check_binary_signature(filepath):
    """Checks if a binary is signed on macOS and Windows."""
    if not filepath or not os.path.exists(filepath):
        return "N/A"
        
    if sys.platform == "win32":
        system_prefixes = [os.environ.get("SystemRoot", "C:\\Windows"), os.environ.get("ProgramFiles", "C:\\Program Files")]
        if any(filepath.lower().startswith(p.lower()) for p in system_prefixes):
            return "Signed (System)"
        try:
            escaped_path = filepath.replace("'", "''")
            cmd = ['powershell', '-NoProfile', '-Command', f"(Get-AuthenticodeSignature '{escaped_path}').Status"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if "Valid" in res.stdout:
                return "Signed"
            else:
                return "Unsigned"
        except Exception:
            return "Unsigned"
    else:
        # Optimise system paths to speed up scans
        system_prefixes = ["/System", "/usr", "/bin", "/sbin", "/Library/Apple", "/Applications/Xcode.app"]
        if any(filepath.startswith(p) for p in system_prefixes):
            return "Signed (System)"
        try:
            res = subprocess.run(["codesign", "-dv", filepath], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                return "Signed"
            else:
                return "Unsigned"
        except Exception:
            return "Unsigned"

_threats_cache = {"data": None, "ts": 0}

def perform_threat_scan():
    """Performs real-world threat hunting and memory diagnostics on macOS."""
    global _threats_cache
    if _threats_cache["data"] is not None and (time.time() - _threats_cache["ts"] < 30):
        return _threats_cache["data"]

    # 1. Audit System details
    uid = "N/A"
    try:
        uid = os.getuid()
    except AttributeError:
        pass
        
    import getpass
    username = getpass.getuser()
    
    sip_enabled = True
    tcc_full_disk = False
    sudo_access = "Unknown"
    is_root = False
    
    if sys.platform == "win32":
        sip_enabled = "N/A (Windows)"
        tcc_full_disk = "N/A (Windows)"
        try:
            import ctypes
            is_root = ctypes.windll.shell32.IsUserAnAdmin() != 0
            sudo_access = "Admin" if is_root else "Standard User"
        except Exception:
            pass
    else:
        is_root = (uid == 0)
        try:
            res = subprocess.run(["csrutil", "status"], capture_output=True, text=True, timeout=2)
            if "disabled" in res.stdout.lower():
                sip_enabled = False
        except Exception:
            pass
            
        safari_dir = os.path.expanduser("~/Library/Safari")
        tcc_full_disk = os.path.exists(safari_dir) and os.access(safari_dir, os.R_OK)
        
        sudo_access = "Required"
        try:
            import grp
            sudo_group = [g for g in grp.getgrall() if g.gr_name == 'admin']
            is_admin = username in (sudo_group[0].gr_mem if sudo_group else [])
            if is_admin:
                sudo_access = "Admin Group Member"
        except Exception:
            pass
            
    system_status = {
        "sip_enabled": sip_enabled,
        "uid": uid,
        "username": username,
        "is_root": is_root,
        "sudo_access": sudo_access,
        "tcc_full_disk": tcc_full_disk,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # 2. Process threat hunt
    processes = []
    try:
        if sys.platform == "win32":
            cmd = ['powershell', '-NoProfile', '-Command', "Get-Process | Select-Object Id, Name, Path, CPU, WorkingSet | ConvertTo-Json -Compress"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if res.returncode == 0 and res.stdout.strip():
                try:
                    proc_list = json.loads(res.stdout)
                    if isinstance(proc_list, dict):
                        proc_list = [proc_list]
                    for p in proc_list:
                        pid = p.get("Id", 0)
                        ppid = 0
                        name = p.get("Name", "Unknown")
                        path = p.get("Path") or ""
                        cpu_val = p.get("CPU")
                        cpu = float(cpu_val) if cpu_val else 0.0
                        mem_val = p.get("WorkingSet")
                        mem = float(mem_val) / (1024*1024) if mem_val else 0.0
                        user = username
                        
                        risk = "LOW"
                        rules = []
                        details = ""
                        
                        temp_prefixes = [os.environ.get("TEMP", "C:\\Temp").lower(), os.environ.get("TMP", "C:\\Tmp").lower()]
                        if path and any(path.lower().startswith(temp) for temp in temp_prefixes):
                            risk = "HIGH"
                            rules.append("Execution from Temporary Directory")
                            details += f"Binary resides in temporary folder: {path}. "
                            
                        if path and (os.environ.get("USERPROFILE", "C:\\Users").lower() in path.lower() or "appdata" in path.lower()):
                            sig = check_binary_signature(path)
                            if sig == "Unsigned":
                                if risk != "HIGH":
                                    risk = "MEDIUM"
                                rules.append("Unsigned Binary in User Space")
                                details += "Binary is not cryptographically signed. "
                        
                        system_binary_names = ["svchost", "lsass", "csrss", "smss", "winlogon", "explorer"]
                        if name.lower() in system_binary_names:
                            system_prefixes = [os.environ.get("SystemRoot", "C:\\Windows").lower()]
                            if path and not any(path.lower().startswith(system) for system in system_prefixes):
                                risk = "HIGH"
                                rules.append("Hidden Process Masking")
                                details += f"Process matches system name '{name}' but runs from non-system path: {path}. "
                                
                        hacking_names = ["nc", "ncat", "netcat", "socat", "mimikatz", "cobaltstrike", "reverse_shell", "payload", "exploit", "gobuster", "nmap", "powershell"]
                        if any(hn in name.lower() for hn in hacking_names):
                            if name.lower() != "powershell" or risk != "LOW":
                                risk = "HIGH" if name.lower() != "powershell" else "MEDIUM"
                                rules.append("Known Pentest / Hacking Tool")
                                details += f"Process name matches security testing or exploit tool keyword. "
                                
                        interpreter_names = ["python", "python3", "perl", "ruby", "node", "pwsh", "cmd"]
                        if name.lower() in interpreter_names and (cpu > 20.0 or mem > 100.0):
                            risk = "MEDIUM" if risk == "LOW" else risk
                            rules.append("High-Resource Script Interpreter")
                            details += f"Script interpreter is using high CPU ({cpu:.1f}%) or memory ({mem:.1f}MB). "

                        processes.append({
                            "pid": pid,
                            "ppid": ppid,
                            "user": user,
                            "cpu": round(cpu, 1),
                            "mem": round(mem, 1),
                            "name": name,
                            "path": path,
                            "risk": risk,
                            "rules": rules,
                            "details": details or "No anomalies detected."
                        })
                except Exception as e:
                    print(f"[!] Windows process JSON parse failed: {e}")
        else:
            res = subprocess.run(["ps", "-ax", "-o", "pid,ppid,user,%cpu,%mem,comm"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                lines = res.stdout.strip().split('\n')
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = line.strip().split(None, 5)
                    if len(parts) < 6:
                        continue
                    try:
                        pid = int(parts[0])
                        ppid = int(parts[1])
                        user = parts[2]
                        cpu = float(parts[3])
                        mem = float(parts[4])
                        path = parts[5]
                        name = os.path.basename(path)
                        
                        risk = "LOW"
                        rules = []
                        details = ""
                        
                        temp_prefixes = ["/tmp/", "/var/tmp/", "/private/tmp/", "/private/var/tmp/"]
                        if any(path.startswith(p) for p in temp_prefixes):
                            risk = "HIGH"
                            rules.append("Execution from Temporary Directory")
                            details += f"Binary resides in temporary folder: {path}. "
                            
                        if "/Users/" in path or "/var/folders/" in path:
                            sig = check_binary_signature(path)
                            if sig == "Unsigned":
                                if risk != "HIGH":
                                    risk = "MEDIUM"
                                rules.append("Unsigned Binary in User Space")
                                details += "Binary is not cryptographically signed. "
                        
                        system_binary_names = ["launchd", "kernel_task", "syslogd", "opendirectoryd", "configd", "logd"]
                        if name in system_binary_names:
                            system_prefixes = ["/System", "/usr", "/bin", "/sbin", "/Library/Apple"]
                            if not any(path.startswith(p) for p in system_prefixes):
                                risk = "HIGH"
                                rules.append("Hidden Process Masking")
                                details += f"Process matches system name '{name}' but runs from user/non-system path: {path}. "
                                
                        hacking_names = ["nc", "ncat", "netcat", "socat", "mimikatz", "cobaltstrike", "reverse_shell", "payload", "exploit", "gobuster", "nmap"]
                        if any(hn in name.lower() for hn in hacking_names):
                            risk = "HIGH"
                            rules.append("Known Pentest / Hacking Tool")
                            details += f"Process name matches security testing or exploit tool keyword. "
                            
                        interpreter_names = ["python", "python3", "perl", "ruby", "node"]
                        if name in interpreter_names and (cpu > 20.0 or mem > 15.0):
                            risk = "MEDIUM"
                            rules.append("High-Resource Script Interpreter")
                            details += f"Script interpreter is using high CPU ({cpu}%) or memory ({mem}%). "

                        processes.append({
                            "pid": pid,
                            "ppid": ppid,
                            "user": user,
                            "cpu": cpu,
                            "mem": mem,
                            "name": name,
                            "path": path,
                            "risk": risk,
                            "rules": rules,
                            "details": details or "No anomalies detected."
                        })
                    except Exception:
                        pass
    except Exception as e:
        print(f"[!] Process scan failed: {e}")

    # 3. Active Sockets Hunt
    sockets = []
    try:
        if sys.platform == "win32":
            res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                lines = res.stdout.strip().split('\n')
                for line in lines[4:]:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        try:
                            proto = parts[0]
                            local = parts[1]
                            remote = parts[2]
                            if proto == "TCP":
                                state = parts[3]
                                pid = int(parts[4])
                            else:
                                state = "N/A"
                                pid = int(parts[3])
                                
                            cmd = next((p["name"] for p in processes if p["pid"] == pid), "Unknown")
                            risk = "LOW"
                            user = username
                            typ = "IPv4" if "127.0.0.1" in local or "." in local else "IPv6"
                            
                            if remote != "0.0.0.0:0" and remote != "[::]:0" and not any(l in remote for l in ["127.0.0.1", "localhost", "::1", "0.0.0.0", "*:*"]):
                                port = remote.split(":")[-1] if ":" in remote else ""
                                if port and port not in ["80", "443", "8080", "3000", "5000", "8000"]:
                                    risk = "MEDIUM"
                                    
                            sockets.append({
                                "command": cmd,
                                "pid": pid,
                                "user": user,
                                "proto": proto,
                                "type": typ,
                                "local": local,
                                "remote": remote,
                                "state": state,
                                "risk": risk
                            })
                        except Exception:
                            pass
        else:
            res = subprocess.run(["lsof", "-i", "-n", "-P"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                lines = res.stdout.strip().split('\n')
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = line.strip().split(None, 8)
                    if len(parts) < 9:
                        continue
                    try:
                        cmd = parts[0]
                        pid = int(parts[1])
                        user = parts[2]
                        fd = parts[3]
                        typ = parts[4]
                        dev = parts[5]
                        sz = parts[6]
                        proto = parts[7]
                        name_col = parts[8]
                        
                        local = ""
                        remote = ""
                        state = "LISTEN"
                        risk = "LOW"
                        
                        if "->" in name_col:
                            local_part, remote_part = name_col.split("->", 1)
                            local = local_part.strip()
                            if "(" in remote_part:
                                r_addr, st = remote_part.strip().split(" ", 1)
                                remote = r_addr.strip()
                                state = st.replace("(", "").replace(")", "").strip()
                            else:
                                remote = remote_part.strip()
                                state = "ESTABLISHED"
                        else:
                            local = name_col.strip()
                            remote = "*"
                            if "(" in local:
                                l_addr, st = local.split(" ", 1)
                                local = l_addr.strip()
                                state = st.replace("(", "").replace(")", "").strip()
                        
                        shell_interpreters = ["sh", "bash", "zsh", "python", "python3", "perl", "ruby", "nc", "netcat", "ncat", "socat"]
                        if cmd.lower() in shell_interpreters:
                            risk = "HIGH"
                            
                        if remote != "*" and not any(l in remote for l in ["127.0.0.1", "localhost", "::1", "0.0.0.0"]):
                            port = remote.split(":")[-1] if ":" in remote else ""
                            if port and port not in ["80", "443", "8080", "3000", "5000", "8000"]:
                                risk = "MEDIUM" if risk != "HIGH" else "HIGH"
                                
                        sockets.append({
                            "command": cmd,
                            "pid": pid,
                            "user": user,
                            "proto": proto,
                            "type": typ,
                            "local": local,
                            "remote": remote,
                            "state": state,
                            "risk": risk
                        })
                    except Exception:
                        pass
    except Exception as e:
        print(f"[!] Sockets scan failed: {e}")

    # 4. Shell Commands History Audit
    commands = []
    if sys.platform == "win32":
        history_paths = [
            os.path.expanduser(r"~\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
        ]
    else:
        history_paths = [
            os.path.expanduser("~/.zsh_history"),
            os.path.expanduser("~/.bash_history")
        ]
    for hp in history_paths:
        if os.path.exists(hp):
            try:
                with open(hp, 'rb') as f:
                    raw = f.read().replace(b'\x00', b'').decode('utf-8', errors='replace')
                lines = raw.split('\n')
                for line in lines[-200:]:
                    line = line.strip()
                    if not line:
                        continue
                        
                    timestamp = "N/A"
                    cmd_str = line
                    
                    if line.startswith(": ") and ";" in line:
                        try:
                            meta, cmd_str = line.split(";", 1)
                            epoch = meta.split(":")[1].strip()
                            timestamp = datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            pass
                            
                    suspicious = False
                    category = "None"
                    reason = ""
                    
                    if any(k in cmd_str for k in ["history -c", "history -w", "unset HISTFILE", "rm .zsh_history", "rm .bash_history"]):
                        suspicious = True
                        category = "Defense Evasion"
                        reason = "Log wiper command sequence detected."
                    elif any(k in cmd_str for k in ["nc -e", "nc -l", "ncat", "socat", "/dev/tcp/", "socket.socket", "subprocess.Popen"]):
                        suspicious = True
                        category = "Reverse Shell"
                        reason = "Network socket execution parameters detected."
                    elif ("curl" in cmd_str or "wget" in cmd_str) and ("|" in cmd_str or "chmod" in cmd_str or " -o" in cmd_str or " -O" in cmd_str):
                        suspicious = True
                        category = "Download & Execute"
                        reason = "Piped script download and execution indicator."
                    elif any(k in cmd_str for k in ["sudo -i", "sudo -s", "su root", "chmod +s", "chmod 4755"]):
                        suspicious = True
                        category = "Privilege Escalation"
                        reason = "Superuser promotion shell request."
                        
                    commands.append({
                        "command": cmd_str,
                        "timestamp": timestamp,
                        "suspicious": suspicious,
                        "category": category,
                        "reason": reason
                    })
            except Exception as e:
                print(f"[!] History parse failed for {hp}: {e}")
                
    commands.reverse()

    scan_results = {
        "system": system_status,
        "processes": processes,
        "sockets": sockets,
        "history": commands[:150]
    }
    _threats_cache.update({"data": scan_results, "ts": time.time()})
    return scan_results

# --- THREAD-SAFE MULTI-THREADED HTTP PORT SERVER ---
class ForensicHTTPServer(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        # Log requests to stderr for daemon.log visibility
        sys.stderr.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTTP {self.address_string()}: {format % args}\n")

    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Private-Network', 'true')
        super().end_headers()

    def check_auth(self):
        token = self.headers.get('X-Bootstrap-Token')
        if token != BOOTSTRAP_TOKEN:
            self.send_response(403)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Forbidden - Invalid Bootstrap Token"}).encode('utf-8'))
            return False
        return True

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'X-Bootstrap-Token, Content-Type')
        self.end_headers()

    def do_GET(self):
        if self.path == '/session_key':
            if not self.check_auth():
                return
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"key_hex": session_hmac_key.hex()}).encode('utf-8'))
            

            
        elif self.path == '/classifier_weights.json':
            if not self.check_auth():
                return
                
            weights_payload = {
                "version": "1.0",
                "calibrated_against": ["claude-3.5-sonnet", "gpt-4o", "gemini-1.5-pro"],
                "corpus_size": 150,
                "weights": {
                    "claude": { "docstring_ratio": 0.45, "type_annotation": 0.35, "snake_case_ratio": 0.20 },
                    "chatgpt": { "comment_density": 0.50, "entry_point": 0.30, "double_quote_ratio": 0.20 },
                    "gemini": { "single_quote_ratio": 0.60, "modular_structure": 0.40 },
                    "human": { "naming_inconsistency": 0.55, "generic_variables": 0.45 }
                },
                "overlap_warnings": ["claude_chatgpt_double_quote", "version_calibration"]
            }
            
            # HMAC-sign
            sig = sign_payload_raw(weights_payload, session_hmac_key)
            envelope = {
                "payload": weights_payload,
                "hmac_sha256": sig
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(envelope).encode('utf-8'))
            
        elif self.path == '/threats_scan':
            if not self.check_auth():
                return
            
            scan_results = perform_threat_scan()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(scan_results).encode('utf-8'))
            
        elif self.path.startswith('/live_evidence.json'):
            if not self.check_auth():
                return
            super().do_GET()
            
        else:
            super().do_GET()

class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

def main():
    parser = argparse.ArgumentParser(description="Next-Level Chromium & Native App AI Forensics Daemon")
    parser.add_argument("-i", "--interval", type=int, default=3, help="Polling interval (default: 3)")
    parser.add_argument("-e", "--encrypted-key", action="store_true", help="Decrypt Ed25519 PEM key at startup")
    args = parser.parse_args()
    
    print_banner()
    
    # Bootstrap Token & Dynamic Session Key Setup
    global BOOTSTRAP_TOKEN, session_hmac_key, key_version, DECRYPTED_PRIVATE_KEY
    BOOTSTRAP_TOKEN = secrets.token_hex(16)
    session_hmac_key = os.urandom(32)
    key_version = 1
    
    home = os.path.expanduser("~")
    ai_forensics_dir = os.path.join(home, ".ai-forensics")
    os.makedirs(ai_forensics_dir, exist_ok=True)
    with open(os.path.join(ai_forensics_dir, ".session_hmac_key"), 'w') as f:
        f.write(session_hmac_key.hex())
        
    print(f"\n{GREEN}[BOOTSTRAP] Dashboard token: {BOOTSTRAP_TOKEN}{RESET}\n")
    
    # Encrypted private key startup loading
    if args.encrypted_key:
        import getpass
        try:
            slsa_dir = os.path.join(os.path.expanduser("~"), "slsa-agentic")
            passphrase = getpass.getpass(f"Enter passphrase for {os.path.join(slsa_dir, 'slsa_agentic_ed25519.enc.pem')}: ")
            enc_key_path = os.path.join(slsa_dir, "slsa_agentic_ed25519.enc.pem")
            
            # Decrypt PEM using cryptography library in-memory
            with open(enc_key_path, 'rb') as f:
                enc_bytes = f.read()
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            DECRYPTED_PRIVATE_KEY = load_pem_private_key(enc_bytes, password=passphrase.encode('utf-8'))
            print(f"{GREEN}[+] Decrypted private key loaded in-memory successfully.{RESET}")
        except Exception as e:
            print(f"{RED}[!] Key decryption failed: {e}{RESET}")
            sys.exit(1)
    else:
        # Load plaintext key if it exists
        slsa_dir = os.path.join(os.path.expanduser("~"), "slsa-agentic")
        plaintext_key = os.path.join(slsa_dir, "slsa_agentic_ed25519.pem")
        if os.path.exists(plaintext_key):
            try:
                with open(plaintext_key, 'rb') as f:
                    pem_bytes = f.read()
                from cryptography.hazmat.primitives.serialization import load_pem_private_key
                DECRYPTED_PRIVATE_KEY = load_pem_private_key(pem_bytes, password=None)
                print(f"{GREEN}[+] Plaintext private key loaded in-memory successfully.{RESET}")
            except Exception as e:
                print(f"{YELLOW}[!] Plaintext key found but could not load: {e}{RESET}")

    # Start multi-threaded local static HTTP & loopback API server
    def start_local_server():
        try:
            server = ThreadingHTTPServer(('127.0.0.1', 8000), ForensicHTTPServer)
            server.serve_forever()
        except Exception as e:
            print(f"{RED}[!] Server error: {e}{RESET}")
            
    srv_thread = threading.Thread(target=start_local_server, daemon=True)
    srv_thread.start()
    print(f"{GREEN}[+] static dashboard webserver & APIs listening on http://127.0.0.1:8000/index.html?token={BOOTSTRAP_TOKEN}{RESET}")

    # Automatically launch dashboard in default browser with the correct token
    import webbrowser
    def open_browser():
        time.sleep(1.0)
        url = f"http://127.0.0.1:8000/index.html?token={BOOTSTRAP_TOKEN}"
        try:
            webbrowser.open(url)
        except Exception as e:
            print(f"{YELLOW}[!] Failed to auto-open browser: {e}{RESET}")
            
    threading.Thread(target=open_browser, daemon=True).start()

    forensic_paths = get_forensic_paths()
    temp_dir = "./_temp_forensic_extract"
    os.makedirs(temp_dir, exist_ok=True)
    
    active_monitors = []
    for bot_key, dir_path in forensic_paths["indexeddb"].items():
        if os.path.exists(dir_path):
            active_monitors.append(bot_key)
            print(f"[*] Detected LevelDB path for {bot_key}: {dir_path}")
            
    last_state = {
        "history": [],
        "cookies": [],
        "prompts": [],
        "downloads": [],
        "claudecode": [],
        "clipboard": ""
    }
    
    logs = [
        f"{datetime.now().strftime('%H:%M:%S')} [SYS] Live Forensic Monitor Daemon Active",
        f"{datetime.now().strftime('%H:%M:%S')} [SYS] Scanners active. Monitoring system clipboard..."
    ]
    
    last_rotation = time.time()
    try:
        while True:
            # Key rotation check
            if time.time() - last_rotation > 3600:
                session_hmac_key = os.urandom(32)
                key_version += 1
                with open(os.path.join(ai_forensics_dir, ".session_hmac_key"), 'w') as f:
                    f.write(session_hmac_key.hex())
                last_rotation = time.time()
                print(f"{YELLOW}[*] Key Rotated. Version: {key_version}{RESET}")
                logs.append(f"{datetime.now().strftime('%H:%M:%S')} [KEY] HMAC session key rotated (v{key_version})")
                
            warnings_list = []
            
            hist_tmp = safe_copy_db(forensic_paths["chrome_history"], "History.tmp", temp_dir, warnings_list)
            cook_tmp = safe_copy_db(forensic_paths["chrome_cookies"], "Cookies.tmp", temp_dir, warnings_list)
            edge_hist_tmp = safe_copy_db(forensic_paths["edge_history"], "Edge_History.tmp", temp_dir, warnings_list)
            edge_cook_tmp = safe_copy_db(forensic_paths["edge_cookies"], "Edge_Cookies.tmp", temp_dir, warnings_list)
            ff_hist_tmp = safe_copy_db(forensic_paths["firefox_history"], "FF_History.tmp", temp_dir, warnings_list)
            ff_cook_tmp = safe_copy_db(forensic_paths["firefox_cookies"], "FF_Cookies.tmp", temp_dir, warnings_list)
            safari_hist_tmp = safe_copy_db(forensic_paths["safari_history"], "Safari_History.tmp", temp_dir, warnings_list)
            
            history_hash = get_file_sha256(hist_tmp) if hist_tmp else "N/A"
            cookies_hash = get_file_sha256(cook_tmp) if cook_tmp else "N/A"
            
            history = []
            cookies = []
            downloads = []
            
            if hist_tmp:
                history.extend(parse_chrome_history(hist_tmp))
                downloads.extend(parse_chrome_downloads(hist_tmp))
            if cook_tmp:
                cookies.extend(parse_chrome_cookies(cook_tmp))
                
            if edge_hist_tmp:
                history.extend(parse_chrome_history(edge_hist_tmp))
                downloads.extend(parse_chrome_downloads(edge_hist_tmp))
            if edge_cook_tmp:
                cookies.extend(parse_chrome_cookies(edge_cook_tmp))
                
            if ff_hist_tmp:
                history.extend(parse_firefox_history(ff_hist_tmp))
            if ff_cook_tmp:
                cookies.extend(parse_firefox_cookies(ff_cook_tmp))
                
            if safari_hist_tmp:
                history.extend(parse_safari_history(safari_hist_tmp))
                
            prompts = []
            conversations = []
            for bot_key in active_monitors:
                bot_name = bot_key.split('_')[0]
                dir_path = forensic_paths["indexeddb"][bot_key]
                bot_prompts, bot_convs = carve_leveldb_deleted_data(dir_path, bot_name, warnings_list)
                prompts.extend(bot_prompts)
                conversations.extend(bot_convs)
                
            claudecode_sessions = scan_claude_cli_sessions(warnings_list)
            
            clip_text = get_system_clipboard()
            if clip_text and clip_text != last_state["clipboard"]:
                ai_terms = ["chatgpt", "claude", "gemini", "prompt", "exploit", "cve", "payload", "cookie", "session"]
                if any(term in clip_text.lower() for term in ai_terms) or len(clip_text) > 40:
                    clip_summary = clip_text[:60].replace('\n', ' ') + "..."
                    logs.append(f"{datetime.now().strftime('%H:%M:%S')} [CLIPBOARD] Captured copy-paste content: '{clip_summary}'")
                    print(f"{YELLOW}[+] Clipboard Scraped: {clip_summary}{RESET}")
                    
                    prompts.append({
                        "bot": "system_clipboard",
                        "role": "user",
                        "parts": [f"Clipboard Capture: {clip_text}"],
                        "deleted": False,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                last_state["clipboard"] = clip_text
                
            if len(history) > len(last_state["history"]):
                diff = len(history) - len(last_state["history"])
                logs.append(f"{datetime.now().strftime('%H:%M:%S')} [HASH] History DB SHA-256: {history_hash[:20]}...")
                logs.append(f"{datetime.now().strftime('%H:%M:%S')} [DB] Scraped {diff} new history visits to AI portals.")
                print(f"{CYAN}[+] History update. Hash: {history_hash[:20]}{RESET}")
                
            if len(cookies) > len(last_state["cookies"]):
                diff = len(cookies) - len(last_state["cookies"])
                logs.append(f"{datetime.now().strftime('%H:%M:%S')} [HASH] Cookies DB SHA-256: {cookies_hash[:20]}...")
                logs.append(f"{datetime.now().strftime('%H:%M:%S')} [DB] Scraped {diff} new session credentials.")
                print(f"{CYAN}[+] Cookie update. Hash: {cookies_hash[:20]}{RESET}")
                
            if len(downloads) > len(last_state["downloads"]):
                diff = len(downloads) - len(last_state["downloads"])
                logs.append(f"{datetime.now().strftime('%H:%M:%S')} [DOWNLOAD] Scraped {diff} new file downloads.")
                print(f"{GREEN}[+] Carved downloads update: {diff} new files.{RESET}")
                
            if len(prompts) > len(last_state["prompts"]):
                diff = len(prompts) - len(last_state["prompts"])
                deleted_diff = sum(1 for p in prompts if p["deleted"]) - sum(1 for p in last_state["prompts"] if p["deleted"])
                active_diff = diff - deleted_diff
                
                if active_diff > 0:
                    logs.append(f"{datetime.now().strftime('%H:%M:%S')} [MEM] Carved {active_diff} active prompts.")
                if deleted_diff > 0:
                    logs.append(f"{datetime.now().strftime('%H:%M:%S')} {RED}[LEVELDB CARVE] Scraped {deleted_diff} DELETED chats!{RESET}")
                    print(f"{RED}[+] Scraped {deleted_diff} DELETED chats!{RESET}")
            
            last_state["history"] = history
            last_state["cookies"] = cookies
            last_state["prompts"] = prompts
            last_state["downloads"] = downloads
            
            payload = {
                "status": "MONITOR_ACTIVE",
                "last_sync": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                "logs": logs[-18:],
                "history": history,
                "cookies": cookies,
                "prompts": prompts,
                "conversations": conversations,
                "downloads": downloads,
                "claudecode_sessions": claudecode_sessions,
                "hashes": {
                    "history": history_hash,
                    "cookies": cookies_hash
                },
                "warnings": warnings_list
            }
            
            # Wrap live evidence inside secure envelope
            envelope = sign_evidence(payload, session_hmac_key)
            
            with open("live_evidence.json", 'w', encoding='utf-8') as f:
                json.dump(envelope, f, indent=2)
                
            time.sleep(args.interval)
            
    except KeyboardInterrupt:
        print(f"\n{RED}[*] Daemon stopped by investigator. Cleaning workspace.{RESET}")
        clean_temp(temp_dir)
        sys.exit(0)

if __name__ == "__main__":
    main()
