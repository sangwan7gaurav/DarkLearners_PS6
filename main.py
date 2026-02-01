import sys
import os
import subprocess
import hashlib
import json
import datetime
import shutil
import time
import tempfile
import magic
import random       # <--- Added for Tab 6
import webbrowser

# -----------------------------------------------------------------------------
# CONFIGURATION & IMPORTS
# -----------------------------------------------------------------------------
# GET A FREE KEY AT: https://www.virustotal.com/gui/join-us
VT_API_KEY = "61f033aaa13db3074c1b5c5109b9569b60b644e55be809b9059781aa0b1f8197" 

try:
    import requests
    # --- EXISTING IMPORTS ---
    from PyQt6.QtWidgets import (QApplication, QWidget, QMainWindow, QPushButton, QTextEdit,
                                 QVBoxLayout, QHBoxLayout, QTabWidget, QLabel, QTableWidget, 
                                 QTableWidgetItem, QHeaderView, QProgressBar, QListWidget,
                                 QSplitter, QMessageBox, QFrame, QFileDialog, QComboBox, QGridLayout)
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl  # <--- Added QUrl
    from PyQt6.QtGui import QColor, QFont, QPalette

    # --- NEW IMPORTS REQUIRED FOR TAB 6 ---
    from PyQt6.QtWebEngineWidgets import QWebEngineView     # <--- Fixes NameError
    import folium                                           # <--- Required for Map
    import exifread                                         # <--- Required for GPS Extraction
    from geopy.geocoders import Nominatim                   # <--- Required for City names

except ImportError as e:
    print("CRITICAL: Missing dependencies.")
    print(f"Error: {e}")
    # Update the install command to include the new libraries
    print("Run: pip3 install requests PyQt6 PyQt6-WebEngine folium exifread geopy")
    sys.exit(1)

# =============================================================================
#  BACKEND: ADB & FORENSIC LOGIC
# =============================================================================

class ADBConnector:
    """Handles ADB connections, optimized for macOS."""
    adb_path = "adb"

    @staticmethod
    def find_adb():
        """Auto-detects ADB path."""
        # 1. Check if adb is in the current directory (preferred for self-contained apps)
        if os.path.exists("adb.exe"): return os.path.abspath("adb.exe")
        
        # 2. Check PATH
        if shutil.which("adb"): return "adb"
        
        # 3. Check Common Windows Paths
        possible_paths = [
            os.path.expanduser("~\\AppData\\Local\\Android\\Sdk\\platform-tools\\adb.exe"),
            "C:\\platform-tools\\adb.exe",
            "C:\\adb\\adb.exe"
        ]
        
        # 4. Check Common Mac/Linux Paths (Fallback)
        possible_paths.extend([
            "/opt/homebrew/bin/adb",
            "/usr/local/bin/adb",
            os.path.expanduser("~/Library/Android/sdk/platform-tools/adb")
        ])
        
        for p in possible_paths:
            if os.path.exists(p): return p
            
        return "adb" # Default expectation of PATH

    @staticmethod
    def run(cmd_args):
        try:
            cmd = [ADBConnector.adb_path] + cmd_args
            # Windows: subprocess might need shell=True or creationflags if console pops up, but usually OK.
            creationflags = 0
            if sys.platform == "win32":
                creationflags = subprocess.CREATE_NO_WINDOW
                
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=15, creationflags=creationflags)
            if res.returncode != 0 and res.stderr:
                return f"ERROR: {res.stderr.strip()}"
            return res.stdout.strip()
        except Exception as e:
            return f"EXEC_ERROR: {str(e)}"

# Set ADB Path immediately
ADBConnector.adb_path = ADBConnector.find_adb()

class ForensicEngine:
    """Core logic for extraction and analysis."""
    
    @staticmethod
    def get_device_info():
        info = ""
        info += "MODEL: " + ADBConnector.run(['shell', 'getprop', 'ro.product.model']) + "\n"
        info += "ANDROID: " + ADBConnector.run(['shell', 'getprop', 'ro.build.version.release']) + "\n"
        info += "SERIAL: " + ADBConnector.run(['shell', 'getprop', 'ro.serialno']) + "\n"
        info += "SECURITY: " + ADBConnector.run(['shell', 'getprop', 'ro.build.version.security_patch']) + "\n"
        batt = ADBConnector.run(['shell', 'dumpsys', 'battery'])
        if "level:" in batt:
            import re
            lvl = re.search(r'level: (\d+)', batt)
            if lvl: info += f"BATTERY: {lvl.group(1)}%\n"
        return info

    @staticmethod
    def get_apps():
        raw = ADBConnector.run(['shell', 'pm', 'list', 'packages', '-3']) # -3 = Third party only
        apps = []
        if "package:" in raw:
            for line in raw.splitlines():
                if line.strip():
                    apps.append(line.replace("package:", "").strip())
        return sorted(apps)

    @staticmethod
    def get_history(content_type):
        """
        Extracts Call Logs or SMS using content provider query.
        content_type: 'call_log/calls' or 'sms'
        """
        uri = f"content://{content_type}"
        cols = "number:date:type:duration" if "call" in content_type else "address:date:type:body"
        
        cmd = ['shell', 'content', 'query', '--uri', uri, '--projection', cols, '--sort', '"date DESC"']
        raw = ADBConnector.run(cmd)
        
        data = []
        if "Row:" in raw:
            for line in raw.splitlines():
                if "Row:" in line:
                    item = {}
                    # Simple regex parser
                    import re
                    for key in ["number", "address", "date", "body", "type", "duration"]:
                        m = re.search(f"{key}=(.*?)(,|$)", line)
                        if m: item[key] = m.group(1)
                    
                    # Clean Date
                    if "date" in item:
                        try:
                            ts = int(item["date"]) / 1000
                            item["date"] = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        except: pass
                    data.append(item)
        return data

    @staticmethod
    def pull_and_hash_apk(package_name):
        """Pulls APK, hashes it, returns hash."""
        # Use simple "adb" command, assuming it's in PATH or detected earlier
        adb_cmd = ADBConnector.adb_path 
        
        # 1. Get Path
        path_out = ADBConnector.run(['shell', 'pm', 'path', package_name])
        clean_path = path_out.replace("package:", "").strip()
        if not clean_path or "ERROR" in clean_path:
            raise Exception("Could not find APK path. Is device connected?")
        
        # 2. Pull
        local_filename = f"temp_{package_name}.apk"
        ADBConnector.run(['pull', clean_path, local_filename])
        
        if not os.path.exists(local_filename):
            raise Exception("Pull failed.")
            
        # 3. Hash
        sha256_hash = hashlib.sha256()
        with open(local_filename, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        file_hash = sha256_hash.hexdigest()
        
        # 4. Cleanup
        os.remove(local_filename)
        return file_hash

# =============================================================================
#  WORKER THREADS (Prevents Freezing)
# =============================================================================

class VTScanWorker(QThread):
    """Thread to handle VirusTotal API usage."""
    log = pyqtSignal(str)
    result = pyqtSignal(dict)
    
    def __init__(self, package_name):
        super().__init__()
        self.package_name = package_name

    def run(self):
        self.log.emit(f"Step 1: Locating APK for {self.package_name}...")
        try:
            # 1. Get Hash
            apk_hash = ForensicEngine.pull_and_hash_apk(self.package_name)
            self.log.emit(f"Step 2: APK Hash Calculated: {apk_hash[:15]}...")
            
            # 2. Query VirusTotal
            if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
                self.log.emit("ERROR: API Key not set. Please edit the script.")
                return

            self.log.emit("Step 3: Querying VirusTotal Database...")
            url = f"https://www.virustotal.com/api/v3/files/{apk_hash}"
            headers = {"x-apikey": VT_API_KEY}
            
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                self.result.emit(stats)
                self.log.emit("Scan Complete.")
            elif response.status_code == 404:
                self.log.emit("Result: File not found in VirusTotal database (Unknown/Clean).")
                self.result.emit({"malicious": 0, "suspicious": 0, "clean": "Unknown"})
            else:
                self.log.emit(f"API Error: {response.status_code} - {response.text}")

        except Exception as e:
            self.log.emit(f"Error: {str(e)}")

class HistoryWorker(QThread):
    finished = pyqtSignal(list, str) # data, type
    
    def __init__(self, c_type):
        super().__init__()
        self.c_type = c_type
        
    def run(self):
        data = ForensicEngine.get_history(self.c_type)
        self.finished.emit(data, self.c_type)

class LocalForensicWorker(QThread):
    """Worker for local binary analysis with VT/OTX integration."""
    log = pyqtSignal(str)
    result = pyqtSignal(dict)
    finished = pyqtSignal()
    
    EXECUTABLE_MIMES = [
        'application/x-dosexec',
        'application/x-executable',
        'application/x-sharedlib',
        'application/x-object',
        'application/x-mach-binary'
    ]
    
    def __init__(self, path, mode="VT"):
        super().__init__()
        self.path = path
        self.mode = mode  # "VT" or "OTX"
        
    def run(self):
        try:
            self.log.emit(f"[*] Starting {self.mode} scan on: {self.path}")
            
            files_processed = 0
            executables_found = 0
            vt_checked = 0
            
            try:
                import magic
            except ImportError:
                self.log.emit("[!] python-magic not installed. Using extension-based detection.")
                magic = None
            
            for root, _, files in os.walk(self.path):
                if self.isInterruptionRequested():
                    self.log.emit("[!] Scan interrupted by user.")
                    break
                    
                for file in files:
                    if self.isInterruptionRequested():
                        break
                        
                    full_path = os.path.join(root, file)
                    files_processed += 1
                    
                    # Detect file type
                    is_executable = False
                    file_type = "Unknown"
                    
                    try:
                        if magic:
                            mime = magic.from_file(full_path, mime=True)
                            file_type = mime
                            if any(m in mime for m in self.EXECUTABLE_MIMES):
                                is_executable = True
                        
                        # Also check by extension
                        ext = os.path.splitext(file)[1].lower()
                        if ext in ['.exe', '.dll', '.so', '.apk', '.elf', '.dex', '.sh']:
                            is_executable = True
                            if file_type == "Unknown":
                                file_type = f"Executable ({ext})"
                                
                    except Exception as e:
                        self.log.emit(f"[!] Error detecting type for {file}: {e}")
                        continue
                    
                    if is_executable:
                        executables_found += 1
                        
                        # Calculate hash
                        file_hash = self._calculate_sha256(full_path)
                        if not file_hash:
                            continue
                        
                        self.log.emit(f"\n{'='*60}")
                        self.log.emit(f"[EXECUTABLE #{executables_found}]")
                        self.log.emit(f"  FILE: {full_path}")
                        self.log.emit(f"  TYPE: {file_type}")
                        self.log.emit(f"  SHA256: {file_hash}")
                        
                        # Check against VT or OTX
                        risk = "UNKNOWN"
                        
                        try:
                            if self.mode == "VT":
                                if VT_API_KEY and VT_API_KEY != "YOUR_VIRUSTOTAL_API_KEY_HERE":
                                    self.log.emit(f"  [VT] Checking VirusTotal...")
                                    risk = self._check_virustotal(file_hash)
                                    vt_checked += 1
                                    self.log.emit(f"  [VT RESULT] {risk}")
                                else:
                                    self.log.emit(f"  [VT] API key not set - skipping VT check")
                            elif self.mode == "OTX":
                                self.log.emit(f"  [OTX] Checking AlienVault OTX...")
                                risk = self._check_otx(file_hash)
                                self.log.emit(f"  [OTX RESULT] {risk}")
                        except Exception as inner_e:
                             self.log.emit(f"  [!] API Check Error: {inner_e}")
                             risk = f"ERROR: {inner_e}"
                        
                        # Emit result for any connected handlers
                        self.result.emit({
                            "path": full_path,
                            "type": file_type,
                            "hash": file_hash,
                            "risk": risk
                        })
            
            self.log.emit(f"\n{'='*60}")
            self.log.emit(f"[SCAN COMPLETE]")
            self.log.emit(f"  Files processed: {files_processed}")
            self.log.emit(f"  Executables found: {executables_found}")
            if self.mode == "VT":
                self.log.emit(f"  VT API checks: {vt_checked}")
                
        except Exception as global_e:
            self.log.emit(f"\n[!!!] CRITICAL WORKER ERROR: {str(global_e)}")
            import traceback
            self.log.emit(traceback.format_exc())
            
        self.finished.emit()
    
    def _calculate_sha256(self, filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return None
    
    def _check_virustotal(self, file_hash):
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": VT_API_KEY}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                mal = stats.get("malicious", 0)
                susp = stats.get("suspicious", 0)
                if mal > 0:
                    self.log.emit(f"    [VT] DANGER: {mal} malicious detections!")
                    return f"HIGH RISK ({mal} detections)"
                elif susp > 0:
                    return f"SUSPICIOUS ({susp})"
                else:
                    return "CLEAN"
            elif response.status_code == 404:
                return "NOT IN VT DATABASE"
            elif response.status_code == 429:
                self.log.emit("    [VT] Rate limit exceeded, waiting...")
                import time
                time.sleep(60)
                return "RATE LIMITED"
            else:
                return f"VT ERROR ({response.status_code})"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def _check_otx(self, file_hash):
        OTX_KEY = "5f803ef30e5013eb124bb9cad96c7921d46a29e26a6d42e8b3c2522a71be71f1"
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
            headers = {"X-OTX-API-KEY": OTX_KEY}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                pulse_info = data.get("pulse_info", {})
                count = pulse_info.get("count", 0)
                if count > 0:
                    self.log.emit(f"    [OTX] DANGER: Found in {count} pulses!")
                    return f"HIGH RISK ({count} pulses)"
                else:
                    return "CLEAN"
            elif response.status_code == 404:
                return "NOT IN OTX DATABASE"
            else:
                return f"OTX ERROR ({response.status_code})"
        except Exception as e:
            return f"ERROR: {str(e)}"

class CarveWorker(QThread):
    """Worker for carving executables from disk dumps."""
    log = pyqtSignal(str)
    result = pyqtSignal(dict)
    finished = pyqtSignal()
    
    def __init__(self, tar_path):
        super().__init__()
        self.tar_path = tar_path
        
    def run(self):
        import tarfile
        self.log.emit(f"[*] Starting carve on: {self.tar_path}")
        
        try:
            if not tarfile.is_tarfile(self.tar_path):
                self.log.emit("[!] Error: Not a valid TAR file.")
                self.finished.emit()
                return
                
            output_dir = os.path.join(os.path.dirname(self.tar_path), "carved_output")
            os.makedirs(output_dir, exist_ok=True)
            
            with tarfile.open(self.tar_path, 'r') as tar:
                for member in tar.getmembers():
                    if self.isInterruptionRequested():
                        self.log.emit("[!] Carving interrupted.")
                        break
                        
                    if member.isfile():
                        ext = os.path.splitext(member.name)[1].lower()
                        if ext in ['.exe', '.dll', '.so', '.apk', '.elf', '.dex']:
                            try:
                                tar.extract(member, output_dir)
                                extracted_path = os.path.join(output_dir, member.name)
                                
                                # Calculate hash
                                sha256 = hashlib.sha256()
                                with open(extracted_path, "rb") as f:
                                    for chunk in iter(lambda: f.read(4096), b""):
                                        sha256.update(chunk)
                                
                                self.log.emit(f"[+] Extracted: {member.name}")
                                self.result.emit({
                                    "path": extracted_path,
                                    "type": f"Carved {ext}",
                                    "hash": sha256.hexdigest(),
                                    "risk": "EXTRACTED"
                                })
                            except Exception as e:
                                self.log.emit(f"[!] Error extracting {member.name}: {e}")
            
            self.log.emit(f"[*] Carving complete. Output: {output_dir}")
        except Exception as e:
            self.log.emit(f"[!] Carve error: {e}")
        
        self.finished.emit()

class LiveAndroidWorker(QThread):
    """Worker for live ADB hidden file scanning."""
    log = pyqtSignal(str)
    result = pyqtSignal(dict)
    finished = pyqtSignal()
    
    SUSPICIOUS_PATHS = [
        "/data/local/tmp",
        "/sdcard/Android/data",
        "/sdcard/.hidden",
        "/data/data"
    ]
    
    def __init__(self, target=""):
        super().__init__()
        self.target = target
        
    def run(self):
        self.log.emit("[*] Starting live ADB scan for hidden/suspicious files...")
        
        for path in self.SUSPICIOUS_PATHS:
            if self.isInterruptionRequested():
                self.log.emit("[!] Scan interrupted.")
                break
                
            self.log.emit(f"[*] Scanning: {path}")
            try:
                result = ADBConnector.run(['shell', 'ls', '-la', path])
                if "Permission denied" not in result and "No such file" not in result:
                    for line in result.splitlines():
                        if line.strip() and not line.startswith('total'):
                            parts = line.split()
                            if len(parts) >= 8:
                                filename = parts[-1]
                                if filename.startswith('.') or filename.endswith('.sh') or filename.endswith('.so'):
                                    full_path = f"{path}/{filename}"
                                    self.log.emit(f"[+] Found: {full_path}")
                                    self.result.emit({
                                        "path": full_path,
                                        "type": "Hidden/Suspicious",
                                        "hash": "N/A (on device)",
                                        "risk": "NEEDS REVIEW"
                                    })
            except Exception as e:
                self.log.emit(f"[!] Error scanning {path}: {e}")
        
        self.log.emit("[*] ADB scan complete.")
        self.finished.emit()


# =============================================================================
#  GUI IMPLEMENTATION
# =============================================================================

class ModernApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DarkLearners_PS6")
        self.resize(1200, 800)
        self.setup_ui()
        self.setup_styles()

    def setup_styles(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #0d1117; }
            QWidget { color: #c9d1d9; font-family: 'Segoe UI', sans-serif; }
            QTabWidget::pane { border: 1px solid #30363d; top: -1px; }
            QTabBar::tab { background: #161b22; color: #8b949e; padding: 10px 20px; border: 1px solid #30363d; }
            QTabBar::tab:selected { background: #0d1117; color: #58a6ff; border-bottom: 2px solid #58a6ff; }
            QPushButton { background: #21262d; border: 1px solid #30363d; padding: 8px 16px; border-radius: 6px; font-weight: bold; }
            QPushButton:hover { background: #30363d; border-color: #8b949e; }
            QPushButton#ActionBtn { background: #238636; color: white; border: none; }
            QPushButton#ActionBtn:hover { background: #2ea043; }
            QTableWidget { background: #0d1117; gridline-color: #30363d; border: none; }
            QHeaderView::section { background: #161b22; padding: 5px; border: none; font-weight: bold; }
            QListWidget { background: #0d1117; border: 1px solid #30363d; font-size: 13px; }
            QListWidget::item { padding: 8px; }
            QListWidget::item:selected { background: #1f6feb; color: white; }
            QTextEdit { background: #0d1117; border: 1px solid #30363d; color: #00ff88; font-family: Consolas; }
        """)

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Header
        header = QLabel("PS6_DarkLearners")
        header.setStyleSheet("font-size: 22px; font-weight: 900; color: #58a6ff; margin-bottom: 10px;")
        layout.addWidget(header)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.addTab(self.tab_dashboard(), "Dashboard")
        self.tabs.addTab(self.tab_malware(), "Malware Analysis")
        self.tabs.addTab(self.tab_history(), "Forensic History")
        self.tabs.addTab(self.tab_5(), "Advanced Forensics")
        self.tabs.addTab(self.tab_6(), "Geo-Mapping")

        layout.addWidget(self.tabs)

        # Status Bar
        self.status = QLabel("Ready")
        self.status.setStyleSheet("color: #8b949e; font-size: 11px;")
        layout.addWidget(self.status)

    # ---------------- TAB 1: DASHBOARD (Mission Control) ----------------
    def tab_dashboard(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # --- WELCOME HEADER ---
        header = QLabel("Mobile Forensics Dashboard")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #58a6ff;")
        layout.addWidget(header)
        
        subtitle = QLabel("Analyze Android devices, extract evidence, and detect threats")
        subtitle.setStyleSheet("font-size: 13px; color: #8b949e; margin-bottom: 10px;")
        layout.addWidget(subtitle)
        
        # --- DEVICE STATUS CARD ---
        status_card = QFrame()
        status_card.setStyleSheet("""
            QFrame { background: #161b22; border-radius: 12px; border: 1px solid #30363d; padding: 15px; }
            QLabel { color: #8b949e; font-size: 12px; }
            QLabel#StatusVal { color: #58a6ff; font-weight: bold; font-size: 13px; }
            QLabel#StatusTitle { color: #c9d1d9; font-size: 14px; font-weight: bold; }
        """)
        card_layout = QVBoxLayout(status_card)
        
        lbl_status_title = QLabel("Connected Device")
        lbl_status_title.setObjectName("StatusTitle")
        card_layout.addWidget(lbl_status_title)
        
        # Status Grid
        grid_info = QGridLayout()
        grid_info.setSpacing(10)
        
        self.lbl_model = QLabel("Not Connected"); self.lbl_model.setObjectName("StatusVal")
        self.lbl_serial = QLabel("--"); self.lbl_serial.setObjectName("StatusVal")
        self.lbl_android = QLabel("--"); self.lbl_android.setObjectName("StatusVal")
        self.lbl_battery = QLabel("--"); self.lbl_battery.setObjectName("StatusVal")
        
        grid_info.addWidget(QLabel("Device Model:"), 0, 0)
        grid_info.addWidget(self.lbl_model, 0, 1)
        grid_info.addWidget(QLabel("Serial Number:"), 0, 2)
        grid_info.addWidget(self.lbl_serial, 0, 3)
        grid_info.addWidget(QLabel("Android Version:"), 1, 0)
        grid_info.addWidget(self.lbl_android, 1, 1)
        grid_info.addWidget(QLabel("Battery Level:"), 1, 2)
        grid_info.addWidget(self.lbl_battery, 1, 3)
        
        card_layout.addLayout(grid_info)
        
        btn_refresh = QPushButton("Refresh Device Status")
        btn_refresh.setStyleSheet("background: #21262d; color: #58a6ff; border: 1px solid #30363d; padding: 8px; border-radius: 6px;")
        btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_refresh.clicked.connect(self.refresh_dashboard_info)
        card_layout.addWidget(btn_refresh)
        
        layout.addWidget(status_card)
        
        # --- QUICK ACTIONS SECTION ---
        actions_label = QLabel("Quick Actions")
        actions_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #c9d1d9; margin-top: 10px;")
        layout.addWidget(actions_label)
        
        grid_tools = QGridLayout()
        grid_tools.setSpacing(12)
        
        # Action Card Style
        card_style = """
            QPushButton {
                background: #21262d; 
                border: 1px solid #30363d; 
                border-radius: 10px;
                padding: 20px; 
                text-align: left; 
                font-size: 13px; 
                color: #c9d1d9;
            }
            QPushButton:hover { 
                background: #30363d; 
                border-color: #58a6ff; 
            }
        """
        
        b1 = QPushButton("ADB Local Scan\nScan connected Android device for hidden files")
        b1.setStyleSheet(card_style)
        b1.setCursor(Qt.CursorShape.PointingHandCursor)
        b1.clicked.connect(lambda: self.switch_to_tab5(3))
        
        b2 = QPushButton("VirusTotal Check\nAnalyze files with Magic + Androguard + VT")
        b2.setStyleSheet(card_style)
        b2.setCursor(Qt.CursorShape.PointingHandCursor)
        b2.clicked.connect(lambda: self.switch_to_tab5(0))
        
        b3 = QPushButton("OTX Threat Intel\nCheck file hashes against AlienVault OTX")
        b3.setStyleSheet(card_style)
        b3.setCursor(Qt.CursorShape.PointingHandCursor)
        b3.clicked.connect(lambda: self.switch_to_tab5(1))
        
        b4 = QPushButton("Carve Disk Image\nExtract executables from .tar dump files")
        b4.setStyleSheet(card_style)
        b4.setCursor(Qt.CursorShape.PointingHandCursor)
        b4.clicked.connect(lambda: self.switch_to_tab5(2))
        
        grid_tools.addWidget(b1, 0, 0)
        grid_tools.addWidget(b2, 0, 1)
        grid_tools.addWidget(b3, 1, 0)
        grid_tools.addWidget(b4, 1, 1)
        
        layout.addLayout(grid_tools)
        
        # --- EXPORT SECTION ---
        export_btn = QPushButton("Export Full Forensic Report")
        export_btn.setStyleSheet("background: #238636; color: white; font-weight: bold; padding: 12px; border-radius: 8px; font-size: 14px;")
        export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        export_btn.clicked.connect(self.save_report)
        layout.addWidget(export_btn)
        
        layout.addStretch()
        return w

    def refresh_dashboard_info(self):
        try:
            # We parse the raw string logic from previous get_device_info, 
            # but ideally ForensicEngine should return a dict. 
            # For now, let's just grab raw and regex it or update ForensicEngine.
            # Start simple:
            raw = ForensicEngine.get_device_info()
            for line in raw.splitlines():
                if "MODEL:" in line: self.lbl_model.setText(line.split(":")[1].strip())
                if "SERIAL:" in line: self.lbl_serial.setText(line.split(":")[1].strip())
                if "ANDROID:" in line: self.lbl_android.setText(line.split(":")[1].strip())
                if "BATTERY:" in line: self.lbl_battery.setText(line.split(":")[1].strip())
            self.status.setText("Dashboard updated.")
        except:
            self.status.setText("Device not connected.")

    def switch_to_tab5(self, mode_index):
        self.tabs.setCurrentIndex(3) # Now index 3 (Dashboard=0, Malware=1, History=2, Advanced=3)
        if hasattr(self, 'combo_mode'):
            self.combo_mode.setCurrentIndex(mode_index)

    # ---------------- TAB 2: MALWARE ANALYSIS (Merged with Upload) ----------------
    def tab_malware(self):
        w = QWidget()
        main_layout = QVBoxLayout(w)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header = QLabel("Malware Analysis")
        header.setStyleSheet("font-size: 22px; font-weight: bold; color: #58a6ff;")
        main_layout.addWidget(header)
        
        subtitle = QLabel("Scan device apps or upload files for VirusTotal analysis")
        subtitle.setStyleSheet("font-size: 12px; color: #8b949e;")
        main_layout.addWidget(subtitle)
        
        # Content Area
        content = QHBoxLayout()
        
        # --- LEFT PANEL: Source Selection ---
        left_card = QFrame()
        left_card.setStyleSheet("""
            QFrame { background: #161b22; border-radius: 10px; border: 1px solid #30363d; padding: 15px; }
        """)
        left_layout = QVBoxLayout(left_card)
        
        # Mode tabs within the panel
        source_label = QLabel("")
        source_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #c9d1d9;")
        left_layout.addWidget(source_label)
        
        # Source Mode Buttons
        mode_row = QHBoxLayout()
        self.btn_mode_device = QPushButton("Device Apps")
        self.btn_mode_device.setStyleSheet("background: #238636; color: white; font-weight: bold; padding: 8px; border-radius: 6px;")
        self.btn_mode_device.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_mode_device.clicked.connect(lambda: self.switch_malware_mode("device"))
        
        self.btn_mode_upload = QPushButton("Upload File")
        self.btn_mode_upload.setStyleSheet("background: #21262d; color: #8b949e; font-weight: bold; padding: 8px; border-radius: 6px; border: 1px solid #30363d;")
        self.btn_mode_upload.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_mode_upload.clicked.connect(lambda: self.switch_malware_mode("upload"))
        
        mode_row.addWidget(self.btn_mode_device)
        mode_row.addWidget(self.btn_mode_upload)
        left_layout.addLayout(mode_row)
        
        # Stacked widget for different modes
        self.malware_stack = QFrame()
        stack_layout = QVBoxLayout(self.malware_stack)
        stack_layout.setContentsMargins(0, 10, 0, 0)
        
        # Device Apps List
        self.app_list = QListWidget()
        self.app_list.setStyleSheet("""
            QListWidget { 
                background: #0d1117; 
                color: #c9d1d9; 
                border: 1px solid #30363d; 
                border-radius: 6px;
                padding: 5px;
            }
            QListWidget::item:selected { background: #1f6feb; color: white; }
            QListWidget::item:hover { background: #21262d; }
        """)
        stack_layout.addWidget(self.app_list)
        
        # Upload section (hidden by default)
        self.upload_frame = QFrame()
        upload_layout = QVBoxLayout(self.upload_frame)
        upload_layout.setContentsMargins(0, 0, 0, 0)
        
        self.lbl_uploaded_file = QLabel("No file selected")
        self.lbl_uploaded_file.setStyleSheet("color: #8b949e; padding: 20px; background: #0d1117; border: 1px dashed #30363d; border-radius: 6px; text-align: center;")
        self.lbl_uploaded_file.setAlignment(Qt.AlignmentFlag.AlignCenter)
        upload_layout.addWidget(self.lbl_uploaded_file)
        
        btn_browse_file = QPushButton("Browse File...")
        btn_browse_file.setStyleSheet("background: #21262d; color: #58a6ff; padding: 8px; border-radius: 6px; border: 1px solid #30363d;")
        btn_browse_file.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_browse_file.clicked.connect(self.upload_malware_file)
        upload_layout.addWidget(btn_browse_file)
        
        self.upload_frame.hide()
        stack_layout.addWidget(self.upload_frame)
        
        left_layout.addWidget(self.malware_stack)
        
        # Action buttons
        btn_load_apps = QPushButton("Load Device Apps")
        btn_load_apps.setStyleSheet("background: #238636; color: white; font-weight: bold; padding: 10px; border-radius: 6px;")
        btn_load_apps.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_load_apps.clicked.connect(self.load_apps)
        self.btn_load_device_apps = btn_load_apps
        left_layout.addWidget(btn_load_apps)
        
        # --- RIGHT PANEL: Analysis ---
        right_card = QFrame()
        right_card.setStyleSheet("""
            QFrame { background: #161b22; border-radius: 10px; border: 1px solid #30363d; padding: 15px; }
        """)
        right_layout = QVBoxLayout(right_card)
        
        lbl_analysis = QLabel("Analysis Results")
        lbl_analysis.setStyleSheet("font-size: 14px; font-weight: bold; color: #c9d1d9;")
        right_layout.addWidget(lbl_analysis)
        
        # Risk Score Display
        self.lbl_score = QLabel("Risk Score: --/--")
        self.lbl_score.setStyleSheet("font-size: 24px; font-weight: bold; color: #8b949e; padding: 10px;")
        self.lbl_score.setAlignment(Qt.AlignmentFlag.AlignCenter)
        right_layout.addWidget(self.lbl_score)
        
        # Progress Bar
        self.vt_progress = QProgressBar()
        self.vt_progress.setTextVisible(False)
        self.vt_progress.setStyleSheet("""
            QProgressBar { height: 8px; background: #21262d; border-radius: 4px; }
            QProgressBar::chunk { background: #1f6feb; border-radius: 4px; }
        """)
        right_layout.addWidget(self.vt_progress)
        
        # Log Area
        self.vt_log = QTextEdit()
        self.vt_log.setReadOnly(True)
        self.vt_log.setStyleSheet("""
            QTextEdit { 
                font-family: Consolas, monospace; 
                font-size: 11px; 
                background: #0d1117; 
                color: #8b949e; 
                border: 1px solid #30363d; 
                border-radius: 6px;
                padding: 8px;
            }
        """)
        right_layout.addWidget(self.vt_log)
        
        # Scan Button
        btn_scan_app = QPushButton("Scan Selected")
        btn_scan_app.setStyleSheet("background: #da3633; color: white; font-weight: bold; padding: 12px; border-radius: 6px; font-size: 14px;")
        btn_scan_app.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_scan_app.clicked.connect(self.scan_selected_app)
        right_layout.addWidget(btn_scan_app)
        
        # Add panels to content
        content.addWidget(left_card, 1)
        content.addWidget(right_card, 2)
        
        main_layout.addLayout(content)
        return w

    def switch_malware_mode(self, mode):
        """Switch between device apps and upload file modes."""
        if mode == "device":
            self.btn_mode_device.setStyleSheet("background: #238636; color: white; font-weight: bold; padding: 8px; border-radius: 6px;")
            self.btn_mode_upload.setStyleSheet("background: #21262d; color: #8b949e; font-weight: bold; padding: 8px; border-radius: 6px; border: 1px solid #30363d;")
            self.app_list.show()
            self.upload_frame.hide()
            self.btn_load_device_apps.show()
        else:
            self.btn_mode_upload.setStyleSheet("background: #1f6feb; color: white; font-weight: bold; padding: 8px; border-radius: 6px;")
            self.btn_mode_device.setStyleSheet("background: #21262d; color: #8b949e; font-weight: bold; padding: 8px; border-radius: 6px; border: 1px solid #30363d;")
            self.app_list.hide()
            self.upload_frame.show()
            self.btn_load_device_apps.hide()

    def upload_malware_file(self):
        """Upload a file for malware analysis."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File for Analysis",
            "",
            "All Files (*);;APK (*.apk);;Executables (*.exe *.elf);;ZIP (*.zip)"
        )
        if path:
            self.uploaded_file_path = path
            self.lbl_uploaded_file.setText(f"Selected: {os.path.basename(path)}")
            self.lbl_uploaded_file.setStyleSheet("color: #58a6ff; padding: 20px; background: #0d1117; border: 1px solid #238636; border-radius: 6px;")
            self.vt_log.append(f"[+] File selected: {os.path.basename(path)}")

    # ---------------- TAB 3: HISTORY ----------------
    def tab_history(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header = QLabel("Call & SMS History Analyzer")
        header.setStyleSheet("font-size: 22px; font-weight: bold; color: #58a6ff;")
        layout.addWidget(header)
        
        subtitle = QLabel("Fetch and analyze communication patterns with frequency heatmaps")
        subtitle.setStyleSheet("font-size: 12px; color: #8b949e;")
        layout.addWidget(subtitle)
        
        # Buttons Card
        btn_card = QFrame()
        btn_card.setStyleSheet("QFrame { background: #161b22; border-radius: 10px; border: 1px solid #30363d; padding: 15px; }")
        btn_layout = QHBoxLayout(btn_card)
        
        b_call = QPushButton("Fetch Call Logs")
        b_call.setStyleSheet("background: #238636; color: white; font-weight: bold; padding: 12px 20px; border-radius: 6px;")
        b_call.setCursor(Qt.CursorShape.PointingHandCursor)
        b_call.clicked.connect(lambda: self.load_history('call_log/calls'))
        
        b_sms = QPushButton("Fetch SMS Messages")
        b_sms.setStyleSheet("background: #1f6feb; color: white; font-weight: bold; padding: 12px 20px; border-radius: 6px;")
        b_sms.setCursor(Qt.CursorShape.PointingHandCursor)
        b_sms.clicked.connect(lambda: self.load_history('sms'))
        
        btn_layout.addWidget(b_call)
        btn_layout.addWidget(b_sms)
        btn_layout.addStretch()
        layout.addWidget(btn_card)
        
        # Legend with color indicators
        legend_frame = QFrame()
        legend_layout = QHBoxLayout(legend_frame)
        legend_layout.setContentsMargins(0, 5, 0, 5)
        
        red_box = QLabel()
        red_box.setFixedSize(16, 16)
        red_box.setStyleSheet("background: #da3633; border-radius: 3px;")
        red_label = QLabel("High Frequency")
        red_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        
        blue_box = QLabel()
        blue_box.setFixedSize(16, 16)
        blue_box.setStyleSheet("background: #1f6feb; border-radius: 3px;")
        blue_label = QLabel("Long Duration")
        blue_label.setStyleSheet("color: #8b949e; font-size: 12px;")
        
        legend_layout.addWidget(red_box)
        legend_layout.addWidget(red_label)
        legend_layout.addSpacing(20)
        legend_layout.addWidget(blue_box)
        legend_layout.addWidget(blue_label)
        legend_layout.addStretch()
        layout.addWidget(legend_frame)
        
        # Results Table
        self.hist_table = QTableWidget()
        self.hist_table.horizontalHeader().setStretchLastSection(True)
        self.hist_table.setStyleSheet("""
            QTableWidget { 
                background: #0d1117; 
                color: #c9d1d9; 
                border: 1px solid #30363d; 
                border-radius: 6px;
            }
            QHeaderView::section { 
                background: #161b22; 
                color: #58a6ff; 
                font-weight: bold; 
                padding: 8px;
                border: none;
            }
        """)
        layout.addWidget(self.hist_table)
        
        return w
    # ================= TAB 4 : UPLOAD & OFFLINE ANALYSIS =================

    def tab_4(self):
        w = QWidget()
        layout = QVBoxLayout(w)

        title = QLabel("Tab_4")
        title.setStyleSheet("font-size:18px; font-weight:900; color:#58a6ff;")
        layout.addWidget(title)

        btn_layout = QHBoxLayout()

        self.tab4_upload_btn = QPushButton("Upload ")
        self.tab4_upload_btn.setObjectName("ActionBtn")
        self.tab4_upload_btn.clicked.connect(self.tab4_upload_evidence)

        self.tab4_analyze_btn = QPushButton("Run Analysis")
        self.tab4_analyze_btn.setEnabled(False)
        self.tab4_analyze_btn.clicked.connect(self.tab4_run_analysis)

        btn_layout.addWidget(self.tab4_upload_btn)
        btn_layout.addWidget(self.tab4_analyze_btn)
        layout.addLayout(btn_layout)

        layout.addWidget(QLabel("Analysis Logs"))
        self.tab4_log = QTextEdit()
        self.tab4_log.setReadOnly(True)
        self.tab4_log.setFixedHeight(180)
        layout.addWidget(self.tab4_log)

        layout.addWidget(QLabel("Analysis Results"))
        self.tab4_table = QTableWidget(0, 3)
        self.tab4_table.setHorizontalHeaderLabels(["Artifact", "Finding", "Details"])
        self.tab4_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.tab4_table)

        return w


    def tab4_upload_evidence(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Upload Evidence",
            "",
            "All Files (*);;APK (*.apk);;ZIP (*.zip);;DB (*.db)"
        )

        if not path:
            return

        base_dir = os.path.join(os.getcwd(), "cases")
        os.makedirs(base_dir, exist_ok=True)

        self.tab4_case_dir = os.path.join(
            base_dir,
            "case_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        )
        upload_dir = os.path.join(self.tab4_case_dir, "uploads")
        os.makedirs(upload_dir, exist_ok=True)

        dest = os.path.join(upload_dir, os.path.basename(path))
        shutil.copy(path, dest)

        self.tab4_current_file = dest
        self.tab4_log.append(f"[+] Uploaded: {os.path.basename(dest)}")
        self.tab4_log.append(f"[+] Case directory: {self.tab4_case_dir}")
        self.tab4_analyze_btn.setEnabled(True)


    def tab4_run_analysis(self):
        if not hasattr(self, "tab4_current_file"):
            QMessageBox.warning(self, "No Evidence", "Please upload evidence first.")
            return

        self.tab4_log.append("[*] Starting forensic analysis...")
        self.tab4_table.setRowCount(0)
        self.tab4_analyze_btn.setEnabled(False)

        try:
            results = self.tab4_simple_analysis(self.tab4_current_file)
            self.tab4_show_results(results)
            self.tab4_log.append("[+] Analysis completed.")
        except Exception as e:
            self.tab4_log.append(f"[!] Analysis error: {str(e)}")

        self.tab4_analyze_btn.setEnabled(True)


    def tab4_simple_analysis(self, path):
        findings = []

        size = os.path.getsize(path)
        sha256 = hashlib.sha256(open(path, "rb").read()).hexdigest()
        ext = os.path.splitext(path)[1].lower()

        findings.append({
            "artifact": os.path.basename(path),
            "finding": "File Size",
            "detail": f"{size} bytes"
        })

        findings.append({
            "artifact": os.path.basename(path),
            "finding": "SHA256 Hash",
            "detail": sha256
        })

        if ext in [".apk", ".exe", ".elf", ".sh"]:
            findings.append({
                "artifact": os.path.basename(path),
                "finding": "Executable Artifact",
                "detail": "Potentially suspicious – requires deeper analysis"
            })

        return findings


    def tab4_show_results(self, results):
        self.tab4_table.setRowCount(len(results))
        for row, item in enumerate(results):
            self.tab4_table.setItem(row, 0, QTableWidgetItem(item["artifact"]))
            self.tab4_table.setItem(row, 1, QTableWidgetItem(item["finding"]))
            self.tab4_table.setItem(row, 2, QTableWidgetItem(item["detail"]))



    # ================= TAB 5 : ADVANCED FORENSICS (Carve, VT, OTX) =================

    def tab_5(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # --- HEADER ---
        header = QLabel("Advanced Forensic Scanner")
        header.setStyleSheet("font-size: 22px; font-weight: bold; color: #58a6ff;")
        layout.addWidget(header)
        
        subtitle = QLabel("Analyze binaries, check threat intel, and extract evidence from dumps")
        subtitle.setStyleSheet("font-size: 12px; color: #8b949e;")
        layout.addWidget(subtitle)
        
        # --- MODE SELECTION CARD ---
        mode_card = QFrame()
        mode_card.setStyleSheet("""
            QFrame { background: #161b22; border-radius: 10px; border: 1px solid #30363d; padding: 15px; }
            QLabel { color: #c9d1d9; font-size: 13px; }
        """)
        mode_layout = QVBoxLayout(mode_card)
        
        mode_label = QLabel("Select Analysis Mode:")
        mode_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        mode_layout.addWidget(mode_label)
        
        self.combo_mode = QComboBox()
        self.combo_mode.addItems([
            "1. Local Binary Analysis (Magic + Androguard + VT)", 
            "2. OTX Threat Intel Scan", 
            "3. Carve Executables from Disk Dump",
            "4. Live ADB Hidden File Scan"
        ])
        self.combo_mode.setStyleSheet("""
            QComboBox { 
                padding: 10px; 
                color: #c9d1d9; 
                background: #21262d; 
                border: 1px solid #30363d;
                border-radius: 6px;
                font-size: 13px;
            }
        """)
        mode_layout.addWidget(self.combo_mode)
        
        # Path Input Row
        path_row = QHBoxLayout()
        
        path_label = QLabel("Target Path:")
        path_label.setStyleSheet("font-weight: bold;")
        
        self.inp_path = QTextEdit()
        self.inp_path.setPlaceholderText("Select folder or .tar file depending on mode...")
        self.inp_path.setFixedHeight(35)
        self.inp_path.setStyleSheet("background: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 5px;")
        
        btn_browse = QPushButton("Browse")
        btn_browse.setStyleSheet("background: #21262d; color: #58a6ff; border: 1px solid #30363d; padding: 8px 15px; border-radius: 6px;")
        btn_browse.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_browse.clicked.connect(self.browse_folder)
        
        path_row.addWidget(path_label)
        path_row.addWidget(self.inp_path, 1)
        path_row.addWidget(btn_browse)
        mode_layout.addLayout(path_row)
        
        # Action Buttons Row
        btn_row = QHBoxLayout()
        
        self.btn_run_forensics = QPushButton("Start Analysis")
        self.btn_run_forensics.setStyleSheet("background: #238636; color: white; font-weight: bold; padding: 12px 25px; border-radius: 6px; font-size: 14px;")
        self.btn_run_forensics.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_run_forensics.clicked.connect(self.start_forensic_task)
        
        self.btn_stop_forensics = QPushButton("Stop")
        self.btn_stop_forensics.setStyleSheet("background: #da3633; color: white; font-weight: bold; padding: 12px 25px; border-radius: 6px; font-size: 14px;")
        self.btn_stop_forensics.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_stop_forensics.setEnabled(False)
        self.btn_stop_forensics.clicked.connect(self.stop_forensic_task)
        
        btn_row.addWidget(self.btn_run_forensics)
        btn_row.addWidget(self.btn_stop_forensics)
        btn_row.addStretch()
        mode_layout.addLayout(btn_row)
        
        layout.addWidget(mode_card)

        # --- LOGS SECTION (Full Height) ---
        log_label = QLabel("Real-time Analysis Log")
        log_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #c9d1d9;")
        layout.addWidget(log_label)
        
        self.forensic_log = QTextEdit()
        self.forensic_log.setReadOnly(True)
        self.forensic_log.setStyleSheet("""
            QTextEdit { 
                font-family: Consolas, monospace; 
                font-size: 12px; 
                background: #0d1117; 
                color: #00ff88; 
                border: 1px solid #30363d; 
                border-radius: 6px;
                padding: 10px;
            }
        """)
        layout.addWidget(self.forensic_log, 1)  # Stretch factor 1 to fill space
        
        return w

    def browse_folder(self):
        # Mode specific browsing
        mode = self.combo_mode.currentIndex()
        if mode == 2: # Carving needs a file
             f, _ = QFileDialog.getOpenFileName(self, "Select Dump File", "", "TAR Archives (*.tar);;All Files (*)")
             if f: self.inp_path.setText(f)
        else:
            d = QFileDialog.getExistingDirectory(self, "Select Directory to Analyze")
            if d: self.inp_path.setText(d)

    def start_forensic_task(self):
        mode = self.combo_mode.currentIndex()
        target = self.inp_path.toPlainText().strip()
        
        if not target:
            QMessageBox.warning(self, "Error", "Please define a target path.")
            return

        self.forensic_log.clear()
        self.btn_run_forensics.setEnabled(False)
        self.btn_stop_forensics.setEnabled(True)
        
        # Select Worker based on Mode
        if mode == 0:
            self.worker = LocalForensicWorker(target, mode="VT")
        elif mode == 1:
            self.worker = LocalForensicWorker(target, mode="OTX")
        elif mode == 2:
            self.worker = CarveWorker(target)
        else:
            self.worker = LiveAndroidWorker(target)
            
        self.worker.log.connect(self.forensic_log.append)
        # self.worker.result.connect(self.add_forensic_row) # Table removed
        self.worker.finished.connect(self.on_forensic_finished)
        self.worker.start()

    def stop_forensic_task(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.requestInterruption()
            self.forensic_log.append("[!] Stopping analysis... Please wait.")
            self.btn_stop_forensics.setEnabled(False)

    def on_forensic_finished(self):
        self.btn_run_forensics.setEnabled(True)
        self.btn_stop_forensics.setEnabled(False)
        self.forensic_log.append("[*] Task Finished/Stopped.")
	
    def tab_6(self):
        w = QWidget()
        layout = QVBoxLayout(w)

        title = QLabel("Random Image Sampler & Geo-Mapper")
        title.setStyleSheet("font-size:18px; font-weight:800; color:#58a6ff;")
        layout.addWidget(title)

        # Control Panel
        ctrl = QHBoxLayout()

        self.tab6_days = QTextEdit()
        self.tab6_days.setFixedHeight(30)
        self.tab6_days.setText("20")  # Default to 20 random images

        self.tab6_pull_btn = QPushButton("1. Randomize & Pull")
        self.tab6_pull_btn.clicked.connect(self.tab6_pull_images)

        self.tab6_scan_btn = QPushButton("2. Map Locations")
        self.tab6_scan_btn.setObjectName("ActionBtn")
        self.tab6_scan_btn.setEnabled(False)
        self.tab6_scan_btn.clicked.connect(self.tab6_run_analysis)

        ctrl.addWidget(QLabel("Sample Size (Count):"))
        ctrl.addWidget(self.tab6_days)
        ctrl.addWidget(self.tab6_pull_btn)
        ctrl.addWidget(self.tab6_scan_btn)

        layout.addLayout(ctrl)

        # Log Window
        self.tab6_log = QTextEdit()
        self.tab6_log.setReadOnly(True)
        self.tab6_log.setFixedHeight(150)
        layout.addWidget(self.tab6_log)

        # Map View
        self.tab6_map = QWebEngineView()
        layout.addWidget(self.tab6_map)

        return w

    def tab6_pull_images(self):
        """
        Efficiently lists files on device, picks random sample, 
        and downloads ONLY that sample.
        """
        self.tab6_log.clear()
        
        try:
            sample_count = int(self.tab6_days.toPlainText().strip())
        except ValueError:
            QMessageBox.warning(self, "Error", "Please enter a valid number (e.g., 20)")
            return

        self.tab6_img_dir = tempfile.mkdtemp(prefix="img_geo_sample_")
        self.tab6_log.append(f"[*] target temp dir: {self.tab6_img_dir}")

        # 1. Define paths to scan on the phone
        target_dirs = [
            "/sdcard/DCIM/Camera",
            "/sdcard/Pictures", 
            "/sdcard/WhatsApp Images" # Note: WhatsApp usually strips EXIF, but included as requested
        ]

        all_remote_files = []

        # 2. List files WITHOUT downloading (using adb shell ls)
        self.tab6_log.append("[*] Scanning device file lists (this is fast)...")
        
        for d in target_dirs:
            try:
                # Using subprocess directly to capture stdout
                # We use 'ls' because 'find' is not available on all Android shells
                cmd = ["adb", "shell", "ls", d]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    files = result.stdout.strip().split('\n')
                    for f in files:
                        f = f.strip()
                        if f.lower().endswith(('.jpg', '.jpeg')):
                            # Construct full remote path
                            full_path = f"{d}/{f}"
                            all_remote_files.append(full_path)
            except Exception as e:
                self.tab6_log.append(f"[!] Error scanning {d}: {str(e)}")

        if not all_remote_files:
            self.tab6_log.append("[!] No images found on device.")
            return

        # 3. Random Selection
        total_found = len(all_remote_files)
        real_sample_size = min(total_found, sample_count)
        
        selected_files = random.sample(all_remote_files, real_sample_size)
        self.tab6_log.append(f"[*] Found {total_found} images. Selected {real_sample_size} random files.")

        # 4. Download ONLY the selected files
        self.tab6_log.append("[*] pulling selected files...")
        success_count = 0
        
        for remote_path in selected_files:
            # We assume ADBConnector is your helper, but here we likely need standard pull
            # If your ADBConnector.run takes ["pull", remote, local]:
            try:
                # Pull specific file to the temp dir
                ADBConnector.run(["pull", remote_path, self.tab6_img_dir])
                success_count += 1
            except Exception as e:
                print(e)

        self.tab6_log.append(f"[+] Download complete. {success_count} files ready.")
        self.tab6_scan_btn.setEnabled(True)

    def tab6_run_analysis(self):
        """
        Analyzes the files currently in the temp folder and maps them.
        """
        geolocator = Nominatim(user_agent="geo_forensics_tool_v1")
        locations = []
        
        self.tab6_log.append("[*] Extracting GPS data...")

        # Scan the temp directory (which now only contains our random sample)
        for root, _, files in os.walk(self.tab6_img_dir):
            for f in files:
                if not f.lower().endswith(('.jpg', '.jpeg')):
                    continue

                try:
                    path = os.path.join(root, f)
                    with open(path, 'rb') as img:
                        tags = exifread.process_file(img, details=False)

                    # Extract Date
                    img_date = str(tags.get('EXIF DateTimeOriginal', 'Unknown Date'))

                    # Extract GPS
                    gps = self.tab6_extract_gps(tags)
                    if not gps:
                        self.tab6_log.append(f"[-] No GPS: {f}")
                        continue

                    lat, lon = gps
                    
                    # Get City Name (Optional - remove if too slow)
                    try:
                        loc = geolocator.reverse(f"{lat},{lon}", language='en', zoom=10)
                        city = loc.raw.get("address", {}).get("city", "Unknown")
                    except:
                        city = "Unknown"

                    locations.append({
                        "lat": lat,
                        "lon": lon,
                        "city": city,
                        "date": img_date,
                        "filename": f
                    })
                    
                except Exception as e:
                    self.tab6_log.append(f"[!] Error reading {f}")
                    continue

        if not locations:
            self.tab6_log.append("[!] No valid GPS data found in the sample.")
            return

        self.tab6_log.append(f"[+] Mapping {len(locations)} locations...")
        self.tab6_generate_map(locations)

    # ... keep your existing tab6_extract_gps and tab6_generate_map methods ...

    def tab6_extract_gps(self, tags):
        try:
            def conv(v):
                return float(v[0].num)/v[0].den + \
                    float(v[1].num)/(60*v[1].den) + \
                    float(v[2].num)/(3600*v[2].den)

            lat = conv(tags['GPS GPSLatitude'].values)
            lon = conv(tags['GPS GPSLongitude'].values)

            if tags['GPS GPSLatitudeRef'].values != 'N':
                lat = -lat
            if tags['GPS GPSLongitudeRef'].values != 'E':
                lon = -lon

            return lat, lon
        except:
            return None


    def tab6_generate_map(self, locations):
        # Calculate the average center of all your photos
        if locations:
            avg_lat = sum(loc["lat"] for loc in locations) / len(locations)
            avg_lon = sum(loc["lon"] for loc in locations) / len(locations)
            start_coords = [avg_lat, avg_lon]
            start_zoom = 10  # Zoom in closer since we know the area
        else:
            # Fallback if something goes wrong
            start_coords = [20.5937, 78.9629] 
            start_zoom = 5

        # Create map centered on the photos
        fmap = folium.Map(location=start_coords, zoom_start=start_zoom)

        # Add the markers as before
        city_count = {}
        for loc in locations:
            city_count[loc["city"]] = city_count.get(loc["city"], 0) + 1
            
            folium.CircleMarker(
                [loc["lat"], loc["lon"]],
                radius=6,
                popup=f"<b>{loc['city']}</b><br>{loc['date']}<br>{loc['filename']}",
                tooltip=loc['city'],
                color="red",
                fill=True,
                fill_color="red"
            ).add_to(fmap)

        map_path = os.path.join(self.tab6_img_dir, "image_geo_map.html")
        fmap.save(map_path)

        # Try to load in QWebEngineView, but also open in browser as fallback
        try:
            self.tab6_map.load(QUrl.fromLocalFile(map_path))
            self.tab6_log.append(f"[+] Map saved and centered at {start_coords}")
        except Exception as e:
            self.tab6_log.append(f"[!] Could not display map in-app: {e}")

        # Always open in default browser as well
        import webbrowser
        webbrowser.open(f"file://{map_path}")
        self.tab6_log.append("[+] Map opened in your web browser.")




    # ---------------- GUI HELPER METHODS (Restored) ----------------

    def run_device_scan(self):
        try:
            info = ForensicEngine.get_device_info()
            self.dash_out.setText(info)
            self.status.setText("Device info updated.")
        except Exception as e:
            self.dash_out.setText(f"Error: {e}")

    def load_apps(self):
        self.app_list.clear()
        try:
            apps = ForensicEngine.get_apps()
            self.app_list.addItems(apps)
            self.status.setText(f"Loaded {len(apps)} apps.")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def scan_selected_app(self):
        item = self.app_list.currentItem()
        if not item:
            QMessageBox.warning(self, "Warning", "Please select an app from the list first.")
            return

        pkg = item.text()
        self.vt_log.clear()
        self.vt_log.append(f"Starting analysis for: {pkg}")
        self.vt_progress.setRange(0, 0) # Infinite loading
        self.lbl_score.setText("Risk Score: Analyzing...")
        
        self.vt_worker = VTScanWorker(pkg)
        self.vt_worker.log.connect(self.vt_log.append)
        self.vt_worker.result.connect(self.display_vt_results)
        self.vt_worker.finished.connect(lambda: self.vt_progress.setRange(0, 100))
        self.vt_worker.start()

    def display_vt_results(self, stats):
        malicious = stats.get('malicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        total = malicious + harmless + undetected
        
        color = "#2ea043" # Green
        if malicious > 0: color = "#da3633" # Red
        
        self.lbl_score.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {color};")
        self.lbl_score.setText(f"Risk Score: {malicious}/{total} Vendors flagged this.")
        
        self.vt_log.append("\n--- FINAL REPORT ---")
        self.vt_log.append(f"Malicious: {malicious}")
        self.vt_log.append(f"Clean/Harmless: {harmless}")
        if malicious > 0:
            QMessageBox.warning(self, "THREAT DETECTED", f"This app was flagged by {malicious} security vendors!")

    def load_history(self, c_type):
        self.hist_table.setRowCount(0)
        self.hist_table.setColumnCount(0)
        self.status.setText("Fetching history...")
        
        self.hist_worker = HistoryWorker(c_type)
        self.hist_worker.finished.connect(self.populate_table)
        self.hist_worker.start()

    def populate_table(self, data, c_type):
        """
        Processes raw history data:
        1. Aggregates by Phone Number.
        2. Color codes (Heatmap).
        3. AUTOMATICALLY SORTS by Frequency (Descending).
        """
        # 1. Handle Empty Data
        if not data:
            QMessageBox.information(self, "Empty", "No data found or permission denied.")
            self.status.setText("Fetch complete: 0 records.")
            self.hist_table.setRowCount(0)
            return

        # 2. Setup Table Columns
        self.hist_table.setSortingEnabled(False) 
        self.hist_table.clear()
        
        stats = {}

        # --- LOGIC FOR CALL LOGS ---
        if "call" in c_type:
            self.hist_table.setColumnCount(3)
            self.hist_table.setHorizontalHeaderLabels(["Phone Number", "Frequency", "Total Duration (s)"])
            
            for item in data:
                phone_num = item.get("number", "Unknown")
                try:
                    d_str = item.get("duration", "0")
                    duration = int(d_str) if d_str and str(d_str).isdigit() else 0
                except:
                    duration = 0
                
                if phone_num not in stats:
                    stats[phone_num] = {'count': 0, 'duration': 0}
                stats[phone_num]['count'] += 1
                stats[phone_num]['duration'] += duration

        # --- LOGIC FOR SMS ---
        elif "sms" in c_type:
            self.hist_table.setColumnCount(2)
            self.hist_table.setHorizontalHeaderLabels(["Address / Sender", "Message Count"])
            
            for item in data:
                addr = item.get("address", "Unknown")
                if addr not in stats:
                    stats[addr] = {'count': 0, 'duration': 0}
                stats[addr]['count'] += 1

        # 3. Calculate Max Values for Heatmap Scaling
        if not stats: return
        max_count = max((d['count'] for d in stats.values()), default=1)
        max_duration = max((d['duration'] for d in stats.values()), default=1)

        # 4. Populate & Color Rows
        self.hist_table.setRowCount(len(stats))
        
        for row_idx, (key, val) in enumerate(stats.items()):
            count = val['count']
            duration = val['duration']
            
            # Col 0: Key (Phone/Address)
            self.hist_table.setItem(row_idx, 0, QTableWidgetItem(str(key)))
            
            # Col 1: Frequency (Red Heatmap)
            item_count = QTableWidgetItem()
            item_count.setData(Qt.ItemDataRole.DisplayRole, count) 
            
            intensity = count / max_count
            alpha = int(40 + (160 * intensity)) 
            item_count.setBackground(QColor(255, 0, 0, alpha))
            self.hist_table.setItem(row_idx, 1, item_count)
            
            # Col 2: Duration (Blue Heatmap) - Only for Calls
            if "call" in c_type:
                item_dur = QTableWidgetItem()
                item_dur.setData(Qt.ItemDataRole.DisplayRole, duration)
                
                dur_intensity = duration / max_duration
                dur_alpha = int(40 + (160 * dur_intensity))
                item_dur.setBackground(QColor(0, 0, 255, dur_alpha))
                
                self.hist_table.setItem(row_idx, 2, item_dur)

        # 5. RE-ENABLE SORTING & AUTO-SORT BY FREQUENCY
        self.hist_table.setSortingEnabled(True)
        self.hist_table.sortItems(1, Qt.SortOrder.DescendingOrder)
        
        self.status.setText(f"Analyzed {len(data)} raw events -> {len(stats)} unique contacts.")

    def save_report(self):
        fname, _ = QFileDialog.getSaveFileName(self, "Save Report", "Forensic_Report.txt")
        if fname:
            with open(fname, 'w') as f:
                f.write("MOBILE FORENSIC REPORT\n")
                f.write("======================\n")
                f.write(f"Generated: {datetime.datetime.now()}\n\n")
                f.write("DEVICE INFO:\n")
                f.write(self.dash_out.toPlainText())
                f.write("\n\nEND OF REPORT")
            QMessageBox.information(self, "Success", "Report saved.")



if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ModernApp()
    window.show()
    sys.exit(app.exec())
