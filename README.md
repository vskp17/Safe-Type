# SafeType: A Privacy-Preserving Defensive Framework for Detecting Unauthorized Input Monitoring

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Framework: SafeType](https://img.shields.io/badge/SafeType-Defensive--Security-cyan.svg)](https://github.com/safetype/safetype)
[![Tests: 21 Passed](https://img.shields.io/badge/tests-21%20passed-brightgreen.svg)](tests/)

---

## 📜 Abstract & Executive Summary

**SafeType** is an enterprise-grade defensive Windows security framework designed to detect process behaviors and telemetry associated with unauthorized input monitoring software (keyloggers, stealth input hooks, spyware). 

Unlike traditional endpoint agents or invasive monitoring software that compromise user privacy by inspecting input buffers, **SafeType enforces a strict Zero-Keystroke Privacy Guarantee**. SafeType operates exclusively on non-invasive process metadata, cryptographic binary hashes, static YARA API signatures, active network socket telemetry, and Windows startup persistence configurations.

SafeType introduces an explainable **0–100 Risk Engine** governed by a mathematical **Multi-Indicator Safety Theorem**, ensuring zero false-positive alerts on single benign anomalies.

---

## 🛡️ Formal Zero-Keystroke Safety Guarantee

> [!IMPORTANT]  
> **PRIVACY & SAFETY PROOF**:  
> SafeType contains **ZERO keystroke logging, ZERO input hook interception, ZERO password recording, and ZERO key event buffer reads**. All behavioral inferences are derived strictly from standard Windows API metadata structures (`psutil`, `winreg`, system event maps, static binary signatures, and socket tables).

```
 ┌─────────────────────────────────────────────────────────────┐
 │                   USER INPUT SUBSYSTEM                      │
 │   [Keyboard / Mouse] ──► [OS Raw Input Buffer / Hooks]      │
 └──────────────────────────────┬──────────────────────────────┘
                                │
                   NEVER ACCESSED BY SAFETYPE (🚫)
                                │
 ┌──────────────────────────────┴──────────────────────────────┐
 │                   SAFETYPE DEFENSIVE BOUNDARY               │
 │   ✔ Process Enumeration & Parent Lineage (psutil)          │
 │   ✔ Loaded Windowing DLL References (user32.dll)            │
 │   ✔ Outbound Socket Exfiltration Analysis                  │
 │   ✔ Cryptographic Binary Hashing (SHA-256 / MD5)            │
 │   ✔ Static YARA Keylogging API Signature Engine            │
 │   ✔ Windows Autorun Registry & Startup Folder Inspection   │
 └─────────────────────────────────────────────────────────────┘
```

---

## 🏛️ End-to-End System Architecture

SafeType consists of 6 decoupled, modular architectural layers:

```
+-----------------------------------------------------------------------------------+
|                            1. TELEMETRY COLLECTION LAYER                          |
|  ProcessCollector        NetworkCollector        YaraEngine       HashUtil        |
|  (Process Enumeration)   (Socket Inspection)     (API Signatures) (SHA256/MD5)    |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        2. BEHAVIORAL OBSERVATION ENGINE                           |
|  Normalizes raw process attributes into standardized EventRecord objects          |
|  (UNUSUAL_EXE_LOCATION, INPUT_MONITORING_BEHAVIOR, OUTBOUND_NETWORK_EXFILTRATION) |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        3. EXPLAINABLE RISK EVALUATION                             |
|  Raw Score:  S_raw = ∑ w_i                                                        |
|  Safety Theorem: If |Indicators| ≤ 1 ⟹ Max Risk Score = 55 (MEDIUM)             |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                           4. SQLITE PERSISTENCE LAYER                             |
|  [processes]            [events]           [persistence]         [detections]     |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                       5. ACTIVE QUARANTINE & REMEDIATION                          |
|  1-Click Process Termination (psutil.kill) + Binary Executable File Quarantine    |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                    6. ENTERPRISE DASHBOARD & INCIDENT EXPORTER                    |
|  Streamlit UI + Plotly Risk Gauges + Event Timelines + HTML/PDF & JSON Exporters  |
+-----------------------------------------------------------------------------------+
```

---

## 📐 Mathematical Risk Formulation & Indicator Weights

SafeType computes an explainable risk score $S \in [0, 100]$ for each process $p$:

$$S_{\text{raw}}(p) = \sum_{i \in \mathcal{T}(p)} w_i$$

Where $\mathcal{T}(p)$ is the set of triggered detection rules and $w_i$ is the indicator weight:

| Indicator Rule ID | Description | Score Weight ($w_i$) | Playbook Action |
| :--- | :--- | :---: | :--- |
| `INPUT_MONITORING_BEHAVIOR` | Untrusted binary referencing input/windowing hooks | **+35** | Inspect window hooks & terminate process |
| `YARA_SIGNATURE_MATCH` | Static match for keylogging API strings (`SetWindowsHookEx`) | **+25** | Quarantine binary executable file |
| `SUSPICIOUS_PERSISTENCE` | Autorun key / Startup folder entry targeting Temp/AppData | **+25** | Remove Registry Run key / Startup entry |
| `OUTBOUND_NETWORK_EXFILTRATION` | Active outbound socket connection from untrusted binary | **+20** | Block remote IP address at host firewall |
| `UNUSUAL_EXE_LOCATION` | Binary running from `Temp`, `Public`, or `Downloads` | **+20** | Relocate binary out of temporary path |
| `UNUSUAL_PROCESS_CONTEXT` | SYSTEM privilege execution from user directory | **+15** | Audit account privileges & tokens |
| `MISSING_SIGNATURE` | Unsigned binary or missing version metadata in user folder | **+15** | Perform code signature verification |
| `SUSPICIOUS_ANCESTRY` | Binary spawned by background script interpreter (`cmd`/`powershell`) | **+15** | Trace parent process tree for attack vector |

### 🔒 Multi-Indicator Safety Theorem
To eliminate false-positive alerts on single benign background processes:

$$S_{\text{final}}(p) = \begin{cases} \min(S_{\text{raw}}(p), 55), & \text{if } |\mathcal{T}(p)| \le 1 \\ \min(S_{\text{raw}}(p), 100), & \text{if } |\mathcal{T}(p)| \ge 2 \end{cases}$$

### Severity Classification Spectrum

| Score Range | Severity Level | Badge Color | SOC Response Protocol |
| :---: | :---: | :---: | :--- |
| **0 – 29** | `LOW` | `#00E676` (Emerald Green) | Normal background process operation |
| **30 – 59** | `MEDIUM` | `#FFC107` (Amber) | Monitor behavioral telemetry |
| **60 – 79** | `HIGH` | `#FF9100` (Orange) | Investigate parent lineage & sockets |
| **80 – 100** | `CRITICAL` | `#FF1744` (Crimson) | Immediate 1-click quarantine & binary deletion |

---

## ⚡ Core Enterprise Capabilities

### 1. Live System Telemetry Scanning
Queries live Windows operating system processes in real-time, retrieving PIDs, executable paths, parent PIDs, user contexts, open network sockets, cryptographic hashes, and startup registry items.

### 2. Active Process Quarantine & File Deletion
Provides interactive `[ 🛑 Terminate & Quarantine Process ]` action buttons in the Streamlit dashboard. Kills the target PID (`psutil.Process(pid).kill()`), deletes the binary executable file from disk if located in user paths, resets the risk score to `0` (`LOW`), and prompts the user to re-scan.

### 3. Outbound Network Socket Inspection
Monitors active TCP/UDP connections (`psutil.net_connections()`), identifying untrusted binaries maintaining active outbound `ESTABLISHED` sockets to remote IP endpoints.

### 4. Static YARA API String Engine
Inspects executable files on disk for static keylogging API strings (`SetWindowsHookEx`, `GetAsyncKeyState`, `GetForegroundWindow`, `WH_KEYBOARD_LL`, `RegisterRawInputDevices`).

### 5. Executive Incident Exporter
Generates downloadable **Executive HTML Audit Reports** and **JSON Threat Reports** for SOC analysts and management.

---

## ⚙️ Installation & Usage Guide

### Prerequisites
- Python 3.11+
- Windows 10/11 (or Linux/macOS for test suites)

### Setup
```bash
# Clone repository
git clone https://github.com/safetype/safetype.git
cd safetype

# Install dependencies
pip install -r requirements.txt
```

### Running SafeType

#### 1. Perform Live System Telemetry Scan
```bash
python main.py --scan
```

#### 2. Launch Enterprise Dashboard
```bash
python main.py --dashboard
# OR via streamlit
streamlit run safetype/app/dashboard.py
```

---

## 🧪 Benchmark & Test Suite

SafeType includes 21 comprehensive automated unit tests covering all core engines:

```bash
python -m pytest tests/ -v
```

```text
tests/test_collectors.py::test_process_collector_runs_safely PASSED      [  4%]
tests/test_collectors.py::test_behavior_collector_location_checks PASSED [  9%]
tests/test_collectors.py::test_behavior_collector_analysis PASSED        [ 14%]
tests/test_collectors.py::test_persistence_collector_runs_safely PASSED  [ 19%]
tests/test_database.py::test_db_initialization PASSED                    [ 23%]
tests/test_database.py::test_process_upsert_and_retrieve PASSED          [ 28%]
tests/test_database.py::test_event_logging PASSED                        [ 33%]
tests/test_database.py::test_persistence_logging PASSED                  [ 38%]
tests/test_database.py::test_detection_storage_and_quarantine PASSED     [ 42%]
tests/test_network.py::test_network_collector_runs_safely PASSED         [ 47%]
tests/test_network.py::test_network_exfiltration_detection PASSED        [ 52%]
tests/test_report.py::test_report_generation PASSED                      [ 57%]
tests/test_rules.py::test_input_monitoring_rule PASSED                   [ 61%]
tests/test_rules.py::test_persistence_rule PASSED                        [ 66%]
tests/test_rules.py::test_unusual_location_rule PASSED                   [ 71%]
tests/test_rules.py::test_ancestry_rule PASSED                           [ 76%]
tests/test_scoring.py::test_severity_level_mapping PASSED                [ 80%]
tests/test_scoring.py::test_single_indicator_safety_policy PASSED        [ 85%]
tests/test_scoring.py::test_multi_indicator_critical_risk PASSED         [ 90%]
tests/test_yara_hash.py::test_hash_computation PASSED                    [ 95%]
tests/test_yara_hash.py::test_yara_signature_match PASSED                [100%]

============================= 21 passed in 2.74s =============================
```

---

## 📄 JSON Threat Incident Report Format

```json
{
  "framework": "SafeType Defensive Security",
  "generated_at": "2026-09-14T05:25:00+00:00",
  "target_process": {
    "pid": 9988,
    "process_name": "StealthInputHook_Demo.exe",
    "exe_path": "C:\\Users\\Public\\Libraries\\StealthInputHook_Demo.exe",
    "risk_score": 95,
    "severity_level": "CRITICAL",
    "user_context": "User",
    "parent_pid": 3304
  },
  "triggered_indicators": [
    "INPUT_MONITORING_BEHAVIOR",
    "YARA_SIGNATURE_MATCH",
    "UNUSUAL_EXE_LOCATION",
    "SUSPICIOUS_PERSISTENCE",
    "SUSPICIOUS_ANCESTRY"
  ],
  "recommended_actions": [
    "CRITICAL: Terminate process PID 9988",
    "Quarantine binary executable file on disk",
    "Delete startup VBS script in Start Menu",
    "Inspect parent PowerShell execution tree for attack vector"
  ]
}
```

---

## 📄 License & Citation

Licensed under the **MIT License**.

```bibtex
@article{safetype2026,
  title={SafeType: A Privacy-Preserving Defensive Windows Security Framework},
  author={SafeType Defensive Security Group},
  year={2026},
  publisher={GitHub Research}
}
```
