# Secure File Transfer Monitoring System

## Overview

This project is a Python-based application that monitors file activity in real time. It detects file creation, modification, and movement inside a selected folder.

The system identifies sensitive and high-risk files, verifies file integrity using hashing, and generates alerts and reports for suspicious activity.

---

## Setup Instructions

### 1. Clone the Repository

```bash
https://github.com/Boltx099/Secure_File_Transfer_Monitoring_System.git
```

### 2. Install Dependency

```bash
pip install watchdog
```
### 3. Run the Application

```bash
python secure_file_transfer_monitor.py
```
---
## Usage
* Start the application
* Click Start Monitoring
* The system monitors the folder: watch_here
* Create or modify files inside the folder
* View logs and alerts in the GUI
----

## Testing
* Create test.txt → normal log
* Create secret.pdf → alert triggered
* Create data.zip → high-risk detection
* Modify a file → modification detected
* Move a file → movement detected
---

## Output
* Real-time logs in GUI
* Alerts for sensitive files
* File hash values
* Generated report: ```security_report.txt```

## Proof of Concept (PoC)

This section demonstrates how the system detects different types of file activities and generates alerts.

### Scenario 1: Normal File Creation

1. Start monitoring  
2. Create a file: `test.txt`  

Result:
- Event logged as normal activity  
- No alert triggered  

---

### Scenario 2: Sensitive File Detection

1. Create a file: `secret.pdf`  

Result:
- File identified as sensitive  
- Alert generated in GUI  
- Event logged with alert status  

---

### Scenario 3: High-Risk File Detection

1. Create a file: `data.zip`  

Result:
- File flagged as high-risk  
- Alert triggered  
- Logged with high-risk status  

---

### Scenario 4: File Modification

1. Modify an existing file  

Result:
- Modification event detected  
- Hash recalculated  
- Logged in system  

---

### Scenario 5: File Movement

1. Rename or move a file inside the monitored folder  

Result:
- Movement event detected  
- Logged with updated path  

---

### Scenario 6: Bulk File Activity

1. Copy multiple files (10+ files) into the monitored folder  

Result:
- Multiple events detected  
- System flags bulk activity  
- Alert message generated  

---
### Demo Video


