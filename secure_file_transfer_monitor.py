#!/usr/bin/env python3

import os
import hashlib
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from pathlib import Path
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FileMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Monitor")
        self.root.geometry("900x700")
        self.root.configure(bg="#2b2b2b")

        self.events = []
        self.seen_files = set()
        self.observer = None

        self.watch_path = tk.StringVar(value="./watch_here")
        self.sensitive_extensions = {'.pdf', '.docx', '.xlsx', '.zip', '.pem', '.key'}

        self.setup_ui()

    def setup_ui(self):
        tk.Label(self.root, text="Secure File Monitor",
                 font=("Segoe UI", 16, "bold"),
                 fg="white", bg="#2b2b2b").pack(pady=10)

        frame = tk.Frame(self.root, bg="#3c3c3c")
        frame.pack(fill="x", padx=10, pady=5)

        tk.Button(frame, text="Start", command=self.start_monitoring, bg="green", fg="white").pack(side="left", padx=5)
        tk.Button(frame, text="Stop", command=self.stop_monitoring, bg="red", fg="white").pack(side="left", padx=5)
        tk.Button(frame, text="Select Folder", command=self.select_folder, bg="blue", fg="white").pack(side="left", padx=5)
        tk.Button(frame, text="Generate Report", command=self.generate_report, bg="orange").pack(side="left", padx=5)
        tk.Button(frame, text="Clear Log", command=self.clear_log, bg="gray", fg="white").pack(side="left", padx=5)

        tk.Entry(frame, textvariable=self.watch_path, width=40).pack(side="right", padx=5)

        self.status = tk.StringVar(value="Stopped")
        tk.Label(frame, textvariable=self.status, fg="yellow", bg="#3c3c3c").pack(side="right", padx=10)

        self.log = scrolledtext.ScrolledText(self.root, bg="#1a1a1a", fg="white", height=25)
        self.log.pack(fill="both", expand=True, padx=10, pady=10)

    def log_message(self, msg):
        time = datetime.now().strftime("%H:%M:%S")
        self.log.insert(tk.END, f"[{time}] {msg}\n")
        self.log.see(tk.END)

    def calculate_hash(self, path):
        try:
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()[:16]
        except:
            return "ERROR"

    def is_sensitive(self, filename):
        return filename.lower().endswith(tuple(self.sensitive_extensions))

    class Handler(FileSystemEventHandler):
        def __init__(self, gui):
            self.gui = gui

        def process(self, path, event_type):
            path = Path(path)
            name = path.name

            if event_type == "CREATED" and str(path) in self.gui.seen_files:
                return

            self.gui.seen_files.add(str(path))

            try:
                size = path.stat().st_size / 1024
            except:
                size = 0

            file_hash = self.gui.calculate_hash(path)
            sensitive = self.gui.is_sensitive(name)
            high_risk = name.endswith(('.zip', '.pem', '.key'))

            event = {
                "time": datetime.now().isoformat(),
                "file": name,
                "path": str(path),
                "event": event_type,
                "size": size,
                "hash": file_hash,
                "sensitive": sensitive,
                "alert": sensitive or high_risk
            }

            self.gui.events.append(event)

            if high_risk:
                status = "HIGH RISK"
            elif sensitive:
                status = "ALERT"
            else:
                status = "INFO"

            log_msg = f"{event_type} | {status} | {name} | {size:.1f}KB | {file_hash}"
            self.gui.log_message(log_msg)

            if len(self.gui.events) > 10:
                self.gui.log_message("ALERT: Bulk activity detected")

        def on_created(self, event):
            if not event.is_directory:
                self.process(event.src_path, "CREATED")

        def on_modified(self, event):
            if not event.is_directory:
                self.process(event.src_path, "MODIFIED")

        def on_moved(self, event):
            if not event.is_directory:
                self.process(event.dest_path, "MOVED")

    def start_monitoring(self):
        path = self.watch_path.get()
        os.makedirs(path, exist_ok=True)

        self.handler = self.Handler(self)
        self.observer = Observer()
        self.observer.schedule(self.handler, path, recursive=False)
        self.observer.start()

        self.status.set("Running")
        self.log_message(f"Monitoring started on {path}")

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()

        self.status.set("Stopped")
        self.log_message("Monitoring stopped")

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.watch_path.set(folder)

    def generate_report(self):
        if not self.events:
            messagebox.showinfo("Report", "No data available")
            return

        report_file = "security_report.txt"

        total = len(self.events)
        sensitive = sum(1 for e in self.events if e["sensitive"])
        alerts = sum(1 for e in self.events if e["alert"])

        with open(report_file, "w") as f:
            f.write("SECURE FILE MONITOR REPORT\n")
            f.write("=" * 40 + "\n\n")
            f.write(f"Generated: {datetime.now()}\n\n")

            f.write("SUMMARY\n")
            f.write(f"Total Events: {total}\n")
            f.write(f"Sensitive Files: {sensitive}\n")
            f.write(f"Alerts: {alerts}\n\n")

            f.write("EVENT DETAILS\n")
            f.write("-" * 40 + "\n")

            for e in self.events:
                f.write(f"{e['time']}\n")
                f.write(f"{e['event']} | {e['file']} | {e['size']:.1f}KB\n")
                f.write(f"Hash: {e['hash']}\n")
                f.write(f"Sensitive: {e['sensitive']} | Alert: {e['alert']}\n")
                f.write("-" * 40 + "\n")

        messagebox.showinfo("Report Generated", f"Saved as {report_file}")

    def clear_log(self):
        self.log.delete(1.0, tk.END)
        self.events.clear()
        self.seen_files.clear()
        self.log_message("Log and events cleared")


def main():
    root = tk.Tk()
    app = FileMonitorGUI(root)

    def close():
        if app.observer:
            app.observer.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", close)
    root.mainloop()


if __name__ == "__main__":
    main()