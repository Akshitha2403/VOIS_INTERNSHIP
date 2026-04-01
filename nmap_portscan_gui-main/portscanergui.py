import socket
import threading
import time
import queue
import sys
import customtkinter as ctk
from tkinter import messagebox, filedialog

# ---------------------------
# Theme Setup
# ---------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

# ---------------------------
# Service Map
# ---------------------------
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
}

# ---------------------------
# Scanner Logic (UNCHANGED)
# ---------------------------
class PortScanner:
    def __init__(self, target, start_port, end_port, timeout=0.5, max_workers=500):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_workers = max_workers
        self._stop_event = threading.Event()

        self.total_ports = max(0, end_port - start_port + 1)
        self.scanned_count = 0
        self.open_ports = []
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()

    def stop(self):
        self._stop_event.set()

    def _scan_port(self, port):
        if self._stop_event.is_set():
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                with self._lock:
                    self.open_ports.append((port, service))
                self.result_queue.put(('open', port, service))
            s.close()
        except Exception:
            pass
        finally:
            with self._lock:
                self.scanned_count += 1
            self.result_queue.put(('progress', self.scanned_count, self.total_ports))

    def resolve_target(self):
        return socket.gethostbyname(self.target)

    def run(self):
        sem = threading.Semaphore(self.max_workers)
        threads = []

        for port in range(self.start_port, self.end_port + 1):
            if self._stop_event.is_set():
                break
            sem.acquire()
            t = threading.Thread(target=self._worker_wrapper, args=(sem, port), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.result_queue.put(('done', None, None))

    def _worker_wrapper(self, sem, port):
        try:
            self._scan_port(port)
        finally:
            sem.release()

# ---------------------------
# MODERN GUI
# ---------------------------
class ScannerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("⚡ Nmap Scanner Pro")
        self.geometry("750x600")

        self.scanner = None
        self.scanner_thread = None

        self.build_ui()

    def build_ui(self):
        # Title
        title = ctk.CTkLabel(self, text="⚡ PORT SCANNER TOOL", font=("Arial", 24, "bold"))
        title.pack(pady=20)

        # Input Frame
        frame = ctk.CTkFrame(self)
        frame.pack(pady=10)

        self.entry_target = ctk.CTkEntry(frame, placeholder_text="Enter IP Address", width=200)
        self.entry_target.grid(row=0, column=0, padx=10, pady=10)

        self.entry_start = ctk.CTkEntry(frame, placeholder_text="Start Port", width=100)
        self.entry_start.insert(0, "1")
        self.entry_start.grid(row=0, column=1, padx=10)

        self.entry_end = ctk.CTkEntry(frame, placeholder_text="End Port", width=100)
        self.entry_end.insert(0, "1024")
        self.entry_end.grid(row=0, column=2, padx=10)

        # Buttons
        self.btn_scan = ctk.CTkButton(self, text="🔍 Scan", command=self.start_scan)
        self.btn_scan.pack(pady=10)

        self.btn_stop = ctk.CTkButton(self, text="⛔ Stop", command=self.stop_scan)
        self.btn_stop.pack(pady=5)

        # Output Box
        self.output = ctk.CTkTextbox(self, width=600, height=300)
        self.output.pack(pady=20)

        # Clear + Save
        bottom = ctk.CTkFrame(self)
        bottom.pack(pady=10)

        ctk.CTkButton(bottom, text="🧹 Clear", command=self.clear_output).grid(row=0, column=0, padx=10)
        ctk.CTkButton(bottom, text="💾 Save", command=self.save_output).grid(row=0, column=1, padx=10)

    # ---------------------------
    # Functions
    # ---------------------------
    def log(self, text):
        self.output.insert("end", text + "\n")
        self.output.see("end")

    def clear_output(self):
        self.output.delete("1.0", "end")

    def save_output(self):
        file = filedialog.asksaveasfilename(defaultextension=".txt")
        if file:
            with open(file, "w") as f:
                f.write(self.output.get("1.0", "end"))

    def start_scan(self):
        target = self.entry_target.get()

        try:
            start = int(self.entry_start.get())
            end = int(self.entry_end.get())
        except:
            messagebox.showerror("Error", "Invalid ports")
            return

        if not target:
            messagebox.showerror("Error", "Enter target")
            return

        self.clear_output()
        self.log(f"Scanning {target}...\n")

        self.scanner = PortScanner(target, start, end)
        self.scanner_thread = threading.Thread(target=self.run_scan)
        self.scanner_thread.start()

        self.after(100, self.update_output)

    def run_scan(self):
        try:
            ip = self.scanner.resolve_target()
            self.log(f"Resolved IP: {ip}")
        except:
            self.log("Failed to resolve target")
            return

        self.scanner.run()

    def update_output(self):
        try:
            while True:
                msg, a, b = self.scanner.result_queue.get_nowait()

                if msg == 'open':
                    self.log(f"[+] Port {a} ({b}) OPEN")

                elif msg == 'done':
                    self.log("\nScan Complete!")
                    return
        except queue.Empty:
            pass

        self.after(100, self.update_output)

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.log("Scan stopped")

# ---------------------------
# Run App
# ---------------------------
if __name__ == "__main__":
    app = ScannerGUI()
    app.mainloop()