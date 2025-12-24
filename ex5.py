import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Toplevel
from tkinter.scrolledtext import ScrolledText
import re, html, threading, time
from urllib.parse import unquote
from collections import OrderedDict
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


# =========================================================
# THREAT INTEL
# =========================================================
KNOWN_MALICIOUS_IPS = {"192.168.1.100", "10.10.10.10"}
BLOCKED_IPS = set()

# =========================================================
# LOG PARSING
# =========================================================
APACHE_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d{3})'
)

def normalize(text):
    return html.unescape(unquote(text))

def parse_log_line(line):
    line = normalize(line.strip())
    m = APACHE_PATTERN.search(line)
    if m:
        return (m.group("time"), m.group("ip"), m.group("status"), m.group("request"), line)
    ip = re.search(r'\d+\.\d+\.\d+\.\d+', line)
    return ("-", ip.group(0) if ip else "N/A", "-", line[:120], line)

# =========================================================
# RULES
# =========================================================
DEFAULT_PATTERNS = OrderedDict([

    # ---------------- AUTH ATTACKS ----------------
    ("Multiple Failed Login Indicators",
     r"(failed login|authentication failure|invalid user|invalid password|login failed|incorrect password)"),

    ("Credential Stuffing Probe",
     r"(username=|login=|user=).{1,80}(password=|pass=|pwd=)"),

    # ---------------- SQL INJECTION ----------------
    ("SQLi - Tautology OR 1=1",
     r"(\bor\b\s*1=1|\band\b\s*1=1|'1'='1'|\"1\"=\"1\"|\bunion\b.*\bselect\b)"),

    ("SQL Injection",
     r"(select.+from|union\s+select|drop\s+table|insert\s+into|update\s+\w+|delete\s+from|--)"),

    # ---------------- COMMAND INJECTION ----------------
    ("Command Injection / Shell",
     r"(;|\|\||&&|\b(cmd|powershell|bash|sh|wget|curl|nc|netcat|exec)\b)"),

    # ---------------- FILE INCLUSION ----------------
    ("Local File Inclusion (LFI) / RFI",
     r"(\.\./|\.\.\\|/etc/passwd|/proc/self/environ|boot.ini|win.ini|http://|https://.*\.php)"),

    # ---------------- SSRF ----------------
    ("SSRF / Internal URL Fetch",
     r"(http://127\.0\.0\.1|http://localhost|169\.254\.169\.254|http://\d{1,3}(\.\d{1,3}){3})"),

    # ---------------- XSS ----------------
    ("XSS - Script / Event Handlers",
     r"(<script>|</script>|javascript:|onerror=|onload=|alert\(|<svg|<iframe)"),

    # ---------------- PATH TRAVERSAL ----------------
    ("Encoded Path Traversal",
     r"(%2e%2e%2f|%252e%252e%252f|\.\./|\.\.\\)"),

    ("Path Traversal Encoded Variants",
     r"(%c0%ae%c0%ae|%uff0e%uff0e)"),

    # ---------------- FILE UPLOAD ----------------
    ("File Upload to Admin / Upload Endpoint",
     r"(POST\s+/.*upload|multipart/form-data|filename=)"),

    # ---------------- SENSITIVE FILE ACCESS ----------------
    ("Sensitive File Access",
     r"(/etc/passwd|/etc/shadow|wp-config.php|id_rsa|\.git/config)"),

    # ---------------- DISCOVERY / RECON ----------------
    ("Discovery / Recon Probes",
     r"(/robots.txt|/sitemap.xml|/\.git/|/\.env|phpinfo\.php|/admin|/wp-admin)"),

    # ---------------- DATA EXFIL ----------------
    ("Long Query / Possible Exfil",
     r".{200,}"),

    # ---------------- SCANNERS ----------------
    ("Scanner / Automation UA",
     r"(sqlmap|nikto|nmap|masscan|acunetix|burp|python-requests)"),

    # ---------------- STATUS ABUSE ----------------
    ("Repeated 4xx/5xx Status",
     r"\b(401|403|404|500|502|503|504)\b"),

    # ---------------- ENCODED PAYLOAD ----------------
    ("Base64 / Hex Payload in URL/Body",
     r"([A-Za-z0-9+/]{40,}={0,2}|\\x[0-9A-Fa-f]{2,})"),

    # ---------------- OPEN REDIRECT ----------------
    ("Open Redirect Param",
     r"(redirect=|return=|next=)\s*(https?://)"),

    # ---------------- ADMIN LOGIN ----------------
    ("Default Admin Login Probe",
     r"(/admin/login|/administrator|/index/manager/html)")
])

class RuleDetector:
    def __init__(self, patterns):
        self.compiled = {k: re.compile(v, re.I) for k, v in patterns.items()}

    def detect(self, text):
        return [k for k, r in self.compiled.items() if r.search(text)]

# =========================================================
# MAIN APP
# =========================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Log-Based Threat Detection System")
        self.geometry("1450x820")
        self.configure(bg="#02040F")

        self.detector = RuleDetector(DEFAULT_PATTERNS)
        self.parsed_rows = []
        self.alerts = []
        self.realtime_running = False
        self.log_file_path = None

        self.build_ui()

    # ================= UI =================
    def build_ui(self):

        header = tk.Frame(self, bg="#010410", height=70)
        header.pack(fill="x")

        tk.Label(
            header,
            text="🛡 LOG-BASED THREAT DETECTION SYSTEM",
            bg="#020617",
            fg="#38bdf8",
            font=("Segoe UI", 20, "bold")
        ).pack(side="left", padx=20)

        self.status_badge = tk.Label(
            header,
            text="STATUS : IDLE",
            bg="#065f46",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            padx=14, pady=6
        )
        self.status_badge.pack(side="right", padx=20)

        # ---------- METRICS ----------
        cards = tk.Frame(self, bg="#020514")
        cards.pack(fill="x", pady=8)

        def metric(title, color):
            box = tk.Frame(cards, bg="#010611",
                           highlightbackground=color, highlightthickness=2,
                           padx=20, pady=10)
            box.pack(side="left", padx=12)
            tk.Label(box, text=title, bg="#020617",
                     fg=color, font=("Segoe UI", 10, "bold")).pack()
            lbl = tk.Label(box, text="0", bg="#020617",
                           fg="white", font=("Segoe UI", 20, "bold"))
            lbl.pack()
            return lbl

        self.logs_count = metric("TOTAL LOGS", "#38bdf8")
        self.alerts_count = metric("ALERTS", "#ef4444")
        self.blocked_count = metric("BLOCKED IPS", "#f97316")

        # ---------- BUTTONS ----------
        btn_bar = tk.Frame(self, bg="#020617")
        btn_bar.pack(fill="x", pady=10)

        def action_btn(text, color, cmd):
            return tk.Button(
                btn_bar, text=text, bg=color, fg="white",
                font=("Segoe UI", 10, "bold"),
                relief="flat", padx=14, pady=8, command=cmd
            )

        action_btn("Upload Log", "#2563eb", self.upload_log).pack(side="left", padx=6)
        action_btn("Run Detection", "#16a34a", self.run_detection).pack(side="left", padx=6)
        action_btn("Start Real-Time", "#0891b2", self.start_realtime).pack(side="left", padx=6)
        action_btn("Stop Real-Time", "#be123c", self.stop_realtime).pack(side="left", padx=6)
        action_btn("Generate PDF", "#f97316", self.generate_report).pack(side="left", padx=6)
        action_btn("Show Rules", "#7c3aed", self.show_rules).pack(side="left", padx=6)
        action_btn("Blocked IPs", "#dc2626", self.show_blocked).pack(side="left", padx=6)

        # ---------- TABLES ----------
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background="#020617",
                        foreground="white", fieldbackground="#020614",
                        rowheight=24)
        style.configure("Treeview.Heading", background="#1e293b",
                        foreground="#38bdf8", font=("Segoe UI", 10, "bold"))

        paned = ttk.PanedWindow(self, orient="vertical")
        paned.pack(fill="both", expand=True)

        self.logs_tree = ttk.Treeview(
            paned, columns=("Time", "IP", "Status", "Request"), show="headings"
        )
        for c, w in zip(("Time","IP","Status","Request"), (200,120,80,300)):
            self.logs_tree.heading(c, text=c)
            self.logs_tree.column(c, width=w)

        self.logs_tree.tag_configure("alert", background="#7f1d1d")
        paned.add(self.logs_tree, weight=3)

        self.alerts_tree = ttk.Treeview(
            paned, columns=("Rule", "Time", "IP", "Snippet"), show="headings"
        )
        for c, w in zip(("Rule","Time","IP","Snippet"), (220,180,120,300)):
            self.alerts_tree.heading(c, text=c)
            self.alerts_tree.column(c, width=w)

        paned.add(self.alerts_tree, weight=2)

    # ================= LOGIC =================
    def upload_log(self):
        path = filedialog.askopenfilename(filetypes=[("Log files", "*.log *.txt")])
        if not path:
            return

        self.log_file_path = path
        self.parsed_rows.clear()
        self.alerts.clear()
        BLOCKED_IPS.clear()

        self.logs_tree.delete(*self.logs_tree.get_children())
        self.alerts_tree.delete(*self.alerts_tree.get_children())

        with open(path, "r", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= 1000:
                    break
                parsed = parse_log_line(line)
                self.parsed_rows.append(parsed)
                self.logs_tree.insert("", "end", values=parsed[:4])

        self.logs_count.config(text=str(len(self.parsed_rows)))
        self.status_badge.config(text="STATUS : LOG LOADED", bg="#1d4ed8")

    def run_detection(self):
        if not self.parsed_rows:
            messagebox.showwarning("No Logs", "Upload log first")
            return

        self.alerts.clear()
        BLOCKED_IPS.clear()
        self.alerts_tree.delete(*self.alerts_tree.get_children())

        for idx, row in enumerate(self.parsed_rows):
            time_s, ip, status, req, raw = row
            hits = self.detector.detect(raw)

            if hits:
                self.logs_tree.item(self.logs_tree.get_children()[idx], tags=("alert",))
                for h in hits:
                    self.alerts.append((h, time_s, ip, raw[:120]))
                    self.alerts_tree.insert("", "end",
                        values=(h, time_s, ip, raw[:120]))
                    if ip not in ("-", "N/A"):
                        BLOCKED_IPS.add(ip)

        self.alerts_count.config(text=str(len(self.alerts)))
        self.blocked_count.config(text=str(len(BLOCKED_IPS)))
        self.status_badge.config(text="STATUS : SCAN COMPLETED", bg="#7f1d1d")

    # ================= REAL TIME =================
    def start_realtime(self):
        if not self.log_file_path:
            messagebox.showwarning("No File", "Upload a log file first")
            return
        if self.realtime_running:
            return

        self.realtime_running = True
        self.status_badge.config(text="STATUS : REAL-TIME ON", bg="#16a34a")
        threading.Thread(target=self.realtime_loop, daemon=True).start()

    def stop_realtime(self):
        self.realtime_running = False
        self.status_badge.config(text="STATUS : REAL-TIME OFF", bg="#7c2d12")

    def realtime_loop(self):
        with open(self.log_file_path, "r", errors="ignore") as f:
            f.seek(0, 2)
            while self.realtime_running:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue

                parsed = parse_log_line(line)
                self.parsed_rows.append(parsed)
                self.logs_tree.insert("", "end", values=parsed[:4])
                self.logs_count.config(text=str(len(self.parsed_rows)))

                hits = self.detector.detect(parsed[4])
                if hits:
                    self.logs_tree.item(self.logs_tree.get_children()[-1], tags=("alert",))
                    for h in hits:
                        self.alerts.append((h, parsed[0], parsed[1], parsed[4][:120]))
                        self.alerts_tree.insert("", "end",
                            values=(h, parsed[0], parsed[1], parsed[4][:120]))
                        if parsed[1] not in ("-", "N/A"):
                            BLOCKED_IPS.add(parsed[1])

                    self.alerts_count.config(text=str(len(self.alerts)))
                    self.blocked_count.config(text=str(len(BLOCKED_IPS)))

    # ================= REPORT =================
    def generate_report(self):
        if not self.alerts:
            messagebox.showinfo("No Alerts", "Nothing to export")
            return

        path = filedialog.asksaveasfilename(defaultextension=".pdf")
        if not path:
            return

        c = canvas.Canvas(path, pagesize=A4)
        y = A4[1] - 40
        c.setFont("Helvetica-Bold", 16)
        c.drawString(40, y, "Threat Detection Report")
        y -= 30

        c.setFont("Helvetica", 10)
        for r, t, ip, snip in self.alerts:
            if y < 60:
                c.showPage()
                y = A4[1] - 40
            c.drawString(40, y, f"{r} | {ip} | {t}")
            y -= 18

        c.save()
        messagebox.showinfo("Saved", "PDF report generated")

    def show_blocked(self):
        win = Toplevel(self)
        win.title("Blocked IPs")
        txt = ScrolledText(win)
        txt.pack(fill="both", expand=True)
        for ip in sorted(BLOCKED_IPS):
            txt.insert(tk.END, ip + "\n")
        txt.config(state="disabled")

    def show_rules(self):
        win = Toplevel(self)
        win.title("Detection Rules")
        txt = ScrolledText(win, bg="#020708", fg="cyan", font=("Consolas", 10))
        txt.pack(fill="both", expand=True)
        for rule, pattern in DEFAULT_PATTERNS.items():
            txt.insert(tk.END, f"{rule}\n{pattern}\n{'-'*40}\n")
        txt.config(state="disabled")

# ================= RUN =================
if __name__ == "__main__":
    App().mainloop()