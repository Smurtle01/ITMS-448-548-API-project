import tkinter as tk
from tkinter import ttk
from api_client import *
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class ThreatDashboard:

    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Threat Intelligence Dashboard")
        self.root.geometry("1200x750")

        # UI 
        ttk.Button(root, text="Load Threat Data", command=self.load_data).pack(pady=10)

        self.output = tk.Text(root, height=18, width=130)
        self.output.pack()

        self.chart_frame = tk.Frame(root)
        self.chart_frame.pack(fill="both", expand=True)


    # LOAD DATA FROM ALL 4 APIS

    def load_data(self):

        self.output.delete(1.0, tk.END)
        self.output.insert(tk.END, "Loading data...\n\n")

        self.nvd = fetch_nvd_vulnerabilities(keyword_search="ransomware", limit=25)
        self.kev = fetch_cisa_kev()
        self.mitre = fetch_mitre_attack()
        self.urlhaus = fetch_urlhaus_recent()

        self.analyze()


    # ANALYSIS ENGINE
    
    def analyze(self):

        # 1. NVD ANALYSIS

        critical = 0
        high = 0
        medium = 0
        scores = []

        for vuln in self.nvd:
            sev = vuln.get("severity", "UNKNOWN")
            score = vuln.get("cvss_score", 0)

            if sev == "CRITICAL":
                critical += 1
            elif sev == "HIGH":
                high += 1
            elif sev == "MEDIUM":
                medium += 1

            if isinstance(score, (int, float)):
                scores.append(score)

        avg_score = sum(scores) / len(scores) if scores else 0

        # 2. OTHER DATA COUNTS

        kev_count = len(self.kev) if self.kev else 0
        urlhaus_count = len(self.urlhaus) if self.urlhaus else 0

        # MITRE is huge JSON → just summarize objects
        mitre_objects = len(self.mitre.get("objects", [])) if self.mitre else 0

        # 3. RISK SCORE ENGINE

        risk_score = (critical * 3) + (high * 2) + (medium * 1)

        # 4. OUTPUT REPORT

        self.output.delete(1.0, tk.END)

        self.output.insert(tk.END, "=== CYBER THREAT INTELLIGENCE REPORT ===\n\n")

        self.output.insert(tk.END, f"NVD Vulnerabilities: {len(self.nvd)}\n")
        self.output.insert(tk.END, f"Critical: {critical}\n")
        self.output.insert(tk.END, f"High: {high}\n")
        self.output.insert(tk.END, f"Medium: {medium}\n")
        self.output.insert(tk.END, f"Average CVSS Score: {avg_score:.2f}\n\n")

        self.output.insert(tk.END, f"CISA KEV (exploited vulns): {kev_count}\n")
        self.output.insert(tk.END, f"URLHaus Malware URLs: {urlhaus_count}\n")
        self.output.insert(tk.END, f"MITRE ATT&CK Objects: {mitre_objects}\n\n")

        self.output.insert(tk.END, f" Threat Risk Score: {risk_score}\n\n")

        # 5. INTELLIGENCE SUMMARY
        
        if risk_score > 50:
            self.output.insert(tk.END, " HIGH THREAT ENVIRONMENT DETECTED\n")
        elif risk_score > 20:
            self.output.insert(tk.END, " MODERATE THREAT ACTIVITY\n")
        else:
            self.output.insert(tk.END, " LOW THREAT ACTIVITY\n")

        # 6. VISUALIZATION

        self.make_charts(critical, high, medium, scores, kev_count, urlhaus_count)

    # CHARTS (MULTI-VIEW DASHBOARD)

    def make_charts(self, critical, high, medium, scores, kev_count, urlhaus_count):

        # clear old charts
        for widget in self.chart_frame.winfo_children():
            widget.destroy()

        # CHART 1: CVE SEVERITY
        
        fig1, ax1 = plt.subplots()
        ax1.bar(["Critical", "High", "Medium"], [critical, high, medium])
        ax1.set_title("CVE Severity Distribution")

        canvas1 = FigureCanvasTkAgg(fig1, master=self.chart_frame)
        canvas1.draw()
        canvas1.get_tk_widget().pack()

        # CHART 2: CVSS SCORES

        if scores:
            fig2, ax2 = plt.subplots()
            ax2.hist(scores, bins=10)
            ax2.set_title("CVSS Score Distribution")

            canvas2 = FigureCanvasTkAgg(fig2, master=self.chart_frame)
            canvas2.draw()
            canvas2.get_tk_widget().pack()

        # CHART 3: THREAT SOURCES

        fig3, ax3 = plt.subplots()
        ax3.pie(
            [kev_count, urlhaus_count],
            labels=["CISA KEV", "URLHaus"],
            autopct="%1.1f%%"
        )
        ax3.set_title("External Threat Sources")

        canvas3 = FigureCanvasTkAgg(fig3, master=self.chart_frame)
        canvas3.draw()
        canvas3.get_tk_widget().pack()



# RUN APP

root = tk.Tk()
app = ThreatDashboard(root)
root.mainloop()