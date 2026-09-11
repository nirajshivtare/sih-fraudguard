from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 15)
        self.cell(0, 10, "FraudGuard AI: Architectural & Forensic Review (SIH 26106)", border=False, align="C")
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

pdf = PDF(orientation="L", format="A4")
pdf.add_page()
pdf.set_font("helvetica", size=9)

data = [
    ["Feature", "SIH Requirement", "Current Implementation", "Accuracy", "Weakness / Recommended Fix"],
    ["1. Email header forensics", "Extract metadata transparently.", "Extracts From, To, Subj, Auth. Hashes via SHA-256.", "High", "Misses X-Mailer, Message-ID. Fix: Extract in parser.py."],
    ["2. Received hop reconstruction", "Chronological hop chain.", "Regex on Received headers & reverses them.", "Medium/High", "Complex headers might fail. Fix: Use mail-parser lib."],
    ["3. Sender spoofing detection", "Detect forged senders.", "Checks Auth-Results (Alignment).", "High", "Misses homoglyphs. Fix: Add Levenshtein distance check."],
    ["4. SPF/DKIM/DMARC", "Strict auth checks.", "Parses Auth-Results string for PASS/FAIL.", "Medium", "Relies on upstream MTA. Fix: Add dkimpy to manual verify."],
    ["5. Domain alignment", "Check Return-Path vs From.", "Strict string comparison.", "High", "Misses org domain (mail.domain.com). Fix: Use tldextract."],
    ["6. IOC extraction", "Extract Domains, IPs, URLs.", "Extracts IPs, domains, URLs via Regex.", "Medium", "Misses attachment hashes. Fix: Add email.iter_attachments()."],
    ["7. IOC classification", "Classify (Benign/Malicious).", "Lists IOCs without classification.", "Low", "All look suspicious. Fix: Classify CDNs as BENIGN."],
    ["8. URL analysis", "Analyze URL risk/redirects.", "Extracts raw URL text only.", "Low", "No reputation check. Fix: Add Google Safe Browsing API."],
    ["9. IP intelligence", "ASN, ISP, Provider.", "Queries ip-api.com.", "Medium", "Free tier, no reputation. Fix: Add AbuseIPDB/VirusTotal."],
    ["10. Geolocation", "Accurate physical location.", "Uses ip-api.com for City/Country.", "Medium", "IP geolocation is imprecise. Fix: Keep 'Probable' terminology."],
    ["11. VPN/Proxy/Tor detection", "Detect obscured infra.", "String match on ISP name ('vpn', 'cloud').", "Low/Medium", "Misses residential proxies. Fix: Add Proxy/Tor exit DB."],
    ["12. Threat correlation", "Link infrastructure evidence.", "Vis.js graphs Email -> IP -> ISP.", "High", "Doesn't graph URLs. Fix: Add URLs/domains as Vis.js nodes."],
    ["13. Attribution limitations", "Do not overclaim.", "Origin Confidence drops 40% if cloud/VPN.", "High", "Perfectly aligned with SIH. No fix needed."],
    ["14. AI/NLP analysis", "Detect social engineering.", "TF-IDF + keywords.", "Medium", "TF-IDF lacks semantics. Fix: Use HuggingFace transformer."],
    ["15. Explainable risk scoring", "Transparent score.", "Aggregates evidence, outputs trust/risk strings.", "High", "Excellent implementation. No fix needed."],
    ["16. Traceability confidence", "Rate hop reliability.", "Deducts for private IPs, proxies, missing headers.", "High", "Excellent implementation. No fix needed."],
    ["17. Forensic report", "Exportable case file.", "Generates .txt report with SHA-256.", "Medium", "Standard .txt. Fix: Export highly formatted PDF."],
    ["18. PII masking", "Protect privacy.", "UI badge only.", "Low", "Backend doesn't redact. Fix: Add regex to mask emails in text."],
    ["19. Security of uploads", "Prevent exploits.", "Processed as byte stream. HTML tags stripped.", "High", "Highly secure. Fix: Add file-size limit to prevent DoS."],
    ["20. Fake/hardcoded data", "Prohibit fake data.", "Removed all hardcoded mock VT results.", "High", "Relies on live extraction. No fix needed."]
]

# Column widths
col_widths = [40, 45, 60, 25, 105]

# Table Header
pdf.set_font("helvetica", "B", 10)
for i in range(len(data[0])):
    pdf.cell(col_widths[i], 10, data[0][i], border=1, align="C")
pdf.ln()

# Table Body
pdf.set_font("helvetica", size=9)
for row in data[1:]:
    # Determine the maximum height needed for this row
    nb_lines = 1
    for i in range(len(row)):
        lines = len(pdf.multi_cell(col_widths[i], 6, row[i], split_only=True))
        if lines > nb_lines:
            nb_lines = lines
    
    h = 6 * nb_lines
    # Check if a page break is needed
    if pdf.get_y() + h > pdf.page_break_trigger:
        pdf.add_page()
    
    x = pdf.get_x()
    y = pdf.get_y()
    
    for i in range(len(row)):
        # Save x,y
        pdf.set_xy(x, y)
        pdf.multi_cell(col_widths[i], 6, row[i], border=1, align="L")
        x += col_widths[i]
        
    pdf.set_xy(pdf.l_margin, y + h)

# Verdict
pdf.ln(10)
pdf.set_font("helvetica", "B", 12)
pdf.cell(0, 10, "Judge's Verdict & Summary", border=False, ln=True)
pdf.set_font("helvetica", size=10)
verdict_text = (
    "The system successfully transitioned from a conceptual mock-up to a technically viable, forensic prototype. "
    "It excels in explainable scoring, infrastructure traceability, and strict adherence to evidence.\n\n"
    "The biggest remaining weaknesses that a tough judge might poke holes in are IOC Classification (failing to distinguish a benign CDN URL from a phishing link) "
    "and PII Masking (claiming it's active when the backend isn't actually redacting the text)."
)
pdf.multi_cell(0, 6, verdict_text)

pdf.output("FraudGuard_SIH26106_Review.pdf")
print("PDF generated successfully.")
