"""
build_lncs_paper.py
===================
Builds the VSDE / PLSF Zero-Trust BEC paper as a Springer LNCS-compliant
Word document, using the official splnproc2510 proceedings template.

Output : F:\\enterprise_ngfw\\modules\\email_security\\paper.docx
Template: F:\\enterprise_ngfw\\modules\\email_security\\_word_template\\splnproc2510.docm
Images  : F:\\enterprise_ngfw\\modules\\email_security\\VSDE_PLSF_ZeroTrust_BEC\\
"""

import os
import sys
import shutil

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from docx import Document
from docx.shared import Inches, Pt, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from lxml import etree

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE      = os.path.dirname(os.path.abspath(__file__))
PAPER_DIR = os.path.join(BASE, "VSDE_PLSF_ZeroTrust_BEC")
TMPL_DIR  = os.path.join(BASE, "_word_template")
TEMPLATE  = os.path.join(TMPL_DIR, "splnproc2510.docm")
OUT_PATH  = os.path.join(BASE, "paper.docx")
IMGS      = PAPER_DIR   # image1.png / image6.png live here


# ── OMML Math Equations ───────────────────────────────────────────────────────
OMML_NS = "http://schemas.openxmlformats.org/officeDocument/2006/math"

EQ1 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:sSub><m:sSubPr><m:ctrlPr><w:rPr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:i/><w:iCs/></w:rPr></m:ctrlPr></m:sSubPr>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>D</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>c</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:t xml:space="preserve"> = 1 \u2212 </m:t></m:r>
  <m:f>
    <m:fPr><m:ctrlPr><w:rPr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:i/></w:rPr></m:ctrlPr></m:fPr>
    <m:num>
      <m:r><m:rPr><m:sty m:val="bi"/></m:rPr><m:t>e</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t xml:space="preserve"> \u00b7 </m:t></m:r>
      <m:r><m:rPr><m:sty m:val="bi"/></m:rPr><m:t>\u0113</m:t></m:r>
    </m:num>
    <m:den>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>\u2016</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="bi"/></m:rPr><m:t>e</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>\u2016 \u00b7 \u2016</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="bi"/></m:rPr><m:t>\u0113</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>\u2016</m:t></m:r>
    </m:den>
  </m:f>
</m:oMath>"""

EQ2 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:sSub><m:sSubPr><m:ctrlPr/></m:sSubPr>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>S</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>composite</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:t xml:space="preserve"> = </m:t></m:r>
  <m:sSub><m:sSubPr><m:ctrlPr/></m:sSubPr>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>w</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>dc</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:t xml:space="preserve"> \u00b7 </m:t></m:r>
  <m:sSub><m:sSubPr><m:ctrlPr/></m:sSubPr>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>D</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>c</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:t xml:space="preserve"> + </m:t></m:r>
  <m:sSub><m:sSubPr><m:ctrlPr/></m:sSubPr>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>w</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>lbec</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:t xml:space="preserve"> \u00b7 </m:t></m:r>
  <m:sSub><m:sSubPr><m:ctrlPr/></m:sSubPr>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>L</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>bec</m:t></m:r></m:sub>
  </m:sSub>
</m:oMath>"""

EQ3 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>R</m:t></m:r>
  <m:r><m:t xml:space="preserve"> = 1 \u2212 </m:t></m:r>
  <m:f>
    <m:fPr><m:ctrlPr/></m:fPr>
    <m:num>
      <m:d><m:dPr><m:begChr m:val="|"/><m:endChr m:val="|"/><m:ctrlPr/></m:dPr>
        <m:e>
          <m:sSub><m:sSubPr><m:ctrlPr/></m:sSubPr>
            <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>T</m:t></m:r></m:e>
            <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>DOM</m:t></m:r></m:sub>
          </m:sSub>
          <m:r><m:t xml:space="preserve"> \u2229 </m:t></m:r>
          <m:sSub><m:sSubPr><m:ctrlPr/></m:sSubPr>
            <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>T</m:t></m:r></m:e>
            <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>visual</m:t></m:r></m:sub>
          </m:sSub>
        </m:e>
      </m:d>
    </m:num>
    <m:den>
      <m:d><m:dPr><m:begChr m:val="|"/><m:endChr m:val="|"/><m:ctrlPr/></m:dPr>
        <m:e>
          <m:sSub><m:sSubPr><m:ctrlPr/></m:sSubPr>
            <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>T</m:t></m:r></m:e>
            <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>DOM</m:t></m:r></m:sub>
          </m:sSub>
          <m:r><m:t xml:space="preserve"> \u222a </m:t></m:r>
          <m:sSub><m:sSubPr><m:ctrlPr/></m:sSubPr>
            <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>T</m:t></m:r></m:e>
            <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>visual</m:t></m:r></m:sub>
          </m:sSub>
        </m:e>
      </m:d>
    </m:den>
  </m:f>
</m:oMath>"""


# ── Utilities ─────────────────────────────────────────────────────────────────

def find_style(doc, name, default='Normal'):
    """Case-insensitive paragraph style lookup."""
    from docx.enum.style import WD_STYLE_TYPE
    target = name.lower().replace(' ', '').replace('_', '')
    for s in doc.styles:
        if s.type != WD_STYLE_TYPE.PARAGRAPH:
            continue
        if s.name.lower().replace(' ', '').replace('_', '') == target:
            return s.name
    for s in doc.styles:
        if s.type != WD_STYLE_TYPE.PARAGRAPH:
            continue
        if target in s.name.lower().replace(' ', '').replace('_', ''):
            return s.name
    return default


def para(doc, text, style, bold=False, italic=False, sz=10,
         align=WD_ALIGN_PARAGRAPH.JUSTIFY, sb=0, sa=6,
         left_in=0, first_in=0):
    p = doc.add_paragraph(style=style)
    p.alignment = align
    p.paragraph_format.space_before = Pt(sb)
    p.paragraph_format.space_after  = Pt(sa)
    if left_in:
        p.paragraph_format.left_indent = Inches(left_in)
    if first_in:
        p.paragraph_format.first_line_indent = Inches(first_in)
    r = p.add_run(text)
    r.font.name   = 'Times New Roman'
    r.font.size   = Pt(sz)
    r.font.bold   = bold
    r.font.italic = italic
    return p


def insert_eq(doc, omml_str, eq_num, style):
    p = doc.add_paragraph(style=style)
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after  = Pt(4)
    p._p.append(etree.fromstring(omml_str))
    r = p.add_run(f'    ({eq_num})')
    r.font.name = 'Times New Roman'
    r.font.size = Pt(10)
    return p


def set_borders(table):
    """Booktabs-style: thick top/bottom, medium header rule, no inside rules."""
    tblPr = table._tbl.tblPr
    tB = tblPr.find(qn('w:tblBorders'))
    if tB is None:
        tB = OxmlElement('w:tblBorders')
        tblPr.append(tB)
    else:
        tB.clear()
    for tag, sz in [('top', 8), ('bottom', 8)]:
        b = OxmlElement(f'w:{tag}')
        b.set(qn('w:val'), 'single')
        b.set(qn('w:sz'), str(sz))
        b.set(qn('w:space'), '0')
        b.set(qn('w:color'), 'auto')
        tB.append(b)
    for tag in ('left', 'right', 'insideH', 'insideV'):
        b = OxmlElement(f'w:{tag}')
        b.set(qn('w:val'), 'none')
        tB.append(b)
    # Header bottom rule
    if len(table.rows) > 0:
        for cell in table.rows[0].cells:
            tcPr = cell._tc.get_or_add_tcPr()
            tcB  = tcPr.find(qn('w:tcBorders'))
            if tcB is None:
                tcB = OxmlElement('w:tcBorders')
                tcPr.append(tcB)
            else:
                tcB.clear()
            b = OxmlElement('w:bottom')
            b.set(qn('w:val'), 'single')
            b.set(qn('w:sz'), '6')
            b.set(qn('w:space'), '0')
            b.set(qn('w:color'), 'auto')
            tcB.append(b)


def add_table(doc, caption, headers, rows, num,
              cap_sty, col_widths=None, left_cols=None):
    # Caption above
    cp = doc.add_paragraph(style=cap_sty)
    cp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cp.paragraph_format.space_before = Pt(10)
    cp.paragraph_format.space_after  = Pt(3)
    rl = cp.add_run(f'Table {num}. ')
    rl.font.name = 'Times New Roman'
    rl.font.bold = True
    rl.font.size = Pt(9)
    rd = cp.add_run(caption)
    rd.font.name = 'Times New Roman'
    rd.font.size = Pt(9)

    left_cols = left_cols or set()
    tbl = doc.add_table(rows=1 + len(rows), cols=len(headers))
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit   = False
    if col_widths:
        for row in tbl.rows:
            for i, w in enumerate(col_widths):
                row.cells[i].width = Inches(w)

    for i, h in enumerate(headers):
        c = tbl.rows[0].cells[i]
        c.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        p = c.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT if i in left_cols else WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after  = Pt(2)
        r = p.add_run(h)
        r.font.name = 'Times New Roman'
        r.font.bold = True
        r.font.size = Pt(9)

    for ri, row_data in enumerate(rows):
        row = tbl.rows[ri + 1]
        for ci, val in enumerate(row_data):
            c = row.cells[ci]
            c.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            p = c.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT if ci in left_cols else WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after  = Pt(1)
            r = p.add_run(str(val))
            r.font.name = 'Times New Roman'
            r.font.size = Pt(8.5)

    set_borders(tbl)

    # Allow rows to break across pages → prevents large blank gaps
    from docx.oxml.ns import qn
    from lxml import etree
    for row in tbl.rows:
        tr = row._tr
        trPr = tr.find(qn('w:trPr'))
        if trPr is None:
            trPr = etree.SubElement(tr, qn('w:trPr'))
            tr.insert(0, trPr)
        # Remove any existing cantSplit, then add cantSplit=false
        for cs in trPr.findall(qn('w:cantSplit')):
            trPr.remove(cs)
        cs_el = etree.SubElement(trPr, qn('w:cantSplit'))
        cs_el.set(qn('w:val'), '0')

    sp = doc.add_paragraph()
    sp.paragraph_format.space_before = Pt(0)
    sp.paragraph_format.space_after  = Pt(6)
    sp.add_run().font.size = Pt(1)
    return tbl



def add_figure(doc, filename, width_in, caption, num, cap_sty):
    path = os.path.join(IMGS, filename)
    fp = doc.add_paragraph()
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fp.paragraph_format.space_before = Pt(8)
    fp.paragraph_format.space_after  = Pt(2)
    if os.path.exists(path):
        fp.add_run().add_picture(path, width=Inches(min(width_in, 4.5)))
    else:
        r = fp.add_run(f'[Figure {num}: {filename} not found]')
        r.font.italic = True
        r.font.size   = Pt(9)
    cp = doc.add_paragraph(style=cap_sty)
    cp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cp.paragraph_format.space_before = Pt(2)
    cp.paragraph_format.space_after  = Pt(8)
    r1 = cp.add_run(f'Fig. {num}. ')
    r1.font.name = 'Times New Roman'
    r1.font.bold = True
    r1.font.size = Pt(9)
    r2 = cp.add_run(caption)
    r2.font.name = 'Times New Roman'
    r2.font.size = Pt(9)


def bold_lead(doc, label, rest, style, sb=0, sa=6):
    """Paragraph with a bold run followed by a normal run."""
    p = doc.add_paragraph(style=style)
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.space_before = Pt(sb)
    p.paragraph_format.space_after  = Pt(sa)
    r1 = p.add_run(label)
    r1.font.name = 'Times New Roman'
    r1.font.bold = True
    r1.font.size = Pt(10)
    r2 = p.add_run(rest)
    r2.font.name = 'Times New Roman'
    r2.font.size = Pt(10)
    return p


# ── Build ─────────────────────────────────────────────────────────────────────

def build():
    if not os.path.exists(TEMPLATE):
        raise FileNotFoundError(f"Springer template not found:\n  {TEMPLATE}")

    # splnproc2510.docm is macro-enabled; convert to plain .docx via Word COM
    converted = TEMPLATE.replace('.docm', '_converted.docx')
    if not os.path.exists(converted):
        print("Converting .docm template to .docx via Microsoft Word...")
        try:
            import win32com.client
            word = win32com.client.Dispatch('Word.Application')
            word.Visible = False
            d = word.Documents.Open(os.path.abspath(TEMPLATE))
            d.SaveAs2(os.path.abspath(converted), FileFormat=16)  # 16 = wdFormatDocumentDefault
            d.Close(False)
            word.Quit()
            print(f"  Saved converted template: {converted}")
        except Exception as e:
            raise RuntimeError(
                f"Could not convert {TEMPLATE} to .docx via Word COM.\n"
                f"Error: {e}\n"
                "Make sure Microsoft Word is installed."
            ) from e
    else:
        print(f"Using cached converted template: {converted}")

    doc = Document(converted)

    # ── Discover styles ───────────────────────────────────────────────────────
    from docx.enum.style import WD_STYLE_TYPE
    print("Paragraph styles in template:")
    for s in doc.styles:
        if s.type == WD_STYLE_TYPE.PARAGRAPH:
            print(f"  '{s.name}'")

    h1   = find_style(doc, 'heading1',          'Heading 1')
    h2   = find_style(doc, 'heading2',          'Heading 2')
    h3   = find_style(doc, 'Heading 3',         'Heading 3')
    bdy  = find_style(doc, 'p1a',               'Normal')
    cap  = find_style(doc, 'figurecaption',     'Normal')
    tcs  = find_style(doc, 'tablecaption',      cap)
    rfs  = find_style(doc, 'referenceitem',     'Normal')
    ttl  = find_style(doc, 'papertitle',        'Normal')
    ath  = find_style(doc, 'author',            'Normal')
    aff  = find_style(doc, 'address',           'Normal')
    abs_ = find_style(doc, 'abstract',          'Normal')
    kwd  = find_style(doc, 'keywords',          'Normal')
    eqs  = find_style(doc, 'equation',          bdy)

    print(f"\nStyles used: H1={h1!r} H2={h2!r} Body={bdy!r} "
          f"Cap={cap!r} Refs={rfs!r} Title={ttl!r}")

    # Clear template placeholders
    for p in list(doc.paragraphs):
        p._element.getparent().remove(p._element)
    for t in list(doc.tables):
        t._element.getparent().remove(t._element)

    # =========================================================================
    # TITLE
    # =========================================================================
    print("Writing title block...")
    pt = doc.add_paragraph(style=ttl)
    pt.alignment = WD_ALIGN_PARAGRAPH.CENTER
    pt.paragraph_format.space_before = Pt(0)
    pt.paragraph_format.space_after  = Pt(10)
    rt = pt.add_run(
        "Visual-Semantic Desynchronization and Psycho-Linguistic Fingerprinting: "
        "A Zero-Trust AI Framework for Detecting Evasive BEC Attacks"
    )
    rt.font.name = 'Times New Roman'
    rt.font.size = Pt(14)
    rt.font.bold = True

    # Authors
    pa = doc.add_paragraph(style=ath)
    pa.alignment = WD_ALIGN_PARAGRAPH.CENTER
    pa.paragraph_format.space_before = Pt(8)
    pa.paragraph_format.space_after  = Pt(2)
    ra = pa.add_run(
        "Waheeb Al-Humayri\u00b9, Mubarak Altamimi\u00b2, "
        "Nehad T.A. Ramaha\u00b2, and Ismail R. Karas\u00b2"
    )
    ra.font.name = 'Times New Roman'
    ra.font.size = Pt(12)

    aff_lines = [
        "\u00b9 Dept. of Cybersecurity, The National University, Taiz, Yemen",
        "   waheeb.alhumayri@gmail.com",
        "\u00b2 Dept. of Computer Engineering, Karab\u00fck University, Karab\u00fck, Turkey",
        "   {eng.mobaraktamimi@yahoo.com, nehadramaha@karabuk.edu.tr, "
        "ismail.karas@karabuk.edu.tr}",
    ]
    for line in aff_lines:
        pa2 = doc.add_paragraph(style=aff)
        pa2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        pa2.paragraph_format.space_before = Pt(1)
        pa2.paragraph_format.space_after  = Pt(1)
        ra2 = pa2.add_run(line)
        ra2.font.name = 'Times New Roman'
        ra2.font.size = Pt(10)

    # =========================================================================
    # ABSTRACT
    # =========================================================================
    print("Writing abstract...")
    pabs = doc.add_paragraph(style=abs_)
    pabs.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    pabs.paragraph_format.space_before = Pt(14)
    pabs.paragraph_format.space_after  = Pt(4)
    pabs.paragraph_format.left_indent  = Inches(0.5)
    pabs.paragraph_format.right_indent = Inches(0.5)
    r1 = pabs.add_run("Abstract. ")
    r1.font.name = 'Times New Roman'
    r1.font.bold = True
    r1.font.size = Pt(9)
    r2 = pabs.add_run(
        "Business Email Compromise (BEC) has evolved into a human-centered attack "
        "combining persuasive language and visual evasion. Adversaries exploit LLMs "
        "to imitate executive tone and manipulate HTML/CSS so that a gateway parses "
        "benign content while the recipient reads a malicious message. This paper "
        "proposes a locally deployable Zero-Trust framework for enterprise SMTP "
        "inspection, evaluated on a 1,122-email corpus (1,012 PLSF + 110 VSDE) within "
        "an NGFW-based research environment. The framework employs a Two-Stage "
        "Gatekeeper: Psycho-Linguistic Sender Fingerprinting (PLSF)\u2014modelling "
        "sender behaviour via Sentence-Transformer embeddings and lexical BEC "
        "indicators\u2014and the Visual-Semantic Desynchronization Engine (VSDE), "
        "invoked selectively when Stage\u00a01 flags suspicious CSS markers or elevated "
        "anomaly. All processing is fully local. The anomaly threshold \u03bb is "
        "calibrated on benign emails only, preserving zero-shot operation. PLSF "
        "achieves a cross-validated weighted F1 of 85\u00a0%\u00a0\u00b1\u00a06\u00a0% "
        "(BEC-class F1\u00a0=\u00a090\u00a0% full-split), AUC\u00a0=\u00a00.91, "
        "MCC\u00a0=\u00a00.57\u00a0\u00b1\u00a00.10, without labelled attack data. "
        "VSDE achieves F1\u00a0=\u00a082\u00a0%, AUC\u00a0=\u00a00.89. The gatekeeper "
        "reduces per-email latency from 26\u00a0s to 234\u00a0ms (GPU, 5\u00a0% "
        "suspicious traffic), establishing a viable inline deployment path."
    )
    r2.font.name = 'Times New Roman'
    r2.font.size = Pt(9)

    pkw = doc.add_paragraph(style=kwd)
    pkw.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    pkw.paragraph_format.space_before = Pt(2)
    pkw.paragraph_format.space_after  = Pt(14)
    pkw.paragraph_format.left_indent  = Inches(0.5)
    pkw.paragraph_format.right_indent = Inches(0.5)
    r_kl = pkw.add_run("Keywords: ")
    r_kl.font.name = 'Times New Roman'
    r_kl.font.bold = True
    r_kl.font.size = Pt(9)
    r_kv = pkw.add_run(
        "Business Email Compromise \u00b7 Zero-Trust Architecture \u00b7 "
        "Psycho-Linguistic Fingerprinting \u00b7 Visual-Semantic Desynchronization "
        "\u00b7 CSS Evasion Detection \u00b7 NGFW."
    )
    r_kv.font.name = 'Times New Roman'
    r_kv.font.size = Pt(9)

    # =========================================================================
    # 1  INTRODUCTION
    # =========================================================================
    print("Writing Section 1...")
    doc.add_paragraph("Introduction", style=h1)

    para(doc,
        "Enterprise email remains a dominant attack surface because it targets human "
        "judgment rather than software vulnerabilities. According to the FBI Internet "
        "Crime Complaint Center, BEC generated more than $2.9 billion in adjusted "
        "losses in 2023\u00a0[1]. Traditional protections such as SPF, DKIM, and DMARC "
        "authenticate sending infrastructure but cannot detect messages sent from "
        "compromised accounts or crafted to mimic a trusted executive.", bdy)

    para(doc,
        "The threat landscape has intensified with generative AI. LLMs produce fluent, "
        "role-consistent emails that imitate executive tone with minimal effort\u00a0[2]. "
        "Concurrently, adversaries exploit HTML/CSS tricks\u2014zero-font overlays, "
        "white-on-white text, off-screen indentation\u2014to create a gap between what "
        "automated parsers inspect and what users read. Cisco Talos documented active "
        "abuse of hidden text salting in phishing campaigns\u00a0[3], illustrating the "
        "practical relevance of this rendering-layer vulnerability.", bdy)

    para(doc,
        "Current systems cannot jointly handle AI-assisted BEC and rendering-layer "
        "evasion. This gap motivates a unified approach that analyses behavioural and "
        "visual inconsistencies under a Zero-Trust model\u2014treating every email as "
        "an independent verification event without trusting sender history, protocol "
        "compliance, or parser output alone.", bdy)

    bold_lead(doc, "Contributions.", "  This paper makes three contributions:", bdy, sa=4)

    contrib_data = [
        ("Psycho-Linguistic Sender Fingerprinting (PLSF): ",
         "zero-shot executive impersonation detection via semantic drift against an "
         "adaptive sender profile, deployable from historical benign email alone."),
        ("Visual-Semantic Desynchronization (VSDE): ",
         "a computable Jaccard distance between DOM-extracted and OCR-derived visual "
         "token sets, enabling direct detection of CSS-based evasion."),
        ("Local NGFW-based SMTP inspection pipeline: ",
         "a privacy-preserving two-stage gatekeeper integrating both engines with zero "
         "external cloud dependencies."),
    ]
    for i, (lbl, rest) in enumerate(contrib_data, 1):
        pc = doc.add_paragraph(style=bdy)
        pc.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        pc.paragraph_format.space_before = Pt(0)
        pc.paragraph_format.space_after  = Pt(3)
        pc.paragraph_format.left_indent  = Inches(0.3)
        rl = pc.add_run(f"{i}.\u2002{lbl}")
        rl.font.name = 'Times New Roman'
        rl.font.bold = True
        rl.font.size = Pt(10)
        rd = pc.add_run(rest)
        rd.font.name = 'Times New Roman'
        rd.font.size = Pt(10)

    # =========================================================================
    # 2  RELATED WORK
    # =========================================================================
    print("Writing Section 2...")
    doc.add_paragraph("Related Work", style=h1)

    para(doc,
        "Email defence has progressed from metadata anomaly detection and protocol "
        "validation (SPF/DKIM) to supervised text classification\u00a0[4] and "
        "behavioural authorship verification. Sentence-BERT embeddings enable semantic "
        "sender profiling\u00a0[5]; EmailProfiler\u00a0[6], authorship-similarity "
        "modelling\u00a0[7], writeprint-based deception detection\u00a0[8], stylometric "
        "and deep-learning analysis\u00a0[9,10], and classifier-stacking "
        "approaches\u00a0[11] confirm that linguistic behavioural traces are strong "
        "discriminating signals. However, these methods depend on labelled corpora or "
        "static retraining, limiting zero-day enterprise applicability. LLM-generated "
        "phishing exacerbates this gap\u00a0[12], though LLM-based defences such as "
        "ChatSpamDetector\u00a0[13] show that language-model defences can be "
        "operationalised in practice. Experimental design has benefited from established "
        "corpora including Enron and CEAS\u00a0[14].", bdy)

    para(doc,
        "Visual rendering attacks represent a distinct and underaddressed threat "
        "surface. PhishIntention\u00a0[15] leverages visual page appearance for phishing "
        "intent inference using Vision Transformer features\u00a0[16]. Work on content "
        "concealment\u00a0[17] and HTML cloaking\u00a0[18] confirms that CSS tricks "
        "actively deceive both users and automated parsers\u2014a gap innerText-based "
        "parsers cannot bridge. At the architectural level, Zero Trust mandates "
        "continuous per-message verification\u00a0[19]; Cidon et al.\u00a0[20] "
        "demonstrated high-precision BEC detection when sender identity, context, and "
        "transactional intent are jointly modelled, and recent taxonomies confirm BEC "
        "requires dedicated pipelines\u00a0[21,22,23]. Commercial BEC platforms "
        "(Abnormal Security, Proofpoint EFD, Microsoft Defender O365) employ strong "
        "NLP-behavioural models but share a structural blind spot: none inspect the "
        "visual rendering layer for CSS-based content manipulation, and all require "
        "cloud-SaaS infrastructure incompatible with air-gapped "
        "environments\u00a0[24,25,26]. The present work unifies behavioural profiling "
        "and visual-rendering verification within a local NGFW pipeline\u2014a "
        "combination not addressed by any single prior system.", bdy)

    # =========================================================================
    # 3  METHODOLOGY
    # =========================================================================
    print("Writing Section 3...")
    doc.add_paragraph("Methodology", style=h1)

    doc.add_paragraph("System Architecture Overview", style=h2)
    para(doc,
        "The framework applies a Two-Stage Gatekeeper: Stage\u00a01 runs PLSF semantic "
        "encoding and DOM/CSS pre-screening on every email (\u223c74.4\u00a0ms); "
        "Stage\u00a02 invokes VSDE deep visual rendering only when Stage\u00a01 detects "
        "CSS evasion markers or elevated anomaly. A Risk Fusion Engine aggregates "
        "outputs and issues an allow or block decision. Fig.\u00a01 illustrates the "
        "complete workflow.", bdy)
    add_figure(doc, "image1.png", 4.0,
               "System workflow of the proposed Zero-Trust BEC detection framework.",
               1, cap)

    doc.add_paragraph("Psycho-Linguistic Sender Fingerprinting (PLSF)", style=h2)
    para(doc,
        "PLSF models a sender\u2019s normal communication profile by encoding each email "
        "with a sentence transformer (all-MiniLM-L6-v2\u00a0[27,28]) and measuring "
        "semantic drift from the historical baseline. Let e\u1d9c\u1d58\u02b3\u02b3 \u2208 "
        "\u211d\u00b3\u2078\u2074 be the SBERT embedding of the incoming email and "
        "\u0113\u0332\u1d47\u1d43\u02e2\u1d49 be the exponential moving average of the "
        "sender\u2019s historical embeddings. The semantic drift score is:", bdy)
    insert_eq(doc, EQ1, 1, eqs)
    para(doc,
        "Because semantic drift alone is insufficient against AI-generated BEC, PLSF "
        "integrates a lexical risk scanner L\u1d47\u1d49\u1d9c \u2208 [0,1] detecting fraud "
        "cues (urgent payment requests, invoice manipulation, authority pressure). The "
        "composite anomaly score is:", bdy)
    insert_eq(doc, EQ2, 2, eqs)
    para(doc,
        "with empirically calibrated weights w\u1d48\u1d9c = 0.4, w\u1d3d\u1d47\u1d49\u1d9c = 0.6. "
        "A message is flagged when S\u1d9c\u2092\u2098\u2097\u2092\u209b\u1d49 > \u03bb "
        "(\u03bb\u2092\u209a\u209c \u2248 0.240, calibrated on benign training splits only). "
        "Benign messages update \u0113\u0332\u1d47\u1d43\u02e2\u1d49 via exponential moving "
        "average, allowing natural baseline drift without retraining.", bdy)

    doc.add_paragraph("Visual-Semantic Desynchronization Engine (VSDE)", style=h2)
    para(doc,
        "VSDE detects rendering-layer evasion by comparing two token sets from the same "
        "email. T\u1d30\u1d3a\u1d39 is extracted from the raw HTML/MIME source via DOM "
        "parsing. A headless browser (Playwright\u00a0[29]) renders the email and "
        "EasyOCR\u00a0[30] extracts the visually rendered token set T\u1d20\u1d35\u209b\u1d58\u1d43\u1d38. "
        "The Visual-Semantic Desynchronization Ratio is:", bdy)
    insert_eq(doc, EQ3, 3, eqs)
    para(doc,
        "A value of R \u2192 1 indicates substantial divergence between parser-visible and "
        "user-visible content\u2014the hallmark of CSS-based evasion. The threshold was "
        "calibrated from \u03bb\u1d3f = 0.35 (18/50 false positives) to \u03bb\u1d3f = 0.45 "
        "to account for EasyOCR noise on benign email, reducing false positives to 3/50 "
        "while maintaining strong evasion recall.", bdy)

    doc.add_paragraph("Two-Stage Gatekeeper and Local Zero-Trust Integration", style=h2)
    para(doc,
        "Stage\u00a01 applies lightweight DOM parsing and CSS anomaly pre-screening in "
        "parallel with SBERT encoding (\u223c74.4\u00a0ms). Stage\u00a02 invokes deep "
        "visual rendering and EasyOCR selectively\u2014only when Stage\u00a01 detects "
        "CSS evasion markers or elevated behavioural anomaly. The expected per-email "
        "latency is E[T] = T\u209b\u209c\u1d43\u1d4d\u1d49\u2081 + "
        "p\u209b\u1d58\u209b\u209a\u1d49\u1d9c\u1d35\u2092\u1d58\u209e \u00d7 T\u209b\u209c\u1d43\u1d4d\u1d49\u2082. "
        "The entire pipeline executes locally without external cloud dependencies, "
        "adhering to NIST SP\u00a0800-207\u00a0[19].", bdy)

    # =========================================================================
    # 4  EXPERIMENTAL SETUP
    # =========================================================================
    print("Writing Section 4...")
    doc.add_paragraph("Experimental Setup", style=h1)

    para(doc,
        "The evaluation used a 1,122-email corpus: 1,012 PLSF emails from the Enron "
        "database\u00a0[31] and Nazario phishing corpus\u00a0[32] (800 seed + 152 primary "
        "test + 60 LLM-BEC), plus 110 VSDE HTML emails. For PLSF, 800 normal emails "
        "(200 per executive: Jeff Dasovich, Sally Beck, Chris Germany, Eric Bass) seeded "
        "the behavioural baseline; the primary test pool comprised 152 emails (52 normal, "
        "100 BEC; 2:1 imbalance). An additional 60 LLM-synthesised BEC emails (GPT-4o "
        "and Llama-3-70B) evaluated generative-AI robustness. For VSDE, 110 HTML emails "
        "were compiled: 50 benign, 50 CSS-evasion, and 10 adversarial CSS "
        "(1\u20133 hidden tokens). Table\u00a01 summarises the configuration.", bdy)

    add_table(doc,
        "Experimental Configuration.",
        ["Parameter / Component", "Configuration Value"],
        [
            ["Dataset",
             "1,012 PLSF (800 Seed + 152 Primary + 60 LLM-BEC); 110 VSDE HTML"],
            ["Embedding Model",
             "all-MiniLM-L6-v2, 384-dim (SentenceTransformer)\u00a0[27,28]"],
            ["PLSF Weights",
             "w\u1d48\u1d9c = 0.4 (semantic), w\u1d3d\u1d47\u1d49\u1d9c = 0.6 (lexical)"],
            ["PLSF Threshold (\u03bb)",
             "Calibrated per sender (Mean \u03bb\u2092\u209a\u209c \u2248 0.240)"],
            ["VSDE Threshold (R)", "R > 0.45 (calibrated to mitigate OCR noise)"],
            ["Validation", "5-Fold Stratified Cross-Validation"],
            ["Baselines",
             "TF-IDF+SVM; SBERT+OCSVM; Semantic-only; Lexical-only; OCR-only"],
        ],
        1, tcs, col_widths=[2.0, 3.5], left_cols={0, 1})

    # =========================================================================
    # 5  RESULTS AND DISCUSSION
    # =========================================================================
    print("Writing Section 5...")
    doc.add_paragraph("Results and Discussion", style=h1)

    doc.add_paragraph("PLSF Classification Performance", style=h2)
    para(doc,
        "Table\u00a02 reports 5-fold stratified cross-validation results. The "
        "cross-validated weighted F1 is 85\u00a0%\u00a0\u00b1\u00a06\u00a0% "
        "(BEC-class F1 under 2:1 distribution; each fold\u2019s threshold calibrated "
        "on benign splits only). On the full held-out test split, PLSF achieves "
        "Precision\u00a0=\u00a082\u00a0%, Recall\u00a0=\u00a0100\u00a0%, "
        "F1\u00a0=\u00a090\u00a0%, reported in Table\u00a03 for baseline comparison.", bdy)

    add_table(doc,
        "PLSF 5-Fold Cross-Validation Results (Calibrated Threshold). "
        "MCC from actual predictions under 2:1 class imbalance.",
        ["Fold", "Precision", "Recall", "F1", "MCC",
         "\u03bb\u2092\u209a\u209c"],
        [
            ["1",             "77 %",          "100 %",         "87 %",          "0.59", "0.240"],
            ["2",             "77 %",          "100 %",         "87 %",          "0.59", "0.240"],
            ["3",             "83 %",          "100 %",         "91 %",          "0.71", "0.240"],
            ["4",             "77 %",          "100 %",         "87 %",          "0.55", "0.230"],
            ["5",             "87 %",          "65 %",          "74 %",          "0.42", "0.270"],
            ["Mean\u00b1SD",  "80\u00b15 %",   "93\u00b116 %",  "85\u00b16 %",
             "0.57\u00b10.10", "0.244\u00b10.015"],
        ],
        2, tcs)

    para(doc,
        "Fold\u00a05 exhibits lower recall (65\u00a0%, \u03bb = 0.270) due to "
        "boundary-score overlap in 0.22\u20130.27. Sender baseline stability was "
        "validated across historical seed sizes: 20 emails "
        "(\u03bb\u2092\u209a\u209c=0.270, P=87\u00a0%, R=96\u00a0%, F1=91\u00a0%), "
        "60 emails (\u03bb\u2092\u209a\u209c=0.240, P=82\u00a0%, R=100\u00a0%, F1=90\u00a0%), "
        "200 emails (\u03bb\u2092\u209a\u209c=0.235, P=83\u00a0%, R=100\u00a0%, F1=91\u00a0%). "
        "This confirms rapid onboarding from as few as 20 benign emails without "
        "requiring historical threat archives.", bdy)

    doc.add_paragraph("Robustness to LLM-Generated Executive Impersonation", style=h2)
    para(doc,
        "GPT-4o and Llama-3-70B stylometric mimicry lowered mean semantic drift from "
        "D\u1d9c = 0.749 (legacy BEC) to D\u1d9c = 0.582, degrading recall to 68.3\u00a0% "
        "under semantic distance alone. However, the lexical scanner reliably triggered "
        "(mean L\u1d47\u1d49\u1d9c = 0.764 vs.\u00a00.128 on normal email). Under the "
        "composite model, PLSF achieved F1\u00a0=\u00a088.3\u00a0%, "
        "Recall\u00a0=\u00a091.7\u00a0%, MCC\u00a0=\u00a00.66 against the LLM corpus, "
        "confirming that the hybrid design successfully counterbalances generative "
        "semantic mimicry.", bdy)

    doc.add_paragraph("VSDE CSS Evasion Detection", style=h2)
    para(doc,
        "Table\u00a03 compares EasyOCR-based visual extraction with browser innerText "
        "on the 110-email dataset. The confusion matrix yields TP\u00a0=\u00a044, "
        "TN\u00a0=\u00a047, FP\u00a0=\u00a03, FN\u00a0=\u00a016.", bdy)

    add_table(doc,
        "VSDE CSS Evasion Detection Results (R > 0.45). "
        "MCC from actual predictions, 60 evasive : 50 benign.",
        ["Metric", "EasyOCR (Visual)", "innerText (Browser)"],
        [
            ["Samples Tested",             "110",   "110"],
            ["Correctly Detected",         "44/60", "12/60"],
            ["Precision",                  "94 %",  "100 %"],
            ["Recall",                     "73 %",  "20 %"],
            ["F1-Score",                   "82 %",  "33 %"],
            ["MCC",                        "0.68",  "0.32"],
            ["Avg Desync Ratio (Evasive)", "0.589", "0.170"],
        ],
        3, tcs, col_widths=[2.6, 1.8, 1.8])

    para(doc,
        "The innerText parser returned R = 0.000 for white-on-white text across all "
        "8 test samples. EasyOCR, operating on rendered pixels, detected these cases "
        "(Mean R = 0.496). The calibrated threshold R > 0.45 reduces benign false "
        "positives from 18/50 to 3/50. For adversarial CSS (1\u20133 hidden tokens), "
        "only 2/10 samples exceed R > 0.45, suggesting a detection boundary; "
        "larger-scale adversarial evaluation is needed.", bdy)

    doc.add_paragraph("Baseline Comparison and ROC Analysis", style=h2)
    para(doc,
        "Table\u00a04 compares all systems. The supervised SVM achieves the highest "
        "F1 (98\u00a0%, MCC\u00a0=\u00a00.94) but requires labelled attack examples. "
        "PLSF operates zero-shot and reaches F1\u00a0=\u00a090\u00a0%, "
        "MCC\u00a0=\u00a00.69. Critically, both the Lexical-Only and OCR-Only baselines "
        "yield MCC\u00a0=\u00a00.00. PLSF achieves AUC\u00a0=\u00a00.91; VSDE achieves "
        "AUC\u00a0=\u00a00.89 (Fig.\u00a02).", bdy)

    add_table(doc,
        "Comprehensive Baseline Comparison. MCC from actual system predictions "
        "under experimental class distributions.",
        ["System", "Method", "Precision", "Recall", "F1", "MCC"],
        [
            ["PLSF (This Work)", "Hybrid Sem.(0.4)+Lex.(0.6)", "82 %", "100 %", "90 %", "0.69"],
            ["SVM + TF-IDF",     "Supervised ML",              "96 %", "100 %", "98 %", "0.94"],
            ["SBERT + OCSVM",    "Embedding anomaly",          "88 %", "89 %",  "89 %", "0.66"],
            ["Semantic-Only",    "Cosine distance only",       "81 %", "100 %", "89 %", "0.66"],
            ["Lexical-Only",     "BEC indicator scoring",      "66 %", "100 %", "79 %", "0.00"],
            ["VSDE (R>0.45)",    "Jaccard DOM-Visual",         "94 %", "73 %",  "82 %", "0.68"],
            ["OCR-Only",         "Visual scan, no DOM",        "55 %", "100 %", "71 %", "0.00"],
        ],
        4, tcs, col_widths=[1.6, 2.0, 0.85, 0.75, 0.6, 0.6],
        left_cols={0, 1})

    add_figure(doc, "image6.png", 4.0,
               "ROC curves: PLSF (AUC\u00a0=\u00a00.91), VSDE-OCR (AUC\u00a0=\u00a00.89), "
               "SVM baseline (AUC\u00a0=\u00a00.98).",
               2, cap)

    doc.add_paragraph("Latency and Empirical Gatekeeper Validation", style=h2)
    para(doc,
        "All benchmarks were measured on a local testbed (Intel Core i7, 32\u00a0GB RAM, "
        "NVIDIA RTX GPU). Table\u00a05 reports per-email component latencies and the "
        "two-stage gatekeeper simulation under enterprise traffic distributions.", bdy)

    add_table(doc,
        "Per-Email Latency (top) and Two-Stage Gatekeeper Simulation (bottom).",
        ["Component / Scenario", "Mode", "Suspicious Ratio", "Mean Latency"],
        [
            ["SBERT Semantic Encoding",       "CPU",      "\u2014",  "72.54\u00a0ms"],
            ["DOM & CSS Parsing",             "CPU",      "\u2014",  "1.87\u00a0ms"],
            ["Playwright + EasyOCR",          "CPU",      "\u2014",  "26,106\u00a0ms"],
            ["Playwright + EasyOCR",          "CUDA GPU", "\u2014",  "3,200\u00a0ms"],
            ["Na\u00efve Full Visual (No Gate)","CPU",    "100 %",   "26,181\u00a0ms (Relay Timeout)"],
            ["Two-Stage Gatekeeper",          "CPU",      "5 %",     "1,380\u00a0ms (Deferred Viable)"],
            ["Two-Stage Gatekeeper",          "CUDA GPU", "5 %",     "234\u00a0ms (Inline Real-Time)"],
        ],
        5, tcs, col_widths=[2.3, 1.0, 1.2, 1.7], left_cols={0})

    para(doc,
        "At p\u209b\u1d58\u209b\u209a\u1d49\u1d9c\u1d35\u2092\u1d58\u209e = 0.05 on CPU, the "
        "gatekeeper reduces average latency from 26.18\u00a0s to 1.38\u00a0s (18.97\u00d7 "
        "speedup). With GPU acceleration, latency drops to 234\u00a0ms\u2014beneath "
        "standard enterprise MTA milter timeout thresholds (10\u201330\u00a0s), "
        "establishing VSDE as a viable inline inspection stage.", bdy)

    doc.add_paragraph("Discussion", style=h2)
    para(doc,
        "The results confirm that combining behavioural profiling with visual-rendering "
        "integrity checking produces a system meaningfully different from either "
        "component alone. PLSF\u2019s zero-shot capability\u2014F1\u00a0=\u00a090\u00a0%, "
        "AUC\u00a0=\u00a00.91 using only historical normal email\u2014is a practical "
        "advantage over supervised approaches requiring labelled attack examples. The "
        "VSDE analysis reveals a fundamental limitation of conventional text extraction: "
        "innerText returns R = 0.000 for white-on-white text, confirming that CSS evasion "
        "cannot be detected by DOM-level analysis alone. The adversarial boundary (fewer "
        "than three hidden tokens escaping detection) is an acknowledged limitation: fuzzy "
        "Jaccard matching via character-level k-gram overlap can raise this lower bound "
        "in future work.", bdy)

    # =========================================================================
    # 6  CONCLUSION
    # =========================================================================
    print("Writing Section 6...")
    doc.add_paragraph("Conclusion", style=h1)

    para(doc,
        "This paper presents a Zero-Trust AI framework for BEC detection that jointly "
        "analyses linguistic behaviour and visual rendering integrity within a fully "
        "local, NGFW-based Two-Stage Gatekeeper pipeline. Key results: "
        "(1)\u00a0PLSF achieves zero-shot sender profiling at BEC-class "
        "F1\u00a0=\u00a090\u00a0% (cross-validated weighted F1\u00a0=\u00a085\u00a0%"
        "\u00a0\u00b1\u00a06\u00a0%, AUC\u00a0=\u00a00.91), threshold calibrated on "
        "benign emails only, requiring as few as 20 seed emails. "
        "(2)\u00a0OCR-based visual rendering exposes CSS evasion\u2014particularly "
        "white-on-white text\u2014bypassing the innerText DOM-text baseline "
        "(F1\u00a0=\u00a033\u00a0% vs.\u00a0VSDE: F1\u00a0=\u00a082\u00a0%). "
        "(3)\u00a0The gatekeeper reduces per-email latency to 234\u00a0ms on GPU "
        "(5\u00a0% suspicious traffic), establishing a viable inline path. "
        "Limitations: EasyOCR noise, micro-payload blind spot (2/10 adversarial "
        "samples detected), single-organisation corpus. Future work: fuzzy k-gram "
        "Jaccard; GPU stress-testing (>10,000\u00a0msgs/min); 500+ LLM-BEC suite.", bdy)

    # =========================================================================
    # ACKNOWLEDGEMENTS & DISCLOSURE
    # =========================================================================
    ack_style = find_style(doc, 'acknowlegments', bdy)

    bold_lead(doc,
        "Acknowledgements. ",
        "The authors received no specific funding for this work.",
        ack_style, sb=12, sa=4)
    bold_lead(doc,
        "Disclosure of Interests. ",
        "The authors have no competing interests to declare that are relevant "
        "to the content of this article.",
        ack_style, sb=0, sa=12)

    # =========================================================================
    # REFERENCES
    # =========================================================================
    print("Writing References...")
    doc.add_paragraph("References", style=h1)

    entries = [
        "FBI IC3 (2024). Internet Crime Report 2023. https://www.ic3.gov/",
        "Hazell, J. (2023). Spear Phishing With Large Language Models. arXiv:2305.06972.",
        "Cisco Talos (2024). Hidden text salting: The anti-analysis technique making a "
        "comeback in email attacks. Talos Blog.",
        "Fang, Y. et al. (2019). Phishing email detection using improved RCNN model with "
        "multilevel vectors and attention mechanism. IEEE Access 7, 56329\u201356340.",
        "Reimers, N., Gurevych, I. (2019). Sentence-BERT: Sentence Embeddings Using "
        "Siamese BERT-Networks. EMNLP-IJCNLP 2019, 3982\u20133992.",
        "Duman, S. et al. (2016). EmailProfiler: Spearphishing filtering with header "
        "and stylometric features. IEEE COMPSAC 2016, 408\u2013415.",
        "Chen, R. et al. (2011). E-mail authorship verification for forensic "
        "investigation. ACM SAC 2011, 1422\u20131427.",
        "Pearl, L., Steyvers, M. (2012). Detecting authorship deception. Language "
        "and Linguistics Compass 6(9), 570\u2013583.",
        "Gr\u00f6ndahl, T. et al. (2019). All You Need is \u201cLove\u201d: Evading "
        "Hate Speech Detection. AISec 2019, 2\u201314.",
        "Wosah, O. et al. (2025). Analysing the performance of Deep Learning models "
        "for phishing email detection. Information Security Journal: A Global Perspective.",
        "Chanis, A., Kotonya, G. (2024). Enhancing phishing email detection with "
        "classifier stacking. Int. Journal of Information Security (2024).",
        "Heiding, F. et al. (2024). Devising and Detecting Phishing: Large Language "
        "Models vs. Smaller Human Models. IEEE Access 12, 43135\u201343155.",
        "Koide, T. et al. (2024). ChatSpamDetector: Leveraging Large Language Models "
        "for Effective Phishing Email Detection. arXiv:2402.18093.",
        "Cormack, G.V., Lynam, T.R. (2008). CEAS 2008 Spam Filtering Track. "
        "Proc. CEAS 2008.",
        "Liu, B. et al. (2022). Inferring Phishing Intention via Webpage Appearance "
        "and Semantics. arXiv:2210.07478.",
        "Dosovitskiy, A. et al. (2021). An Image is Worth 16x16 Words: Transformers "
        "for Image Recognition at Scale. ICLR 2021.",
        "Betts, H., Edwards, M. (2024). Exploring hidden text in HTML phishing emails. "
        "Proc. ARES 2024, 1\u20139.",
        "Guo, X. et al. (2025). HTML email cloaking for anti-spam evasion. "
        "Computers & Security 148, 104119.",
        "Rose, S. et al. (2020). Zero Trust Architecture. NIST SP 800-207.",
        "Cidon, A. et al. (2019). High Precision Detection of Business Email "
        "Compromise. USENIX Security 2019, 1291\u20131307.",
        "Almutairi, N. et al. (2025). Business Email Compromise Detection: "
        "A Systematic Survey. IEEE Access 13.",
        "Almutairi, N. et al. (2024). A Taxonomy for Business Email Compromise "
        "Attacks. arXiv:2409.17699.",
        "Cross, C., Gillett, R. (2018). Exploiting trust for financial gain: an "
        "overview of Business Email Compromise fraud. J. Financial Crime 25(1), "
        "200\u2013210.",
        "Abnormal Security (2024). Attune Product Brief. abnormalsecurity.com.",
        "Proofpoint (2024). Supernova\u2014Advanced Email Security Datasheet. "
        "proofpoint.com.",
        "Microsoft Corporation (2024). What\u2019s new in Microsoft Defender for "
        "Office\u00a0365. Microsoft Security Docs.",
        "Wang, W. et al. (2020). MiniLM: Deep Self-Attention Distillation for "
        "Task-Agnostic Compression of Pre-Trained Transformers. NeurIPS 2020.",
        "Reimers, N., Gurevych, I. (2021). The Curse of Dense Low-Dimensional "
        "Information Retrieval for Large Index Sizes. arXiv:2012.14210.",
        "Microsoft Corporation (2024). Playwright for Python. "
        "https://playwright.dev/python/",
        "JaidedAI (2024). EasyOCR. https://github.com/JaidedAI/EasyOCR",
        "Klimt, B., Yang, Y. (2004). The Enron Corpus: A New Dataset for Email "
        "Classification Research. ECML 2004, 217\u2013226.",
        "Nazario, J. (2004). Phishing corpus. "
        "https://monkey.org/~jose/phishing/",
    ]

    for i, entry in enumerate(entries, 1):
        p = doc.add_paragraph(style=rfs)
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after  = Pt(2)
        p.paragraph_format.left_indent  = Pt(18)
        p.paragraph_format.first_line_indent = Pt(-18)
        r = p.add_run(f'[{i}] {entry}')
        r.font.name = 'Times New Roman'
        r.font.size = Pt(9)

    # ── Save ──────────────────────────────────────────────────────────────────
    doc.save(OUT_PATH)
    kb = os.path.getsize(OUT_PATH) / 1024
    print(f"\n{'='*60}")
    print(f"  DONE  \u2192  {OUT_PATH}")
    print(f"  Size  : {kb:.1f} KB")
    print(f"{'='*60}\n")


if __name__ == '__main__':
    build()
