import os
import re
import sys
import shutil

# Ensure UTF-8 output encoding for Windows console/terminal
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import docx
from docx import Document
from docx.shared import Inches, Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.enum.section import WD_SECTION
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from lxml import etree

# ─── PATHS ───────────────────────────────────────────────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(BASE) # F:\zero-trust-email-bec-dataset-main

# Images folder location
IMGS = os.path.join(WORKSPACE, "extracted_images")
if not os.path.exists(IMGS):
    IMGS = os.path.join(BASE, "extracted_images")

TEMPLATE_PATH = os.path.join(BASE, "Conference-template-A4_٠٢٠٦٣٥.docx")
if not os.path.exists(TEMPLATE_PATH):
    TEMPLATE_PATH = os.path.join(BASE, "Conference-template-A4_٠٢٠٦٣٥.doc")
if not os.path.exists(TEMPLATE_PATH):
    TEMPLATE_PATH = os.path.join(WORKSPACE, "Conference-template-A4_٠٢٠٦٣٥.doc")
OUT_PATH = os.path.join(BASE, "VSDesync_PLSF_ZeroTrust_BEC_AIP_REVISED_IEEE.docx")
OUT_PATH_ALT = os.path.join(BASE, "VSDE_PLSF_ZeroTrust_BEC_IEEE.docx")

# ─── OMML NAMESPACE & MATH FORMULAS ──────────────────────────────────────────
OMML_NS = "http://schemas.openxmlformats.org/officeDocument/2006/math"

EQ1 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:sSub>
    <m:sSubPr><m:ctrlPr><w:rPr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:i/><w:iCs/></w:rPr></m:ctrlPr></m:sSubPr>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>D</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>c</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:t xml:space="preserve"> = 1 − </m:t></m:r>
  <m:f>
    <m:fPr><m:ctrlPr><w:rPr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:i/></w:rPr></m:ctrlPr></m:fPr>
    <m:num>
      <m:r><m:rPr><m:sty m:val="bi"/></m:rPr><m:t>e</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t xml:space="preserve"> </m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>⋅</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t xml:space="preserve"> </m:t></m:r>
      <m:r><m:rPr><m:sty m:val="bi"/></m:rPr><m:t>ē</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t xml:space="preserve"> </m:t></m:r>
    </m:num>
    <m:den>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>║</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="bi"/></m:rPr><m:t>e</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>║ ⋅ ║</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="bi"/></m:rPr><m:t>ē</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>║</m:t></m:r>
    </m:den>
  </m:f>
</m:oMath>"""

EQ2 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:sSub>
    <m:sSubPr><m:ctrlPr/></m:sSubPr>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>S</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>composite</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:t xml:space="preserve"> = </m:t></m:r>
  <m:sSub>
    <m:sSubPr><m:ctrlPr/></m:sSubPr>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>w</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>dc</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:t xml:space="preserve"> ⋅ </m:t></m:r>
  <m:sSub>
    <m:sSubPr><m:ctrlPr/></m:sSubPr>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>D</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>c</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:t xml:space="preserve"> + </m:t></m:r>
  <m:sSub>
    <m:sSubPr><m:ctrlPr/></m:sSubPr>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>w</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>lbec</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:t xml:space="preserve"> ⋅ </m:t></m:r>
  <m:sSub>
    <m:sSubPr><m:ctrlPr/></m:sSubPr>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>L</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>bec</m:t></m:r></m:sub>
  </m:sSub>
</m:oMath>"""

EQ3 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>R</m:t></m:r>
  <m:r><m:t xml:space="preserve"> = 1 − </m:t></m:r>
  <m:f>
    <m:fPr><m:ctrlPr/></m:fPr>
    <m:num>
      <m:d>
        <m:dPr>
          <m:begChr m:val="|"/>
          <m:endChr m:val="|"/>
          <m:ctrlPr/>
        </m:dPr>
        <m:e>
          <m:sSub>
            <m:sSubPr><m:ctrlPr/></m:sSubPr>
            <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>T</m:t></m:r></m:e>
            <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>DOM</m:t></m:r></m:sub>
          </m:sSub>
          <m:r><m:t xml:space="preserve"> ∩ </m:t></m:r>
          <m:sSub>
            <m:sSubPr><m:ctrlPr/></m:sSubPr>
            <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>T</m:t></m:r></m:e>
            <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>visual</m:t></m:r></m:sub>
          </m:sSub>
        </m:e>
      </m:d>
    </m:num>
    <m:den>
      <m:d>
        <m:dPr>
          <m:begChr m:val="|"/>
          <m:endChr m:val="|"/>
          <m:ctrlPr/>
        </m:dPr>
        <m:e>
          <m:sSub>
            <m:sSubPr><m:ctrlPr/></m:sSubPr>
            <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>T</m:t></m:r></m:e>
            <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>DOM</m:t></m:r></m:sub>
          </m:sSub>
          <m:r><m:t xml:space="preserve"> ∪ </m:t></m:r>
          <m:sSub>
            <m:sSubPr><m:ctrlPr/></m:sSubPr>
            <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>T</m:t></m:r></m:e>
            <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>visual</m:t></m:r></m:sub>
          </m:sSub>
        </m:e>
      </m:d>
    </m:den>
  </m:f>
</m:oMath>"""


# ─── TEMPLATE CONVERSION & INSPECTION HELPERS ─────────────────────────────────

def ensure_docx_template(template_path):
    """
    Ensures python-docx can open the template. If it's a binary .doc, 
    converts it to .docx using win32com (Word) on Windows.
    """
    if not os.path.exists(template_path):
        docx_cand = template_path + "x"
        if os.path.exists(docx_cand):
            return docx_cand
        raise FileNotFoundError(f"Template file not found at: {template_path}")
        
    with open(template_path, 'rb') as f:
        magic = f.read(4)
        
    if magic.startswith(b'PK\x03\x04'):
        if template_path.lower().endswith('.docx'):
            return template_path
        else:
            docx_path = template_path + "x"
            print(f"Template is a renamed docx file. Copying to {docx_path}...")
            shutil.copy2(template_path, docx_path)
            return docx_path
            
    if template_path.lower().endswith('.doc'):
        docx_path = template_path + "x"
        if os.path.exists(docx_path):
            print(f"Using already converted docx template: {docx_path}")
            return docx_path
            
        print("Template is a binary .doc file. Attempting conversion via MS Word COM...")
        try:
            import win32com.client
            word = win32com.client.Dispatch("Word.Application")
            word.Visible = False
            abs_doc = os.path.abspath(template_path)
            abs_docx = os.path.abspath(docx_path)
            
            doc = word.Documents.Open(abs_doc)
            doc.SaveAs2(abs_docx, FileFormat=16)
            doc.Close()
            word.Quit()
            print(f"Conversion successful! Converted to: {docx_path}")
            return docx_path
        except Exception as e:
            print(f"COM conversion failed: {e}")
            print("Please check if MS Word is installed. Or manually save the template as a .docx file and try again.")
            raise e
            
    return template_path


def find_style(doc, target_name, default='Normal'):
    """
    Looks for the best matching style name in the document's style sheet.
    Performs case-insensitive search and removes spaces. Only matches PARAGRAPH styles.
    """
    from docx.enum.style import WD_STYLE_TYPE
    target = target_name.lower().replace(' ', '').replace('_', '')
    
    for style in doc.styles:
        if style.type != WD_STYLE_TYPE.PARAGRAPH:
            continue
        s_name = style.name.lower().replace(' ', '').replace('_', '')
        if s_name == target:
            return style.name
            
    best_match = None
    for style in doc.styles:
        if style.type != WD_STYLE_TYPE.PARAGRAPH:
            continue
        s_name = style.name.lower().replace(' ', '').replace('_', '')
        if target in s_name:
            best_match = style.name
            break
            
    if best_match:
        return best_match
        
    fallback_map = {
        'papertitle': ['paper title', 'title', 'document title'],
        'author': ['author', 'author name', 'authors'],
        'authoraffiliation': ['affiliation', 'author affiliation', 'affiliations', 'aff'],
        'abstract': ['abstract', 'abstract text'],
        'keywords': ['keywords', 'index terms'],
        'heading1': ['heading 1', 'heading1', 'h1'],
        'heading2': ['heading 2', 'heading2', 'h2'],
        'heading3': ['heading 3', 'heading3', 'h3'],
        'heading5': ['heading 5', 'heading5', 'h5'],
        'bodytext': ['body text', 'body', 'normal', 'paragraph'],
        'references': ['references', 'reference', 'reference text', 'bib'],
        'tablehead': ['table head', 'table title', 'table caption'],
        'tablecolhead': ['table col head', 'table header', 'table col'],
        'tablecopy': ['table copy', 'table text', 'table body'],
        'figurecaption': ['figure caption', 'caption', 'figure']
    }
    
    if target in fallback_map:
        for fb in fallback_map[target]:
            fb_norm = fb.lower().replace(' ', '').replace('_', '')
            for style in doc.styles:
                if style.type != WD_STYLE_TYPE.PARAGRAPH:
                    continue
                s_name = style.name.lower().replace(' ', '').replace('_', '')
                if fb_norm == s_name or fb_norm in s_name:
                    return style.name
                    
    return default


# ─── PARSING & FORMATTING HELPERS ─────────────────────────────────────────────

def add_formatted_paragraph(doc, text, style='Normal', indent=None):
    """
    Parses string for markdown styles (***bolditalic***, **bold**, *italic*, `code`)
    and writes formatting runs. Uses Times New Roman and default styling.
    """
    p = doc.add_paragraph(style=style)
    if indent is not None:
        p.paragraph_format.first_line_indent = indent
        
    pattern = re.compile(r'(\*\*\*.*?\*\*\*|\*\*.*?\*\*|\*.*?\*|`.*?`)')
    parts = pattern.split(text)
    
    for part in parts:
        if not part:
            continue
        if part.startswith('***') and part.endswith('***'):
            r = p.add_run(part[3:-3])
            r.font.name = "Times New Roman"
            r.font.bold = True
            r.font.italic = True
        elif part.startswith('**') and part.endswith('**'):
            r = p.add_run(part[2:-2])
            r.font.name = "Times New Roman"
            r.font.bold = True
        elif part.startswith('*') and part.endswith('*'):
            r = p.add_run(part[1:-1])
            r.font.name = "Times New Roman"
            r.font.italic = True
        elif part.startswith('`') and part.endswith('`'):
            r = p.add_run(part[1:-1])
            r.font.name = "Consolas"
            r.font.size = Pt(8.5)
        else:
            r = p.add_run(part)
            r.font.name = "Times New Roman"
    return p


def insert_equation_native(doc, omml_str, eq_num, style='Normal'):
    """
    Inserts a single paragraph with a centered equation and a right-aligned number.
    Uses tabs for alignment within standard templates.
    """
    p = doc.add_paragraph(style=style)
    p.paragraph_format.space_before = Pt(3)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    eq_el = etree.fromstring(omml_str)
    p._p.append(eq_el)
    
    r = p.add_run(f'    ({eq_num})')
    r.font.name = "Times New Roman"
    r.font.size = Pt(9.5)
    return p


def format_ieee_table(table, grid=False, inside_h=False):
    """
    Sets clean scientific rules on the table (similar to booktabs / IEEE rules):
    - Top/Bottom borders: solid 1.0 pt
    - Header bottom border: solid 0.75 pt
    - If inside_h or grid is True: adds thin horizontal rules between data rows (0.5 pt)
    - If grid is True: adds thin vertical borders
    """
    tblPr = table._tbl.tblPr
    tblBorders = tblPr.find(qn('w:tblBorders'))
    if tblBorders is None:
        tblBorders = OxmlElement('w:tblBorders')
        tblPr.append(tblBorders)
    else:
        tblBorders.clear()
        
    # Top border (1.0 pt)
    top = OxmlElement('w:top')
    top.set(qn('w:val'), 'single')
    top.set(qn('w:sz'), '8')
    top.set(qn('w:space'), '0')
    top.set(qn('w:color'), 'auto')
    tblBorders.append(top)
    
    # Bottom border (1.0 pt)
    bottom = OxmlElement('w:bottom')
    bottom.set(qn('w:val'), 'single')
    bottom.set(qn('w:sz'), '8')
    bottom.set(qn('w:space'), '0')
    bottom.set(qn('w:color'), 'auto')
    tblBorders.append(bottom)
    
    # Left and Right borders
    for b_name in ['left', 'right']:
        b = OxmlElement(f'w:{b_name}')
        b.set(qn('w:val'), 'single' if grid else 'none')
        if grid:
            b.set(qn('w:sz'), '4')
            b.set(qn('w:color'), 'D3D3D3')
        tblBorders.append(b)
        
    # Inside horizontal borders between rows
    insideH = OxmlElement('w:insideH')
    if grid or inside_h:
        insideH.set(qn('w:val'), 'single')
        insideH.set(qn('w:sz'), '4') # 0.5 pt
        insideH.set(qn('w:color'), 'D3D3D3') # Light clean gray
    else:
        insideH.set(qn('w:val'), 'none')
    tblBorders.append(insideH)
    
    # Inside vertical borders
    insideV = OxmlElement('w:insideV')
    if grid:
        insideV.set(qn('w:val'), 'single')
        insideV.set(qn('w:sz'), '4')
        insideV.set(qn('w:color'), 'D3D3D3')
    else:
        insideV.set(qn('w:val'), 'none')
    tblBorders.append(insideV)
    
    # Add bottom border to header row (0.75 pt)
    for cell in table.rows[0].cells:
        tc = cell._tc
        tcPr = tc.get_or_add_tcPr()
        tcBorders = tcPr.find(qn('w:tcBorders'))
        if tcBorders is None:
            tcBorders = OxmlElement('w:tcBorders')
            tcPr.append(tcBorders)
        else:
            tcBorders.clear()
            
        b_cell = OxmlElement('w:bottom')
        b_cell.set(qn('w:val'), 'single')
        b_cell.set(qn('w:sz'), '6') # 0.75 pt
        b_cell.set(qn('w:space'), '0')
        b_cell.set(qn('w:color'), 'auto')
        tcBorders.append(b_cell)
        
        for edge in ('top', 'left', 'right'):
            e = OxmlElement(f'w:{edge}')
            e.set(qn('w:val'), 'none')
            tcBorders.append(e)


def to_roman(val):
    """Converts an integer to a Roman numeral (up to 10)."""
    roman_map = {1: 'I', 2: 'II', 3: 'III', 4: 'IV', 5: 'V', 6: 'VI', 7: 'VII', 8: 'VIII', 9: 'IX', 10: 'X'}
    return roman_map.get(int(val), str(val))


def add_table_ieee(doc, caption_text, headers, rows, table_num, caption_style='Normal', 
                   inside_h=False, grid=False, align_left=False, col_widths=None):
    """
    Adds a formatted scientific table with a Table Caption centered above it.
    Uses template style for table head (which automatically provides TABLE X. numbering in Word).
    Supports inside_h for horizontal row dividers and custom column alignments.
    """
    cap = doc.add_paragraph(style=caption_style)
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cap.paragraph_format.space_before = Pt(8)
    cap.paragraph_format.space_after = Pt(4)
    
    # Check if caption style already has automatic numbering attached
    has_num = False
    if hasattr(cap.style, '_element') and cap.style._element.xpath('./w:pPr/w:numPr'):
        has_num = True
        
    if not has_num:
        roman_num = to_roman(table_num)
        run_num = cap.add_run(f"TABLE {roman_num}.  ")
        run_num.font.name = "Times New Roman"
        run_num.font.bold = True
        run_num.font.size = Pt(8.0)
    
    # Table description in uppercase/small caps without repeating 'TABLE X.'
    run_desc = cap.add_run(caption_text.upper())
    run_desc.font.name = "Times New Roman"
    run_desc.font.size = Pt(8.0)
    
    table = doc.add_table(rows=1 + len(rows), cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    # Set custom column widths if provided
    if col_widths and len(col_widths) == len(headers):
        for r in table.rows:
            for i, w in enumerate(col_widths):
                r.cells[i].width = Inches(w)
    
    hdr = table.rows[0]
    hdr.height = Cm(0.5)
    for i, h in enumerate(headers):
        cell = hdr.cells[i]
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT if align_left else WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(2)
        run = p.add_run(h)
        run.font.name = "Times New Roman"
        run.font.bold = True
        run.font.size = Pt(8.0)
        
    for r_idx, row_data in enumerate(rows):
        row = table.rows[r_idx + 1]
        row.height = Cm(0.4)
        for c_idx, val in enumerate(row_data):
            cell = row.cells[c_idx]
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT if align_left else WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(2)
            run = p.add_run(str(val))
            run.font.name = "Times New Roman"
            run.font.size = Pt(7.5)
            
    format_ieee_table(table)
    
    p_spacer = doc.add_paragraph()
    p_spacer.paragraph_format.space_before = Pt(0)
    p_spacer.paragraph_format.space_after = Pt(4)
    r = p_spacer.add_run()
    r.font.size = Pt(1)
    return table


def add_centered_image(doc, filename, width, caption_text, fig_num,
                       caption_style='Normal', alt_text=''):
    """
    Adds a centered image with a Figure Caption below it.
    Uses template style for figure caption (which automatically provides Fig. X. numbering in Word).
    alt_text: Springer Nature / WCAG-compliant alternative text for accessibility.
    """
    path = os.path.join(IMGS, filename)
    if os.path.exists(path):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(4)
        p.paragraph_format.space_after = Pt(2)
        run = p.add_run()
        pic = run.add_picture(path, width=Inches(min(width, 3.45)))

        # ── Inject Alt Text into the drawing XML (Springer accessibility requirement) ──
        # The inline drawing element contains a <wp:docPr> element which holds title and descr.
        if alt_text:
            try:
                # Navigate: run._r -> w:drawing -> wp:inline -> wp:docPr
                drawing_elem = run._r.find(qn('w:drawing'))
                if drawing_elem is not None:
                    inline = drawing_elem.find(qn('wp:inline'),
                        namespaces={'wp': 'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing'})
                    if inline is not None:
                        doc_pr = inline.find(
                            '{http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing}docPr')
                        if doc_pr is not None:
                            doc_pr.set('descr', alt_text)
                            doc_pr.set('title', f'Fig. {fig_num}')
            except Exception:
                pass  # Alt text injection failed silently; image still inserted

        cap = doc.add_paragraph(style=caption_style)
        cap.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        cap.paragraph_format.space_before = Pt(2)
        cap.paragraph_format.space_after = Pt(6)

        has_num = False
        if hasattr(cap.style, '_element') and cap.style._element.xpath('./w:pPr/w:numPr'):
            has_num = True

        if not has_num:
            run_lbl = cap.add_run(f"Fig. {fig_num}.  ")
            run_lbl.font.name = "Times New Roman"
            run_lbl.font.bold = False
            run_lbl.font.size = Pt(8.0)

        run_desc = cap.add_run(caption_text)
        run_desc.font.name = "Times New Roman"
        run_desc.font.size = Pt(8.0)
    else:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(f"[Fig. {fig_num}: {caption_text} - Image file '{filename}' not found]")
        run.font.italic = True
        run.font.size = Pt(8.0)


# ─── CORE BUILD PROCEDURE ────────────────────────────────────────────────────

def build_docx():
    print("Preparing template file...")
    active_template = ensure_docx_template(TEMPLATE_PATH)
    
    print("Initializing document...")
    doc = Document(active_template)
    
    # Enable document-wide automatic hyphenation and allow capitalized words to be hyphenated
    settings_el = doc.settings._element
    
    # Remove doNotHyphenateCaps if present so capitalized terms (e.g. Visual-Semantic Desynchronization) can split cleanly
    do_not_hyphen_caps = settings_el.find(qn('w:doNotHyphenateCaps'))
    if do_not_hyphen_caps is not None:
        settings_el.remove(do_not_hyphen_caps)
        
    auto_hyphen = settings_el.find(qn('w:autoHyphenation'))
    if auto_hyphen is None:
        auto_hyphen = OxmlElement('w:autoHyphenation')
        auto_hyphen.set(qn('w:val'), 'true')
        settings_el.append(auto_hyphen)
    else:
        auto_hyphen.set(qn('w:val'), 'true')
        
    title_style = find_style(doc, 'Paper Title', 'Normal')
    author_style = find_style(doc, 'Author', 'Normal')
    aff_style = find_style(doc, 'Affiliation', 'Normal')
    abs_style = find_style(doc, 'Abstract', 'Normal')
    kw_style = find_style(doc, 'Keywords', 'Normal')
    h1_style = find_style(doc, 'Heading 1', 'Heading 1')
    h2_style = find_style(doc, 'Heading 2', 'Heading 2')
    h3_style = find_style(doc, 'Heading 3', 'Heading 3')
    h5_style = find_style(doc, 'Heading 5', 'Heading 5')
    para_style = find_style(doc, 'Body Text', 'Normal')
    ref_style = find_style(doc, 'references', 'Normal')
    tbl_head_style = find_style(doc, 'table head', 'Normal')
    fig_cap_style = find_style(doc, 'figure caption', 'Normal')
    
    print(f"Resolved Styles: Title='{title_style}', Author='{author_style}', Affiliation='{aff_style}', "
          f"Abstract='{abs_style}', Keywords='{kw_style}', H1='{h1_style}', H2='{h2_style}', "
          f"BodyText='{para_style}', Ref='{ref_style}'")
    
    # ── Clear template placeholders ──
    print("Clearing template placeholders...")
    for p in list(doc.paragraphs):
        p._element.getparent().remove(p._element)
    for t in list(doc.tables):
        t._element.getparent().remove(t._element)
        
    # ── SECTION 1: Title & Authors Block (Single Column across page) ──
    print("Setting up Section 1 (Title and Author layout across full width)...")
    sec1 = doc.sections[0]
    
    sectPr1 = sec1._sectPr
    cols1 = sectPr1.xpath('./w:cols')
    if not cols1:
        cols1 = OxmlElement('w:cols')
        sectPr1.append(cols1)
    else:
        cols1 = cols1[0]
    cols1.set(qn('w:num'), '1')
    cols1.set(qn('w:space'), '720')
    
    # Paper Title (24 pt, Centered, Style: paper title)
    p_title = doc.add_paragraph(style=title_style)
    p_title.paragraph_format.space_before = Pt(12)
    p_title.paragraph_format.space_after = Pt(12)
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_title = p_title.add_run(
        "Visual-Semantic Desynchronization and Psycho-Linguistic Fingerprinting:\n"
        "A Zero-Trust AI Framework for Detecting Evasive BEC Attacks"
    )
    r_title.font.name = "Times New Roman"
    r_title.font.bold = False
    r_title.font.size = Pt(24)
    
    # 2-Author Side-by-Side Block (Clean borderless table across page)
    print("Creating Author Block (side-by-side columns)...")
    auth_table = doc.add_table(rows=1, cols=2)
    auth_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    auth_table.autofit = False
    
    tblPr = auth_table._tbl.tblPr
    tblBorders = OxmlElement('w:tblBorders')
    for b_name in ['top', 'left', 'bottom', 'right', 'insideH', 'insideV']:
        b = OxmlElement(f'w:{b_name}')
        b.set(qn('w:val'), 'none')
        tblBorders.append(b)
    tblPr.append(tblBorders)
    
    col_w = Inches(3.45)
    for row in auth_table.rows:
        row.cells[0].width = col_w
        row.cells[1].width = col_w
        
    # Author 1: Waheeb Al-Humayri
    cell_a1 = auth_table.rows[0].cells[0]
    p_a1 = cell_a1.paragraphs[0]
    p_a1.style = author_style
    p_a1.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_a1.paragraph_format.space_before = Pt(6)
    p_a1.paragraph_format.space_after = Pt(2)
    r = p_a1.add_run("Waheeb Al-Humayri")
    r.font.name = "Times New Roman"
    r.font.size = Pt(11.0)
    r.font.bold = True
    
    a1_lines = [
        ("dept. of Cybersecurity", True),
        ("The National University", True),
        ("Taiz, Yemen", False),
        ("waheeb.alhumayri@gmail.com", False)
    ]
    for text, is_italic in a1_lines:
        p = cell_a1.add_paragraph(style=aff_style)
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(1)
        r = p.add_run(text)
        r.font.name = "Times New Roman"
        r.font.size = Pt(10.0)
        r.font.italic = is_italic
        
    # Author 2: Mubarak Altamimi
    cell_a2 = auth_table.rows[0].cells[1]
    p_a2 = cell_a2.paragraphs[0]
    p_a2.style = author_style
    p_a2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_a2.paragraph_format.space_before = Pt(6)
    p_a2.paragraph_format.space_after = Pt(2)
    r = p_a2.add_run("Mubarak Altamimi")
    r.font.name = "Times New Roman"
    r.font.size = Pt(11.0)
    r.font.bold = True
    
    a2_lines = [
        ("dept. of Computer Engineering", True),
        ("Karabük University", True),
        ("Karabük, Turkey", False),
        ("eng.mobaraktamimi@yahoo.com", False)
    ]
    for text, is_italic in a2_lines:
        p = cell_a2.add_paragraph(style=aff_style)
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(1)
        r = p.add_run(text)
        r.font.name = "Times New Roman"
        r.font.size = Pt(10.0)
        r.font.italic = is_italic
        
    # Spacer below authors
    p_sp = doc.add_paragraph()
    p_sp.paragraph_format.space_before = Pt(0)
    p_sp.paragraph_format.space_after = Pt(6)
    r_sp = p_sp.add_run()
    r_sp.font.size = Pt(1)

    # ── SECTION 2: Body Text (Two Columns: Abstract, Keywords, and Sections) ──
    print("Creating Section 2 (Two Columns with Abstract & Keywords inside left column)...")
    sec2 = doc.add_section(WD_SECTION.CONTINUOUS)
    
    sectPr2 = sec2._sectPr
    cols2 = sectPr2.xpath('./w:cols')
    if not cols2:
        cols2 = OxmlElement('w:cols')
        sectPr2.append(cols2)
    else:
        cols2 = cols2[0]
    cols2.set(qn('w:num'), '2')
    cols2.set(qn('w:space'), '360') # 18 pt gap (0.25 in)
    
    # ── ABSTRACT (In Left Column) ──
    print("Writing Abstract into column 1...")
    p_abs = doc.add_paragraph(style=abs_style)
    p_abs.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p_abs.paragraph_format.space_before = Pt(0)
    p_abs.paragraph_format.space_after = Pt(6)
    p_abs.paragraph_format.first_line_indent = Pt(0)
    
    r_lbl = p_abs.add_run("Abstract—")
    r_lbl.font.name = "Times New Roman"
    r_lbl.font.bold = True
    r_lbl.font.italic = True
    r_lbl.font.size = Pt(9.0)
    
    abs_text = (
        "Business Email Compromise (BEC) has evolved from simple spoofing into a human-centered attack model "
        "that combines persuasive language, account abuse, and visual evasion. Modern adversaries exploit "
        "large language models (LLMs) to imitate executive tone and manipulate HTML/CSS such that a secure "
        "email gateway parses benign content while the recipient reads a malicious message. This paper "
        "proposes a locally deployable Zero-Trust framework for enterprise email inspection, evaluated on a "
        "1,122-email research corpus (1,012 PLSF emails and 110 VSDE HTML emails) within a next-generation "
        "firewall (NGFW)-based research environment. "
        "The framework integrates two complementary engines organized in a Two-Stage Gatekeeper Architecture: "
        "Psycho-Linguistic Sender Fingerprinting (PLSF), "
        "which models sender behavior via Sentence-Transformer embeddings and lexical BEC indicators, and the "
        "Visual-Semantic Desynchronization Engine (VSDE), which measures discrepancy between DOM-extracted "
        "tokens and visually rendered tokens extracted via headless browser rendering and OCR. VSDE is invoked "
        "selectively only when Stage 1 flags suspicious CSS markers or elevated behavioral anomaly. All processing "
        "remains local, with no cloud dependencies. PLSF achieves a mean cross-validated weighted F1 of 85% ± 6% "
        "(BEC-class F1 = 90% on the full held-out test split), an AUC of 0.91, and a Matthews Correlation "
        "Coefficient (MCC) of 0.57 ± 0.10 across folds (0.69 on the full held-out test split), "
        "computed from actual predictions under the 2:1 class imbalance—operating without any labeled attack data. "
        "The anomaly threshold (λ) is calibrated exclusively on benign training-split emails, preserving the "
        "zero-shot property. "
        "VSDE achieves an F1-score of 82% and an AUC of 0.89 under calibrated threshold conditions. PLSF runs "
        "at 72.54 ms per email, suitable for inline SMTP inspection; the VSDE visual path (~26 s on CPU) "
        "requires further optimization for production deployment, meaning VSDE currently operates as a high-confidence "
        "secondary inspection stage rather than a mandatory inline path. These results support treating every inbound "
        "message as an independent verification event combining linguistic and visual integrity checks, "
        "rather than relying on static signatures alone."
    )
    r_body = p_abs.add_run(abs_text)
    r_body.font.name = "Times New Roman"
    r_body.font.bold = True
    r_body.font.size = Pt(9.0)
    
    # ── KEYWORDS (In Left Column) ──
    print("Writing Keywords into column 1...")
    p_kw = doc.add_paragraph(style=kw_style)
    p_kw.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p_kw.paragraph_format.space_before = Pt(0)
    p_kw.paragraph_format.space_after = Pt(10)
    p_kw.paragraph_format.first_line_indent = Pt(0)
    
    r_kw_lbl = p_kw.add_run("Keywords—")
    r_kw_lbl.font.name = "Times New Roman"
    r_kw_lbl.font.bold = True
    r_kw_lbl.font.italic = True
    r_kw_lbl.font.size = Pt(9.0)
    
    r_kw_vals = p_kw.add_run("Business Email Compromise, Zero-Trust Architecture, Psycho-Linguistic Fingerprinting, Visual-Semantic Desynchronization, Email Security, CSS Evasion Detection, Matthews Correlation Coefficient, Sentence Transformers, NGFW.")
    r_kw_vals.font.name = "Times New Roman"
    r_kw_vals.font.italic = True
    r_kw_vals.font.size = Pt(9.0)
    
    # ── 1. INTRODUCTION ──
    # Note: Heading 1 in the template automatically provides "I. ", so we only pass the title text!
    print("Writing Section I: Introduction...")
    doc.add_paragraph("INTRODUCTION", style=h1_style)
    
    add_formatted_paragraph(doc, 
        "Enterprise email remains a dominant attack surface because it targets human judgment rather than software "
        "vulnerabilities. According to the FBI Internet Crime Complaint Center, BEC generated more than $2.9 billion "
        "in adjusted losses in 2023, confirming that socially engineered email fraud remains one of the highest-impact "
        "cybercrime categories [6]. Traditional protections such as SPF, DKIM, and DMARC authenticate sending "
        "infrastructure but cannot reliably detect messages sent from compromised legitimate accounts or messages "
        "crafted to mimic a trusted executive.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "The threat landscape has intensified with the rise of generative AI. LLMs can now produce fluent, localized, "
        "and role-consistent emails that imitate executive tone with minimal effort [2]. At the same time, adversaries "
        "exploit HTML and CSS tricks—zero-font overlays, hidden layers, white-on-white text, and off-screen indentation—"
        "to create a gap between what automated parsers inspect and what users actually read. Cisco Talos has documented "
        "active abuse of hidden text salting in phishing campaigns, illustrating the practical relevance of this "
        "rendering-layer vulnerability [7].",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "Current detection systems remain limited in their ability to handle personalized, AI-assisted BEC that combines "
        "linguistic persuasion with rendering-layer evasion. This gap motivates a unified approach that jointly analyzes "
        "behavioral and visual inconsistencies within each inbound email.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "This paper addresses these challenges through a Zero-Trust architecture that performs local, per-message "
        "re-verification within a research-oriented NGFW framework. The proposed system does not trust sender history, "
        "protocol compliance, or parser output alone. Instead, it combines behavioral-linguistic validation with "
        "visual-semantic consistency checking to make an allow/block decision.",
        style=para_style, indent=Pt(14.4)
    )
    
    # Research Question Block (indented block)
    p_rq = doc.add_paragraph(style=para_style)
    p_rq.paragraph_format.left_indent = Cm(0.4)
    p_rq.paragraph_format.right_indent = Cm(0.4)
    p_rq.paragraph_format.first_line_indent = Pt(0)
    p_rq.paragraph_format.space_before = Pt(4)
    p_rq.paragraph_format.space_after = Pt(4)
    r_rq = p_rq.add_run(
        "Research Question: Can an enterprise NGFW combine linguistic behavioral analysis with visual-DOM "
        "consistency checking to detect AI-assisted email impersonation and CSS-based evasion in a zero-trust setting, "
        "without relying on labeled attack data?"
    )
    r_rq.font.name = "Times New Roman"
    r_rq.font.italic = True
    r_rq.font.size = Pt(9.5)
    
    # Statement of Contributions (Heading 2 automatically provides "A. ")
    p_contr = doc.add_paragraph("Statement of Contributions", style=h2_style)
    p_contr.paragraph_format.space_before = Pt(8)
    p_contr.paragraph_format.space_after = Pt(4)
    
    add_formatted_paragraph(doc, "This work makes three original contributions:", style=para_style, indent=Pt(14.4))
    
    contribs = [
        "Developing the **Psycho-Linguistic Sender Fingerprinting** engine to detect executive impersonation via semantic drift against an adaptive sender profile, enabling zero-shot deployment from historical benign email alone.",
        "Formalizing **Visual-Semantic Desynchronization** as a computable Jaccard distance between DOM-extracted and OCR-derived visual token sets, enabling direct quantitative detection of CSS-based evasion.",
        "Integrating both engines into a **privacy-preserving local NGFW-based SMTP inspection pipeline** with zero external cloud dependencies."
    ]
    for idx, ct in enumerate(contribs):
        p_li = add_formatted_paragraph(doc, f"({idx+1}) {ct}", style=para_style, indent=Pt(14.4))
        p_li.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p_li.paragraph_format.left_indent = Pt(0)
        p_li.paragraph_format.first_line_indent = Pt(14.4)
        p_li.paragraph_format.space_before = Pt(0)
        p_li.paragraph_format.space_after = Pt(2.5)
                
    add_formatted_paragraph(doc, 
        "To the best of the authors' knowledge, no prior work has jointly addressed all three contributions within a single framework.",
        style=para_style, indent=Pt(14.4)
    )
    
    # ── 2. RELATED WORK ──
    print("Writing Section II: Related Work...")
    doc.add_paragraph("RELATED WORK", style=h1_style)
    
    add_formatted_paragraph(doc,
        "Email defense has progressed from metadata anomaly detection and protocol validation (SPF/DKIM) to "
        "supervised text classification [4] and behavioral authorship verification. Sentence-BERT embeddings enable "
        "semantic sender profiling with minimal feature engineering [5]; EmailProfiler [15], authorship-similarity "
        "modeling [16], writeprint-based deception detection [17], stylometric and deep-learning analysis [18], [19], "
        "and classifier-stacking approaches [20] all confirm that linguistic behavioral traces are strong discriminating "
        "signals. Experimental design in email security has benefited from established corpora including the Enron dataset "
        "and the CEAS spam challenge [10]. However, these methods depend on labeled corpora or static retraining, "
        "limiting zero-day enterprise applicability. LLM-generated phishing exacerbates this gap [23], though "
        "LLM-based classifiers such as ChatSpamDetector [24] show that language-model defenses can be operationalized in practice.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc,
        "Visual rendering attacks represent a distinct and underaddressed threat surface. PhishIntention [1] leverages "
        "visual page appearance to infer phishing intent, exploiting the Vision Transformer (ViT) architecture [3] as "
        "a general-purpose visual feature extractor adapted for layout-aware document understanding. Work on "
        "content concealment [21] and HTML cloaking [22] confirms that CSS tricks actively deceive both users and "
        "automated parsers—a gap innerText-based parsers cannot bridge. At the architectural level, Zero Trust mandates "
        "continuous per-message verification [8]. Within the BEC domain, Cidon et al. [11] showed high-precision "
        "detection is achievable when sender identity, context, and transactional intent are jointly modeled, and recent "
        "taxonomies confirm BEC requires dedicated pipelines beyond generic phishing controls [12], [13], [14]. "
        "The present work unifies behavioral profiling and visual-rendering verification—a combination not addressed "
        "by any single prior system.",
        style=para_style, indent=Pt(14.4)
    )

    add_formatted_paragraph(doc,
        "Commercial BEC defenses have matured significantly. Abnormal Security employs an API-first behavioral "
        "foundation model (Attune 1.0) that profiles identity, relationship graphs, and NLP-derived intent across "
        "Microsoft 365 and Google Workspace via direct API integration—without requiring MX record changes [30]. "
        "Proofpoint's Advanced BEC Defense (Supernova engine) combines supervised and unsupervised ML with supplier "
        "risk analytics and lookalike domain monitoring, operating at both gateway and API-telemetry layers [31]. "
        "Microsoft Defender for Office 365 integrates LLM-based intent analysis (introduced 2024) with cross-product "
        "XDR correlation for automatic attack disruption, though it exhibits a known internal-email blind spot and "
        "requires explicit administrator-configured protected-user policies to cover executive impersonation [32]. "
        "Critically, none of these platforms detect CSS-based presentation-layer evasion—the domain of VSDE—nor do "
        "they offer local, privacy-preserving on-premises deployment, which is mandatory for air-gapped or "
        "sovereignty-constrained enterprise environments.",
        style=para_style, indent=Pt(14.4)
    )
    
    # ── 3. PROPOSED FRAMEWORK ──
    print("Writing Section III: Proposed Framework...")
    doc.add_paragraph("METHODOLOGY", style=h1_style)
    
    p_sov = doc.add_paragraph("System Architecture Overview", style=h2_style)
    p_sov.paragraph_format.space_before = Pt(8)
    p_sov.paragraph_format.space_after = Pt(4)
    
    add_formatted_paragraph(doc, 
        "The framework intercepts inbound SMTP traffic through an NGFW-based inspection layer and applies a "
        "*Two-Stage Gatekeeper Architecture*. In Stage 1, every inbound email undergoes lightweight PLSF semantic "
        "encoding and DOM/CSS pre-screening concurrently (T_Stage1 ≈ 74.4 ms). In Stage 2, the VSDE deep visual "
        "rendering path is invoked *selectively*—only when Stage 1 detects CSS evasion markers or an elevated "
        "PLSF composite score (S_composite > λ_gate). A Risk Fusion Engine aggregates outputs and issues an allow "
        "or block decision. Fig. 1 illustrates the complete workflow.",
        style=para_style, indent=Pt(14.4)
    )
    
    # Figure 1
    add_centered_image(doc, "image1.png", width=3.4, 
                       caption_text="System workflow of the proposed Zero-Trust BEC detection framework.",
                       fig_num=1, caption_style=fig_cap_style,
                       alt_text=(
                           "Flowchart of the Zero-Trust BEC detection system. Incoming email enters the NGFW "
                           "Interception Layer and passes to Content Analysis, which forks in parallel to two "
                           "modules: PLSF (Psycho-Linguistic Sender Fingerprinting) and VSDE (Visual-Semantic "
                           "Desynchronization Engine). Both outputs feed into the Risk Fusion Engine, which "
                           "routes to a Risk High decision diamond: No (Safe) leads to ALLOW; Yes leads to BLOCK."
                       ))
    
    p_plsf = doc.add_paragraph("Psycho-Linguistic Sender Fingerprinting (PLSF)", style=h2_style)
    p_plsf.paragraph_format.space_before = Pt(8)
    p_plsf.paragraph_format.space_after = Pt(4)
    
    add_formatted_paragraph(doc, 
        "PLSF models a sender's normal communication profile by encoding each email with a sentence transformer "
        "(all-MiniLM-L6-v2 [25], [29]) and measuring semantic drift from the historical baseline. Let e_curr ∈ ℝ^384 be "
        "the SBERT embedding of the incoming email and ē_base be the exponential moving average of the sender's "
        "historical embeddings. The semantic drift score is:",
        style=para_style, indent=Pt(14.4)
    )
    
    # Equation 1
    insert_equation_native(doc, EQ1, 1, style=para_style)
    
    add_formatted_paragraph(doc, 
        "Because semantic drift alone is insufficient against AI-generated BEC—which may produce stylistically coherent "
        "yet fraudulent content—PLSF integrates a lexical risk scanner L_bec ∈ [0, 1] that detects fraud-related cues "
        "such as urgent payment requests, invoice manipulation phrases, and authority pressure language. The two signals "
        "are combined into a composite anomaly score:",
        style=para_style, indent=Pt(14.4)
    )
    
    # Equation 2
    insert_equation_native(doc, EQ2, 2, style=para_style)
    
    add_formatted_paragraph(doc, 
        "with empirically calibrated weights w_dc = 0.4 and w_lbec = 0.6. A message is flagged as BEC when "
        "S_composite > λ, where λ is calibrated per-sender using only the benign training-split emails "
        "(no labeled attack samples are used), preserving the zero-shot deployment property "
        "(mean λ_opt ≈ 0.240). Benign messages "
        "update ē_base via exponential moving average, allowing the baseline to drift naturally with legitimate "
        "style evolution without retraining.",
        style=para_style, indent=Pt(14.4)
    )
    
    p_vsde = doc.add_paragraph("Visual-Semantic Desynchronization Engine (VSDE)", style=h2_style)
    p_vsde.paragraph_format.space_before = Pt(8)
    p_vsde.paragraph_format.space_after = Pt(4)
    
    add_formatted_paragraph(doc, 
        "VSDE detects rendering-layer evasion by comparing two token sets derived from the same email. First, T_DOM "
        "is extracted directly from the raw HTML/MIME source via DOM parsing. Second, a headless browser (Playwright [26]) "
        "renders the email as a screenshot, and EasyOCR [27] extracts the visually visible token set T_visual. The "
        "Visual-Semantic Desynchronization Ratio is defined as the Jaccard distance between the two sets:",
        style=para_style, indent=Pt(14.4)
    )
    
    # Equation 3
    insert_equation_native(doc, EQ3, 3, style=para_style)
    
    add_formatted_paragraph(doc, 
        "A value of R → 1 indicates that parser-visible content and user-visible content differ substantially—the "
        "hallmark of CSS-based evasion. An email is flagged as evasive when R > λ_R. Initial testing used λ_R = 0.35; "
        "calibration on the held-out validation partition raised this to λ_R = 0.45 to account for EasyOCR character-recognition "
        "noise on benign email, reducing false positives from 18/50 to 3/50 while maintaining strong evasion recall.",
        style=para_style, indent=Pt(14.4)
    )
    
    p_zt = doc.add_paragraph("Two-Stage Gatekeeper Architecture and Local Zero-Trust Integration", style=h2_style)
    p_zt.paragraph_format.space_before = Pt(8)
    p_zt.paragraph_format.space_after = Pt(4)
    
    add_formatted_paragraph(doc, 
        "To reconcile comprehensive visual-semantic inspection with the stringent latency budgets of inline SMTP message "
        "transfer agents (MTAs), the framework implements an empirically validated *Two-Stage Gatekeeper Architecture*. "
        "In Stage 1, every inbound message undergoes lightweight DOM parsing and CSS anomaly pre-screening (inspecting for "
        "high-risk evasion markers C_markers in {display:none, font-size:0px, opacity:0, visibility:hidden, text-indent < -500px, "
        "color-to-background matching}) executed in parallel with SBERT semantic encoding (T_Stage1 = T_PLSF + T_DOM ≈ 74.4 ms). "
        "In Stage 2, deep visual rendering and EasyOCR verification are invoked selectively—only if Stage 1 detects CSS evasion "
        "markers or elevated behavioral anomaly (S_composite > λ_gate). The overall expected per-email latency is governed by "
        "E[T] = T_Stage1 + p_suspicious * T_Stage2, where p_suspicious denotes the fraction of enterprise email routed to deep "
        "visual verification.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "Crucially, the entire pipeline executes on local infrastructure without external cloud dependencies. No sender "
        "profiles, embeddings, or message contents leave the enterprise perimeter. Every inbound message is treated as an "
        "independent verification challenge: authentication protocols (SPF, DKIM, DMARC) provide auxiliary context but are "
        "never accepted as standalone proof of legitimacy, adhering strictly to NIST Special Publication 800-207 [8].",
        style=para_style, indent=Pt(14.4)
    )
    
    # ── 4. EXPERIMENTAL SETUP ──
    print("Writing Section IV: Experimental Setup...")
    doc.add_paragraph("EXPERIMENTAL SETUP", style=h1_style)
    
    add_formatted_paragraph(doc, 
        "The evaluation used a 1,122-email research corpus: 1,012 PLSF emails "
        "(800 Seed + 152 Primary Test + 60 LLM-BEC Test) compiled from the Enron corporate email database [9] "
        "and the Nazario public phishing corpus [28], plus 110 VSDE HTML emails constructed for visual-rendering evaluation.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "**PLSF Evaluation Corpus.** Raw emails were extracted for four target Enron executives: Jeff Dasovich, "
        "Sally Beck, Chris Germany, and Eric Bass. A total of 200 normal emails per sender (800 total) formed the "
        "historical seed pool for baseline initialization. The primary test pool comprised 152 emails: 52 normal "
        "(13 per executive) and 100 historical BEC/phishing impersonation emails sourced from the Nazario phishing corpus "
        "and Nigerian Fraud dataset [28], randomly assigned to target executives (BEC:Normal ≈ 2:1). To address the "
        "distinct threat of modern generative AI deception, we constructed an additional LLM-Generated Executive "
        "Impersonation Evaluation Suite comprising 60 synthetic BEC emails generated via state-of-the-art LLMs "
        "(GPT-4o and Llama-3-70B). These emails were conditioned on authentic stylistic markers of the target executives "
        "and simulated high-stakes transactional fraud (e.g., out-of-band wire authorizations, confidential acquisition "
        "settlements, and urgent supplier account changes) without grammatical or syntactic flaws. No attack emails "
        "were used during baseline construction.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "**VSDE Evaluation Corpus.** A total of 110 HTML emails were compiled: 50 benign (Enron corporate texts "
        "wrapped in a standard HTML template), 50 standard CSS evasion (malicious payloads hidden via CSS "
        "`display:none`, `visibility:hidden`, `font-size:0px`, `opacity:0`, white-on-white text, and off-screen "
        "positioning), and 10 adversarial CSS emails (minimal-divergence payloads hiding only 1–3 high-risk keywords "
        "within a long benign body to probe the detection boundary).",
        style=para_style, indent=Pt(14.4)
    )
    
    # Table 1
    add_table_ieee(
        doc,
        caption_text="Experimental Configuration.",
        headers=["Parameter / Component", "Configuration Value"],
        rows=[
            ["Dataset Size", "1,012 PLSF (800 Seed + 152 Primary Test + 60 LLM-BEC Test); 110 VSDE HTML Emails"],
            ["Test Set Distribution", "PLSF: 52 Normal, 100 Legacy BEC, 60 LLM-BEC; VSDE: 50 Benign, 50 CSS Evasion, 10 Adv. CSS"],
            ["Semantic Embedding Model", "all-MiniLM-L6-v2 (SentenceTransformer) [25], [29]"],
            ["Embedding Dimensions", "384-dimensional dense vectors"],
            ["PLSF Weights", "w_dc = 0.4 (semantic), w_lbec = 0.6 (lexical)"],
            ["PLSF Anomaly Threshold (λ)", "Calibrated per sender on training splits (Mean λ_opt ≈ 0.240)"],
            ["VSDE Evasion Threshold (R)", "R > 0.45 (calibrated to mitigate OCR noise)"],
            ["Validation Method", "5-Fold Stratified Cross-Validation"],
            ["Baselines", "TF-IDF + Linear SVM (C=1.0); SBERT + One-Class SVM (nu=0.1); Semantic-only; Lexical-only; OCR-only"]
        ],
        table_num=1,
        caption_style=tbl_head_style,
        inside_h=True,
        align_left=True,
        col_widths=[1.25, 2.2]
    )
    
    add_formatted_paragraph(doc, 
        "PLSF was assessed using precision, recall, and macro F1-score under five-fold stratified cross-validation. "
        "VSDE was evaluated on the 110-email HTML corpus using precision, recall, F1-score, average desynchronization "
        "ratio, and processing latency. All evaluation metrics were computed at the class level to account for "
        "the class imbalance.",
        style=para_style, indent=Pt(14.4)
    )
    
    # ── 5. RESULTS ──
    print("Writing Section V: Results...")
    doc.add_paragraph("RESULTS", style=h1_style)
    
    p_res1 = doc.add_paragraph("PLSF Classification Performance", style=h2_style)
    p_res1.paragraph_format.space_before = Pt(8)
    p_res1.paragraph_format.space_after = Pt(4)
    
    add_formatted_paragraph(doc, 
        "Stratified 5-fold cross-validation was performed on the 152-sample PLSF test pool. In each fold, the 800 seed "
        "emails initialized the behavioral baseline, while the test split was scored against the calibrated threshold. "
        "Results are reported in Table II.",
        style=para_style, indent=Pt(14.4)
    )
    
    # Table 2
    add_table_ieee(
        doc,
        caption_text="PLSF 5-Fold Cross-Validation Results (Calibrated Threshold). MCC computed from actual fold predictions under 2:1 class distribution (100 BEC : 52 Normal).",
        headers=["Fold", "Precision", "Recall", "F1-Score", "MCC", "λ_opt"],
        rows=[
            ["1", "77%", "100%", "87%", "0.59", "0.240"],
            ["2", "77%", "100%", "87%", "0.59", "0.240"],
            ["3", "83%", "100%", "91%", "0.71", "0.240"],
            ["4", "77%", "100%", "87%", "0.55", "0.230"],
            ["5", "87%", "65%", "74%", "0.42", "0.270"],
            ["Mean ± SD", "80% ± 5%", "93% ± 16%", "85% ± 6%", "0.57 ± 0.10", "0.244 ± 0.015"]
        ],
        table_num=2,
        caption_style=tbl_head_style
    )
    
    add_formatted_paragraph(doc, 
        "The cross-validated mean weighted F1 is 85% ± 6% (each fold's F1 reflects the BEC-class F1 under the "
        "2:1 BEC-to-Normal class distribution). On the full held-out test split (all 152 samples scored "
        "against the mean calibrated threshold λ = 0.240), PLSF achieves Precision = 82%, Recall = 100%, and "
        "F1 = 90%—values reported in Table VI for comparison with baselines. The cross-validated estimate (85%) "
        "is the conservative generalization bound, while the full-split result (90%) reflects performance under "
        "the operationally calibrated threshold.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "Fold 5 exhibits a distinctly lower recall (65%) with a higher calibrated threshold (λ_opt = 0.270), "
        "compared to uniform 100% recall in Folds 1–4. Inspection reveals that its BEC samples produced composite "
        "anomaly scores clustered in 0.22–0.27—overlapping the tail of the normal distribution—because they combined "
        "moderate lexical risk with relatively low semantic drift, producing structurally ambiguous scores that straddle "
        "the detection boundary. The per-fold MCC of 0.42 for Fold 5 reflects this precision-recall trade-off: "
        "precision is preserved at 87% while recall drops to 65%, a scenario likely to become more prevalent as "
        "LLM-driven BEC matures.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "A key finding is that the mean semantic deviation D_c was higher for BEC mimicry emails (0.749) than for "
        "normal emails (0.541). Contrary to the initial expectation that LLM-generated text would produce low "
        "semantic drift from the baseline, SBERT embeddings provided a stronger discriminating signal than "
        "anticipated—likely because the BEC test corpus (Nazario/Nigerian Fraud) exhibits substantially different "
        "topical and stylistic patterns compared to authentic Enron executive communication.",
        style=para_style, indent=Pt(14.4)
    )
    
    # Table 3 (Part of PLSF Classification Performance)
    add_table_ieee(
        doc,
        caption_text="Effect of Sender Baseline Seed Size on PLSF Performance.",
        headers=["Seed Size (Emails)", "λ_opt", "Precision", "Recall", "F1-Score"],
        rows=[
            ["20", "0.270", "87%", "96%", "91%"],
            ["60", "0.240", "82%", "100%", "90%"],
            ["200", "0.235", "83%", "100%", "91%"]
        ],
        table_num=3,
        caption_style=tbl_head_style
    )
    
    add_formatted_paragraph(doc, 
        "Even with a seed of only 20 normal emails, PLSF achieves an F1-score of 91%. Performance plateaus "
        "above 20 emails, confirming that the framework can be deployed rapidly without waiting to accumulate "
        "a large sender history—a practical advantage for enterprise onboarding.",
        style=para_style, indent=Pt(14.4)
    )
    
    p_res_llm = doc.add_paragraph("Robustness to LLM-Generated Executive Impersonation", style=h2_style)
    p_res_llm.paragraph_format.space_before = Pt(8)
    p_res_llm.paragraph_format.space_after = Pt(4)
    
    add_formatted_paragraph(doc, 
        "To rigorously evaluate resilience against modern generative threats, the 60 LLM-synthesized executive "
        "impersonation emails were evaluated against the calibrated PLSF profiles. As anticipated, the stylometric "
        "mimicry produced by GPT-4o and Llama-3-70B lowered the mean semantic drift from D_c = 0.749 (observed on "
        "legacy Nazario phishing) down to D_c = 0.582, narrowing the divergence from authentic executive communication "
        "(mean D_c = 0.541). When evaluated using semantic distance alone, recall degraded to 68.3%, demonstrating "
        "that stylistic mimicry alone can partially obscure impersonation.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "However, because fraudulent BEC attacks inherently require deceptive financial calls-to-action (e.g., "
        "urgency constraints, secrecy mandates, and modified settlement coordinates), the lexical risk scanner "
        "reliably triggered (mean L_bec = 0.764 vs. 0.128 on normal emails). Under the composite scoring model "
        "(S_composite = 0.4 D_c + 0.6 L_bec), PLSF achieved Precision = 85.2%, Recall = 91.7%, F1-Score = 88.3%, "
        "and MCC = 0.66 against the LLM-generated corpus at λ = 0.240. This confirms that the hybrid multi-modal design "
        "successfully counterbalances generative semantic mimicry, maintaining robust enterprise defense even when "
        "adversaries employ advanced LLMs.",
        style=para_style, indent=Pt(14.4)
    )
    
    p_res2 = doc.add_paragraph("VSDE Evasion Detection", style=h2_style)
    p_res2.paragraph_format.space_before = Pt(8)
    p_res2.paragraph_format.space_after = Pt(4)
    
    add_formatted_paragraph(doc, 
        "Table IV compares EasyOCR-based visual extraction with browser-based innerText extraction on the 110-email "
        "CSS-evasion dataset. Note: innerText serves as a *separate DOM-text baseline* (T_DOM ↔ T_innerText), not as "
        "a substitute for T_visual in the VSDE formulation. It is included to demonstrate that style-aware browser "
        "text extraction is insufficient for detecting CSS-hidden payloads, motivating the OCR-rendered visual path.",
        style=para_style, indent=Pt(14.4)
    )
    
    # Table 4
    add_table_ieee(
        doc,
        caption_text="VSDE CSS Evasion Detection Results (Calibrated Threshold R > 0.45). MCC computed from actual TP/FP/FN/TN under 60 evasive : 50 benign class distribution.",
        headers=["Metric", "EasyOCR (Visual)", "innerText (Browser)"],
        rows=[
            ["Samples Tested", "110", "110"],
            ["Correctly Detected", "44 / 60", "12 / 60"],
            ["Precision", "94%", "100%"],
            ["Recall", "73%", "20%"],
            ["F1-Score", "82%", "33%"],
            ["MCC", "0.68", "0.32"],
            ["Avg Desync Ratio (Evasive)", "0.589", "0.170"]
        ],
        table_num=4,
        caption_style=tbl_head_style
    )
    
    add_formatted_paragraph(doc, 
        "The critical finding is that the standard browser text parser (innerText) is effectively blind to "
        "CSS-based obfuscation. On white-on-white text evasion specifically, innerText returned R = 0.000 across "
        "all 8 test samples because it reads style-hidden text as though it were visible. EasyOCR, which operates "
        "on rendered pixels, caught these cases with Mean R = 0.496, demonstrating that true visual rendering "
        "is essential for detecting presentation-layer attacks.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "OCR noise elevates the desynchronization ratio on benign emails (Mean R = 0.325). Calibrating the "
        "threshold from R > 0.35 (18/50 false positives) to R > 0.45 reduced benign false positives to 3/50 while "
        "maintaining strong evasive recall.",
        style=para_style, indent=Pt(14.4)
    )
    
    # Figure 2: Confusion Matrix
    add_centered_image(
        doc,
        filename="image8.png",
        width=3.2,
        caption_text="VSDE confusion matrix (EasyOCR, R > 0.45): TP = 44, TN = 47, FP = 3, FN = 16.",
        fig_num=2,
        caption_style=fig_cap_style,
        alt_text=(
            "Confusion matrix for the VSDE module using EasyOCR with desynchronization threshold R greater "
            "than 0.45. The matrix shows: True Negatives (Actual Benign, Predicted Benign) = 47, "
            "False Positives (Actual Benign, Predicted Evasive) = 3, "
            "False Negatives (Actual Evasive, Predicted Benign) = 16, "
            "True Positives (Actual Evasive, Predicted Evasive) = 44. "
            "Color scale: dark brown indicates high cell counts, light beige indicates low counts."
        )
    )
    
    p_res3 = doc.add_paragraph("Adversarial VSDE Robustness", style=h2_style)
    p_res3.paragraph_format.space_before = Pt(8)
    p_res3.paragraph_format.space_after = Pt(4)
    
    add_formatted_paragraph(doc, 
        "Ten adversarially crafted HTML emails with minimal DOM–visual overlap (1–3 hidden tokens) were evaluated to probe the detection boundary.",
        style=para_style, indent=Pt(14.4)
    )
    
    # Table 5
    add_table_ieee(
        doc,
        caption_text="VSDE Adversarial Robustness Results.",
        headers=["Metric", "R > 0.35", "R > 0.45"],
        rows=[
            ["Samples Tested", "10", "10"],
            ["Correctly Detected", "5", "2"],
            ["Precision", "100%", "100%"],
            ["Recall", "50%", "20%"],
            ["F1-Score", "67%", "33%"],
            ["Observed R values", "[0.250, 0.265, 0.298, 0.345, 0.349,", "0.350, 0.353, 0.412, 0.457, 0.477]"]
        ],
        table_num=5,
        caption_style=tbl_head_style
    )
    
    add_formatted_paragraph(doc, 
        "At R > 0.45, only 2 out of 10 adversarial samples exceeded the threshold (observed R ∈ {0.457, 0.477}). "
        "This suggests a practical detection boundary: among this small adversarial sample, micro-payloads "
        "containing 1–3 hidden tokens produced insufficient desynchronization to trigger an alert under the "
        "calibrated threshold. The precision-recall trade-off is direct and "
        "explicit—mitigating OCR-driven false positives necessarily widens the blind spot for micro-payloads. "
        "Larger-scale adversarial evaluation is needed to confirm this boundary definitively.",
        style=para_style, indent=Pt(14.4)
    )
    
    p_res4 = doc.add_paragraph("Baseline Comparison and Ablation", style=h2_style)
    p_res4.paragraph_format.space_before = Pt(8)
    p_res4.paragraph_format.space_after = Pt(4)
    
    add_formatted_paragraph(doc, 
        "The critical distinction is the training data requirement. The supervised SVM achieves the highest F1 "
        "(98%) and MCC (0.94) but requires labeled attack examples. PLSF operates in a zero-shot regime—using only "
        "the target executive's historical normal email—and reaches F1 = 90%, MCC = 0.69. The semantic-only "
        "(F1 = 89%, MCC = 0.66) and lexical-only (F1 = 79%, MCC = 0.00) ablations confirm that the hybrid "
        "combination outperforms either signal alone; the zero MCC for lexical-only—computed from actual "
        "predictions—reveals that despite achieving 100% recall it flags every single email as BEC under the "
        "2:1 class imbalance, rendering it completely impractical for deployment. For visual evasion, the "
        "OCR-only baseline (F1 = 71%, MCC = 0.00) similarly flags all emails, confirming that DOM comparison "
        "is essential for discriminating benign from evasive content. MCC values are computed from actual "
        "system predictions.",
        style=para_style, indent=Pt(14.4)
    )
    
    # Table 6
    add_table_ieee(
        doc,
        caption_text="Comprehensive Baseline Comparison. MCC computed from actual system predictions under experimental class distributions.",
        headers=["System", "Method", "Precision", "Recall", "F1-Score", "MCC"],
        rows=[
            ["PLSF (This Work)", "Hybrid Semantic(0.4)+Lexical(0.6)", "82%", "100%", "90%", "0.69"],
            ["SVM + TF-IDF", "Supervised ML, bag-of-words", "96%", "100%", "98%", "0.94"],
            ["SBERT + OCSVM", "Embedding anomaly, unsupervised", "88%", "89%", "89%", "0.66"],
            ["Semantic-Only", "Cosine distance only", "81%", "100%", "89%", "0.66"],
            ["Lexical-Only", "BEC indicator scoring only", "66%", "100%", "79%", "0.00"],
            ["VSDE (OCR, R>0.45)", "Jaccard DOM-Visual Desync", "94%", "73%", "82%", "0.68"],
            ["OCR-Only Baseline", "Visual scan, no DOM comparison", "55%", "100%", "71%", "0.00"]
        ],
        table_num=6,
        caption_style=tbl_head_style
    )
    
    # Figure 3: ROC Curves
    add_centered_image(doc, "image6.png", width=3.4,
                       caption_text="Receiver Operating Characteristic (ROC) curves for PLSF (AUC=0.91), VSDE-OCR (AUC=0.89), and SVM baseline (AUC=0.98).",
                       fig_num=3, caption_style=fig_cap_style,
                       alt_text=(
                           "Line graph showing Receiver Operating Characteristic (ROC) curves for three classifiers "
                           "plotted as True Positive Rate (Y-axis, 0 to 1) versus False Positive Rate (X-axis, 0 to 1). "
                           "Solid blue line: PLSF with AUC = 0.91, operating point at FPR = 0.42, TPR = 1.00 "
                           "(lambda = 0.240). Dashed red line: VSDE-OCR with AUC = 0.89, operating point at "
                           "FPR = 0.06, TPR = 0.73 (R = 0.45). Dash-dot green line: SVM baseline with AUC = 0.98. "
                           "A diagonal dashed grey line represents the random classifier baseline."
                       ))
    
    p_res5 = doc.add_paragraph("ROC Analysis", style=h2_style)
    p_res5.paragraph_format.space_before = Pt(8)
    p_res5.paragraph_format.space_after = Pt(4)
    
    add_formatted_paragraph(doc, 
        "PLSF achieves AUC = 0.91, approaching the supervised SVM (AUC = 0.98) despite using no labeled threat "
        "data. VSDE achieves AUC = 0.89, reflecting the inherent tension between OCR noise on benign content "
        "and detection sensitivity on evasive payloads.",
        style=para_style, indent=Pt(14.4)
    )
    
    p_res6 = doc.add_paragraph("Latency Analysis and Empirical Gatekeeper Validation", style=h2_style)
    p_res6.paragraph_format.space_before = Pt(8)
    p_res6.paragraph_format.space_after = Pt(4)
    
    add_formatted_paragraph(doc, 
        "All component benchmarks were measured on a local testbed (Intel Core i7 CPU, 32 GB RAM, NVIDIA RTX GPU). "
        "Table VII reports per-email processing times for individual pipeline components across CPU and CUDA GPU modes.",
        style=para_style, indent=Pt(14.4)
    )
    
    # Table 7
    add_table_ieee(
        doc,
        caption_text="Per-Email Component Processing Latency.",
        headers=["Pipeline Component", "Execution Mode", "Mean Latency (ms)"],
        rows=[
            ["SBERT Semantic Encoding", "CPU (Local PyTorch)", "72.54 ms"],
            ["DOM Text & CSS Parsing", "CPU (BeautifulSoup / Regex)", "1.87 ms"],
            ["Playwright innerText Rendering", "Headless Chromium (CPU)", "1,283.89 ms"],
            ["Playwright Screenshot + EasyOCR", "CPU-only (Default)", "26,106.34 ms (26.11 s)"],
            ["Playwright Screenshot + EasyOCR", "GPU-accelerated (CUDA)", "3,200.00 ms (3.20 s)"],
            ["Jaccard Discrepancy Calculation", "CPU", "< 0.01 ms"]
        ],
        table_num=7,
        caption_style=tbl_head_style
    )
    
    add_formatted_paragraph(doc, 
        "While PLSF (72.54 ms) is immediately compatible with inline SMTP processing, unconditional full-rendering "
        "OCR on CPU (~26.11 s) introduces unacceptable latency for enterprise mail relays. To empirically evaluate the "
        "proposed two-stage gatekeeper architecture, we simulated enterprise traffic distributions where varying proportions "
        "(p_suspicious) of inbound emails exhibit suspicious CSS markers or borderline PLSF scores that trigger Stage 2 "
        "visual verification. Results are summarized in Table VIII.",
        style=para_style, indent=Pt(14.4)
    )
    
    # Table 8
    add_table_ieee(
        doc,
        caption_text="Empirical Latency Simulation of Two-Stage Gatekeeper under Enterprise Traffic Distributions.",
        headers=["Inspection Mode", "Compute Engine", "Suspicious Ratio (p)", "Weighted Latency", "Inline SMTP Feasibility"],
        rows=[
            ["Naive Full Visual (No Gate)", "CPU", "100.0%", "26,180.75 ms (26.18 s)", "Incompatible (Relay Timeout)"],
            ["Naive Full Visual (No Gate)", "CUDA GPU", "100.0%", "3,274.41 ms (3.27 s)", "Borderline (High Load Risk)"],
            ["Two-Stage Gatekeeper", "CPU", "5.0%", "1,379.73 ms (1.38 s)", "Viable for Deferred / Quarantine"],
            ["Two-Stage Gatekeeper", "CPU", "2.0%", "596.54 ms (0.60 s)", "Near-Inline Viable (< 1 s)"],
            ["Two-Stage Gatekeeper", "CUDA GPU", "5.0%", "234.41 ms (0.23 s)", "Inline Real-Time Viable (< 250 ms)"],
            ["Two-Stage Gatekeeper", "CUDA GPU", "2.0%", "138.41 ms (0.14 s)", "High-Throughput Inline (< 150 ms)"]
        ],
        table_num=8,
        caption_style=tbl_head_style
    )
    
    add_formatted_paragraph(doc, 
        "As Table VIII demonstrates, under a realistic enterprise traffic profile where 5% of messages require deep "
        "visual confirmation (p_suspicious = 0.05), the two-stage gatekeeper slashes average per-email latency on CPU "
        "from 26.18 s down to 1.38 s (an 18.97× speedup). With GPU acceleration, average per-email latency drops to "
        "234.41 ms (and 138.41 ms at p_suspicious = 0.02)—well beneath standard enterprise MTA milter timeout thresholds "
        "(typically 10–30 s). This empirical simulation directly confirms that selective visual rendering resolves the "
        "inline deployment bottleneck, establishing VSDE as a viable inline inspection stage.",
        style=para_style, indent=Pt(14.4)
    )
    
    # ── 6. DISCUSSION ──
    print("Writing Section VI: Discussion...")
    doc.add_paragraph("DISCUSSION", style=h1_style)
    
    add_formatted_paragraph(doc, 
        "The results demonstrate that combining behavioral profiling with visual-rendering integrity checking produces "
        "a detection system that is meaningfully different from either component alone. PLSF's zero-shot capability—reaching "
        "F1 = 90% and AUC = 0.91 using only historical normal email—is a practical advantage over supervised "
        "approaches that require labeled attack examples, which are often unavailable in enterprise settings until "
        "after an incident occurs.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "The supervised SVM baseline (F1 = 98%) sets an upper performance bound that PLSF approaches within 8 percentage "
        "points. The key advantage of PLSF is its deployment model: no attack data is needed, the baseline adapts "
        "continuously via exponential moving average, and as few as 20 seed emails suffice to initialize an "
        "effective profile. This makes rapid enterprise onboarding feasible.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "The VSDE results reveal a fundamental limitation of conventional text-extraction methods: innerText returns "
        "R = 0.000 for white-on-white text, treating visually invisible content as visible. This confirms that "
        "CSS-based evasion cannot be detected by DOM-level text analysis alone; visual rendering is a necessary "
        "component of a complete defense. The EasyOCR-based approach addresses this gap, though at the cost of "
        "OCR noise and computation time.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "The high 100% recall on the legacy Nazario corpus partly reflects its linguistic distinctiveness from authentic "
        "Enron executive communication. However, our expanded evaluation on style-mimicking LLM-generated emails demonstrates "
        "that PLSF retains strong discriminative capability (F1 = 88.3%, Recall = 91.7%), confirming that the composite "
        "scoring architecture prevents adversaries from evading detection purely through generative fluency. Precision "
        "differences (66%–96%) remain the more informative comparison across baselines, reflecting each system's ability "
        "to avoid false positives on legitimate email. The MCC metric further reveals a nuanced story: despite achieving "
        "100% recall, both the Lexical-Only and OCR-Only baselines yield MCC = 0.00 because they flag every email as "
        "malicious (TN = 0)—exposing complete failure to discriminate the benign class and underscoring that recall-centric "
        "evaluation under class imbalance can be deeply misleading.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc, 
        "The adversarial VSDE results indicate a detection boundary on this 10-sample set: only 2/10 adversarial "
        "samples (R ∈ {0.457, 0.477}) exceeded the calibrated threshold R > 0.45, while 8/10 with 1–3 hidden tokens "
        "remained below it. An adversary aware of this threshold could deliberately limit hidden "
        "content to very few tokens and evade VSDE; this limitation should be validated on a larger adversarial "
        "corpus before drawing definitive conclusions. Fuzzy Jaccard matching using character-level "
        "n-grams or edit distance could raise this lower bound without requiring a lower detection threshold.",
        style=para_style, indent=Pt(14.4)
    )

    # ── Qualitative Comparison with Commercial BEC Solutions ──
    p_comm = doc.add_paragraph("Qualitative Comparison with Commercial BEC Platforms", style=h2_style)
    p_comm.paragraph_format.space_before = Pt(8)
    p_comm.paragraph_format.space_after = Pt(4)

    add_formatted_paragraph(doc,
        "Table IX positions the proposed framework against three leading commercial BEC detection platforms "
        "across five architectural and operational criteria. The comparison is qualitative and based on "
        "publicly available technical documentation and peer-reviewed analyses [30], [31], [32], as direct "
        "empirical benchmarking against proprietary black-box systems lies outside standard academic evaluation scope.",
        style=para_style, indent=Pt(14.4)
    )

    # Table 9 – Qualitative comparison
    add_table_ieee(
        doc,
        caption_text="Qualitative Comparison of BEC Detection Platforms Across Key Operational Criteria.",
        headers=["Criterion", "This Work", "Abnormal Security", "Proofpoint EFD", "MS Defender O365"],
        rows=[
            ["Detection Paradigm",
             "Zero-shot behavioral + visual rendering",
             "Behavioral AI (Identity + Relationship + NLP)",
             "Multi-model ML + Supplier risk + DMARC",
             "LLM intent + XDR correlation"],
            ["CSS/Rendering Evasion",
             "Yes (VSDE — DOM vs. OCR Jaccard)",
             "No (NLP-only, no visual layer)",
             "No (NLP-only, no visual layer)",
             "No (text-based analysis only)"],
            ["Labeled Attack Data Required",
             "No (zero-shot from benign history)",
             "No (behavioral anomaly)",
             "Partial (supervised + unsupervised)",
             "No (behavioral + LLM)"],
            ["Deployment Model",
             "On-premises NGFW (air-gap ready)",
             "Cloud-API (M365 / Google Workspace)",
             "Cloud Gateway + API telemetry",
             "Integrated M365 cloud tenant"],
            ["Privacy / Data Sovereignty",
             "Full (local; zero cloud dependency)",
             "Limited (cloud SaaS; email routed externally)",
             "Limited (cloud SaaS; external processing)",
             "Limited (M365 tenant; Microsoft-managed)"],
        ],
        table_num=9,
        caption_style=tbl_head_style,
        inside_h=True
    )

    add_formatted_paragraph(doc,
        "The comparison exposes a structural blind spot shared by all three commercial platforms: none inspect "
        "the visual rendering layer for CSS-based content manipulation. Abnormal Security's Attune foundation model "
        "and Proofpoint's Supernova engine are confined to NLP-derived signals extracted from email source text "
        "and header metadata—vectors that CSS obfuscation actively exploits by ensuring malicious content is "
        "present in the DOM yet invisible to text parsers [21], [22]. Microsoft Defender's LLM-based intent "
        "analyzer similarly operates on parsed text, and its internal-email blind spot has been documented as a "
        "configuration-dependent limitation requiring explicit protected-user enrollment to function correctly [32]. "
        "From a deployment perspective, all three commercial products are cloud-SaaS platforms requiring email to "
        "traverse external infrastructure, making them incompatible with air-gapped, sovereignty-constrained, or "
        "regulated-data environments where local on-premises processing is a hard requirement. The proposed framework "
        "fills this gap by combining zero-shot behavioral profiling with a local visual rendering engine—capabilities "
        "that are architecturally absent from current commercial offerings.",
        style=para_style, indent=Pt(14.4)
    )
    
    # ── 7. LIMITATIONS AND FUTURE WORK ──
    print("Writing Section VII: Limitations and Future Work...")
    doc.add_paragraph("LIMITATIONS AND FUTURE WORK", style=h1_style)
    
    limitations = [
        ("Corpus Size.", "The PLSF test set (152 emails) and VSDE corpus (110 HTML emails) are small. Five-fold cross-validation provides a reasonable generalization estimate, but validation on larger, operationally representative enterprise datasets is needed to confirm scalability. Therefore, results should be interpreted as a proof-of-concept evaluation rather than a definitive enterprise-scale benchmark."),
        ("BEC Corpus Scale and Diversity.", "While our evaluation incorporated both historical phishing archives and a dedicated 60-sample LLM-synthesized executive impersonation suite demonstrating 88.3% F1 robustness, larger-scale cross-enterprise evaluations spanning multi-turn conversational threads and multi-lingual corporate environments are recommended to validate long-term baseline drift dynamics."),
        ("OCR Noise and Detection Boundary.", """\
EasyOCR recognition errors elevate the desynchronization ratio on benign email \
(Mean R = 0.325), necessitating a conservative threshold (R > 0.45) that simultaneously widens the \
blind spot for micro-payload adversarial attacks: emails containing fewer than three hidden tokens \
escape detection entirely. The root cause is character-level substitution noise introduced by OCR \
(e.g., '0' → 'O', 'l' → 'I', 'rn' → 'm'), which inflates the Jaccard distance between the DOM \
and visual token sets even when content is semantically identical. \
Three complementary remedies are planned. \
First, replacing the binary Jaccard index with a fuzzy variant based on character-level k-gram \
overlap: the k-gram Jaccard similarity between two token sets S_DOM and S_OCR is defined as \
J_k(S_DOM, S_OCR) = |G_k(S_DOM) ∩ G_k(S_OCR)| / |G_k(S_DOM) ∪ G_k(S_OCR)|, where G_k(S) \
denotes the multiset of all character k-grams (k = 2 or 3) extracted from all tokens in S. \
This formulation tolerates single-character substitutions without lowering the global threshold. \
Second, a token-level edit distance guard: if the normalized Levenshtein distance \
d_L(t_i, t_j) between a DOM token t_i and its nearest OCR candidate t_j falls below a tunable \
bound δ (e.g., δ = 0.15), the token pair is treated as a match rather than a discrepancy, \
reducing false positives from OCR noise without compromising sensitivity to genuinely hidden \
payloads. Third, an adaptive threshold mechanism that estimates the per-email OCR confidence \
score from EasyOCR's internal probability output and dynamically tightens or relaxes the \
desynchronization threshold accordingly, reducing the need for a single global cut-off."""),

        ("Visual Pipeline Scalability.", "While our empirical traffic simulation validates that the two-stage gatekeeper achieves an average latency of 234.4 ms on GPU and 1.38 s on CPU across a 95:5 benign-to-suspicious traffic profile, physical cluster stress-testing under peak enterprise burst volumes (>10,000 messages/min) is planned for future operational hardening."),
        ("Class Imbalance.", "The PLSF test set (100 BEC vs. 52 Normal, ≈2:1) represents a moderate imbalance. MCC is reported alongside F1 and AUC throughout this study—the cross-validated MCC of 0.57 ± 0.10 (PLSF) and 0.68 (VSDE) provide imbalance-robust estimates. Future evaluations on larger corpora should treat MCC as a co-primary metric."),
        ("Commercial Benchmarking Scope.", "A qualitative architectural comparison with Abnormal Security, Proofpoint Email Fraud Defense, and Microsoft Defender for Office 365 is presented in Table IX and Section VI, identifying the CSS rendering blind spot and data-sovereignty gap unaddressed by cloud-SaaS platforms. Direct quantitative benchmarking against proprietary systems—which would require licensing, controlled test infrastructure, and disclosure agreements—is recommended as a priority for future collaborative or standardized evaluation."),
        ("Cross-Domain Generalizability.", "All experiments were conducted on Enron executive email—a corpus from a single organization and era. Performance on email from other organizations, industries, or cultural contexts remains untested, and the BEC lexical indicator dictionary may require domain-specific recalibration for non-English environments. Validation on externally sourced enterprise corpora is recommended before operational deployment.")
    ]
    
    for title, desc in limitations:
        p = doc.add_paragraph(style=para_style)
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.paragraph_format.left_indent = Pt(14.4)
        p.paragraph_format.first_line_indent = Pt(0)
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(3)
        
        r_lbl = p.add_run(title + " ")
        r_lbl.font.name = "Times New Roman"
        r_lbl.font.bold = True
        r_lbl.font.size = Pt(10.0)
        
        r_desc = p.add_run(desc)
        r_desc.font.name = "Times New Roman"
        r_desc.font.size = Pt(10.0)
        
    # ── 8. CONCLUSION ──
    print("Writing Section VIII: Conclusion...")
    doc.add_paragraph("CONCLUSION", style=h1_style)
    
    add_formatted_paragraph(doc, 
        "This paper presents a Zero-Trust AI framework for BEC detection that checks both linguistic behavior and "
        "visual rendering integrity, treating every inbound email as an independent verification event. The NGFW-based "
        "prototype implements a Two-Stage Gatekeeper Architecture: Stage 1 applies PLSF behavioral profiling and "
        "CSS pre-screening to every message; Stage 2 invokes the Visual-Semantic Desynchronization Engine "
        "selectively for suspicious emails—enabling detection of both AI-assisted executive impersonation and "
        "CSS-based content hiding within a fully local, privacy-preserving inspection pipeline.",
        style=para_style, indent=Pt(14.4)
    )
    
    add_formatted_paragraph(doc,
        "Key findings: (1) PLSF achieves zero-shot sender profiling at BEC-class F1 = 90% (cross-validated "
        "weighted mean F1 = 85% \u00b1 6%, AUC = 0.91) without any labeled attack data—threshold calibrated solely on "
        "benign training emails—requiring as few as 20 historical emails for effective baseline initialization. "
        "(2) OCR-based visual rendering is necessary to expose CSS evasion tactics\u2014particularly white-on-white text\u2014that "
        "completely bypass conventional DOM text extraction (innerText DOM-text baseline: F1 = 33% vs. VSDE visual path: F1 = 82%). "
        "(3) The empirical traffic simulation confirms that the two-stage gatekeeper architecture reduces average "
        "per-email latency to 234.4 ms on GPU under a 95:5 benign-to-suspicious traffic profile, establishing a "
        "viable path to inline deployment. The evaluation covers a 1,122-email corpus: 152 primary PLSF test emails, "
        "800 seed emails for baseline initialization, 60 LLM-synthesized BEC emails, and 110 VSDE HTML emails.",
        style=para_style, indent=Pt(14.4)
    )

    add_formatted_paragraph(doc,
        "Three directions define the immediate research roadmap. "
        "First, the Jaccard-based desynchronization metric will be extended to a fuzzy variant using character-level "
        "k-gram overlap (k \u2208 {2, 3}), defined as "
        "J_k(S_DOM, S_OCR) = |G_k(S_DOM) \u2229 G_k(S_OCR)| / |G_k(S_DOM) \u222a G_k(S_OCR)|, "
        "where G_k(S) denotes the multiset of k-grams from all tokens in set S. "
        "This formulation tolerates single-character OCR substitutions (e.g., '0'\u2192'O', 'rn'\u2192'm') without "
        "requiring a higher global detection threshold, directly addressing the micro-payload blind spot "
        "identified at fewer than three hidden tokens. A complementary token-level Levenshtein guard "
        "(normalized edit distance \u03b4 < 0.15) will resolve near-match token pairs ambiguous to strict Jaccard. "
        "Second, a GPU-accelerated Playwright rendering cluster will be deployed and stress-tested under peak enterprise "
        "burst loads (>10,000 messages/min) to empirically validate the sub-second latency projection and "
        "determine the operational threshold at which VSDE transitions from a deferred quarantine stage to a mandatory "
        "inline inspection path. Third, the LLM-synthesized evaluation suite will be extended from 60 to 500+ samples "
        "spanning multi-turn conversational threads, multi-lingual corporate environments, and emerging jailbreak-augmented "
        "BEC prompting strategies, providing a standardized robustness benchmark for future comparative studies.",
        style=para_style, indent=Pt(14.4)
    )
    
    # ── REFERENCES ──
    print("Writing References Section...")
    p_ref_head = doc.add_paragraph("REFERENCES", style=h5_style)
    p_ref_head.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_ref_head.paragraph_format.space_before = Pt(12)
    p_ref_head.paragraph_format.space_after = Pt(6)
    
    refs = [
        "R. Liu, Y. Lin, X. Yang, S. H. Ng, D. M. Divakaran, J. S. Dong, and A. H. Y. Tang, \"Inferring Phishing Intention via Webpage Appearance and Dynamics: A Deep Vision Based Approach,\" in Proc. 31st USENIX Security Symposium, Boston, MA, USA, Aug. 2022.",
        "J. Hazell, \"Spear Phishing With Large Language Models,\" arXiv preprint arXiv:2305.06972, May 2023.",
        "A. Dosovitskiy, L. Beyer, A. Kolesnikov, D. Weissenborn, X. Zhai, T. Unterthiner, M. Dehghani, M. Minderer, G. Heigold, S. Gelly, J. Uszkoreit, and N. Houlsby, \"An Image is Worth 16×16 Words: Transformers for Image Recognition at Scale,\" in Proc. 9th Int. Conf. on Learning Representations (ICLR), 2021.",
        "Y. Fang, C. Zhang, C. Huang, L. Liu, and Y. Yang, \"Phishing Email Detection Using Improved RCNN Model With Multilevel Vectors and Attention Mechanism,\" IEEE Access, vol. 7, pp. 56329–56340, 2019. doi: 10.1109/ACCESS.2019.2913705",
        "N. Reimers and I. Gurevych, \"Sentence-BERT: Sentence Embeddings using Siamese BERT-Networks,\" in Proc. 2019 Conf. on Empirical Methods in Natural Language Processing (EMNLP-IJCNLP), Hong Kong, China, Nov. 2019, pp. 3982–3992.",
        "Federal Bureau of Investigation Internet Crime Complaint Center, \"2023 Internet Crime Report,\" U.S. Department of Justice, Washington, DC, USA, 2024. [Online]. Available: https://www.ic3.gov/",
        "Cisco Talos, \"Too salty to handle: Exposing cases of CSS abuse for hidden text salting,\" Cisco Talos Intelligence Blog, Oct. 2024. [Online]. Available: https://blog.talosintelligence.com/too-salty-to-handle-exposing-cases-of-css-abuse-for-hidden-text-salting/",
        "S. Rose, O. Borchert, S. Mitchell, and S. Connelly, \"Zero Trust Architecture,\" NIST Special Publication 800-207, National Institute of Standards and Technology, Gaithersburg, MD, USA, Aug. 2020. doi: 10.6028/NIST.SP.800-207",
        "B. Klimt and Y. Yang, \"The Enron Corpus: A New Dataset for Email Classification Research,\" in Proc. 15th European Conf. on Machine Learning (ECML), Pisa, Italy, Sep. 2004, pp. 217–226.",
        "G. Cormack, \"CEAS 2008 Spam Filtering Challenge,\" in Proc. 5th Conf. on Email and Anti-Spam (CEAS), Mountain View, CA, USA, 2008.",
        "A. Cidon, L. Gavish, I. Bleier, N. Korshun, M. Schweighauser, and A. Tsitkin, \"High Precision Detection of Business Email Compromise,\" in Proc. 28th USENIX Security Symposium, Santa Clara, CA, USA, Aug. 2019, pp. 1291–1307.",
        "A. Almutairi, B. Kang, and N. Alhashimy, \"Business email compromise: A systematic review of understanding, detection, and challenges,\" Computers & Security, vol. 158, article 104630, 2025. doi: 10.1016/j.cose.2024.104630",
        "A. M. Almutairi, B. Kang, and N. A. L. Hashimy, \"Business Email Compromise: A Comprehensive Taxonomy for Detection and Prevention,\" in Proc. 7th Int. Conf. on Information Science and Systems (ICISS), 2024.",
        "C. Cross and R. Gillett, \"Exploiting trust for financial gain: an overview of business email compromise (BEC) fraud,\" Journal of Financial Crime, vol. 27, no. 3, pp. 871–884, 2020. doi: 10.1108/JFC-02-2020-0026",
        "S. Duman, K. K. Cakmakci, M. Egele, W. Robertson, and E. Kirda, \"EmailProfiler: Spearphishing Filtering with Header and Stylometric Features of Emails,\" in Proc. IEEE 40th Annual Computer Software and Applications Conf. (COMPSAC), Atlanta, GA, USA, 2016.",
        "X. Chen, P. Hao, R. Chandramouli, and K. P. Subbalakshmi, \"Authorship Similarity Detection from Email Messages,\" in Machine Learning and Data Mining in Pattern Recognition (MLDM 2011), LNCS vol. 6871, Springer, Berlin, 2011, pp. 375–389.",
        "L. Pearl and M. Steyvers, \"Detecting authorship deception: a supervised machine learning approach using author writeprints,\" Literary and Linguistic Computing, vol. 27, no. 2, pp. 183–201, 2012. doi: 10.1093/llc/fqs003",
        "T. Gröndahl and N. Asokan, \"Text Analysis in Adversarial Settings: Does Deception Leave a Stylistic Trace?\" ACM Computing Surveys, vol. 52, no. 3, article 49, 2019. doi: 10.1145/3310331",
        "P. N. Wosah, A. Mirza, Q. Khan, and W. Sayers, \"Analysing the email data using stylometric method and deep learning to mitigate phishing attack,\" International Journal of Information Technology, vol. 17, pp. 3823–3834, 2025.",
        "I. Chanis and A. Arampatzis, \"Enhancing phishing email detection with stylometric features and classifier stacking,\" International Journal of Information Security, 2024. doi: 10.1007/s10207-024-00928-7",
        "L. Betts, R. Biddle, D. Lottridge, and G. Russello, \"Exploring Content Concealment in Email,\" arXiv preprint arXiv:2410.11169, Oct. 2024.",
        "B. Guo, M. Liu, Y. Ma, R. Li, F. Shi, M. Zhang, B. Liu, C. Xu, H. Duan, G. Hong, M. Yang, and Q. Pan, \"Email Cloaking: Deceiving Users and Spam Email Detectors with Invisible HTML Settings,\" in Proc. 30th European Symposium on Research in Computer Security (ESORICS), 2025.",
        "F. Heiding, B. Schneier, A. Vishwanath, J. Bernstein, and P. S. Park, \"Devising and Detecting Phishing Emails Using Large Language Models,\" IEEE Access, vol. 12, pp. 42131–42146, 2024. doi: 10.1109/ACCESS.2024.3375882",
        "T. Koide, N. Fukushi, H. Nakano, and D. Chiba, \"ChatSpamDetector: Leveraging Large Language Models for Effective Phishing Email Detection,\" in Proc. 20th EAI Int. Conf. on Security and Privacy in Communication Networks (SecureComm), 2024.",
        "W. Wang, F. Wei, L. Dong, H. Bao, N. Yang, and M. Zhou, \"MiniLM: Deep Self-Attention Distillation for Task-Agnostic Compression of Pre-Trained Transformers,\" in Proc. 34th Conf. on Neural Information Processing Systems (NeurIPS), 2020, pp. 5776–5788.",
        "Microsoft Corporation, \"Playwright for Python v1.40: Browser automation library,\" GitHub Repository, 2024. [Online]. Available: https://github.com/microsoft/playwright-python",
        "JaidedAI, \"EasyOCR v1.7: Ready-to-use OCR with 80+ supported languages and CUDA acceleration support,\" GitHub Repository, 2024. [Online]. Available: https://github.com/JaidedAI/EasyOCR",
        "J. Nazario, \"Phishing Corpus,\" 2004, archived at monkey.org. [Online]. Available: https://monkey.org/~jose/phishing/",
        "N. Reimers, \"all-MiniLM-L6-v2,\" Hugging Face Model Hub, Sentence-Transformers, 2021. [Online]. Available: https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2",
        "Abnormal Security, \"Attune 1.0: The Behavioral AI Foundation Model for Human Behavior Security,\" Abnormal Security Technical Documentation, 2024. [Online]. Available: https://abnormalsecurity.com",
        "Proofpoint Inc., \"Advanced BEC Defense: Technical Architecture of the Supernova Detection Engine,\" Proofpoint Technical Documentation, 2024. [Online]. Available: https://www.proofpoint.com",
        "Microsoft Corporation, \"What's New in Microsoft Defender for Office 365: AI-Powered BEC Detection and Automatic Attack Disruption,\" Microsoft Security Documentation, 2024. [Online]. Available: https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/"
    ]
    
    for ref in refs:
        p = doc.add_paragraph(style=ref_style)
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(2.5)
        p.paragraph_format.line_spacing = 1.0
        
        has_num = False
        if hasattr(p.style, '_element') and p.style._element.xpath('./w:pPr/w:numPr'):
            has_num = True
            
        num_match = re.match(r'^\[\d+\]\s*(.*)$', ref)
        if num_match:
            text_part = num_match.group(1)
            if not has_num:
                num_tag = re.match(r'^(\[\d+\]\s*)', ref).group(1)
                r_num = p.add_run(num_tag)
                r_num.font.name = "Times New Roman"
                r_num.font.size = Pt(8.0)
        else:
            text_part = ref
            
        pattern = re.compile(r'(\".*?\")')
        parts = pattern.split(text_part)
        for part in parts:
            if not part:
                continue
            r = p.add_run(part)
            r.font.name = "Times New Roman"
            r.font.size = Pt(8.0)
            if part.startswith('"') and part.endswith('"'):
                r.font.italic = True
            
    # ── SAVE DOCUMENT ──
    save_targets = [OUT_PATH, OUT_PATH_ALT]
    for target in save_targets:
        try:
            print(f"Saving document to: {target}")
            doc.save(target)
            print(f"Saved successfully to: {target}")
        except PermissionError:
            fallback = target.replace(".docx", "_NEW.docx")
            print(f"Note: '{target}' is currently open in Word. Saved to '{fallback}' instead.")
            doc.save(fallback)
            
    print("SUCCESS! Revised paper built on IEEE Template successfully without duplicate numbering.")


if __name__ == "__main__":
    build_docx()

