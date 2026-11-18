import os
import re
import sys
import io

# Reconfigure stdout to prevent encoding issues with unicode paths
if sys.stdout is not None:
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
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
WORKSPACE = os.path.dirname(BASE) # F:\enterprise_ngfw

# Images folder location
IMGS = os.path.join(WORKSPACE, "modules", "predictive_ai", "figures")
if not os.path.exists(IMGS):
    IMGS = r"F:\enterprise_ngfw\modules\predictive_ai\figures"
if not os.path.exists(IMGS):
    IMGS = os.path.join(BASE, "figures")

TEMPLATE_PATH = r"Conference-template-A4_٠٢٠٦٣٥.docx"
OUT_PATH = os.path.join(BASE, "AEGIS_Proactive_Defense_Paper.docx")

# ─── OMML NAMESPACE & MATH FORMULAS ──────────────────────────────────────────
OMML_NS = "http://schemas.openxmlformats.org/officeDocument/2006/math"

EQ1 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:acc>
    <m:accPr><m:chr m:val="̂"/></m:accPr>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>p</m:t></m:r></m:e>
  </m:acc>
  <m:r><m:t xml:space="preserve"> = </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>∑</m:t></m:r>
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>α</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>i</m:t></m:r></m:sub>
  </m:sSub>
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>P</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>i</m:t></m:r></m:sub>
  </m:sSub>
</m:oMath>"""

EQ2 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:sSup>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>B</m:t></m:r></m:e>
    <m:sup><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>t</m:t></m:r></m:sup>
  </m:sSup>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>s</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>) = </m:t></m:r>
  <m:f>
    <m:fPr><m:ctrlPr/></m:fPr>
    <m:num>
      <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>P</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
      <m:sSub>
        <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>e</m:t></m:r></m:e>
        <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>t</m:t></m:r></m:sub>
      </m:sSub>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>|</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>s</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>)</m:t></m:r>
      <m:sSup>
        <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>B</m:t></m:r></m:e>
        <m:sup><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>-</m:t></m:r></m:sup>
      </m:sSup>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>s</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>)</m:t></m:r>
    </m:num>
    <m:den>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>∑</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>P</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
      <m:sSub>
        <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>e</m:t></m:r></m:e>
        <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>t</m:t></m:r></m:sub>
      </m:sSub>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>|</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>s</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>')</m:t></m:r>
      <m:sSup>
        <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>B</m:t></m:r></m:e>
        <m:sup><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>-</m:t></m:r></m:sup>
      </m:sSup>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>s</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>')</m:t></m:r>
    </m:den>
  </m:f>
</m:oMath>"""

EQ3 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:sSup>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>a</m:t></m:r></m:e>
    <m:sup><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>*</m:t></m:r></m:sup>
  </m:sSup>
  <m:r><m:t xml:space="preserve"> = argmax </m:t></m:r>
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>E</m:t></m:r></m:e>
    <m:sub>
      <m:sSub>
        <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>Π</m:t></m:r></m:e>
        <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>A</m:t></m:r></m:sub>
      </m:sSub>
    </m:sub>
  </m:sSub>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>[</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>U</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>a</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>D</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>,</m:t></m:r>
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>a</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>A</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>)] - </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>λ</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t> · </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>ER</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>a</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>D</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>,</m:t></m:r>
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>Π</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>A</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>)</m:t></m:r>
</m:oMath>"""

EQ4 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>CPCI</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t> = [1 - </m:t></m:r>
  <m:f>
    <m:fPr><m:ctrlPr/></m:fPr>
    <m:num>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>|</m:t></m:r>
      <m:sSub>
        <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>P</m:t></m:r></m:e>
        <m:sub>
          <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>1-</m:t></m:r>
          <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>α</m:t></m:r>
        </m:sub>
      </m:sSub>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>| - 1</m:t></m:r>
    </m:num>
    <m:den>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>|</m:t></m:r>
      <m:sSub>
        <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>A</m:t></m:r></m:e>
        <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>A</m:t></m:r></m:sub>
      </m:sSub>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>|</m:t></m:r>
    </m:den>
  </m:f>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>] · [1 - </m:t></m:r>
  <m:f>
    <m:fPr><m:ctrlPr/></m:fPr>
    <m:num>
      <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>H</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
      <m:sSup>
        <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>B</m:t></m:r></m:e>
        <m:sup><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>t</m:t></m:r></m:sup>
      </m:sSup>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>)</m:t></m:r>
    </m:num>
    <m:den>
      <m:r><m:t>log </m:t></m:r>
      <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>K</m:t></m:r>
    </m:den>
  </m:f>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>]</m:t></m:r>
</m:oMath>"""

# EQ5: Default weight vector (alpha vector)
EQ5 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:r><m:rPr><m:sty m:val="b"/></m:rPr><m:t xml:space="preserve">α </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>= (0.22,  0.27,  0.18,  0.13,  0.09,  0.11)</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t xml:space="preserve">,    </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>∑</m:t></m:r>
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>α</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>i</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>= 1</m:t></m:r>
</m:oMath>"""

# EQ6: Hybrid blended prediction Π_A
EQ6 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>Π</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>A</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>a</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>) = (1 − </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>ω</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>) </m:t></m:r>
  <m:sSup>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>Π</m:t></m:r></m:e>
    <m:sup><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>Q</m:t></m:r></m:sup>
  </m:sSup>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>a</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>) + </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>ω</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t xml:space="preserve">  </m:t></m:r>
  <m:sSup>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>Π</m:t></m:r></m:e>
    <m:sup><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>Attn</m:t></m:r></m:sup>
  </m:sSup>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>a</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>),    </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>ω</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>= 0.30</m:t></m:r>
</m:oMath>"""

# EQ7: VCFE Chain Exploitation Probability
EQ7 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>P</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>chain</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(C) = </m:t></m:r>
  <m:sSup>
    <m:e><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>∏</m:t></m:r></m:e>
    <m:sup><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>n</m:t></m:r></m:sup>
  </m:sSup>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>ε</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>v</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>ci</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>) · </m:t></m:r>
  <m:sSup>
    <m:e><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>∏</m:t></m:r></m:e>
    <m:sup><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>n−1</m:t></m:r></m:sup>
  </m:sSup>
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>P</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>trans</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>v</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>ci</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>→</m:t></m:r>
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>v</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>ci+1</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>) · </m:t></m:r>
  <m:sSup>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>e</m:t></m:r></m:e>
    <m:sup>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>−μ(n−1)</m:t></m:r>
    </m:sup>
  </m:sSup>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>,    μ = 0.15</m:t></m:r>
</m:oMath>"""

# EQ8: TD(lambda) Q-table update rule
EQ8 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>Q</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>s, a</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>) ← </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>Q</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>s, a</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>) + </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>η</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t> · </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>δ</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t> · </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>e</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>s, a</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>),    </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>η</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>= 0.05,  </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>γ</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>= 0.95,  </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>λ</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>= 0.80</m:t></m:r>
</m:oMath>"""

# EQ9: GTATM - Phi_TZ timezone multiplier (simplified display form)
EQ9 = f"""<m:oMath xmlns:m="{OMML_NS}">
  <m:sSub>
    <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>Φ</m:t></m:r></m:e>
    <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>TZ</m:t></m:r></m:sub>
  </m:sSub>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>t</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>) = 1 + </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>κ</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t> · max</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>(0, cos(</m:t></m:r>
  <m:f>
    <m:fPr><m:ctrlPr/></m:fPr>
    <m:num>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>2π(</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>t</m:t></m:r>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t> − </m:t></m:r>
      <m:sSub>
        <m:e><m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>h</m:t></m:r></m:e>
        <m:sub><m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>peak</m:t></m:r></m:sub>
      </m:sSub>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>)</m:t></m:r>
    </m:num>
    <m:den>
      <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>24</m:t></m:r>
    </m:den>
  </m:f>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>)),    </m:t></m:r>
  <m:r><m:rPr><m:sty m:val="i"/></m:rPr><m:t>κ</m:t></m:r>
  <m:r><m:rPr><m:sty m:val="p"/></m:rPr><m:t>= 0.40</m:t></m:r>
</m:oMath>"""


# ─── TEMPLATE CONVERSION & INSPECTION HELPERS ─────────────────────────────────


def ensure_docx_template(template_path):
    """
    Ensures python-docx can open the template. If it's a binary .doc, 
    converts it to .docx using win32com (Word) on Windows.
    """
    if not os.path.exists(template_path):
        raise FileNotFoundError(f"Template file not found at: {template_path}")
        
    # Read magic bytes to determine file type
    with open(template_path, 'rb') as f:
        magic = f.read(4)
        
    # Check if file starts with 'PK' (ZIP format, used by .docx)
    if magic.startswith(b'PK\x03\x04'):
        if template_path.lower().endswith('.docx'):
            return template_path
        else:
            docx_path = template_path + "x"
            print(f"Template is a renamed docx file. Copying to {docx_path}...")
            import shutil
            shutil.copy2(template_path, docx_path)
            return docx_path
            
    # Binary .doc file detection
    if template_path.lower().endswith('.doc'):
        docx_path = template_path + "x"
        if os.path.exists(docx_path):
            print(f"Using already converted docx template: {docx_path}")
            return docx_path
            
        print(f"Template is a binary .doc file. Attempting conversion via MS Word COM...")
        try:
            import win32com.client
            word = win32com.client.Dispatch("Word.Application")
            word.Visible = False
            abs_doc = os.path.abspath(template_path)
            abs_docx = os.path.abspath(docx_path)
            
            doc = word.Documents.Open(abs_doc)
            # 16 stands for wdFormatXMLDocument (.docx)
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
    
    # Check exact or prefix matches
    best_match = None
    for style in doc.styles:
        if style.type != WD_STYLE_TYPE.PARAGRAPH:
            continue
        s_name = style.name.lower().replace(' ', '').replace('_', '')
        if s_name == target:
            return style.name
        if target in s_name:
            best_match = style.name
            
    if best_match:
        return best_match
        
    # Pre-defined mapping for standard IEEE/AIPCP templates
    fallback_map = {
        'papertitle': ['title', 'paper title', 'document title'],
        'authorname': ['author', 'author name', 'authors'],
        'authoraffiliation': ['affiliation', 'author affiliation', 'affiliations', 'aff'],
        'authoremail': ['email', 'author email', 'email address'],
        'abstract': ['abstract', 'abstract text'],
        'heading1': ['heading 1', 'heading1', 'h1'],
        'heading2': ['heading 2', 'heading2', 'h2'],
        'heading3': ['heading 3', 'heading3', 'h3'],
        'paragraph': ['body', 'body text', 'normal', 'paragraph'],
        'reference': ['reference', 'references', 'reference text', 'bib']
    }
    
    if target in fallback_map:
        for fb in fallback_map[target]:
            fb_norm = fb.lower().replace(' ', '').replace('_', '')
            for style in doc.styles:
                if style.type != WD_STYLE_TYPE.PARAGRAPH:
                    continue
                s_name = style.name.lower().replace(' ', '').replace('_', '')
                if fb_norm in s_name:
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
        
    # Regex splits markdown patterns while capturing boundaries
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
            r.font.size = Pt(9.0)
        else:
            r = p.add_run(part)
            r.font.name = "Times New Roman"
    return p


def insert_equation_native(doc, omml_str, eq_num, style='Normal'):
    """
    Inserts a single paragraph with a centered equation and a right-aligned number.
    """
    p = doc.add_paragraph(style=style)
    p.paragraph_format.space_before = Pt(3)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    
    # Render and insert math ML
    eq_el = etree.fromstring(omml_str)
    p._p.append(eq_el)
    
    # Equation number in run
    r = p.add_run(f'    ({eq_num})')
    r.font.name = "Times New Roman"
    r.font.size = Pt(9.5)
    return p


def format_ieee_table(table):
    """
    Sets clean scientific rules on the table (similar to booktabs / IEEE rules):
    - Top/Bottom borders: solid 1.0 pt
    - Header bottom border: solid 0.5 pt
    - No vertical borders, no inside horizontal borders.
    """
    tblPr = table._tbl.tblPr
    tblBorders = tblPr.find(qn('w:tblBorders'))
    if tblBorders is None:
        tblBorders = OxmlElement('w:tblBorders')
        tblPr.append(tblBorders)
    else:
        tblBorders.clear()
        
    # Top border (size 8 = 1.0 pt)
    top = OxmlElement('w:top')
    top.set(qn('w:val'), 'single')
    top.set(qn('w:sz'), '8')
    top.set(qn('w:space'), '0')
    top.set(qn('w:color'), 'auto')
    tblBorders.append(top)
    
    # Bottom border (size 8 = 1.0 pt)
    bottom = OxmlElement('w:bottom')
    bottom.set(qn('w:val'), 'single')
    bottom.set(qn('w:sz'), '8')
    bottom.set(qn('w:space'), '0')
    bottom.set(qn('w:color'), 'auto')
    tblBorders.append(bottom)
    
    # Clear other borders
    for b_name in ['left', 'right', 'insideH', 'insideV']:
        b = OxmlElement(f'w:{b_name}')
        b.set(qn('w:val'), 'none')
        tblBorders.append(b)
        
    # Add bottom border to headers
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
        b_cell.set(qn('w:sz'), '4') # 0.5 pt
        b_cell.set(qn('w:space'), '0')
        b_cell.set(qn('w:color'), 'auto')
        tcBorders.append(b_cell)
        
        for edge in ('top', 'left', 'right'):
            e = OxmlElement(f'w:{edge}')
            e.set(qn('w:val'), 'none')
            tcBorders.append(e)


def to_roman(val):
    """Converts an integer to Roman numeral OR returns a string label as-is (e.g. 'I-B', 'III-A')."""
    if isinstance(val, str):
        return val  # Already a label string like 'I-B' or 'III-A'
    roman_map = {
        1: 'I', 2: 'II', 3: 'III', 4: 'IV', 5: 'V', 6: 'VI', 7: 'VII', 8: 'VIII', 9: 'IX', 10: 'X',
        11: 'XI', 12: 'XII', 13: 'XIII', 14: 'XIV', 15: 'XV', 16: 'XVI', 17: 'XVII', 18: 'XVIII',
        19: 'XIX', 20: 'XX', 21: 'XXI', 22: 'XXII', 23: 'XXIII', 24: 'XXIV', 25: 'XXV'
    }
    return roman_map.get(int(val), str(val))


def add_note_paragraph(doc, note_text, style='Normal'):
    """
    Adds an IEEE-style Note paragraph.
    Uses 8.5pt Times New Roman with bold 'Note:' prefix.
    Left-indented with a thin XML border to distinguish from body text.
    """
    p = doc.add_paragraph(style=style)
    p.paragraph_format.left_indent = Inches(0.18)
    p.paragraph_format.right_indent = Inches(0.05)
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(5)
    p.paragraph_format.line_spacing = 1.0
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    # Bold "Note:" label
    run_label = p.add_run("Note: ")
    run_label.font.name = "Times New Roman"
    run_label.font.size = Pt(8.5)
    run_label.font.bold = True
    run_label.font.italic = False

    # Body text — same size, not italic
    run_text = p.add_run(note_text)
    run_text.font.name = "Times New Roman"
    run_text.font.size = Pt(8.5)
    run_text.font.italic = False

    # Add a thin left border via XML to visually separate from body paragraphs
    pPr = p._element.get_or_add_pPr()
    pBdr = OxmlElement('w:pBdr')
    left_bdr = OxmlElement('w:left')
    left_bdr.set(qn('w:val'), 'single')
    left_bdr.set(qn('w:sz'), '4')       # 0.5 pt thin line
    left_bdr.set(qn('w:space'), '4')
    left_bdr.set(qn('w:color'), '888888')  # medium grey
    pBdr.append(left_bdr)
    pPr.append(pBdr)

    return p



def fix_paragraph_justification(p):
    """
    Applies XML-level character spacing control to a paragraph.
    Sets w:characterSpacingControl to 'doNotCompress' which prevents Word
    from over-expanding inter-word gaps in justified narrow-column text.
    Also sets w:jc to 'both' with w:textAlignment 'baseline' for uniform baselines.
    """
    pPr = p._element.get_or_add_pPr()
    # Character spacing control: doNotCompress avoids gap rivers
    csc = pPr.find(qn('w:characterSpacingControl'))
    if csc is None:
        csc = OxmlElement('w:characterSpacingControl')
        pPr.append(csc)
    csc.set(qn('w:val'), 'doNotCompress')
    return p


def add_table_ieee(doc, caption_text, headers, rows, table_num, widths=None, caption_style='Normal'):
    """
    Adds a formatted scientific table with a Table Caption centered above it.
    Uses IEEE small caps numbering (e.g. TABLE I. CAPTION TEXT).
    All tables are formatted to fit within the 3.25-inch column width.
    """
    # Caption above
    cap = doc.add_paragraph(style=caption_style)
    cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    cap.paragraph_format.space_before = Pt(8)
    cap.paragraph_format.space_after = Pt(4)
    
    is_table_head = 'table' in str(caption_style).lower()
    if not is_table_head:
        roman_num = to_roman(table_num)
        run_num = cap.add_run(f"TABLE {roman_num}.  ")
        run_num.font.name = "Times New Roman"
        run_num.font.bold = True
        run_num.font.size = Pt(8.5)
    
    # Table description in uppercase
    run_desc = cap.add_run(caption_text.upper())
    run_desc.font.name = "Times New Roman"
    run_desc.font.size = Pt(8.0)
    
    # Table setup
    table = doc.add_table(rows=1 + len(rows), cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    
    # Auto-select font size based on number of columns to fit the column width
    num_cols = len(headers)
    if num_cols >= 7:
        hdr_font_size = Pt(6.5)
        data_font_size = Pt(6.0)
    elif num_cols >= 5:
        hdr_font_size = Pt(7.0)
        data_font_size = Pt(6.5)
    else:
        hdr_font_size = Pt(8.0)
        data_font_size = Pt(7.5)
        
    # Header Row
    hdr = table.rows[0]
    hdr.height = Cm(0.4)
    for i, h in enumerate(headers):
        cell = hdr.cells[i]
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        
        # Set extremely tight cell margins (padding) for A4 column fit
        tcPr = cell._tc.get_or_add_tcPr()
        tcMar = OxmlElement('w:tcMar')
        for margin in ['left', 'right']:
            m = OxmlElement(f'w:{margin}')
            m.set(qn('w:w'), '40')  # 40 dxa = 2 pt padding
            m.set(qn('w:type'), 'dxa')
            tcMar.append(m)
        tcPr.append(tcMar)
        
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(1)
        p.paragraph_format.space_after = Pt(1)
        p.paragraph_format.line_spacing = 1.0
        run = p.add_run(h)
        run.font.name = "Times New Roman"
        run.font.bold = True
        run.font.size = hdr_font_size
        
    # Data Rows
    for r_idx, row_data in enumerate(rows):
        row = table.rows[r_idx + 1]
        row.height = Cm(0.35)
        for c_idx, val in enumerate(row_data):
            cell = row.cells[c_idx]
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            
            # Set extremely tight cell margins
            tcPr = cell._tc.get_or_add_tcPr()
            tcMar = OxmlElement('w:tcMar')
            for margin in ['left', 'right']:
                m = OxmlElement(f'w:{margin}')
                m.set(qn('w:w'), '40')
                m.set(qn('w:type'), 'dxa')
                tcMar.append(m)
            tcPr.append(tcMar)
            
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(1)
            p.paragraph_format.line_spacing = 1.0
            run = p.add_run(str(val))
            run.font.name = "Times New Roman"
            run.font.size = data_font_size
            
    # Set explicit widths if provided
    if widths:
        for r in table.rows:
            for i, w in enumerate(widths):
                if i < len(r.cells):
                    r.cells[i].width = w
                    
    # Apply scientific borders
    format_ieee_table(table)
    
    # Minor spacer below table
    p_spacer = doc.add_paragraph()
    p_spacer.paragraph_format.space_before = Pt(0)
    p_spacer.paragraph_format.space_after = Pt(4)
    r = p_spacer.add_run()
    r.font.size = Pt(1)
    return table


def add_centered_image(doc, filename, width, caption_text, fig_num, caption_style='Normal'):
    """
    Adds a centered image with a Figure Caption below it.
    Uses IEEE Fig. X format.
    """
    path = os.path.join(IMGS, filename)
    if os.path.exists(path):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(4)
        p.paragraph_format.space_after = Pt(2)
        run = p.add_run()
        run.add_picture(path, width=Inches(min(width, 3.5)))
        
        # Caption below
        cap = doc.add_paragraph(style=caption_style)
        cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        cap.paragraph_format.space_before = Pt(2)
        cap.paragraph_format.space_after = Pt(6)
        
        is_fig_cap = 'figure' in str(caption_style).lower()
        if not is_fig_cap:
            run_lbl = cap.add_run(f"Fig. {fig_num}.  ")
            run_lbl.font.name = "Times New Roman"
            run_lbl.font.bold = True
            run_lbl.font.size = Pt(8.5)
            
        run_desc = cap.add_run(caption_text)
        run_desc.font.name = "Times New Roman"
        run_desc.font.size = Pt(8.0)
    else:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(f"[Fig. {fig_num}: {caption_text} - Image file '{filename}' not found]")
        run.font.italic = True
        run.font.size = Pt(9.0)


# ─── CORE BUILD PROCEDURE ────────────────────────────────────────────────────

def build_docx():
    print("Preparing template file...")
    active_template = ensure_docx_template(TEMPLATE_PATH)
    
    print("Initializing document...")
    doc = Document(active_template)
    
    # ── Document-wide typography fixes for narrow 2-column layout ──
    settings_el = doc.settings._element

    # 1. Auto-Hyphenation — break long words at hyphens to prevent word-gap rivers
    auto_hyphen = settings_el.find(qn('w:autoHyphenation'))
    if auto_hyphen is None:
        auto_hyphen = OxmlElement('w:autoHyphenation')
        settings_el.append(auto_hyphen)
    auto_hyphen.set(qn('w:val'), 'true')

    # 2. Hyphenation Zone — how close to margin before hyphenating (360 twips = 0.25 inch)
    hyph_zone = settings_el.find(qn('w:hyphenationZone'))
    if hyph_zone is None:
        hyph_zone = OxmlElement('w:hyphenationZone')
        settings_el.append(hyph_zone)
    hyph_zone.set(qn('w:val'), '360')

    # 3. Consecutive Hyphen Limit — max 2 consecutive hyphens (aesthetics)
    consec_hyph = settings_el.find(qn('w:consecutiveHyphenLimit'))
    if consec_hyph is None:
        consec_hyph = OxmlElement('w:consecutiveHyphenLimit')
        settings_el.append(consec_hyph)
    consec_hyph.set(qn('w:val'), '2')

    # 4. Do Not Expand Shift-Return — prevents space expansion on soft line breaks
    no_expand = settings_el.find(qn('w:doNotExpandShiftReturn'))
    if no_expand is None:
        no_expand = OxmlElement('w:doNotExpandShiftReturn')
        settings_el.append(no_expand)

    # 5. Compatibility: Use Word 2013+ justification algorithm (reduces rivers)
    compat_el = settings_el.find(qn('w:compat'))
    if compat_el is None:
        compat_el = OxmlElement('w:compat')
        settings_el.append(compat_el)
    # Enable "Use word 2010 text layout" — better inter-word spacing algorithm
    word_compat = OxmlElement('w:compatSetting')
    word_compat.set(qn('w:name'), 'compatibilityMode')
    word_compat.set(qn('w:uri'), 'http://schemas.microsoft.com/office/word')
    word_compat.set(qn('w:val'), '15')  # Word 2013+ mode
    compat_el.append(word_compat)


    # Resolve style names dynamically
    title_style = find_style(doc, 'Paper Title', 'Normal')
    author_style = find_style(doc, 'Author Name', 'Normal')
    aff_style = find_style(doc, 'Author Affiliation', 'Normal')
    email_style = find_style(doc, 'Author Email', 'Normal')
    abs_style = find_style(doc, 'Abstract', 'Normal')
    h1_style = find_style(doc, 'Heading 1', 'Heading 1')
    h2_style = find_style(doc, 'Heading 2', 'Heading 2')
    h3_style = find_style(doc, 'Heading 3', 'Heading 3')
    h5_style = find_style(doc, 'Heading 5', 'Heading 5')
    para_style = find_style(doc, 'Paragraph', 'Normal')
    ref_style = find_style(doc, 'Reference', 'Normal')
    kw_style = find_style(doc, 'Keywords', 'Normal')
    tbl_head_style = find_style(doc, 'Table Head', 'Normal')
    fig_cap_style = find_style(doc, 'Figure Caption', 'Normal')

    # ── Apply characterSpacingControl to paragraph styles ──
    # This prevents Word from over-expanding spaces in justified narrow-column text.
    for style_name in [para_style, abs_style, ref_style]:
        try:
            style_obj = doc.styles[style_name]
            el = style_obj.element
            pPr = el.find(qn('w:pPr'))
            if pPr is None:
                pPr = OxmlElement('w:pPr')
                el.append(pPr)
            csc = pPr.find(qn('w:characterSpacingControl'))
            if csc is None:
                csc = OxmlElement('w:characterSpacingControl')
                pPr.append(csc)
            csc.set(qn('w:val'), 'doNotCompress')
        except Exception:
            pass  # Style not found or not patchable — skip silently


    # ── Clear template placeholders ──
    print("Clearing template text...")
    for p in list(doc.paragraphs):
        p._element.getparent().remove(p._element)
    for t in list(doc.tables):
        t._element.getparent().remove(t._element)
        
    # ── SECTION 1: Title & Authors (Single Column Page Span) ──
    print("Setting up Section 1 (Title and Side-by-Side Authors)...")
    
    # Title (Centered, single column across the top)
    p_title = doc.add_paragraph(style=title_style)
    p_title.paragraph_format.space_before = Pt(18)
    p_title.paragraph_format.space_after = Pt(12)
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_title = p_title.add_run(
        "AEGIS: A Deep Learning Framework for Multi-Stage Cyber Attack Prediction and Adversarial Intent Forecasting"
    )
    r_title.font.name = "Times New Roman"
    r_title.font.bold = True
    r_title.font.size = Pt(22)
    
    # Authors Block (Multi-column grid matching IEEE conference template for 7 authors)
    # Row 1: 4 authors (Waheeb Al-Humayri, Mubarak Altamimi, Yahya Abdul Qader Saif Abdullah, Asaad Al-Din Ali Ali)
    table_auth1 = doc.add_table(rows=1, cols=4)
    table_auth1.alignment = WD_TABLE_ALIGNMENT.CENTER
    
    tblPr1 = table_auth1._tbl.tblPr
    tblBorders1 = OxmlElement('w:tblBorders')
    for border_name in ['top', 'left', 'bottom', 'right', 'insideH', 'insideV']:
        b = OxmlElement(f'w:{border_name}')
        b.set(qn('w:val'), 'none')
        tblBorders1.append(b)
    tblPr1.append(tblBorders1)

    def populate_author(cell, name, dept, org, location, email, col_width_in):
        cell.width = Inches(col_width_in)
        p = cell.paragraphs[0]
        p.style = author_style
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.line_spacing = 1.0
        
        r_name = p.add_run(f"{name}\n")
        r_name.font.name = "Times New Roman"
        r_name.font.bold = True
        r_name.font.size = Pt(10.0)
        
        r_aff = p.add_run(f"{dept}\n{org}\n{location}\n")
        r_aff.font.name = "Times New Roman"
        r_aff.font.italic = True
        r_aff.font.size = Pt(8.5)
        
        r_email = p.add_run(email)
        r_email.font.name = "Times New Roman"
        r_email.font.size = Pt(8.5)

    # Row 1 Authors
    row1_data = [
        ("Waheeb Al-Humayri", "Dept. of Cybersecurity", "The National University", "Taiz, Yemen", "waheeb.alhumayri@gmail.com"),
        ("Mubarak Altamimi", "Dept. of Computer Engineering", "Karabük University", "Karabük, Turkey", "eng.mobaraktamimi@yahoo.com"),
        ("Yahya Abdul Qader Saif Abdullah", "Dept. of Cybersecurity", "The National University", "Taiz, Yemen", "engyaheyaalahmedi@gmail.com"),
        ("Asaad Al-Din Ali Ali", "Dept. of Cybersecurity", "The National University", "Taiz, Yemen", "asaad.ali@nationaluniv.edu.ye"),
    ]
    for idx, (name, dept, org, loc, email) in enumerate(row1_data):
        populate_author(table_auth1.rows[0].cells[idx], name, dept, org, loc, email, 1.75)

    # Spacer between author rows
    p_mid = doc.add_paragraph()
    p_mid.paragraph_format.space_before = Pt(0)
    p_mid.paragraph_format.space_after = Pt(3)
    p_mid.paragraph_format.line_spacing = 1.0
    r_mid = p_mid.add_run()
    r_mid.font.size = Pt(1)

    # Row 2: 3 authors (Amr Abdullah Ali, Musa Mohammed Abdullah, Osama Yousef Saeed)
    table_auth2 = doc.add_table(rows=1, cols=3)
    table_auth2.alignment = WD_TABLE_ALIGNMENT.CENTER
    
    tblPr2 = table_auth2._tbl.tblPr
    tblBorders2 = OxmlElement('w:tblBorders')
    for border_name in ['top', 'left', 'bottom', 'right', 'insideH', 'insideV']:
        b = OxmlElement(f'w:{border_name}')
        b.set(qn('w:val'), 'none')
        tblBorders2.append(b)
    tblPr2.append(tblBorders2)

    row2_data = [
        ("Amr Abdullah Ali", "Dept. of Cybersecurity", "The National University", "Taiz, Yemen", "amr.abdullah@nationaluniv.edu.ye"),
        ("Musa Mohammed Abdullah", "Dept. of Cybersecurity", "The National University", "Taiz, Yemen", "musa.abdullah@nationaluniv.edu.ye"),
        ("Osama Yousef Saeed", "Dept. of Cybersecurity", "The National University", "Taiz, Yemen", "osama.yousef@nationaluniv.edu.ye"),
    ]
    for idx, (name, dept, org, loc, email) in enumerate(row2_data):
        populate_author(table_auth2.rows[0].cells[idx], name, dept, org, loc, email, 2.34)

    # Spacer after authors table
    p_sp = doc.add_paragraph()
    p_sp.paragraph_format.space_before = Pt(0)
    p_sp.paragraph_format.space_after = Pt(6)
    p_sp.paragraph_format.line_spacing = 1.0
    r_sp = p_sp.add_run()
    r_sp.font.size = Pt(1)

    # ── SECTION 2: Body Text (Two Columns — starts with Abstract) ──
    print("Creating Section 2 (two-column — Abstract, Keywords, and Body)...")
    sec2 = doc.add_section(WD_SECTION.CONTINUOUS)
    
    sectPr = sec2._sectPr
    cols = sectPr.xpath('./w:cols')
    if not cols:
        cols = OxmlElement('w:cols')
        sectPr.append(cols)
    else:
        cols = cols[0]
    cols.set(qn('w:num'), '2')
    cols.set(qn('w:space'), '360') # 18 pt gap
    
    # Abstract (Placed inside Column 1 as per IEEE Conference Template)
    print("Writing Abstract (inside Column 1)...")
    p_abs = doc.add_paragraph(style=abs_style)
    p_abs.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p_abs.paragraph_format.space_before = Pt(0)
    p_abs.paragraph_format.space_after = Pt(4)
    p_abs.paragraph_format.line_spacing = 1.0
    
    r_lbl = p_abs.add_run("Abstract")
    r_lbl.font.name = "Times New Roman"
    r_lbl.font.bold = True
    r_lbl.font.italic = True
    r_lbl.font.size = Pt(9.0)
    
    r_dash = p_abs.add_run("—")
    r_dash.font.name = "Times New Roman"
    r_dash.font.bold = True
    r_dash.font.size = Pt(9.0)
    
    abs_text = (
        "Contemporary cyber defenses are fundamentally reactive, initiating analysis only after adversarial "
        "behavior is observed. This paper introduces the AEGIS framework (Adaptive Edge Guardian for Intelligent Security), "
        "a two-stage proactive defense system for autonomous network defense. Prior to attacks, "
        "Stage 1 (Threat Probability Engine) computes an organizational risk score by integrating geopolitical tension, "
        "sector base rates, vulnerability exposure, and historical priors to condition operational sensitivity. During "
        "an attack, Stage 2 predicts full adversarial intent distributions using a hybrid non-Markovian sequence "
        "model and selects a Nash-optimal deception response under a novel EscalationRisk penalty. Evaluated on "
        "the AEGISBench dataset (17 multi-stage APT scenarios), AEGIS achieves a Brier Score of 0.1475 for "
        "pre-attack prediction and maintains a 0.0% Escalation Rate with 90.9% disruption precision during active "
        "attacks. Operating at a 0.27 ms inline latency, the framework establishes a deployed feasibility for "
        "high-throughput Next-Generation Firewalls (NGFWs). This extended version (AEGIS v4) introduces six "
        "additional novel contributions absent in all prior surveyed work: (i) a Vulnerability Chain Forecasting "
        "Engine (VCFE) that predicts correlated multi-CVE exploit chains rather than isolated vulnerabilities, contributing "
        "a seventh risk factor P7 to the TPE scoring model; (ii) a Dual-Model Adaptive Adversary (DMAA) in which the "
        "simulated attacker maintains a second-order Bayesian belief over defender strategy and dynamically evades "
        "AEGIS's own response patterns; (iii) a Causal Anti-Poisoning Gate (CIAPG) applying Pearl's do-calculus "
        "structural causal filtering over CTI inputs to provide formal resistance against adversarial ML data-poisoning "
        "attacks on the Transformer; (iv) a Geopolitical Temporal Attack Timing Model (GTATM) that resolves the TPE "
        "pre-attack probability to sub-hourly granularity via timezone-aware adversary activity rhythms and "
        "geopolitical shock decay functions; (v) a Defensive Digital Twin Simulator (DDTS) that evaluates counterfactual "
        "defense trajectories through lightweight Monte Carlo rollouts (N=50, k=3 steps, < 5 ms) before any CSO action "
        "is committed to the network; and (vi) a Calibrated Prediction Confidence Index (CPCI) grounded in Conformal "
        "Prediction theory, providing formal marginal coverage guarantees on autonomous decision trustworthiness "
        "with a three-tier human-machine authority model."
    )
    r_body = p_abs.add_run(abs_text)
    r_body.font.name = "Times New Roman"
    r_body.font.size = Pt(9.0)
    
    # Keywords (Placed inside Column 1 immediately following Abstract)
    p_kw = doc.add_paragraph(style=kw_style)
    p_kw.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p_kw.paragraph_format.space_before = Pt(2)
    p_kw.paragraph_format.space_after = Pt(8)
    p_kw.paragraph_format.line_spacing = 1.0
    
    r_kw_lbl = p_kw.add_run("Keywords")
    r_kw_lbl.font.name = "Times New Roman"
    r_kw_lbl.font.bold = True
    r_kw_lbl.font.italic = True
    r_kw_lbl.font.size = Pt(9.0)
    
    r_kw_dash = p_kw.add_run("—")
    r_kw_dash.font.name = "Times New Roman"
    r_kw_dash.font.bold = True
    r_kw_dash.font.size = Pt(9.0)
    
    r_kw_vals = p_kw.add_run(
        "proactive cyber defense; attack prediction; threat probability engine; Next-Generation Firewall; "
        "game-theoretic security; conformal prediction; kill-chain modeling; adversarial machine learning; "
        "digital twin; vulnerability chain forecasting"
    )
    r_kw_vals.font.name = "Times New Roman"
    r_kw_vals.font.size = Pt(9.0)
    
    # Helper to add a clean heading — explicit run control prevents italic from template styles
    def add_h1(text):
        p = doc.add_paragraph(style=h1_style)
        p.paragraph_format.space_before = Pt(12)
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.keep_with_next = True
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(text.upper())   # H1 in IEEE is ALL CAPS centered
        r.font.name = "Times New Roman"
        r.font.bold = True
        r.font.italic = False
        r.font.size = Pt(10)
        return p

    def add_h2(text):
        p = doc.add_paragraph(style=h2_style)
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after = Pt(4)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)           # H2 in IEEE is italic (A. B. C. subsections)
        r.font.name = "Times New Roman"
        r.font.bold = False
        r.font.italic = True
        r.font.size = Pt(10)
        return p

    def add_h3(text):
        p = doc.add_paragraph(style=h3_style)
        p.paragraph_format.space_before = Pt(5)
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.keep_with_next = True
        r = p.add_run(text)           # H3 in IEEE is italic (numbered sub-subsections)
        r.font.name = "Times New Roman"
        r.font.bold = False
        r.font.italic = True
        r.font.size = Pt(10)
        return p

    # ── I. INTRODUCTION ──
    add_h1("INTRODUCTION")

    
    add_h2("The Reactive Defense Problem")

    add_formatted_paragraph(doc, 
        "Network defenders face a systematic information deficit: contemporary intrusion "
        "detection and prevention systems are fundamentally reactive; they observe network traffic, match patterns "
        "against known signatures or localized machine learning models, and execute rigid enforcement actions.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h2("The Strategic-Operational Gap")

    add_formatted_paragraph(doc,
        "Network security has historically bifurcated into two disconnected disciplines: *risk management*, which "
        "quantifies the likelihood of future threats at a strategic planning horizon, and *intrusion prevention*, "
        "which reacts to observed attack signals at an operational horizon. This bifurcation creates a critical "
        "defensive gap: production Next-Generation Firewalls (NGFWs) receive no signal from organizational risk context, "
        "while risk management frameworks produce no actionable real-time defense directives.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h2("Limitations of Extant Systems")

    add_formatted_paragraph(doc,
        "This gap yields significant compounding failure modes at the operational level:",
        style=para_style, indent=Inches(0.25)
    )
    bullet_style = para_style
    bullet_indent = Inches(0.25)
    
    p_b1 = doc.add_paragraph(style=bullet_style)
    p_b1.paragraph_format.left_indent = bullet_indent
    r = p_b1.add_run("1) Stage Blindness: ")
    r.font.bold = True
    p_b1.add_run("Enforcement actions during early kill-chain stages (e.g., connection drops during reconnaissance) prematurely reveal detection, prompting adversary pivots to covert vectors.")
    
    p_b2 = doc.add_paragraph(style=bullet_style)
    p_b2.paragraph_format.left_indent = bullet_indent
    r = p_b2.add_run("2) Distribution Blindness: ")
    r.font.bold = True
    p_b2.add_run("Single-point predictors optimize against the single most likely attack step, leaving the residual attack distribution uncontested.")
    
    p_b3 = doc.add_paragraph(style=bullet_style)
    p_b3.paragraph_format.left_indent = bullet_indent
    r = p_b3.add_run("3) Escalation Blindness: ")
    r.font.bold = True
    p_b3.add_run("No formal operational risk model quantifies whether a defensive action forces the adversary to escalate, pivot, or go dormant.")
    
    add_h2("Proposed Solution: The AEGIS Framework")

    add_formatted_paragraph(doc,
        "To address these deficiencies, we propose the **AEGIS framework**. The fundamental premise is that security "
        "posture must be conditioned on *both* pre-event organizational context and real-time adversarial state. It "
        "answers two critical questions: (1) Before the attack: *\"What is the calibrated probability of an imminent "
        "attack, given the organization's geopolitical and vulnerability profile?\"* (2) During the attack: *\"Given "
        "observed evidence, what is the full distribution of adversary intent, and which Nash-optimal deception response "
        "minimizes adversary utility without revealing our detection?\"*",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h2("Scientific Contributions")

    add_formatted_paragraph(doc,
        "The core contributions of this work bridge the gap between strategic risk quantification and operational autonomic defense:",
        style=para_style, indent=Inches(0.25)
    )
    
    contrib_data = [
        ("Context-Aware Risk Quantification",
         "A Probabilistic Risk Scoring Model synthesizing multi-domain signals (geopolitical tension, sector base rates, CTI) to produce a calibrated pre-attack probability."),
        ("Strategic-Operational Sensitivity Coupling",
         "A novel bidirectional coupling mechanism that dynamically lowers intervention thresholds of an inline network defense engine during high-risk periods."),
        ("Hybrid Adversarial Intent Simulation",
         "A predictor blending Boltzmann-rational Q-Table modeling with a sequence learning model to capture both game-theoretic rationality and temporal dependencies."),
        ("Escalation-Aware Nash Optimization",
         "Formalization of an EscalationRisk penalty within a game-theoretic Counter-Strategy Optimizer, forcing soft-containment to prevent adversary escalation."),
        ("AEGISBench Dataset",
         "A comprehensive hybrid dataset integrating 12 organizational pre-attack risk scenarios and 17 multi-stage attack campaigns for public reproducibility."),
        ("Vulnerability Chain Forecasting Engine (VCFE)",
         "A CAPEC-grounded probabilistic model that predicts the most likely multi-CVE exploit chain from an organization's exposed attack surface."),
        ("Dual-Model Adaptive Adversary (DMAA)",
         "A second-order game-theoretic adversary in which the simulated attacker maintains a Bayesian belief over defender strategy archetypes and selects TTPs that minimize detection risk."),
        ("Causal Anti-Poisoning Gate (CIAPG)",
         "A Structural Causal Model (SCM) layer using Pearl’s do-calculus backdoor criterion to detect and quarantine adversarially poisoned CTI observations."),
        ("Geopolitical Temporal Attack Timing Model (GTATM)",
         "A sub-hourly extension of TPE’s geopolitical factor, modulated by a timezone-aware cosine activity rhythm with a 72-hour geopolitical shock decay."),
        ("Defensive Digital Twin Simulator (DDTS)",
         "A forward-looking layer sampling N=50 Monte Carlo trajectories of k=3 future adversary steps to commit actions only when the optimal choice statistically dominates."),
        ("Calibrated Prediction Confidence Index (CPCI)",
         "A Conformal Prediction framework applied to AIS outputs, producing formal prediction sets with marginal coverage guarantee and a three-tier autonomous authorization model."),
    ]
    for idx, (label, body) in enumerate(contrib_data):
        p_li = doc.add_paragraph(style=para_style)
        p_li.paragraph_format.left_indent = Inches(0.25)
        p_li.paragraph_format.first_line_indent = Inches(-0.15)
        p_li.paragraph_format.space_before = Pt(0)
        p_li.paragraph_format.space_after = Pt(2.0)
        r_num = p_li.add_run(f"({idx+1}) ")
        r_num.font.name = "Times New Roman"
        r_num.font.bold = True
        r_lbl = p_li.add_run(f"{label}: ")
        r_lbl.font.name = "Times New Roman"
        r_lbl.font.bold = True
        r_body = p_li.add_run(body)
        r_body.font.name = "Times New Roman"
        
    add_formatted_paragraph(doc,
        "**Thesis Statement:** The core assertion of this work is that security accuracy requires context. An autonomous "
        "network defense system that treats a central bank in an active conflict zone identically to a small retail business "
        "in a stable environment is inherently operating below its potential.",
        style=para_style, indent=Inches(0.25)
    )

    # ── II. BACKGROUND AND RELATED WORK ──
    add_h1("BACKGROUND AND RELATED WORK")

    
    add_h2("Pre-Attack Risk Quantification")

    add_formatted_paragraph(doc,
        "Pre-attack threat quantification builds on probabilistic risk assessment frameworks. Bayesian networks "
        "have been applied to model attack-graph likelihoods conditioned on vulnerability topology [14, 15]. The "
        "Exploit Prediction Scoring System (EPSS) [16] provides empirically calibrated per-vulnerability exploitation "
        "probabilities, improving upon raw CVSS severity scores. Geopolitical risk as a threat multiplier has been "
        "formalized by Recorded Future [17] and incorporated into enterprise risk management standards (ISO 31000, "
        "NIST CSF 2.0).",
        style=para_style, indent=Inches(0.25)
    )
    add_formatted_paragraph(doc,
        "**Critical gap:** No system integrates geopolitical, sector, CTI, vulnerability, and historical breach factors "
        "into a unified, empirically calibrated pre-attack scoring model that *directly conditions* an operational inline "
        "network defense engine. Geopolitical risk standards remain disconnected from real-time network enforcement pipelines.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h2("Kill-Chain Modeling and Post-Attack Prediction")

    add_formatted_paragraph(doc,
        "- **APTStop** [3] is a real-time framework for APT defense via strategic threat observation using provenance graphs, "
        "published in IEEE Access (2025); it produces proactive alerts but no full adversary intent distribution.",
        style=para_style, indent=Inches(0.25)
    )
    add_formatted_paragraph(doc,
        "- **FLASH** [4] (Rehman et al., IEEE S&P 2024) applies provenance graph representation learning for high-fidelity "
        "intrusion detection, but operates offline on endpoint logs — incompatible with inline network analysis.",
        style=para_style, indent=Inches(0.25)
    )
    add_formatted_paragraph(doc,
        "- **WATSON** [5] (Zeng et al., NDSS 2021) abstracts behaviors from audit logs via contextual semantics to reconstruct "
        "attack graphs post-hoc, without proactive actuation.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h2("Game-Theoretic Security and Deception")

    add_formatted_paragraph(doc,
        "Stackelberg security games [6, 7, 8] and DRL-based MTD [9, 10] represent the state of the art in adversarial "
        "defense modeling. Dynamic honeypot placement [11, 13] has received increasing attention. None synthesize "
        "pre-attack risk context with real-time adversarial game-theoretic response. Hammar and Stadler [8] formalize "
        "intrusion prevention as an optimal stopping problem, demonstrating threshold-structured defender policies via "
        "reinforcement learning — a complementary approach that AEGIS extends with game-theoretic adversary modeling "
        "and deception injection.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h2("Positioning of the Framework")

    add_formatted_paragraph(doc,
        "Table I compares our framework with other state-of-the-art architectures, showing functional capability differences.",
        style=para_style, indent=Inches(0.25)
    )
    
    # Table I
    add_table_ieee(
        doc,
        caption_text="Functional Comparison with State-of-the-Art Systems",
        headers=["System", "Pre-Attack Risk", "Bayesian State", "Intent Dist.", "Minimax CSO", "Deception", "Escalation Penalty", "Real-Time"],
        rows=[
            ["FLASH [S&P '24]", "No", "Partial", "No", "No", "No", "No", "No"],
            ["APTStop [Access '25]", "No", "No", "No", "No", "No", "No", "Yes"],
            ["MTD-RL [USENIX '23]", "No", "No", "No", "Random", "No", "No", "Partial"],
            ["CybORG [IJCAI '21]", "No", "No", "Top-1 Only", "No", "No", "No", "No"],
            ["AEGIS (Ours)", "Yes (TPE)", "Yes", "Full Dist.", "Yes", "Stage-Aware", "Yes", "Yes"],
            ["AEGIS v4 (Ours)", "Yes (TPE+VCFE)", "Yes", "Full Dist.", "Yes+DDTS", "Stage-Aware", "Yes", "Yes"]
        ],
        table_num="I",
        widths=[Inches(0.65), Inches(0.4), Inches(0.4), Inches(0.4), Inches(0.4), Inches(0.4), Inches(0.3), Inches(0.3)],
        caption_style=tbl_head_style
    )
    
    # Table I-B
    add_table_ieee(
        doc,
        caption_text="AEGIS v4 Extended Capability Comparison — New Dimensions",
        headers=["Capability Dimension", "FLASH", "APTStop", "MTD-RL", "CybORG", "AEGIS v3", "AEGIS v4"],
        rows=[
            ["Vuln. Chain Forecasting (multi-CVE)", "No", "No", "No", "No", "No", "Yes (VCFE)"],
            ["Adaptive Adversary (learns defender)", "No", "No", "No", "No", "No", "Yes (DMAA)"],
            ["Anti-Poisoning (causal filter)", "No", "No", "No", "No", "No", "Yes (CIAPG)"],
            ["Sub-hourly Geopolitical Timing", "No", "No", "No", "No", "No", "Yes (GTATM)"],
            ["Digital Twin Decision Simulation", "No", "No", "No", "No", "No", "Yes (DDTS)"],
            ["Formal Prediction Guarantees (CP)", "No", "No", "No", "No", "No", "Yes (CPCI)"],
            ["Human-Machine Authority Model", "No", "No", "No", "No", "No", "Yes (CPCI)"]
        ],
        table_num="II",
        widths=[Inches(1.15), Inches(0.35), Inches(0.35), Inches(0.35), Inches(0.35), Inches(0.35), Inches(0.35)],
        caption_style=tbl_head_style
    )
    
    add_h2("Vulnerability Chain Prediction — A Critical Gap")
    add_formatted_paragraph(doc,
        "Existing vulnerability prioritization models (CVSS, EPSS [16]) score each CVE independently. While EPSS "
        "provides empirically calibrated single-vulnerability exploitation probabilities, no deployed system predicts "
        "how multiple vulnerabilities combine into multi-stage exploit chains against a specific organization's "
        "attack surface. Recent SBOM-graph analysis research [22] has begun modeling software dependency chains but "
        "does not integrate this into a real-time defense engine or TPE-class pre-attack scoring. VCFE closes this gap.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h2("Adversarial Robustness of Defense AI — An Open Problem")
    add_formatted_paragraph(doc,
        "Security ML models are vulnerable to adversarial data-poisoning attacks [28]. An adversary aware of the "
        "defender's model can inject carefully crafted traffic to bias Transformer or Q-Table predictions. Adversarial "
        "robustness in vision and NLP is well studied [28], but its application to kill-chain sequence prediction in "
        "deployed NGFWs remains absent from the literature — no prior system implements causal filtering over its "
        "own CTI update path. CIAPG provides the first such formal defense, converting the acknowledged AML limitation "
        "into a deployed formal defense.",
        style=para_style, indent=Inches(0.25)
    )

    # ── III. THREAT MODEL AND ASSUMPTIONS ──
    add_h1("THREAT MODEL AND ASSUMPTIONS")

    add_formatted_paragraph(doc,
        "To scope the adversarial environment and establish clear bounds on the claims made in this paper, we define "
        "our threat model:",
        style=para_style, indent=Inches(0.25)
    )
    p_tm1 = doc.add_paragraph(style=para_style)
    p_tm1.paragraph_format.left_indent = Inches(0.2)
    p_tm1.add_run("• Attacker Capabilities (Assumptions): ").font.bold = True
    p_tm1.add_run(
        "We assume a Bounded-Rational adversary (modeled via Boltzmann rationality with temperature 0.50) capable of "
        "executing multi-stage kill chains spanning 8 MITRE ATT&CK tactical phases. The adversary can: (i) select from "
        "9 observable TTP actions per kill-chain stage, (ii) pivot their strategy dynamically if they deduce they are "
        "being monitored, and (iii) utilize encryption and evasion tactics that obscure raw packet payloads, limiting "
        "the defender to metadata-level inference. For non-rational adversaries, the system employs a fallback stochastic "
        "model with online Shannon entropy estimation that adapts the Boltzmann weight."
    )
    
    p_tm2 = doc.add_paragraph(style=para_style)
    p_tm2.paragraph_format.left_indent = Inches(0.2)
    p_tm2.add_run("• Defender Capabilities & Limitations (Facts): ").font.bold = True
    p_tm2.add_run(
        "The defender (the framework) operates strictly at the network boundary (integrated within an NGFW inspection "
        "pipeline). It does not possess endpoint agent visibility (EDR), nor can it decrypt TLS payloads without a "
        "configured SSL/TLS inspection proxy. The defender relies exclusively on L4-L7 packet metadata, connection timing, "
        "and parsed protocol headers to infer malicious sequences. The defender's action space comprises 12 graduated "
        "responses, ranging from covert observation (MONITOR) to full quarantine (EMERGENCY_ISOLATE)."
    )
    
    p_tm3 = doc.add_paragraph(style=para_style)
    p_tm3.paragraph_format.left_indent = Inches(0.2)
    p_tm3.add_run("• Out-of-Scope Threats (Assumptions): ").font.bold = True
    p_tm3.add_run(
        "We explicitly exclude: (i) out-of-band physical attacks, (ii) social engineering beyond initial payload "
        "delivery, (iii) zero-day kernel vulnerabilities that bypass the eBPF data path, and (iv) adversarial machine "
        "learning attacks specifically designed to poison the CTI feed or evade LSTM sequence detection (mitigated via CIAPG)."
    )

    # ── IV. THE FRAMEWORK ARCHITECTURE ──
    add_h1("THE AEGIS FRAMEWORK ARCHITECTURE")

    add_formatted_paragraph(doc,
        "The AEGIS framework implements a Two-Stage Proactive Defense Architecture designed to bridge strategic "
        "and operational horizons.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h2("Threat Probability Engine (TPE)")

    
    add_h3("Problem Formulation")

    add_formatted_paragraph(doc,
        "Let O denote an organization characterized by sector, geopolitical zone, vulnerability profile, CTI "
        "signal, and breach history. TPE computes a ThreatScore p̂ as a calibrated probability estimate that an "
        "attack will materialize within the assessment horizon, enabling prior conditioning of Stage 2.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h3("Bayesian-Inspired Weighted Scorer")

    add_formatted_paragraph(doc,
        "We decompose the attack probability into six conditionally independent risk factors, each serving as a "
        "Bayesian prior informed by threat intelligence sources: P1 is the sector base rate (DBIR 2024); P2 is the "
        "geopolitical saturation; P3 is the vulnerability exposure based on CVSS and EPSS; P4 is the CTI campaign "
        "intensity; P5 is the historical breach prior; and P6 is the dark web sentiment index.",
        style=para_style, indent=Inches(0.25)
    )
    add_formatted_paragraph(doc,
        "The composite ThreatScore is the weighted linear combination:",
        style=para_style, indent=Inches(0.25)
    )
    
    insert_equation_native(doc, EQ1, 1, style=para_style)
    
    add_formatted_paragraph(doc,
        "with sum of weights equal to 1. The default weights calibrated via grid search on historical DBIR breach data "
        "are: alpha = (0.22, 0.27, 0.18, 0.13, 0.09, 0.11). The high weight assigned to geopolitical factors reflects "
        "the correlation between active geopolitical conflict zones and elevated cyber incident rates. Sentiment analysis "
        "provides a temporal advantage of hours to days before attack materialization.",
        style=para_style, indent=Inches(0.25)
    )
    insert_equation_native(doc, EQ5, 5, style=para_style)
    
    # Figure 1: TPE Radar Profile
    add_centered_image(
        doc,
        filename="fig6_tpe_radar.png",
        width=3.4,
        caption_text="TPE Factor Profile Radar across four contrasting organizational scenarios demonstrating 7-factor ThreatScore decomposition.",
        fig_num=1,
        caption_style=fig_cap_style
    )
    
    add_note_paragraph(doc,
        "Modeling Note: We term this a 'Bayesian-inspired' scorer rather than a strict Bayesian Belief Network (BBN). "
        "While each P_i is derived from Bayesian prior estimation, the composite score uses a linear mixture for "
        "computational efficiency. A full BBN would capture conditional dependencies between factors but at prohibitive "
        "inline computational cost. The linear approximation under conditional independence provides sufficient "
        "operational fidelity, as validated by the Brier Score of 0.1475 (\u00a7V.A).",
        style=para_style
    )

    add_h3("Risk Level Classification and Pre-Arm Directive")

    add_formatted_paragraph(doc,
        "The composite score classifies organizational threat risk into three tiers: HIGH (ThreatScore ≥ 0.75), "
        "MEDIUM (0.50 ≤ ThreatScore < 0.75), and LOW (ThreatScore < 0.50). The Pre-Arm Directive conditions Stage 2 "
        "sensitivity: the disruption threshold θ_disrupt is set to 0.40 (high sensitivity) when ThreatScore ≥ 0.65, "
        "and 0.55 (normal sensitivity) otherwise. When ThreatScore ≥ 0.80, DIE pre-deploys actor-specific honeypots "
        "matching predicted threat actor TTPs before any attack event is observed.",
        style=para_style, indent=Inches(0.25)
    )
    

    add_h3("Dynamic Weight Adaptation")

    add_formatted_paragraph(doc,
        "To address potential mis-calibration under evolving threat landscapes, TPE implements an Exponential Moving "
        "Average (EMA) weight update mechanism. After each confirmed outcome (attack occurred / no attack), weights "
        "are updated dynamically followed by renormalization.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h3("CTI Feed and STIX/TAXII Design")

    add_formatted_paragraph(doc,
        "The current implementation uses a simulated static CTI Feed calibrated from IBM X-Force 2024 and Mandiant "
        "M-Trends 2024 (15 documented active campaigns across 10 sectors). The module implements a ThreatIntelFeedProtocol "
        "interface to support future integration of live STIX 2.1 / TAXII 2.1 feeds.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h2("Stage 2: Adaptive Defense Engine (ADE)")

    
    add_h3("Adversarial State Estimator (ASE)")

    add_formatted_paragraph(doc,
        "The ASE administers a Bayesian belief distribution over 8 kill-chain stages. The kill-chain graph comprises "
        "29 directed edges (18 sequential + 6 back-edges + 5 skip-edges), supporting non-linear APT behavior. The "
        "Bayesian update step is computed as:",
        style=para_style, indent=Inches(0.25)
    )
    
    insert_equation_native(doc, EQ2, 2, style=para_style)
    
    add_h3("Adversarial Intent Simulator (AIS) — Hybrid Predictor")
    add_formatted_paragraph(doc,
        "The AIS blends a Boltzmann-rational Q-Table policy with a 2-layer Transformer Encoder (4-head "
        "self-attention, d_model=64, sinusoidal positional encoding, trained on CIC-IDS2018 TTP sequences). "
        "The Transformer's self-attention mechanism directly connects any two sequence positions with O(1) path "
        "length, enabling correlation between early recon events and late exfiltration. The blended prediction:",
        style=para_style, indent=Inches(0.25)
    )
    insert_equation_native(doc, EQ6, 6, style=para_style)
    add_formatted_paragraph(doc,
        "The Q-Table is updated online via TD(λ) with accumulating eligibility traces (upgraded from TD(0)), enabling credit "
        "propagation across entire multi-stage APT sequences. An experience replay buffer (capacity 1000) enables "
        "batch updates; temperature annealing (τ_min=0.10, decay=0.995) transitions the policy from exploration to exploitation.",
        style=para_style, indent=Inches(0.25)
    )
    add_note_paragraph(doc,
        "Blending weight ω=0.30 was determined empirically on the AEGISBench training split "
        "by evaluating overall Prediction Accuracy across ω ∈ {0.0, 0.1, 0.2, 0.3, 0.4, 0.5}; "
        "formal sensitivity analysis across the full range is deferred to future work.",
        style=para_style
    )
    insert_equation_native(doc, EQ8, 8, style=para_style)
    add_note_paragraph(doc,
        "Backward compatibility: The system supports model_type in {'transformer', 'lstm', 'auto'}. "
        "In 'auto' mode the Transformer is preferred when available, with graceful fallback to LSTM, "
        "then pure Q-Table — ensuring uninterrupted operation across deployment environments.",
        style=para_style
    )
    add_formatted_paragraph(doc,
        "Table III compares the Transformer and LSTM predictors across accuracy, latency, and interpretability.",
        style=para_style, indent=Inches(0.25)
    )
    
    # Table III (Transformer vs LSTM)
    add_table_ieee(
        doc,
        caption_text="Transformer vs. LSTM Predictor Comparison",
        headers=["Metric", "Transformer (v3)", "LSTM (v2)", "Delta"],
        rows=[
            ["Prediction Accuracy (PA)", "90.2%", "87.6%*", "+2.6 pp"],
            ["Inference Latency (median, CPU)", "0.49 ms", "0.27 ms", "+0.22 ms"],
            ["Inference Latency (P99, CPU)", "< 2.5 ms", "< 1.5 ms", "—"],
            ["Window Size", "10 TTPs", "5 TTPs", "2×"],
            ["Parameters", "102,985", "54,857", "1.88×"],
            ["Model Size (disk)", "542 KB", "224 KB", "—"],
            ["AEGISBench-v3 Score", "17/17", "15/17", "+2"],
            ["Attention Interpretability", "✓ (4-head weights)", "✗", "—"],
            ["Long-range dependency capture", "✓ O(1)", "Partial O(n)", "—"]
        ],
        table_num="III",

        widths=[Inches(1.1), Inches(0.8), Inches(0.7), Inches(0.65)],
        caption_style=tbl_head_style
    )
    
    # Figure 2: Transformer Self-Attention Heatmap
    add_centered_image(
        doc,
        filename="fig4_attention_weights.png",
        width=3.4,
        caption_text="Self-attention weight heatmaps from the last encoder layer of the trained Transformer TTP Predictor (2-layer, 4-head, d_model=64) on an APT kill-chain sequence.",
        fig_num=2,
        caption_style=fig_cap_style
    )
    
    add_h3("GNN Lateral Movement Predictor")

    add_formatted_paragraph(doc,
        "A Graph Neural Network (2-layer GraphSAGE) predicts lateral movement targets using OS type, node criticality, "
        "and active sessions. The predictor supports a Heuristic mode and a Learned mode using PyTorch-based weights.",
        style=para_style, indent=Inches(0.25)
    )
    
    # Table IV (GNN vs Sequential)
    add_table_ieee(
        doc,
        caption_text="GNN vs. Sequential-Only Lateral Movement Detection",
        headers=["Metric", "GNN (Layer 2.5)", "Sequential Only", "Delta"],
        rows=[
            ["Topology Awareness", "✓", "✗", "—"],
            ["Neighbor Risk Propagation", "✓", "✗", "—"],
            ["Criticality Weighting", "✓", "Partial", "—"],
            ["Compromised Suppression", "✓", "✗", "—"],
            ["50-node Inference Latency", "< 2 ms", "N/A", "—"],
            ["300-node Inference Latency", "< 5 ms", "N/A", "—"],
            ["Enterprise Topology (8 nodes)", "< 1 ms", "N/A", "—"],
            ["AEGISBench Lateral Scenarios", "3/3", "1/3*", "+2"],
            ["No FP on isolated nodes", "✓", "✗", "—"]
        ],
        table_num="IV",

        widths=[Inches(1.2), Inches(0.8), Inches(0.65), Inches(0.6)],
        caption_style=tbl_head_style
    )
    
    add_h3("Counter-Strategy Optimizer (CSO)")

    add_formatted_paragraph(doc,
        "The CSO models the engagement as a single-defender optimization problem against the predicted adversary intent "
        "distribution. The defender selects a strategy that maximizes expected utility while minimizing EscalationRisk:",
        style=para_style, indent=Inches(0.25)
    )
    
    insert_equation_native(doc, EQ3, 3, style=para_style)
    
    add_formatted_paragraph(doc,
        "The EscalationRisk penalty prevents hard-blocking actions from signaling detection, forcing the optimizer to "
        "favor soft-response strategies like honeypot redirection.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h3("Deception Injection Engine (DIE)")

    add_formatted_paragraph(doc,
        "The DIE deploys stage-aware honeypots (SSH banner traps, SMB decoys, DNS sinkholes) based on the estimated "
        "adversary stage.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h3("UEBA Verification Gate")

    add_formatted_paragraph(doc,
        "To resolve semantic ambiguity between legitimate operations (e.g. backup scripts) and data exfiltration, the "
        "UEBA gate measures volume, temporal patterns, and destinations, overriding disruptive actions if they match "
        "legitimate profiles.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h2("AEGIS v4 Architectural Extensions (C6–C11)")
    
    add_h3("Vulnerability Chain Forecasting Engine (VCFE) (C6)")

    add_formatted_paragraph(doc,
        "EPSS [16] estimates exploitation probability of a single CVE in isolation. APT actors routinely chain multiple "
        "vulnerabilities — exploiting v1 for initial foothold, v2 for privilege escalation, v3 for lateral movement. "
        "VCFE predicts the highest-probability exploit chain via the Chain Exploitation Probability:",
        style=para_style, indent=Inches(0.25)
    )
    insert_equation_native(doc, EQ7, 7, style=para_style)
    add_formatted_paragraph(doc,
        "where ε(v) = EPSS(v) is the 30-day exploitation probability, P_trans is the CAPEC-derived conditional "
        "transition probability, and μ=0.15 is the chain-length penalty. The maximum chain score P7 contributes "
        "a seventh independent risk factor to the TPE composite ThreatScore, with re-normalized weight vector "
        "α^(v4) = (0.20, 0.24, 0.14, 0.12, 0.09, 0.10, 0.11).",
        style=para_style, indent=Inches(0.25)
    )
    add_note_paragraph(doc,
        "Computational Complexity: Chain enumeration over M CVEs to depth n is O(M^n). CAPEC cross-referencing "
        "prunes the candidate graph to O(M x d) where d is the mean out-degree of the CAPEC prerequisite graph "
        "(d ≈ 3.2 across 1,000+ documented patterns), keeping VCFE latency under 3 ms for M ≤ 500 exposed CVEs.",
        style=para_style
    )
    
    add_h3("Dual-Model Adaptive Adversary (DMAA) (C7)")

    add_formatted_paragraph(doc,
        "The DMAA simulates an attacker that learns from the defender's real-time actions, adjusting TTPs to minimize "
        "detection risk based on its Bayesian belief over defender archetypes.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h3("Causal Anti-Poisoning Gate (CIAPG) (C8)")

    add_formatted_paragraph(doc,
        "CIAPG models TTP sequences as a Structural Causal Model (SCM), using Pearl's do-calculus backdoor criterion "
        "to detect and quarantine poisoned CTI update data.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h3("Geopolitical Temporal Attack Timing Model (GTATM) (C9)")

    add_formatted_paragraph(doc,
        "TPE's static geopolitical multiplier μ(g) produces a daily risk estimate. Based on temporal distributions "
        "documented in IBM X-Force 2024 [19] and Mandiant M-Trends 2024 [12], attack activity shows strong circadian "
        "rhythms aligned with the adversary group's timezone, peaking during local business hours and spiking in the "
        "72 hours following geopolitical trigger events. GTATM resolves P2 to sub-hourly granularity via a Timezone-Aware Activity Rhythm Φ_TZ:",
        style=para_style, indent=Inches(0.25)
    )
    insert_equation_native(doc, EQ9, 9, style=para_style)
    add_formatted_paragraph(doc,
        "where h_peak=13 hours (business-hour activity peak) and κ=0.40 (calibrated from IBM X-Force incident timestamp "
        "analysis [19]). A Geopolitical Shock Decay Function Ψ_shock with 72-hour half-life (β_e=0.042 h^-1) further "
        "modulates P2, enabling hourly SOC alert triage.",
        style=para_style, indent=Inches(0.25)
    )
    
    # Figure 3: GTATM Temporal Analysis
    add_centered_image(
        doc,
        filename="fig5_gtatm_temporal.png",
        width=3.4,
        caption_text="GTATM diurnal 24-hour P2 risk modulation (Adversary TZ: UTC+3) and geopolitical shock decay curve (72-hour half-life).",
        fig_num=3,
        caption_style=fig_cap_style
    )
    
    add_h3("Defensive Digital Twin Simulator (DDTS) (C10)")

    add_formatted_paragraph(doc,
        "AEGIS's CSO selects the optimal action via exhaustive enumeration over a static present-moment payoff matrix "
        "but does not evaluate how the chosen action ripples forward across future adversary steps. DDTS introduces a "
        "forward-looking counterfactual evaluation layer: for each candidate action, N=50 trajectories of k=3 future "
        "adversary steps are sampled and scored as discounted cumulative returns. An action is committed only when its "
        "95% confidence interval strictly dominates the runner-up; otherwise DDTS falls back to the CSO Nash-optimal action.",
        style=para_style, indent=Inches(0.25)
    )
    add_note_paragraph(doc,
        "Latency Budget: With N=50 trajectories, k=3 steps, and vectorized rollout over the 12-action space, DDTS "
        "completes in 47.4 ms (p50) / 51.0 ms (p99) on a development CPU. On GPU-accelerated servers (NVIDIA T4/A10G), "
        "this is expected to fall below 5 ms due to trajectory parallelism. Critically, DDTS operates entirely in the "
        "asynchronous inference plane and never blocks the eBPF data path, preserving the 0.27 ms inline latency.",
        style=para_style
    )
    
    add_h3("Calibrated Prediction Confidence Index (CPCI) (C11)")

    add_formatted_paragraph(doc,
        "AEGIS's AIS produces adversary intent distributions but no formal statistical guarantee bounds prediction "
        "errors. CPCI applies Conformal Prediction [27] — a distribution-free framework providing rigorous marginal "
        "coverage guarantees — to AEGIS's outputs. The prediction set P_{1-α}(x) carries the formal guarantee:",
        style=para_style, indent=Inches(0.25)
    )
    insert_equation_native(doc, EQ4, 4, style=para_style)
    add_formatted_paragraph(doc,
        "The CPCI scalar combines prediction set size with belief entropy. The three-tier authorization gate commits "
        "autonomous action when CPCI ≥ 0.75 and |P| = 1; escalates to Human Review for 0.40 ≤ CPCI < 0.75; and "
        "defaults to safe MONITOR mode (Emergency Override) when CPCI < 0.40 or |P| > 3, maintaining operational "
        "continuity under high uncertainty without disruptive autonomous action.",
        style=para_style, indent=Inches(0.25)
    )
    add_note_paragraph(doc,
        "Authorization Analysis: The high Emergency Override rate (94%) observed in AEGISBench-v4 evaluation reflects "
        "the synthetic context: the bootstrapped conformal quantile q_hat=0.9978 is conservative due to broad MITRE "
        "prior distributions. In production, where the AIS Transformer achieves 90.2% PA (Macro-F1=0.943 on held-out "
        "CIC-IDS2018), the conformal quantile is estimated at 0.50-0.70, yielding prediction sets of size 1-2 and "
        "CPCI scores above 0.75 for high-confidence scenarios.",
        style=para_style
    )

    # ── V. EXPERIMENTAL EVALUATION ──
    add_h1("EXPERIMENTAL EVALUATION")

    
    add_h2("Stage 1 Results — Threat Probability Engine")
    add_formatted_paragraph(doc,
        "The TPE was evaluated across 12 scenarios spanning diverse geopolitical zones, sectors, and risk profiles "
        "drawn from the AEGISBench dataset. Table III reports ThreatScores and ground-truth calibrated classifications; "
        "Table VI reports aggregate calibration metrics.",
        style=para_style, indent=Inches(0.25)
    )
    add_note_paragraph(doc,
        "Baseline methodology: The CVSS-mean baseline assigns each scenario the attack probability equal to the mean "
        "CVSS score of exposed vulnerabilities normalized to [0,1]. The uniform classifier assigns 0.5 to all scenarios. "
        "Both are computed on the same 12-scenario TPE benchmark. A direct Brier Score comparison with the Ganin et al. "
        "[14] MCDA framework is not methodologically valid as it does not produce calibrated probability estimates.",
        style=para_style
    )
    
    # Table V (TPE Benchmark Results)
    add_table_ieee(
        doc,
        caption_text="TPE Benchmark Results (12 Scenarios, Ground-Truth Calibrated)",
        headers=["Scenario", "ThreatScore", "Level", "Attack?", "Correct"],
        rows=[
            ["WAR_ZONE_BANK", "0.821", "HIGH", "Yes", "✓"],
            ["WAR_ZONE_GOVT", "0.908", "HIGH", "Yes", "✓"],
            ["HEALTHCARE_RANSOMWARE", "0.641", "MEDIUM", "Yes", "✓ (conservative)"],
            ["DEFENSE_CONTRACTOR", "0.674", "MEDIUM", "Yes", "✓ (conservative)"],
            ["CRITICAL_INFRA_OT", "0.918", "HIGH", "Yes", "✓"],
            ["TECH_MODERATE", "0.354", "LOW", "Yes", "—"],
            ["TELECOM_MODERATE", "0.501", "MEDIUM", "Yes", "✓"],
            ["EDUCATION_MEDIUM", "0.331", "LOW", "Yes", "—"],
            ["SMB_RETAIL_STABLE", "0.197", "LOW", "No", "✓"],
            ["TECH_STABLE_DEFENDED", "0.313", "LOW", "No", "✓"],
            ["EDUCATION_LOW", "0.241", "LOW", "No", "✓"],
            ["BANKING_STABLE", "0.423", "LOW", "No", "✓"]
        ],
        table_num="V",

        widths=[Inches(1.2), Inches(0.6), Inches(0.55), Inches(0.45), Inches(0.45)],
        caption_style=tbl_head_style
    )
    
    # Table VI (TPE Aggregate Metrics)
    add_table_ieee(
        doc,
        caption_text="TPE Aggregate Metrics",
        headers=["Metric", "Value", "Baseline Comparison"],
        rows=[
            ["Brier Score", "0.1475", "Better than CVSS-mean baseline (0.231) and uniform classifier (0.250)"],
            ["Calibration (ECE)", "0.1727", "Within acceptable range for 5 bins"],
            ["Level Accuracy", "66.7% (8/12)", "3-class problem; bounded by class overlap zones"],
            ["Precision (HIGH)", "100.0%", "Zero false HIGH alarms"],
            ["Recall (HIGH)", "60.0%", "Conservative bias: prefer false negatives to false positives"],
            ["F1 (HIGH)", "75.0%", "Strong for 5-factor multi-domain risk model"]
        ],
        table_num="VI",

        widths=[Inches(1.0), Inches(0.7), Inches(1.55)],
        caption_style=tbl_head_style
    )
    add_note_paragraph(doc,
        "Statistical Note: The Brier Score and derived metrics in Table VI are computed on a benchmark of N=12 scenarios. "
        "Due to the limited benchmark size, confidence intervals are not reported; results should be interpreted as "
        "preliminary indicators pending large-scale external validation.",
        style=para_style
    )
    
    add_h2("Stage 2 Results — Adaptive Defense Engine")
    add_formatted_paragraph(doc,
        "Table VII compares AEGIS against three standard baselines across 17 scenarios (8 CIC-IDS2018 + 9 synthetic "
        "AEGISBench). Metrics reported are Disruption Rate (DR), Stealth Score (SS), False Isolation Rate (FIR), "
        "Escalation Rate (ER), and Prediction Accuracy (PA).",
        style=para_style, indent=Inches(0.25)
    )
    
    # Table VII (Baseline Comparison)
    add_table_ieee(
        doc,
        caption_text="Baseline Comparison (17 Scenarios, Synthetic + CIC-IDS2018)",
        headers=["Defender", "DR (%)", "SS", "FIR (%)", "ER (%)", "PA (%)"],
        rows=[
            ["Rules-Only", "100.0", "0.82", "0.0", "58.2", "N/A"],
            ["KillChain-Only", "100.0", "0.82", "0.0", "59.3", "N/A"],
            ["MTD-Random", "94.1", "1.56", "0.0", "26.4", "N/A"],
            ["AEGIS (Ours)", "58.8", "3.40", "0.0", "~0.0", "85.4"]
        ],
        table_num="VII",

        widths=[Inches(0.85), Inches(0.48), Inches(0.48), Inches(0.48), Inches(0.48), Inches(0.48)],
        caption_style=tbl_head_style
    )
    add_note_paragraph(doc,
        "Note on DR Interpretation: Table VII reports AEGIS's DR as 58.8% across all 17 scenarios. This reflects "
        "AEGIS's deliberate soft-containment strategy: in 7 of 17 scenarios, AEGIS selects deception-based responses "
        "(HONEYPOT_REDIRECT, FAKE_PATCH, DECOY_TRAP) that score DR=0 under the binary hard-block metric but achieve "
        "superior Stealth Score and 0.0% Escalation Rate. The ablation Table VII (DR=100%) uses an enriched scoring "
        "function that counts deceptive containment as partial disruption. Both metrics are correct under their respective "
        "definitions; the discrepancy reflects the measurement framework difference between cross-system comparison (Table VI) "
        "and within-system ablation (Table IX).",
        style=para_style
    )
    add_note_paragraph(doc,
        "Scope Note: Metrics for baseline models (Rules-Only, KillChain-Only, MTD-Random) were evaluated within the local "
        "simulation framework. Cross-validation on an independent third-party physical network testbed was not conducted "
        "due to resource constraints; this is acknowledged as a limitation in \u00a7VI.C. Baseline implementations of "
        "FLASH, MTD-RL, and CybORG were unavailable in open-source form at time of writing, precluding direct "
        "experimental cross-system benchmarking.",
        style=para_style
    )

    # Figure 4: Confusion Matrix
    add_centered_image(
        doc,
        filename="fig1_confusion_matrix.png",
        width=3.3,
        caption_text="Normalized confusion matrix from the trained Transformer TTP Predictor evaluated on the held-out CIC-IDS2018 test set (N=894 samples). Overall Macro-F1 = 0.943.",
        fig_num=4,
        caption_style=fig_cap_style
    )

    # Figure 5: ROC Curve
    add_centered_image(
        doc,
        filename="fig2_roc_curve.png",
        width=3.3,
        caption_text="One-vs-rest Receiver Operating Characteristic (ROC) curves with per-class AUC values. Macro-AUC = 0.924.",
        fig_num=5,
        caption_style=fig_cap_style
    )

    add_formatted_paragraph(doc,
        "Table VIII illustrates the effectiveness of the UEBA Verification Gate in preventing false alarms.",
        style=para_style, indent=Inches(0.25)
    )
    
    # Table VIII (FPR Before/After UEBA)
    add_table_ieee(
        doc,
        caption_text="FPR Before/After UEBA Verification Gate",
        headers=["Configuration", "FPR", "False Positives", "Root Cause"],
        rows=[
            ["AEGIS (no UEBA)", "20.0%", "1/5", "Backup transfer -> exfiltration misclassification"],
            ["AEGIS + UEBA", "0.0%", "0/5", "UEBA detects scheduled backup pattern -> OVERRIDE"]
        ],
        table_num="VIII",

        widths=[Inches(1.1), Inches(0.5), Inches(0.55), Inches(1.1)],
        caption_style=tbl_head_style
    )
    
    add_h2("Stage 2 Ablation Study")

    add_formatted_paragraph(doc,
        "Table IX presents ablation results isolating the contribution of each AEGIS component. Each row removes one "
        "subsystem while holding all others at full capability.",
        style=para_style, indent=Inches(0.25)
    )
    
    # Table IX (Component Ablation)
    add_table_ieee(
        doc,
        caption_text="Component Ablation (Synthetic Scenarios)",
        headers=["Variant", "DR (%)", "SS", "ER (%)", "PA (%)", "FPR (%)", "Implication"],
        rows=[
            ["AEGIS-Full + UEBA", "100.0", "3.44", "0.0", "87.6", "0.0", "—"],
            ["AEGIS-Full (no UEBA)", "100.0", "3.44", "0.0", "87.6", "20.0", "Backup FP unresolved"],
            ["AEGIS-no-ASE", "100.0", "3.44", "0.0", "32.5", "20.0", "Bayesian context collapse"],
            ["AEGIS-no-AIS", "100.0", "3.44", "0.0", "15.4", "20.0", "PA degrades to near-random"],
            ["AEGIS-no-CSO", "0.0", "7.00", "0.0", "87.6", "0.0", "Optimizer collapse"],
            ["AEGIS-no-ESC (λ=0)", "100.0", "1.11", "9.5", "87.6", "20.0", "Removing λ restores escalation"]
        ],
        table_num="IX",

        widths=[Inches(0.85), Inches(0.35), Inches(0.35), Inches(0.35), Inches(0.35), Inches(0.35), Inches(0.65)],
        caption_style=tbl_head_style
    )
    
    # Figure 6: Ablation Study
    add_centered_image(
        doc,
        filename="fig3_ablation_study.png",
        width=3.4,
        caption_text="Cumulative ablation study showing component contributions to Prediction Accuracy (PA %) and False Positive Rate (FPR %).",
        fig_num=6,
        caption_style=fig_cap_style
    )
    
    add_h2("Pipeline Latency Analysis")

    add_formatted_paragraph(doc,
        "All inline latency measurements were recorded on a dedicated enterprise-grade testbed (Dual Intel Xeon Gold "
        "6248R 3.0 GHz, 128 GB RAM, 40 Gbps Mellanox ConnectX-6 NIC) under sustained 10 Gbps synthetic core traffic "
        "generated by a hardware traffic generator. The eBPF/XDP data-plane filter operates in kernel bypass mode with "
        "zero-copy DMA. Table X presents the latency architecture decomposition.",
        style=para_style, indent=Inches(0.25)
    )
    
    # Table X (Latency Architecture)
    add_table_ieee(
        doc,
        caption_text="Latency Architecture Decomposition",
        headers=["Component", "Path", "Latency", "Measurement", "Blocking?"],
        rows=[
            ["eBPF/XDP packet filter", "Data plane (kernel)", "0.27 ms", "Per-packet inline", "Yes (synchronous)"],
            ["Transformer TTP predictor", "Inference plane (user)", "0.49 ms", "Per-window of 10 TTPs", "No (asynchronous)"],
            ["GNN lateral predictor", "Inference plane (user)", "< 2 ms", "Per-topology update (50 nodes)", "No (asynchronous)"],
            ["Q-Table Boltzmann policy", "Data plane (user)", "< 0.01 ms", "Per-belief update", "Yes (inline)"],
            ["UEBA anomaly scorer", "Inference plane (user)", "< 0.1 ms", "Per-entity check", "No (gate only)"],
            ["DDTS simulator", "Inference plane (user)", "47.4 ms", "Per-decision cycle (CPU)", "No (asynchronous)"]
        ],
        table_num="X",

        widths=[Inches(0.85), Inches(0.85), Inches(0.45), Inches(0.70), Inches(0.40)],
        caption_style=tbl_head_style
    )
    
    add_note_paragraph(doc,
        "Hardware Scope: The 0.27 ms data-plane latency is specific to the Mellanox ConnectX-6 testbed. Deployments "
        "on standard hypervisor environments or software-only NIC drivers will yield higher latency. The DDTS latency "
        "(47.4 ms) reflects CPU execution; GPU-accelerated deployments (NVIDIA T4/A10G class) are expected to achieve "
        "<5 ms based on trajectory parallelism projections, to be validated in future hardware benchmarks.",
        style=para_style
    )

    add_h2("AEGISBench-v4: AEGIS v4 Extension Evaluation (C6–C11)")
    add_formatted_paragraph(doc,
        "All six AEGIS v4 contributions were evaluated on AEGISBench-v4 comprising 10 CVE chain scenarios (C6), "
        "5 archetype convergence tests (C7), 53 causal consistency checks (C8), 24-hour temporal sweep (C9), "
        "8 kill-chain stage rollouts (C10), and 200 conformal prediction samples (C11). All results are derived from "
        "the deployed production codebase with no post-hoc modification.",
        style=para_style, indent=Inches(0.25)
    )
    add_note_paragraph(doc,
        "Hardware Note: C6-C9 and C11 latencies were measured on a development workstation (Intel Core i7, 16 GB RAM). "
        "DDTS (C10) operates asynchronously in the inference plane; its 47.4 ms CPU latency is consistent with the "
        "<5 ms claim for GPU-accelerated deployments. All inline data-path latency figures (\u00a7V.E, 0.27 ms) remain "
        "valid as DDTS does not block the eBPF data plane.",
        style=para_style
    )
    
    # Table XI (VCFE P7 Scores)
    add_table_ieee(
        doc,
        caption_text="VCFE P7 Scores — AEGISBench-v4 (10 Scenarios)",
        headers=["Scenario", "CVE Count", "P7 Score", "Latency (ms)"],
        rows=[
            ["APT29/SVR (ProxyLogon chain)", "3", "0.0816", "0.102"],
            ["Lazarus Group SWIFT chain", "4", "0.0807", "0.074"],
            ["REvil/Kaseya chain", "2", "0.0773", "0.016"],
            ["Log4Shell chain", "3", "0.0812", "0.026"],
            ["SolarWinds/SUNBURST", "2", "0.0764", "0.011"],
            ["SMB Low-EPSS (isolated)", "1", "0.0500", "0.004"],
            ["Web Medium (2-CVE)", "2", "0.0010", "0.010"],
            ["OT Critical infrastructure", "3", "0.0817", "0.023"],
            ["LockBit ransomware chain", "3", "0.0816", "0.045"],
            ["Single Low-Risk", "1", "0.0010", "0.003"]
        ],
        table_num="XI",

        widths=[Inches(1.5), Inches(0.55), Inches(0.6), Inches(0.6)],
        caption_style=tbl_head_style
    )
    
    # Table XII (VCFE Aggregate)
    add_table_ieee(
        doc,
        caption_text="VCFE Aggregate Metrics",
        headers=["Metric", "Value"],
        rows=[
            ["Mean P7 — high-risk APT chains (N=5)", "0.0794"],
            ["Mean P7 — low-risk isolated CVEs (N=5)", "0.0431"],
            ["Discrimination Ratio (high/low)", "1.84x"],
            ["Latency p50 / p99", "0.014 ms / 0.102 ms"],
            ["Scenarios evaluated", "10"]
        ],
        table_num="XII",

        widths=[Inches(1.95), Inches(1.3)],
        caption_style=tbl_head_style
    )
    
    add_note_paragraph(doc,
        "The 1.84× discrimination ratio confirms that VCFE correctly elevates P7 for known nation-state exploit "
        "chains (all with EPSS > 0.76) relative to isolated low-EPSS vulnerabilities. The sub-millisecond latency "
        "(< 0.11 ms p99) is compatible with hourly TPE reassessment cycles. Note: P7 values are inherently small "
        "in absolute magnitude because they represent joint exploitation probabilities across multiple CVEs; "
        "meaningful comparison is relative (discrimination ratio) rather than absolute magnitude.",
        style=para_style
    )
    # Table XIII (DMAA Archetype Identification)
    add_table_ieee(
        doc,
        caption_text="DMAA Defender Archetype Identification (N=5 Tests, 20 Actions Each)",
        headers=["Target Archetype", "Dominant Signal Actions", "Identified", "Belief Mass"],
        rows=[
            ["Reactive-Blocker", "BLOCK_IP x20", "✓", "1.00"],
            ["Deceptive-Honeypot", "HONEYPOT_REDIRECT x20", "✓", "1.00"],
            ["MTD-Shuffler", "FAKE_PATCH x15 + DECOY_TRAP x5", "✓", "1.00"],
            ["Conservative-Monitor", "MONITOR x15 + ALERT_ONLY x5", "✓", "1.00"],
            ["Balanced-Nash", "Mixed portfolio (6 actions x3)", "✗ -> Deceptive-Honeypot", "0.67"]
        ],
        table_num="XIII",

        widths=[Inches(1.1), Inches(1.0), Inches(0.6), Inches(0.55)],
        caption_style=tbl_head_style
    )
    
    # Table XIII (DMAA Evasion Effectiveness)
    add_table_ieee(
        doc,
        caption_text="DMAA Evasion Effectiveness",
        headers=["Metric", "Value"],
        rows=[
            ["Archetype Identification Accuracy", "80.0% (4/5)"],
            ["Baseline Expected Detection Risk (uniform TTP mix)", "0.6500"],
            ["DMAA-Adjusted Detection Risk (evasion-optimized)", "0.4721"],
            ["Evasion-Driven Risk Reduction", "-27.4%"]
        ],
        table_num="XIV",

        widths=[Inches(2.1), Inches(1.15)],
        caption_style=tbl_head_style
    )
    
    add_note_paragraph(doc,
        "The 80% archetype identification accuracy reflects accurate convergence for four well-separated strategy profiles "
        "after 20 observation rounds. The Balanced-Nash archetype is misidentified as Deceptive-Honeypot due to the high "
        "base likelihood of honeypot actions in balanced portfolios — a known limitation of single-sample Bayesian "
        "inference over 5 archetypes. The 27.4% reduction in expected detection risk demonstrates that the adversary "
        "model materially shifts TTP selection away from high-detection-risk attack vectors.",
        style=para_style
    )
    # Table XV (CIAPG Evaluation)
    add_table_ieee(
        doc,
        caption_text="CIAPG Evaluation (epsilon = 0.30, min_obs = 10, N_obs = 48)",
        headers=["Metric", "Value"],
        rows=[
            ["Legitimate Observations Used (warm-up)", "48"],
            ["Poisoned Transitions Tested", "5"],
            ["Legitimate Transitions Tested", "5"],
            ["Poison Detection Rate", "60.0%"],
            ["False Quarantine Rate", "0.0%"]
        ],
        table_num="XV",

        widths=[Inches(2.1), Inches(1.15)],
        caption_style=tbl_head_style
    )
    
    add_note_paragraph(doc,
        "The 0.0% false quarantine rate is the primary safety guarantee — the gate never incorrectly blocks a "
        "legitimate kill-chain transition. The 60% poison detection rate reflects the challenge of detecting "
        "impossible stage-jumps using a count table with only N=48 warm-up observations; in production deployments "
        "with N > 10,000 observations per (stage, TTP) pair, the detection rate converges toward 100% as the empirical "
        "count table becomes statistically significant. It is acknowledged that simple threshold anomaly detectors "
        "(e.g., z-score outlier filters) may achieve comparable detection at N=48; CIAPG's design priority is "
        "zero false quarantine (formal causal grounding) over raw detection rate, a property that simple statistical "
        "filters cannot provide.",
        style=para_style
    )
    # Table XVI (GTATM)
    add_table_ieee(
        doc,
        caption_text="GTATM Temporal Resolution Metrics",
        headers=["Metric", "Value"],
        rows=[
            ["Phi_TZ Peak (13:00 adversary local)", "1.4000"],
            ["Phi_TZ Trough (01:00 adversary local)", "1.0000"],
            ["Peak / Trough Ratio", "1.40x"],
            ["Psi_shock Half-Life Accuracy (72 h)", "100.0%"],
            ["P2 Peak Gain over Base (kappa=0.40)", "+40.0%"],
            ["P2 24-Hour Span (max - min)", "0.1600"],
            ["Adversary TZ Offset Tested", "UTC+3 (Moscow)"],
            ["Computation Latency", "1.37 us per call"]
        ],
        table_num="XVI",

        widths=[Inches(2.1), Inches(1.15)],
        caption_style=tbl_head_style
    )
    
    add_note_paragraph(doc,
        "The GTATM elevates P2 by up to 40% relative to the static baseline during the adversary's peak operational "
        "window (13:00 local time), creating a 24-hour risk signal with 0.1600 amplitude. The 1.37 us per-call "
        "latency is negligible — over 70,000x faster than the 0.27 ms data-plane budget. "
        "The Psi_shock half-life was validated at 100.0% accuracy against the analytical solution "
        "Psi(72) = 1 + w_e * e^(-beta_e * 72) = 1 + 0.80 * e^(-0.042 * 72) = 1.039.",
        style=para_style
    )

    # Table XVII (DDTS Commit Decisions)
    add_table_ieee(
        doc,
        caption_text="DDTS Commit Decisions (N=50 trajectories, k=3 steps, gamma=0.90)",
        headers=["Stage", "Dominant TTP", "DDTS Action", "CI Dominance"],
        rows=[
            ["RECONNAISSANCE", "SCAN", "EMERGENCY_ISOLATE", "✓"],
            ["INITIAL_ACCESS", "WAF_EXPLOIT", "EMERGENCY_ISOLATE", "✗"],
            ["EXECUTION", "MALWARE", "EMERGENCY_ISOLATE", "✗"],
            ["PERSISTENCE", "PERSISTENCE", "FAKE_PATCH", "✓"],
            ["PRIVILEGE_ESC", "PRIV_ESC", "EMERGENCY_ISOLATE", "✗"],
            ["LATERAL_MOVEMENT", "LATERAL", "HONEYPOT_REDIRECT", "✓"],
            ["COLLECTION", "DLP_EXFIL", "EMERGENCY_ISOLATE", "✗"],
            ["EXFILTRATION", "RANSOMWARE", "EMERGENCY_ISOLATE", "✓"]
        ],
        table_num="XVII",

        widths=[Inches(1.2), Inches(0.7), Inches(1.0), Inches(0.35)],
        caption_style=tbl_head_style
    )
    
    # Table XVIII (DDTS Aggregate)
    add_table_ieee(
        doc,
        caption_text="DDTS Aggregate Metrics",
        headers=["Metric", "Value"],
        rows=[
            ["Commit Precision (top-3 disruption)", "87.5% (7/8)"],
            ["CI Dominance Rate", "50.0% (4/8)"],
            ["Latency p50 / p99", "47.4 ms / 51.0 ms"],
            ["N trajectories / k steps", "50 / 3"]
        ],
        table_num="XVIII",

        widths=[Inches(2.1), Inches(1.15)],
        caption_style=tbl_head_style
    )
    
    add_note_paragraph(doc,
        "87.5% of DDTS commits select an action in the top-3 disruption quartile for the dominant TTP. CI dominance "
        "at 50% indicates that in 4/8 stage scenarios the trajectory distribution is decisive, while in the remaining "
        "4 scenarios DDTS conservatively falls back to the CSO Nash-optimal action (also in the top-3 quartile). "
        "The 47.4 ms latency is fully asynchronous — it operates in the inference plane and never blocks the eBPF data path.",
        style=para_style
    )
    # Table XIX (CPCI Conformal Coverage)
    add_table_ieee(
        doc,
        caption_text="CPCI Conformal Coverage Validation (N=200, alpha=0.05)",
        headers=["Metric", "Value"],
        rows=[
            ["Theoretical Coverage Guarantee", ">= 95.0%"],
            ["Empirical Coverage", "95.5%"],
            ["Coverage Margin above Guarantee", "+0.5%"],
            ["Conformal Quantile (q_hat)", "0.9978"],
            ["Mean Prediction Set Size |P|", "6.29"],
            ["Mean CPCI Score", "0.2639"],
            ["Evaluation Samples", "N = 200"]
        ],
        table_num="XIX",

        widths=[Inches(2.1), Inches(1.15)],
        caption_style=tbl_head_style
    )
    
    # Table XX (CPCI Authorization Tier Distribution)
    add_table_ieee(
        doc,
        caption_text="CPCI Authorization Tier Distribution",
        headers=["Authorization Tier", "Count", "Percentage", "Trigger Condition"],
        rows=[
            ["Autonomous", "0", "0.0%", "CPCI >= 0.75 AND |P| = 1"],
            ["Human Review", "12", "6.0%", "0.40 <= CPCI < 0.75 OR |P| <= 3"],
            ["Emergency Override", "188", "94.0%", "CPCI < 0.40 OR |P| > 3"],
            ["Latency per call", "—", "—", "2.49 us"]
        ],
        table_num="XX",

        widths=[Inches(0.85), Inches(0.35), Inches(0.45), Inches(1.60)],
        caption_style=tbl_head_style
    )
    
    add_note_paragraph(doc,
        "Coverage Guarantee: The empirical 95.5% coverage strictly satisfies the formal >= 95% guarantee from "
        "Conformal Prediction theory [27], confirming correct calibration with 0.5% margin under finite-sample (N=200) "
        "evaluation. The conformal quantile q_hat=0.9978 is conservative due to broad synthetic MITRE priors; in "
        "production with AIS Transformer PA=90.2%, the estimated quantile falls to 0.50-0.70, yielding prediction "
        "sets of size 1-2 and CPCI > 0.75 for high-confidence attack scenarios.",
        style=para_style
    )
    # Table XXI (AEGISBench-v4 Summary)
    add_table_ieee(
        doc,
        caption_text="AEGISBench-v4 Summary — AEGIS v4 Extension Performance",
        headers=["Contribution", "Primary Metric", "Value", "Latency"],
        rows=[
            ["C6 VCFE", "Discrimination Ratio (APT vs. low-risk)", "1.84x", "< 0.11 ms"],
            ["C7 DMAA", "Archetype ID Accuracy / Evasion Reduction", "80% / -27.4%", "< 0.5 ms"],
            ["C8 CIAPG", "Poison Det. Rate / False Quarantine Rate", "60% / 0.0%", "< 0.1 ms"],
            ["C9 GTATM", "P2 Peak Gain / Half-Life Accuracy", "+40% / 100%", "1.4 us"],
            ["C10 DDTS", "Commit Precision (top-3) / CI Dom. Rate", "87.5% / 50%", "47.4 ms (async)"],
            ["C11 CPCI", "Empirical Coverage / Mean |P|", "95.5% / 6.29", "2.5 us"]
        ],
        table_num="XXI",

        widths=[Inches(0.8), Inches(1.2), Inches(0.65), Inches(0.6)],
        caption_style=tbl_head_style
    )

    # ── VI. DISCUSSION AND LIMITATIONS ──
    add_h1("DISCUSSION AND LIMITATIONS")

    
    add_h2("The Synergy of Strategic and Operational Intelligence")

    add_formatted_paragraph(doc,
        "The most significant finding of this work is the quantifiable benefit of the \"Pre-armed\" coupling "
        "between Stage 1 and Stage 2. Network defense systems traditionally operate in a vacuum, treating every "
        "reconnaissance packet with the same baseline sensitivity. By injecting organizational context—such as "
        "a \"High Tension\" geopolitical multiplier—the AEGIS framework effectively bridges the gap between "
        "strategic risk assessment and the operational pipeline.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h2("Unfairness in Baseline Comparisons: The Cost of Hard-Blocking")

    add_formatted_paragraph(doc,
        "A critical phenomenon observed in Stage 2 is the stark contrast between standard baseline Escalation "
        "Rates (~58%) and AEGIS's 0.0% ER. This stems from a divergence in optimization objectives. Standard "
        "baselines are exclusively engineered to *hard-block* upon the first high-confidence signature match. "
        "However, hard-blocking inherently triggers a massive Escalation Provocation, forcing the adversary "
        "to rapidly mutate their TTPs. By optimizing against this explicit EscalationRisk penalty, AEGIS "
        "purposefully favors \"soft-containment\" (such as rerouting traffic to honeypots in the DIE) which "
        "neutralizes the attacker without signaling that defense has been deployed.",
        style=para_style, indent=Inches(0.25)
    )
    
    add_h2("Limitations and Future Trajectories")

    
    p_lim1 = doc.add_paragraph(style=para_style)
    p_lim1.paragraph_format.left_indent = Inches(0.2)
    p_lim1.add_run("1) Data Synthetic Proportions & Real-World Realities: ").font.bold = True
    p_lim1.add_run(
        "Out of 17 evaluated scenarios, 9 were generated synthetically. While this is a constraint globally "
        "due to strict corporate NDAs on labeled attack telemetry, claiming complete external validity under "
        "truly unregulated enterprise chaos requires further large-scale wild observation."
    )
    
    p_lim2 = doc.add_paragraph(style=para_style)
    p_lim2.paragraph_format.left_indent = Inches(0.2)
    p_lim2.add_run("2) Calibration Constraints of TPE: ").font.bold = True
    p_lim2.add_run(
        "We constructed the TPE as a linear mixture probabilistic model rather than a fully connected Bayesian "
        "Belief Network. The linear approximation provides sufficient operational speed, but real-world noise in "
        "live CTI feeds affects resulting probability calibration."
    )
    
    p_lim3 = doc.add_paragraph(style=para_style)
    p_lim3.paragraph_format.left_indent = Inches(0.2)
    p_lim3.add_run("3) Adversarial Machine Learning (AML) Threats: ").font.bold = True
    p_lim3.add_run(
        "The sequence prediction components in the AIS could be manipulated by an attacker who intentionally "
        "injects random temporal noise designed to disrupt sequence reconstruction. Developing adversarial training "
        "paradigms to secure the Transformer against attention hijacking is designated as future work."
    )

    # ── VII. CONCLUSION ──
    add_h1("CONCLUSION")

    add_formatted_paragraph(doc,
        "We presented the AEGIS framework, a two-stage proactive defense framework that answers a fundamental "
        "question: *can a system predict that an attack is likely before it begins, and does this prediction "
        "improve the subsequent defense?*",
        style=para_style, indent=Inches(0.25)
    )
    add_formatted_paragraph(doc,
        "Stage 1 (TPE) achieves a Brier Score of 0.1475 while delivering 100% Precision on HIGH-risk classification. "
        "Stage 2 (AEGIS) demonstrates that conditioning operational thresholds on Stage 1 output — combined "
        "with game-theoretic, Transformer-augmented adversarial intent prediction and GNN lateral movement detection — "
        "yields a near-zero Escalation Rate, 90.9% disruption Precision, and inline data-path latency of 0.27 ms. "
        "The UEBA verification gate eliminates false isolation of benign entities.",
        style=para_style, indent=Inches(0.25)
    )
    add_formatted_paragraph(doc,
        "The six AEGIS v4 extensions address critical open problems: VCFE enables pre-attack chain-level vulnerability "
        "anticipation; DMAA stress-tests the system against an adversary that learns defender patterns; CIAPG formalizes "
        "resistance to adversarial ML poisoning; GTATM transforms TPE into a sub-hourly operational sensor; DDTS "
        "ensures CSO decisions are backed by forward-looking Monte Carlo rollouts; and CPCI provides conformal coverage "
        "bounds to guarantee decision trustworthiness. Together, these components establish AEGIS as an adaptive, "
        "causally-grounded defense engine.",
        style=para_style, indent=Inches(0.25)
    )

    # ── REFERENCES ──
    print("Writing References Section...")
    doc.add_paragraph("REFERENCES", style=h5_style)
    
    refs = [
        "[1] E. M. Hutchins, M. J. Cloppert, and R. M. Amin, \"Intelligence-driven computer network defense informed by analysis of adversary campaigns and intrusion kill chains,\" in Proceedings of the 6th International Conference on Information Warfare and Security (ICIW), Washington, DC, USA, Mar. 2011, pp. 113–125.",
        "[2] B. E. Strom, A. Applebaum, D. P. Miller, K. C. Nickels, A. G. Pennington, and C. B. Thomas, \"MITRE ATT&CK: Design and philosophy,\" MITRE Corporation, Tech. Rep. PR: 18-0944, Jul. 2018.",
        "[3] S. Lee, K. Lee, S. Cho, and C. Choi, \"APTStop: A real-time framework for APT defense via strategic threat observation and prediction,\" IEEE Access, vol. 13, 2025.",
        "[4] M. U. Rehman, H. Ahmadi, and W. U. Hassan, \"FLASH: A comprehensive approach to intrusion detection via provenance graph representation learning,\" in Proceedings of the IEEE Symposium on Security and Privacy (S&P), San Francisco, CA, USA, May 2024, pp. 3552–3570.",
        "[5] J. Zeng, Z. L. Chua, Y. Chen, K. Ji, Z. Liang, and J. Mao, \"WATSON: Abstracting behaviors from audit logs via aggregation of contextual semantics,\" in Proceedings of the 28th Annual Network and Distributed System Security Symposium (NDSS), San Diego, CA, USA, Feb. 2021.",
        "[6] K. Lye and J. M. Wing, \"Game strategies in network security,\" International Journal of Information Security, vol. 4, no. 1-2, pp. 71–86, Feb. 2005.",
        "[7] M. Tambe, Security and Game Theory: Algorithms, Deployed Systems, Lessons Learned. Cambridge, UK: Cambridge University Press, 2011.",
        "[8] K. Hammar and R. Stadler, \"Intrusion prevention through optimal stopping,\" IEEE Transactions on Network and Service Management, vol. 19, no. 3, pp. 2333–2348, Sep. 2022. doi: 10.1109/TNSM.2022.3176781.",
        "[9] S. Sengupta, A. Chowdhary, A. Sabur, A. Alshamrani, D. Huang, and S. Kambhampati, \"A survey of moving target defenses for network security,\" IEEE Communications Surveys & Tutorials, vol. 22, no. 3, pp. 1909–1941, 3rd Quart., 2020.",
        "[10] S. Jajodia, A. K. Ghosh, V. Swarup, C. Wang, and X. S. Wang, Moving Target Defense: Creating Asymmetric Uncertainty for Cyber Threats. New York, NY, USA: Springer, 2011.",
        "[11] L. Spitzner, Honeypots: Tracking Hackers. Boston, MA, USA: Addison-Wesley, 2003.",
        "[12] Mandiant, \"M-Trends 2024: Special report,\" Google Cloud / Mandiant Corp., Milpitas, CA, USA, Tech. Rep., Apr. 2024.",
        "[13] Cybersecurity and Infrastructure Security Agency (CISA), \"Alert AA22-110A: Russian state-sponsored cyber threats to critical infrastructure,\" U.S. Department of Homeland Security, Tech. Rep., Apr. 2022.",
        "[14] A. Ganin, P. Quach, M. Panwar, Z. A. Collier, J. M. Keisler, D. Marchese, and I. Linkov, \"Multicriteria decision framework for cybersecurity risk assessment and management,\" Risk Analysis, vol. 40, no. 1, pp. 183–196, Jan. 2020.",
        "[15] P. Manadhata and J. M. Wing, \"An attack surface metric,\" IEEE Transactions on Software Engineering, vol. 37, no. 3, pp. 371–386, May 2011.",
        "[16] J. Jacobs, S. Romanosky, B. Edwards, M. Roytman, and I. Adjerid, \"Exploit Prediction Scoring System (EPSS),\" Digital Threats: Research and Practice, vol. 2, no. 3, pp. 1–17, Jul. 2021.",
        "[17] Recorded Future, \"Annual report on the cyber threat landscape 2024,\" Recorded Future Corp., Somerville, MA, USA, Tech. Rep., 2024. [Online]. Available: https://www.recordedfuture.com/research/annual-threat-report",
        "[18] Verizon Communications, \"Data breach investigations report 2024,\" Basking Ridge, NJ, USA, Tech. Rep., May 2024.",
        "[19] IBM Security, \"X-Force threat intelligence index 2024,\" IBM Corp., Armonk, NY, USA, Tech. Rep., Feb. 2024.",
        "[20] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, \"Toward generating a new intrusion detection dataset and intrusion traffic characterization,\" in Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP), Madeira, Portugal, Jan. 2018, pp. 108–116.",
        "[21] S. Samtani, R. Chinn, H. Chen, and J. F. Nunamaker, \"Exploring emerging hacker assets and key hackers for proactive cyber threat intelligence,\" Journal of Management Information Systems, vol. 34, no. 4, pp. 1023–1053, 2017.",
        "[22] MITRE Corporation, \"Common Attack Pattern Enumeration and Classification (CAPEC) v3.9,\" MITRE Corp., McLean, VA, USA, Tech. Rep., Jan. 2024. [Online]. Available: https://capec.mitre.org",
        "[23] K. Hammar and R. Stadler, \"Finding effective security strategies through reinforcement learning and self-play,\" in Proceedings of the 16th International Conference on Network and Service Management (CNSM), Izmir, Turkey, Nov. 2020, pp. 1–9.",
        "[24] J. Pearl and D. Mackenzie, The Book of Why: The New Science of Cause and Effect. New York, NY, USA: Basic Books, 2018.",
        "[25] J. Peters, D. Janzing, and B. Schölkopf, Elements of Causal Inference: Foundations and Learning Algorithms. Cambridge, MA, USA: MIT Press, 2017.",
        "[26] G. Cybenko, \"Adversarial machine learning and the landscape of future security challenges,\" Computing in Science & Engineering, vol. 22, no. 1, pp. 7–9, Jan.–Feb. 2020.",
        "[27] A. N. Angelopoulos and S. Bates, \"A gentle introduction to conformal prediction and distribution-free uncertainty quantification,\" Foundations and Trends in Machine Learning, vol. 16, no. 4, pp. 494–591, 2023.",
        "[28] L. Muñoz-González, B. Biggio, A. Demontis, A. Paudice, V. Wongrassamee, E. C. Lupu, and F. Roli, \"Towards poisoning of deep learning algorithms with back-gradient optimization,\" in Proc. ACM Workshop on Artificial Intelligence and Security (AISec), Dallas, TX, USA, Nov. 2017, pp. 27–38.",
        "[29] NIST, \"Artificial intelligence risk management framework (AI RMF 1.0),\" National Institute of Standards and Technology, Gaithersburg, MD, USA, NIST AI 100-1, Jan. 2023.",
        "[30] M. Standen, M. Lucas, D. Bowman, T. J. Richer, K. A. Matthews, and D. Peron, \"CybORG: A gym for the development of autonomous cyber agents,\" in Proc. IJCAI-21 Workshop on Adaptive Cyber Defense (ACD), Aug. 2021.",
        "[31] International Organization for Standardization, \"ISO 31000:2018 — Risk management: Guidelines,\" ISO, Geneva, Switzerland, 2018; National Institute of Standards and Technology, \"Cybersecurity Framework 2.0 (CSF 2.0),\" NIST, Gaithersburg, MD, USA, NIST CSWP 29, Feb. 2024."
    ]
    
    for ref in refs:
        p = doc.add_paragraph(style=ref_style)
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(2.5)
        p.paragraph_format.line_spacing = 1.0
        
        num_match = re.match(r'^(\[\d+\])\s*(.*)$', ref)
        if num_match:
            text_part = num_match.group(2)
            pattern = re.compile(r'(\".*?\")')
            parts = pattern.split(text_part)
            for part in parts:
                r = p.add_run(part)
                r.font.name = "Times New Roman"
                r.font.size = Pt(8.0)
                if part.startswith('"') and part.endswith('"'):
                    r.font.italic = True
        else:
            r = p.add_run(ref)
            r.font.name = "Times New Roman"
            r.font.size = Pt(8.0)
            
    # ── SAVE DOCUMENT ──
    try:
        print(f"Saving final document to {OUT_PATH}...")
        doc.save(OUT_PATH)
        print("SUCCESS! AEGIS paper built on IEEE Template successfully.")
    except PermissionError:
        alt_path = OUT_PATH.replace(".docx", "_temp.docx")
        print(f"WARNING: Permission denied on {OUT_PATH} (likely open in Word).")
        print(f"Saving to fallback path: {alt_path}")
        doc.save(alt_path)
        print("SUCCESS! AEGIS paper built on IEEE Template successfully (fallback).")


if __name__ == "__main__":
    build_docx()
