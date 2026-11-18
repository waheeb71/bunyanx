import os, re, sys, shutil

if sys.stdout is not None:
    try: sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except: pass

from docx import Document
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.enum.section import WD_SECTION
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from lxml import etree

BASE = os.path.dirname(os.path.abspath(__file__))
IMGS = os.path.join(BASE, "evaluation", "figures")
if not os.path.exists(IMGS): IMGS = r"F:\enterprise_ngfw\modules\waf\config\evaluation\figures"

import glob as _glob
_tmpl_matches = _glob.glob(os.path.join(BASE, "Conference-template-A4*.docx"))
TEMPLATE_PATH = _tmpl_matches[0] if _tmpl_matches else os.path.join(BASE, "Conference-template-A4_??????.docx")
OUT_PATH = os.path.join(BASE, "WAF_WAAP_Academic_Paper.docx")

print("WAF paper script loaded OK")
print("IMGS:", IMGS, "exists:", os.path.exists(IMGS))
print("TEMPLATE:", TEMPLATE_PATH, "exists:", os.path.exists(TEMPLATE_PATH))
print("OUT:", OUT_PATH)
