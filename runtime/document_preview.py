"""Read bounded PDF, DOCX, image and ZIP metadata/text without opening desktop apps."""
from __future__ import annotations

import io
import json
import re
import sys
from pathlib import Path
import warnings
import zipfile
from xml.etree import ElementTree

TEXT_LIMIT = 5500
XML_LIMIT = 1_000_000
ZIP_MEMBER_LIMIT = 32_768
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def bounded(stream, n):
    result = stream.read(n + 1)
    if len(result) > n:
        raise ValueError("Decompressed preview exceeds its safety limit; use the original-file handoff instead")
    return result


def render_pdf(raw, start, count):
    from pypdf import PdfReader
    doc = PdfReader(raw, strict=False)
    if doc.is_encrypted:
        raise ValueError("This PDF is encrypted; no password was requested or tried")
    total = len(doc.pages)
    if not total or start > total:
        raise ValueError("PDF page is outside the document")
    pages = []
    left = TEXT_LIMIT
    for p in range(start - 1, min(total, start - 1 + count)):
        value = (doc.pages[p].extract_text() or "").strip()
        pages.append({"page": p + 1, "text": value[:left], "truncated": len(value) > left})
        left -= min(left, len(value))
        if not left:
            break
    return {"type": "pdf", "pages_total": total, "raw_text_available": any(p["text"] for p in pages), "pages": pages}


def render_docx(raw):
    with zipfile.ZipFile(raw) as z:
        member = z.getinfo("word/document.xml")
        if member.file_size > XML_LIMIT:
            raise ValueError("Word XML is too large for preview; fetch the original file instead")
        with z.open(member) as f:
            xml = bounded(f, XML_LIMIT)
        if re.search(rb"<!\s*(DOCTYPE|ENTITY)", xml, flags=re.I):
            raise ValueError("XML entities are not allowed in document previews")
        if b"\x00" in xml:
            raise ValueError("Only UTF-8 Word XML is supported for previews")
        root = ElementTree.fromstring(xml.decode("utf-8-sig"))
    body = root.find(W + "body")
    if body is None:
        raise ValueError("Word document has no document body")
    lines = []
    table_count = 0
    for child in body:
        if child.tag == W + "p":
            lines.append("".join(n.text or "" for n in child.iter(W + "t")))
        elif child.tag == W + "tbl":
            table_count += 1
            for row in child.findall(W + "tr"):
                lines.append(" | ".join("".join(n.text or "" for n in cell.iter(W + "t"))
                                        for cell in row.findall(W + "tc")))
    text = "\n".join(lines).strip()
    return {"type": "docx", "text": text[:TEXT_LIMIT], "tables": table_count, "truncated": len(text) > TEXT_LIMIT}


def render_zip(raw, member):
    with zipfile.ZipFile(raw) as z:
        if not member:
            rows = [{"name": x.filename[:200], "bytes": x.file_size, "folder": x.is_dir()}
                    for x in z.infolist()[:30]]
            return {"type": "zip", "members": rows, "total_members": len(z.infolist())}
        x = z.getinfo(member)
        if x.is_dir() or x.flag_bits & 1 or x.file_size > ZIP_MEMBER_LIMIT:
            raise ValueError("ZIP member is a directory, encrypted or exceeds the preview limit")
        with z.open(x) as fp:
            text = bounded(fp, ZIP_MEMBER_LIMIT).decode("utf-8-sig")
        return {"type": "zip_member", "member": x.filename, "text": text[:TEXT_LIMIT], "truncated": len(text) > TEXT_LIMIT}


def render_image(raw):
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = 25_000_000
    warnings.simplefilter("error", Image.DecompressionBombWarning)
    with Image.open(raw) as im:
        return {"type": "image", "format": im.format, "width": im.width, "height": im.height,
                "mode": im.mode, "frames": getattr(im, "n_frames", 1),
                "note": "For visual inspection or OCR, use original-file handoff."}


def main():
    ext, start, count, member = sys.argv[1:]
    try:
        with io.BytesIO(bounded(sys.stdin.buffer, 20_000_000)) as raw:
            if ext == ".pdf":
                result = render_pdf(raw, int(start), int(count))
            elif ext == ".docx":
                result = render_docx(raw)
            elif ext == ".zip":
                result = render_zip(raw, member)
            else:
                result = render_image(raw)
    except (ValueError, FileNotFoundError) as err:
        result = {"error": str(err)[:180]}
    except (ImportError, ModuleNotFoundError):
        result = {"error": "The local preview library is not installed; use original-file handoff."}
    except Exception as err:
        result = {"error": f"Invalid, encrypted or unsupported document ({type(err).__name__}); no files extracted."}
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
