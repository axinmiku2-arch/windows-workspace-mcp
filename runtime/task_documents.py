"""Convert bounded UTF-8 text into a plain DOCX without launching any process."""
from __future__ import annotations

import hashlib
from xml.etree import ElementTree as ET
import zipfile

from task_verification import read_locked

MAX_TEXT_BYTES = 256 * 1024
MAX_LINES = 4_000
MAX_TABS = 4_096
TEXT_SUFFIXES = frozenset({".txt", ".md", ".csv"})
WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>""".encode("utf-8")
RELATIONSHIPS = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>""".encode("utf-8")


def _word(tag):
    return "{" + WORD_NS + "}" + tag


def convert(source, staged_output, checkpoint, expected_stamp):
    with read_locked(source, MAX_TEXT_BYTES, expected_stamp) as (handle, size):
        raw = handle.read(MAX_TEXT_BYTES + 1)
        if len(raw) != size:
            raise ValueError("The text source changed or exceeds the 256 KiB limit.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        raise ValueError("DOCX input must be UTF-8 text.") from None
    if any(ord(c) < 32 and c not in "\t\r\n" or c in "\ufffe\uffff" for c in text):
        raise ValueError("DOCX input contains characters that cannot be represented in XML.")
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if len(lines) > MAX_LINES:
        raise ValueError("DOCX input exceeds 4,000 lines.")
    if text.count("\t") > MAX_TABS:
        raise ValueError("DOCX input exceeds 4,096 tabs.")
    checkpoint(size, size, force=True)
    document = ET.Element(_word("document"))
    body = ET.SubElement(document, _word("body"))
    for line in lines:
        paragraph = ET.SubElement(body, _word("p"))
        run = ET.SubElement(paragraph, _word("r"))
        for index, token in enumerate(line.split("\t")):
            if index:
                ET.SubElement(run, _word("tab"))
            ET.SubElement(run, _word("t"), {XML_SPACE: "preserve"}).text = token
    xml = ET.tostring(document, encoding="utf-8", xml_declaration=True)
    with staged_output.open("x+b") as output:
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=3) as pkg:
            for name, data in (("[Content_Types].xml", CONTENT_TYPES), ("_rels/.rels", RELATIONSHIPS),
                               ("word/document.xml", xml)):
                # Omit wall-clock timestamps and incidental OS metadata from the output.
                member = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                member.create_system = 0
                pkg.writestr(member, data, zipfile.ZIP_DEFLATED, compresslevel=3)
        output.flush()
        size_out = output.tell()
        output.seek(0)
        digest = hashlib.sha256(output.read()).hexdigest()
    return {"files": 1, "size_bytes": size_out, "sha256": digest,
            "format": "docx", "paragraphs": len(lines), "source_bytes": size}
