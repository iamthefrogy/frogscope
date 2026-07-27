"""Minimal XLSX writer.

An .xlsx file is a zip of XML parts. Writing the handful we need directly avoids
adding openpyxl for one feature — the project has two dependencies and this keeps
it that way. Only what a data export needs: a sheet per table, a frozen bold
header row, autofilter, and sensible column widths.
"""

from __future__ import annotations

import re
import zipfile
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

_INVALID_SHEET = re.compile(r"[\[\]:*?/\\]")
# XML 1.0 forbids most control characters outright, and a stray one makes the
# whole workbook unopenable rather than showing a single bad cell.
_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _esc(text: Any) -> str:
    return (
        _ILLEGAL.sub("", str(text))
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def _col_name(index: int) -> str:
    name = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        name = chr(65 + rem) + name
    return name


def _sheet_name(name: str, taken: set[str]) -> str:
    clean = _INVALID_SHEET.sub("-", str(name))[:31] or "Sheet"
    candidate, suffix = clean, 2
    while candidate.lower() in taken:
        candidate = f"{clean[:28]}-{suffix}"
        suffix += 1
    taken.add(candidate.lower())
    return candidate


def _cell(ref: str, value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, bool):
        return f'<c r="{ref}" t="b"><v>{1 if value else 0}</v></c>'
    if isinstance(value, (int, float)):
        return f'<c r="{ref}"><v>{value}</v></c>'
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value)
    return (f'<c r="{ref}" t="inlineStr"><is>'
            f'<t xml:space="preserve">{_esc(value)}</t></is></c>')


def _sheet_xml(columns: list[str], rows: Iterable[dict]) -> str:
    body: list[str] = []
    count = 1
    header = "".join(
        f'<c r="{_col_name(i)}1" t="inlineStr" s="1"><is><t>{_esc(c)}</t></is></c>'
        for i, c in enumerate(columns))
    body.append(f'<row r="1">{header}</row>')
    for row in rows:
        count += 1
        cells = "".join(
            _cell(f"{_col_name(i)}{count}", row.get(c))
            for i, c in enumerate(columns))
        body.append(f'<row r="{count}">{cells}</row>')

    widths = "".join(
        f'<col min="{i + 1}" max="{i + 1}" '
        f'width="{min(60, max(10, len(str(c)) + 4))}" customWidth="1"/>'
        for i, c in enumerate(columns))

    # Freeze the header and enable filtering: a 90-column export is unusable
    # without both.
    views = ('<sheetViews><sheetView workbookViewId="0">'
             '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" '
             'state="frozen"/></sheetView></sheetViews>')
    autofilter = ""
    if columns:
        last = f"{_col_name(len(columns) - 1)}{max(count, 1)}"
        autofilter = f'<autoFilter ref="A1:{last}"/>'

    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/'
        'spreadsheetml/2006/main">'
        f"{views}<cols>{widths}</cols><sheetData>{''.join(body)}</sheetData>"
        f"{autofilter}</worksheet>"
    )


_STYLES = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
    '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
    '<fills count="2"><fill><patternFill patternType="none"/></fill>'
    '<fill><patternFill patternType="gray125"/></fill></fills>'
    '<borders count="1"><border/></borders>'
    '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>'
    "</cellStyleXfs>"
    '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
    '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
    "</cellXfs></styleSheet>"
)


def write_workbook(path, sheets: list[tuple[str, list[str], Iterable[dict]]],
                   title: str = "frogscope export") -> None:
    """sheets is [(name, columns, rows)]."""
    taken: set[str] = set()
    resolved = [(_sheet_name(n, taken), c, list(r)) for n, c, r in sheets] or [
        (_sheet_name("Empty", taken), ["note"], [{"note": "no data"}])
    ]

    content_types = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
        'content-types">',
        '<Default Extension="rels" ContentType="application/'
        'vnd.openxmlformats-package.relationships+xml"/>',
        '<Default Extension="xml" ContentType="application/xml"/>',
        '<Override PartName="/xl/workbook.xml" ContentType="application/'
        'vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        '<Override PartName="/xl/styles.xml" ContentType="application/'
        'vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
        '<Override PartName="/docProps/core.xml" ContentType="application/'
        'vnd.openxmlformats-package.core-properties+xml"/>',
    ]
    for index in range(len(resolved)):
        content_types.append(
            f'<Override PartName="/xl/worksheets/sheet{index + 1}.xml" '
            f'ContentType="application/vnd.openxmlformats-officedocument.'
            f'spreadsheetml.worksheet+xml"/>')
    content_types.append("</Types>")

    workbook = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
        ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/'
        'relationships">',
        "<sheets>",
    ]
    rels = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/'
        'relationships">',
    ]
    for index, (name, _c, _r) in enumerate(resolved, start=1):
        workbook.append(f'<sheet name="{_esc(name)}" sheetId="{index}" '
                        f'r:id="rId{index}"/>')
        rels.append(f'<Relationship Id="rId{index}" Type="http://schemas.'
                    f'openxmlformats.org/officeDocument/2006/relationships/'
                    f'worksheet" Target="worksheets/sheet{index}.xml"/>')
    workbook.extend(["</sheets>", "</workbook>"])
    rels.append(f'<Relationship Id="rId{len(resolved) + 1}" Type="http://schemas.'
                f'openxmlformats.org/officeDocument/2006/relationships/styles" '
                f'Target="styles.xml"/>')
    rels.append("</Relationships>")

    stamp = datetime.now(UTC).replace(microsecond=0).isoformat()
    core = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/'
        '2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>{_esc(title)}</dc:title>"
        "<dc:creator>frogscope</dc:creator>"
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{stamp}</dcterms:created>'
        "</cp:coreProperties>"
    )

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "".join(content_types))
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
            '2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
            'officeDocument/2006/relationships/officeDocument" '
            'Target="xl/workbook.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/'
            'package/2006/relationships/metadata/core-properties" '
            'Target="docProps/core.xml"/>'
            "</Relationships>")
        zf.writestr("docProps/core.xml", core)
        zf.writestr("xl/workbook.xml", "".join(workbook))
        zf.writestr("xl/_rels/workbook.xml.rels", "".join(rels))
        zf.writestr("xl/styles.xml", _STYLES)
        for index, (_name, columns, rows) in enumerate(resolved, start=1):
            zf.writestr(f"xl/worksheets/sheet{index}.xml",
                        _sheet_xml(columns, rows))
