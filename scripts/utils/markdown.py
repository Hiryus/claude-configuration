"""
Align the columns of markdown tables.
Only table blocks are touched: everything else (code fences, prose, lists) is returned byte-for-byte identical.
"""

import re
import unicodedata

DELIMITER_CELL_RE = re.compile(r"^:?-+:?$")
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
PIPE_RE = re.compile(r"(?<!\\)\|")

MIN_WIDTH = 3
WIDE_WIDTHS = ("W", "F")

LEFT = "left"
RIGHT = "right"
CENTER = "center"
NONE = "none"

# ============================================================================
# Cells
# ============================================================================

def display_width(text:str) -> int:
    """Terminal columns taken by `text` (CJK/emoji count double, combining marks zero)."""
    width = 0
    for char in text:
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in WIDE_WIDTHS else 1
    return width

def split_cells(line:str) -> list[str]:
    """Split a row on unescaped pipes (GFM: only `\\|` escapes a cell separator)."""
    stripped = line.strip()
    cells:list[str] = []
    current = ""
    index = 0
    while index < len(stripped):
        char = stripped[index]
        if char == "\\" and index + 1 < len(stripped) and stripped[index + 1] == "|":
            current += "\\|"
            index += 2
            continue
        if char == "|":
            cells.append(current)
            current = ""
        else:
            current += char
        index += 1
    cells.append(current)

    # Leading/trailing pipes are borders, not empty cells.
    if stripped.startswith("|"):
        cells.pop(0)
    if len(cells) > 1 and stripped.endswith("|") and not stripped.endswith("\\|"):
        cells.pop()
    return [cell.strip() for cell in cells]

def pad(cell:str, width:int, alignment:str) -> str:
    missing = max(0, width - display_width(cell))
    if alignment == RIGHT:
        return " " * missing + cell
    if alignment == CENTER:
        left = missing // 2
        return " " * left + cell + " " * (missing - left)
    return cell + " " * missing

# ============================================================================
# Rows
# ============================================================================

def is_delimiter_row(cells:list[str]) -> bool:
    return bool(cells) and all(DELIMITER_CELL_RE.match(cell) for cell in cells)

def alignment_of(cell:str) -> str:
    left = cell.startswith(":")
    right = cell.endswith(":")
    if left and right:
        return CENTER
    if right:
        return RIGHT
    if left:
        return LEFT
    return NONE

def render_delimiter(width:int, alignment:str) -> str:
    if alignment == CENTER:
        return ":" + "-" * (width - 2) + ":"
    if alignment == RIGHT:
        return "-" * (width - 1) + ":"
    if alignment == LEFT:
        return ":" + "-" * (width - 1)
    return "-" * width

def render_row(cells:list[str], widths:list[int], alignments:list[str], indent:str) -> str:
    rendered = [
        pad(cell, widths[index], alignments[index] if index < len(alignments) else NONE)
        for index, cell in enumerate(cells)
    ]
    return f"{indent}| " + " | ".join(rendered) + " |"

# ============================================================================
# Blocks
# ============================================================================

def is_row_candidate(line:str) -> bool:
    """A row must be unindented (4+ spaces is a code block) and hold an unescaped pipe."""
    if line.strip() == "" or line.startswith("    ") or FENCE_RE.match(line):
        return False
    return bool(PIPE_RE.search(line))

def table_end(lines:list[str], start:int) -> int:
    """Index just past the last body row of the table starting at `start`."""
    end = start + 2
    while end < len(lines) and is_row_candidate(lines[end]):
        end += 1
    return end

def table_starts_at(lines:list[str], index:int) -> bool:
    """GFM table: a header row, then a delimiter row with the same number of cells."""
    if index + 1 >= len(lines):
        return False
    if not is_row_candidate(lines[index]) or not is_row_candidate(lines[index + 1]):
        return False
    header = split_cells(lines[index])
    delimiter = split_cells(lines[index + 1])
    return is_delimiter_row(delimiter) and len(delimiter) == len(header)

def format_table(lines:list[str]) -> list[str]:
    indent = lines[0][:len(lines[0]) - len(lines[0].lstrip())]
    rows = [split_cells(line) for line in lines]
    header, delimiter, body = rows[0], rows[1], rows[2:]
    alignments = [alignment_of(cell) for cell in delimiter]

    # Short rows get padded to the header width; extra cells keep their content
    # but never widen the header (that would add a column to the table).
    body = [row + [""] * (len(header) - len(row)) for row in body]
    widths = [MIN_WIDTH] * max(len(row) for row in [header, *body])
    for row in [header, *body]:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], display_width(cell))

    return [
        render_row(header, widths, alignments, indent),
        indent + "| " + " | ".join(
            render_delimiter(widths[index], alignments[index])
            for index in range(len(delimiter))
        ) + " |",
        *(render_row(row, widths, alignments, indent) for row in body),
    ]

# ============================================================================
# Document
# ============================================================================

def align_tables(text:str) -> str:
    lines = text.split("\n")
    output:list[str] = []
    fence:str | None = None
    index = 0

    while index < len(lines):
        line = lines[index]
        marker = FENCE_RE.match(line)
        if fence is not None:
            if marker and marker.group(1)[0] == fence[0] and len(marker.group(1)) >= len(fence):
                fence = None
            output.append(line)
            index += 1
            continue
        if marker:
            fence = marker.group(1)
            output.append(line)
            index += 1
            continue
        if table_starts_at(lines, index):
            end = table_end(lines, index)
            output.extend(format_table(lines[index:end]))
            index = end
            continue
        output.append(line)
        index += 1

    return "\n".join(output)
