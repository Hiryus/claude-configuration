# pyright: reportMissingImports=false

import json
from pathlib import Path

from post_markdown import main
from utils.markdown import align_tables

# ============================================================================
# Helpers
# ============================================================================

def run(tmp_path:Path, content:str, name="notes.md", tool_name="Write"):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    response = main({
        "hook_event_name": "PostToolUse",
        "tool_name": tool_name,
        "tool_input": {"file_path": str(path)},
    })
    return path.read_text(encoding="utf-8"), response

# ============================================================================
# Alignment
# ============================================================================

def test_pads_cells_to_the_widest_value():
    source = "| a | long value |\n|---|---|\n| longer header | b |\n"
    assert align_tables(source) == (
        "| a             | long value |\n"
        "| ------------- | ---------- |\n"
        "| longer header | b          |\n"
    )

def test_adds_missing_border_pipes():
    assert align_tables("a | bb\n--- | ---\nccc | d\n") == (
        "| a   | bb  |\n"
        "| --- | --- |\n"
        "| ccc | d   |\n"
    )

def test_keeps_alignment_markers_and_aligns_content():
    source = "| a | b | c |\n|:--|--:|:-:|\n| xxxx | yyyy | zzzz |\n"
    assert align_tables(source) == (
        "| a    |    b |  c   |\n"
        "| :--- | ---: | :--: |\n"
        "| xxxx | yyyy | zzzz |\n"
    )

def test_pads_short_rows_and_keeps_extra_cells():
    source = "| a | b |\n| --- | --- |\n| 1 |\n| 1 | 2 | 3 |\n"
    assert align_tables(source) == (
        "| a   | b   |\n"
        "| --- | --- |\n"
        "| 1   |     |\n"
        "| 1   | 2   | 3   |\n"
    )

def test_counts_wide_characters_as_two_columns():
    source = "| 日本語 | b |\n| --- | --- |\n| x | y |\n"
    assert align_tables(source) == (
        "| 日本語 | b   |\n"
        "| ------ | --- |\n"
        "| x      | y   |\n"
    )

def test_is_idempotent():
    once = align_tables("| a | bbbb |\n|---|---|\n| cc | d |\n")
    assert align_tables(once) == once

# ============================================================================
# Non-tables
# ============================================================================

def test_leaves_inline_pipes_alone():
    # scripts/rules.md is full of shell fragments like `>|` in prose.
    source = "The `>`, `>>`, `>|` redirects count as writes.\n\nNext line.\n"
    assert align_tables(source) == source

def test_leaves_fenced_code_blocks_alone():
    source = "```\n| a | b |\n|---|---|\n| c | d |\n```\n"
    assert align_tables(source) == source

def test_leaves_indented_code_blocks_alone():
    source = "Text:\n\n    | a | b |\n    |---|---|\n"
    assert align_tables(source) == source

def test_ignores_setext_heading_under_a_line_with_a_pipe():
    source = "some | text\n-----------\n"
    assert align_tables(source) == source

def test_does_not_split_escaped_pipes():
    source = "| a | b |\n| --- | --- |\n| x \\| y | z |\n"
    assert align_tables(source) == (
        "| a      | b   |\n"
        "| ------ | --- |\n"
        "| x \\| y | z   |\n"
    )

def test_stops_the_table_at_a_blank_line():
    source = "| a | b |\n|---|---|\n| c | d |\n\n| e | f |\n"
    assert align_tables(source) == (
        "| a   | b   |\n"
        "| --- | --- |\n"
        "| c   | d   |\n"
        "\n"
        "| e | f |\n"
    )

# ============================================================================
# Hook
# ============================================================================

def test_rewrites_the_file_and_warns_the_agent(tmp_path):
    content, response = run(tmp_path, "| a | bbbb |\n|---|---|\n| cc | d |\n")
    assert content == "| a   | bbbb |\n| --- | ---- |\n| cc  | d    |\n"
    context = json.loads(response)["hookSpecificOutput"]["additionalContext"]
    assert "never align table pipes yourself" in context

def test_stays_silent_when_nothing_changes(tmp_path):
    source = "| a   | b   |\n| --- | --- |\n| c   | d   |\n"
    content, response = run(tmp_path, source)
    assert (content, response) == (source, None)

def test_ignores_non_markdown_files(tmp_path):
    source = "| a | bbbb |\n|---|---|\n"
    content, response = run(tmp_path, source, name="table.txt")
    assert (content, response) == (source, None)

def test_ignores_other_tools(tmp_path):
    source = "| a | bbbb |\n|---|---|\n"
    content, response = run(tmp_path, source, tool_name="Read")
    assert (content, response) == (source, None)

def test_ignores_missing_files():
    assert main({
        "tool_name": "Write",
        "tool_input": {"file_path": "/nowhere/missing.md"},
    }) is None
