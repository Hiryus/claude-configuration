import json
import sys
from pathlib import Path

from utils.markdown import align_tables


def main(input_data:dict):
    if input_data.get("tool_name") not in ("Write", "Edit", "MultiEdit"):
        return

    file_path = input_data.get("tool_input", {}).get("file_path")
    if not file_path or not file_path.lower().endswith(".md", ".markdown"):
        return

    path = Path(file_path)
    if not path.is_file():
        return

    original = path.read_text(encoding="utf-8")
    formatted = align_tables(original)
    if formatted != original:
        path.write_text(formatted, encoding="utf-8")


if __name__ == "__main__":
    try:
        main(json.loads(sys.stdin.read()))
    except Exception as err:  # noqa: BLE001
        print(json.dumps({"systemMessage": f"post_markdown hook error: {err}"}))
