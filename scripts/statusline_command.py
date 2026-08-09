"""
Formatter called by claude to render the status bar with context size and usage.
Reads the status-line JSON payload from stdin and prints one line of colored text.
"""
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import SupportsFloat, SupportsInt

ESC = "\x1b"
RESET = f"{ESC}[0m"
BLUE = f"{ESC}[94m"
CYAN = f"{ESC}[96m"
GREY = f"{ESC}[38;5;240m"
GREEN = f"{ESC}[32m"
YELLOW = f"{ESC}[33m"
ORANGE = f"{ESC}[38;5;208m"
RED = f"{ESC}[31m"
PIPE = f" {BLUE}|{RESET} "


@dataclass
class Status:
    cwd:Path
    effort_level:str
    model_id:str
    model_name:str
    tokens_max:int
    tokens_used:int
    tokens_used_pct:float
    usage_long_pct:float
    usage_long_reset:float
    usage_short_pct:float
    usage_short_reset:float


def coerce_float(value:object) -> float:
    if isinstance(value, float):
        return value
    if isinstance(value, SupportsFloat):
        return float(value)
    return 0.0


def coerce_integer(value:object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, SupportsInt):
        return int(value)
    return 0


def format_count(n:int) -> str:
    if n >= 1_000_000:
        return f"{round(n / 1_000_000, 1)}M"
    if n >= 1_000:
        return f"{round(n / 1_000, 1)}k"
    return str(n)


def get_tokens_color(nb_tokens:int) -> str:
    if nb_tokens > 120_000:
        return RED
    elif nb_tokens > 100_000:
        return ORANGE
    elif nb_tokens > 75_000:
        return YELLOW
    return GREEN


def get_usage_color(pct:float) -> str:
    if pct > 80:
        return RED
    if pct > 50:
        return YELLOW
    return GREEN


def format_time_until(unix_ts:float) -> str|None:
    try:
        reset_at = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
        diff = reset_at - datetime.now(timezone.utc)
        total_minutes = diff.total_seconds() / 60
        if total_minutes <= 0:
            return None
        total_days = total_minutes / (60 * 24)
        total_hours = total_minutes / 60
        if total_days >= 2:
            return f"{round(total_days)}d"
        if total_hours >= 2:
            return f"{round(total_hours)}h"
        return f"{round(total_minutes)}m"
    except (OverflowError, OSError, ValueError):
        return None


def read_input() -> Status:
    raw = sys.stdin.readline()
    input_data = {}
    if raw:
        try:
            input_data = json.loads(raw)
        except json.JSONDecodeError:
            input_data = {}

    context_window = input_data.get("context_window") or {}
    effort = input_data.get("effort") or {}
    model = input_data.get("model") or {}
    rate_limits = input_data.get("rate_limits") or {}
    five_hour = rate_limits.get("five_hour") or {}
    seven_day = rate_limits.get("seven_day") or {}

    workspace = input_data.get("workspace") or {}
    cwd = workspace.get("current_dir") or input_data.get("cwd")

    return Status(
        cwd=Path(cwd) if cwd else Path.cwd(),
        effort_level=str(effort.get("level") or ""),
        model_id=str(model.get("id")),
        model_name=str(model.get("display_name")),
        tokens_max=coerce_integer(context_window.get("context_window_size")),
        tokens_used=coerce_integer(context_window.get("total_input_tokens")),
        tokens_used_pct=coerce_float(context_window.get("used_percentage")),
        usage_long_pct=coerce_float(seven_day.get("used_percentage")),
        usage_long_reset=coerce_float(seven_day.get("resets_at")),
        usage_short_pct=coerce_float(five_hour.get("used_percentage")),
        usage_short_reset=coerce_float(five_hour.get("resets_at")),
    )


def main():
    status = read_input()
    status_line_parts = [f"{GREY}repo:{RESET}{CYAN}{status.cwd.name}{RESET}"]

    ctx = f"{GREY}ctx:{RESET}{get_tokens_color(status.tokens_used)}{format_count(status.tokens_used)}{RESET}/{format_count(status.tokens_max)}"
    if status.tokens_used_pct > 0.0:
        ctx += f" ({get_usage_color(status.tokens_used_pct)}{round(status.tokens_used_pct)}%{RESET})"
    status_line_parts.append(ctx)

    if status.usage_short_pct > 0:
        color = get_usage_color(status.usage_short_pct)
        time = format_time_until(status.usage_short_reset)
        status_line_parts.append(f"{GREY}usage:{RESET}{color}{round(status.usage_short_pct)}%{RESET}" + (f"/{time}" if time else ""))
    if status.usage_long_pct > 0:
        color = get_usage_color(status.usage_long_pct)
        time = format_time_until(status.usage_long_reset)
        status_line_parts.append(f"{GREY}usage:{RESET}{color}{round(status.usage_long_pct)}%{RESET}" + (f"/{time}" if time else ""))

    if status.model_name:
        status_line_parts.append(f"{GREY}model:{RESET}{CYAN}{status.model_id}{RESET}")
    if status.effort_level:
        status_line_parts.append(f"{GREY}effort:{RESET}{status.effort_level}")

    sys.stdout.write(PIPE.join(status_line_parts))


if __name__ == "__main__":
    main()
