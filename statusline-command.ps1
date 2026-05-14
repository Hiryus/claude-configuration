$raw = [Console]::In.ReadLine()
$input_data = if ($raw) { $raw | ConvertFrom-Json -ErrorAction SilentlyContinue } else { $null }


$used_tokens = if ($input_data.context_window.total_input_tokens) { $input_data.context_window.total_input_tokens } else { 0 }
$max_tokens  = if ($input_data.context_window.context_window_size)  { $input_data.context_window.context_window_size }  else { 0 }
$used_pct    = $input_data.context_window.used_percentage

$five_pct   = $input_data.rate_limits.five_hour.used_percentage
$five_reset = $input_data.rate_limits.five_hour.resets_at
$week_pct   = $input_data.rate_limits.seven_day.used_percentage
$week_reset = $input_data.rate_limits.seven_day.resets_at

$esc    = [char]27
$reset  = "${esc}[0m"
$blue   = "${esc}[94m"
$green  = "${esc}[32m"
$yellow = "${esc}[33m"
$red    = "${esc}[31m"
$pipe   = " ${blue}|${reset} "

function Format-Tokens($n) {
    if ($n -ge 1000000) { return "$([math]::Round($n/1000000, 1))M" }
    if ($n -ge 1000)    { return "$([math]::Round($n/1000, 1))k" }
    return "$n"
}

function Get-UsageColor($pct) {
    if ($null -ne $pct -and $pct -gt 80) { return $red }
    if ($null -ne $pct -and $pct -gt 50) { return $yellow }
    return $green
}

function Format-TimeUntil($unixTs) {
    if (-not $unixTs) { return $null }
    try {
        $resetAt = [DateTimeOffset]::FromUnixTimeSeconds($unixTs)
        $diff = $resetAt - [DateTimeOffset]::UtcNow
        if ($diff.TotalMinutes -le 0) { return $null }
        if ($diff.TotalDays -ge 2)   { return "$([math]::Round($diff.TotalDays))d" }
        if ($diff.TotalHours -ge 2)  { return "$([math]::Round($diff.TotalHours))h" }
        return "$([math]::Round($diff.TotalMinutes))m"
    } catch { return $null }
}

$pctColor = if ($null -ne $used_pct -and $used_pct -gt 80) { $red }
            elseif ($null -ne $used_pct -and $used_pct -gt 50) { $yellow }
            else { $green }

$tokColor = if ($used_tokens -gt 100000) { $red }
            elseif ($used_tokens -gt 75000) { $yellow }
            else { $green }

$ctx = "${tokColor}$(Format-Tokens $used_tokens)${reset}/$(Format-Tokens $max_tokens)"
if ($null -ne $used_pct) { $ctx += " (${pctColor}$([math]::Round($used_pct))%${reset})" }

$limits = @()
if ($null -ne $five_pct) {
    $c = Get-UsageColor $five_pct
    $t = Format-TimeUntil $five_reset
    $limits += "5h:${c}$([math]::Round($five_pct))%${reset}$(if ($t) { "/$t" })"
}
if ($null -ne $week_pct) {
    $c = Get-UsageColor $week_pct
    $t = Format-TimeUntil $week_reset
    $limits += "7d:${c}$([math]::Round($week_pct))%${reset}$(if ($t) { "/$t" })"
}

$cwd = if ($input_data.workspace.current_dir) { $input_data.workspace.current_dir } elseif ($input_data.cwd) { $input_data.cwd } else { "" }
$repo = if ($cwd -match '^D:\\dev\\([^\\]+)') { $matches[1] } else { "" }

$out = if ($repo) { "repo:${blue}${repo}${reset}${pipe}ctx:${ctx}" } else { "ctx:${ctx}" }
if ($limits.Count -gt 0) { $out += $pipe + ($limits -join " ") }

Write-Host -NoNewline $out
