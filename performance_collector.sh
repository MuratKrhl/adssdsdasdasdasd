#!/usr/bin/env bash

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
TIMEOUT=10
OUTPUT_FILE="performance_inventory.csv"
JSON_OUTPUT_FILE=""
OVERALL_SLOW_FILE=""
HOURLY_TREND_FILE=""
ENVIRONMENT="unknown"
MAIN_CONFIG=""
PROBE_HOST_OVERRIDE=""
PROBE_SCHEME="https"
PROBE_PORT=""
INSECURE=1
VERBOSE=0
TAIL_LINES=50000
SKIP_PROBES=0
SLOW_TOP_N=20
AWK_BIN="gawk"
GENERATED_AT=""

TMP_DIR=""
ROUTES_RAW=""
ROUTES_CATALOG=""
RUNTIME_TSV=""
PROBE_TSV=""
ROUTE_REPORT_TSV=""
OVERALL_ENDPOINT_RAW_TSV=""
OVERALL_ENDPOINT_TSV=""
HOURLY_RAW_TSV=""
HOURLY_TREND_TSV=""
RUNTIME_AWK_SCRIPT=""
CONFIG_LIST=""

declare -A HOST_TLS_VERSION_CACHE=()
declare -A HOST_CIPHER_CACHE=()

usage() {
  cat <<'EOF'
Usage:
  performance_collector.sh --config /etc/nginx/nginx.conf [options]

Options:
  --config FILE         Main nginx config file. Required.
  --env NAME            Environment label written to export. Default: unknown
  --output FILE         Final single CSV export. Default: performance_inventory.csv
  --json-output FILE    Optional JSON export file
  --overall-slow FILE   Optional overall slow endpoints CSV export
  --hourly-trend FILE   Optional hourly trend CSV export
  --slow-top N          Row count for overall slow endpoint export. Default: 20
  --probe-host HOST     Override server_name for active probes
  --scheme http|https   Probe scheme. Default: https
  --port PORT           Override probe port
  --timeout SEC         Curl/openssl timeout. Default: 10
  --tail-lines N        Analyze only the last N log lines per file. 0 means full log. Default: 50000
  --skip-probes         Disable active curl/openssl probes
  --secure              Verify TLS certificates during curl probes
  --verbose             Print progress logs
  -h, --help            Show help

Expected log fields:
  request= / status= / method= / request_time= / upstream_addr=
  Optional but recommended:
  upstream_response_time= / upstream_connect_time= / upstream_cache_status=
  body_bytes_sent= or bytes_sent= / client_ip= / ssl_protocol=

Notes:
  - This script is intentionally separate from inventory collection.
  - Its focus is runtime performance, percentiles, upstream balance and probe timing.
  - RiskScore is always included in the main CSV.
  - JSON, overall slow endpoints and hourly trends are generated when their
    corresponding output options are provided.
  - Requires: bash, gawk, sed, grep, sort, tail, tr, curl, openssl, mktemp, cp, date
  - JSON export additionally requires: python
EOF
}

log() {
  if [[ "$VERBOSE" -eq 1 ]]; then
    printf '[INFO] %s\n' "$*" >&2
  fi
}

die() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}

need_bin() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required binary: $1"
}

cleanup() {
  if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR:-}" ]]; then
    rm -rf "$TMP_DIR"
  fi
}

trap cleanup EXIT

abs_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    printf '%s\n' "$path"
    return
  fi

  local dir base
  dir="$(cd "$(dirname "$path")" && pwd -P)"
  base="$(basename "$path")"
  printf '%s/%s\n' "$dir" "$base"
}

normalize_location() {
  local path="${1-}"
  if [[ -z "$path" ]]; then
    printf '/'
    return
  fi

  if [[ "$path" != /* ]]; then
    printf '%s' "$path"
    return
  fi

  if [[ "$path" != "/" ]]; then
    path="${path%/}"
    [[ -z "$path" ]] && path="/"
  fi
  printf '%s' "$path"
}

detect_route_type() {
  local route="${1,,}"
  case "$route" in
    *auth/login/oauth*|*/oauth*|*/login*) printf 'auth' ;;
    *payment*|*fund*|*loan*|*credit*|*account*|*iban*|*transfer*) printf 'financial' ;;
    /api*|*/api/*|*/v1/*|*/v2/*|*/v3/*) printf 'api' ;;
    *dashboard*|*/ui/*|*/web/*|*/frontend/*) printf 'frontend' ;;
    @*) printf 'named' ;;
    \~*) printf 'regex' ;;
    *) printf 'spa' ;;
  esac
}

choose_probe_host() {
  local server_names="$1"
  local token

  for token in $server_names; do
    [[ -z "$token" ]] && continue
    [[ "$token" = "_" ]] && continue
    [[ "$token" = "~"* ]] && continue
    if [[ "$token" == \*.* ]]; then
      token="${token#*.}"
    fi
    if [[ -n "$token" && "$token" == *.* ]]; then
      printf '%s' "$token"
      return
    fi
  done

  for token in $server_names; do
    [[ -n "$token" && "$token" != "_" ]] || continue
    printf '%s' "$token"
    return
  done

  printf ''
}

join_url_path() {
  local left="$1"
  local right="$2"

  [[ -z "$left" ]] && left="/"
  [[ -z "$right" ]] && right="/"

  if [[ "$left" != "/" ]]; then
    left="${left%/}"
  fi
  right="${right#/}"

  if [[ "$left" = "/" ]]; then
    if [[ -z "$right" ]]; then
      printf '/'
    else
      printf '/%s' "$right"
    fi
  elif [[ -z "$right" ]]; then
    printf '%s' "$left"
  else
    printf '%s/%s' "$left" "$right"
  fi
}

extract_include_targets() {
  local file="$1"
  sed -E 's/[[:space:]]*#.*$//' "$file" | sed -nE 's/^[[:space:]]*include[[:space:]]+([^;]+);/\1/p'
}

collect_config_files() {
  local main="$1"
  local -a queue=("$main")
  local -A seen=()
  local current current_abs current_dir include pattern

  : > "$CONFIG_LIST"

  while [[ ${#queue[@]} -gt 0 ]]; do
    current="${queue[0]}"
    queue=("${queue[@]:1}")

    current_abs="$(abs_path "$current")"
    [[ -f "$current_abs" ]] || continue
    [[ -n "${seen[$current_abs]:-}" ]] && continue
    seen["$current_abs"]=1
    printf '%s\n' "$current_abs" >> "$CONFIG_LIST"

    current_dir="$(dirname "$current_abs")"
    while IFS= read -r include; do
      [[ -z "$include" ]] && continue
      if [[ "$include" != /* ]]; then
        pattern="$current_dir/$include"
      else
        pattern="$include"
      fi

      shopt -s nullglob
      for candidate in $pattern; do
        [[ -f "$candidate" ]] && queue+=("$candidate")
      done
      shopt -u nullglob
    done < <(extract_include_targets "$current_abs")
  done
}

parse_nginx_config() {
  local -a files=()
  mapfile -t files < "$CONFIG_LIST"
  [[ ${#files[@]} -gt 0 ]] || die "No nginx config files resolved from $MAIN_CONFIG"

  "$AWK_BIN" '
    function trim(s) {
      sub(/^[[:space:]]+/, "", s)
      sub(/[[:space:]]+$/, "", s)
      return s
    }

    function sanitize(s) {
      sub(/[[:space:]]*#.*/, "", s)
      return trim(s)
    }

    function emit_route(backend_host, real_backend) {
      if (loc_path == "" || loc_proxy_pass == "") {
        return
      }

      backend_host = loc_proxy_pass
      sub(/^[A-Za-z]+:\/\//, "", backend_host)
      sub(/[\/\?].*$/, "", backend_host)
      sub(/\$.*/, "", backend_host)

      real_backend = loc_real_backend
      if (real_backend == "" && backend_host in upstream_servers) {
        real_backend = upstream_servers[backend_host]
      }
      if (real_backend == "") {
        real_backend = backend_host
      }

      if (loc_access_log == "") {
        loc_access_log = server_access_log
      }
      if (loc_access_log == "") {
        loc_access_log = "-"
      }

      print route_id, FILENAME, server_names, loc_modifier, loc_path, loc_proxy_pass, real_backend, loc_access_log, backend_host
      route_id++
    }

    BEGIN {
      OFS = "\t"
      depth = 0
      route_id = 1
    }

    {
      line = sanitize($0)
      if (line == "") {
        next
      }

      work = line
      open_count = gsub(/\{/, "{", work)
      work = line
      close_count = gsub(/\}/, "}", work)

      if (match(line, /^[[:space:]]*upstream[[:space:]]+([^[:space:]{]+)[[:space:]]*\{/, m)) {
        current_upstream = m[1]
        upstream_depth = depth + 1
      } else if (current_upstream != "" && match(line, /^[[:space:]]*server[[:space:]]+([^;]+);/, m)) {
        upstream_member = trim(m[1])
        split(upstream_member, parts, /[[:space:]]+/)
        upstream_member = parts[1]
        if (upstream_servers[current_upstream] == "") {
          upstream_servers[current_upstream] = upstream_member
        } else {
          upstream_servers[current_upstream] = upstream_servers[current_upstream] "|" upstream_member
        }
      }

      if (match(line, /^[[:space:]]*server[[:space:]]*\{/, m) && loc_path == "") {
        in_server = 1
        server_depth = depth + 1
        server_names = ""
        server_access_log = ""
      }

      if (in_server && loc_path == "" && match(line, /^[[:space:]]*server_name[[:space:]]+([^;]+);/, m)) {
        server_names = trim(m[1])
      }

      if (in_server && loc_path == "" && match(line, /^[[:space:]]*access_log[[:space:]]+([^;]+);/, m)) {
        server_access_log = trim(m[1])
        split(server_access_log, access_parts, /[[:space:]]+/)
        server_access_log = access_parts[1]
        if (server_access_log == "off") {
          server_access_log = "-"
        }
      }

      if (in_server && match(line, /^[[:space:]]*location[[:space:]]+((=|\^~|~\*|~)[[:space:]]+)?([^[:space:]{]+)[[:space:]]*\{/, m)) {
        loc_modifier = trim(m[2])
        loc_path = trim(m[3])
        loc_proxy_pass = ""
        loc_real_backend = ""
        loc_access_log = ""
        loc_depth = depth + 1
      }

      if (loc_path != "" && match(line, /^[[:space:]]*proxy_pass[[:space:]]+([^;]+);/, m)) {
        loc_proxy_pass = trim(m[1])
      }

      if (loc_path != "" && match(line, /^[[:space:]]*proxy_ssl_name[[:space:]]+([^;]+);/, m)) {
        loc_real_backend = trim(m[1])
      }

      if (loc_path != "" && match(line, /^[[:space:]]*access_log[[:space:]]+([^;]+);/, m)) {
        loc_access_log = trim(m[1])
        split(loc_access_log, access_parts, /[[:space:]]+/)
        loc_access_log = access_parts[1]
        if (loc_access_log == "off") {
          loc_access_log = "-"
        }
      }

      depth += open_count - close_count

      if (loc_path != "" && depth < loc_depth) {
        emit_route()
        loc_path = ""
        loc_modifier = ""
        loc_proxy_pass = ""
        loc_real_backend = ""
        loc_access_log = ""
      }

      if (in_server && depth < server_depth) {
        in_server = 0
        server_names = ""
        server_access_log = ""
      }

      if (current_upstream != "" && depth < upstream_depth) {
        current_upstream = ""
      }
    }
  ' "${files[@]}" > "$ROUTES_RAW"
}

build_routes_catalog() {
  "$AWK_BIN" -v env_name="$ENVIRONMENT" '
    BEGIN { OFS = "\t" }
    {
      location = $5
      if (location == "" || location == "@") {
        next
      }
      print $1, env_name, $2, $3, $4, $5, $6, $7, $8, $9
    }
  ' "$ROUTES_RAW" | while IFS=$'\t' read -r route_id env_name config_file server_names modifier location backend real_backend access_log backend_host; do
    probe_host=""
    route_type=""
    normalized_location=""

    normalized_location="$(normalize_location "$location")"
    route_type="$(detect_route_type "$modifier$normalized_location")"
    probe_host="$PROBE_HOST_OVERRIDE"
    if [[ -z "$probe_host" ]]; then
      probe_host="$(choose_probe_host "$server_names")"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$route_id" \
      "$env_name" \
      "$config_file" \
      "$server_names" \
      "$modifier" \
      "$normalized_location" \
      "$route_type" \
      "$backend" \
      "$real_backend" \
      "$access_log" \
      "$backend_host" \
      "$probe_host"
  done > "$ROUTES_CATALOG"
}

create_runtime_awk_script() {
  RUNTIME_AWK_SCRIPT="$TMP_DIR/runtime_analysis.awk"
  cat > "$RUNTIME_AWK_SCRIPT" <<'EOF'
function tolower_safe(s) { return tolower(s) }

function ignore_path(path, lower) {
  lower = tolower_safe(path)
  if (lower ~ /\.(svg|png|jpe?g|gif|css|js|woff2?|map|ico|ttf|eot)(\?.*)?$/) {
    return 1
  }
  if (lower ~ /^\/(non-core-assets|locales|static|assets|rb_)(\/|$)/) {
    return 1
  }
  return 0
}

function parse_numeric(raw,    cleaned, parts, i, n, sum, count) {
  if (raw == "" || raw == "-") {
    return ""
  }
  cleaned = raw
  gsub(/,/, " ", cleaned)
  gsub(/:/, " ", cleaned)
  gsub(/;/, " ", cleaned)
  n = split(cleaned, parts, /[[:space:]]+/)
  sum = 0
  count = 0
  for (i = 1; i <= n; i++) {
    if (parts[i] ~ /^-?[0-9]+(\.[0-9]+)?$/) {
      sum += parts[i]
      count++
    }
  }
  if (count == 0) {
    return ""
  }
  return sum / count
}

function extract_hour(    ts) {
  ts = kv["timestamp"]
  if (ts == "") ts = kv["ts"]
  if (ts == "") ts = kv["time"]
  if (ts == "") ts = kv["time_local"]
  if (ts == "") ts = kv["datetime"]
  if (ts == "") return ""

  gsub(/^\[/, "", ts)
  gsub(/\]$/, "", ts)
  gsub(/"/, "", ts)

  if (ts ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}/) {
    return substr(ts, 1, 13)
  }
  if (ts ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}/) {
    gsub(/ /, "T", ts)
    return substr(ts, 1, 13)
  }
  if (ts ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}/) {
    gsub(/_/, "T", ts)
    return substr(ts, 1, 13)
  }
  return ""
}

function load_routes(    line, parts) {
  while ((getline line < route_file) > 0) {
    split(line, parts, "\t")
    route_ids[++route_count] = parts[1]
    route_values[route_count] = parts[2]
    route_lengths[route_count] = length(parts[2])
  }
  close(route_file)

  for (i = 1; i <= route_count; i++) {
    route_order[i] = i
  }
  for (i = 1; i <= route_count; i++) {
    for (j = i + 1; j <= route_count; j++) {
      if (route_lengths[route_order[j]] > route_lengths[route_order[i]]) {
        tmp = route_order[i]
        route_order[i] = route_order[j]
        route_order[j] = tmp
      }
    }
  }
}

function best_route(path,    i, idx, candidate, next_char) {
  for (i = 1; i <= route_count; i++) {
    idx = route_order[i]
    candidate = route_values[idx]
    if (candidate == "/") {
      return route_ids[idx]
    }
    if (index(path, candidate) == 1) {
      next_char = substr(path, length(candidate) + 1, 1)
      if (path == candidate || candidate ~ /\/$/ || next_char == "/" || next_char == "" || next_char == "?") {
        return route_ids[idx]
      }
    }
  }
  return ""
}

function parse_line(    n, i, item, pos, key, value) {
  delete kv
  n = split($0, items, /[[:space:]]+/)
  for (i = 1; i <= n; i++) {
    item = items[i]
    pos = index(item, "=")
    if (pos == 0) {
      continue
    }
    key = substr(item, 1, pos - 1)
    value = substr(item, pos + 1)
    gsub(/^"/, "", value)
    gsub(/"$/, "", value)
    kv[key] = value
  }
}

function top_value(prefix, route_id,    key, count, winner, best, parts) {
  winner = "-"
  best = -1
  for (key in counters) {
    split(key, parts, SUBSEP)
    if (parts[1] == prefix && parts[2] == route_id) {
      count = counters[key]
      if (count > best) {
        best = count
        winner = parts[3]
      }
    }
  }
  return winner
}

function top_upstream_share(route_id, winner, total, key) {
  winner = top_value("upstream", route_id)
  if (winner == "-" || upstream_total[route_id] == 0) {
    return "0.00"
  }
  key = "upstream" SUBSEP route_id SUBSEP winner
  total = (counters[key] / upstream_total[route_id]) * 100
  return sprintf("%.2f", total)
}

function count_unique_upstreams(route_id,    key, total, parts) {
  total = 0
  for (key in seen_upstream) {
    split(key, parts, SUBSEP)
    if (parts[1] == route_id) {
      total++
    }
  }
  return total
}

function percentile(route_id, p,    n, i, idx, values, sorted) {
  n = latency_count[route_id]
  if (n == 0) {
    return "0.0000"
  }
  delete values
  for (i = 1; i <= n; i++) {
    values[i] = latency_values[route_id, i]
  }
  asort(values, sorted)
  idx = int((p * n) + 0.999999)
  if (idx < 1) idx = 1
  if (idx > n) idx = n
  return sprintf("%.4f", sorted[idx])
}

function slowest_endpoint(route_id, mode,    key, avg, best, best_ep, parts) {
  best = -1
  best_ep = "-"
  for (key in endpoint_latency_count) {
    split(key, parts, SUBSEP)
    if (parts[1] == route_id) {
      avg = endpoint_latency_sum[key] / endpoint_latency_count[key]
      if (avg > best) {
        best = avg
        best_ep = parts[2]
      }
    }
  }
  if (mode == "name") {
    return best_ep
  }
  if (best < 0) {
    return "0.0000"
  }
  return sprintf("%.4f", best)
}

BEGIN {
  OFS = "\t"
  load_routes()
}

{
  parse_line()

  request = kv["request"]
  if (request == "") {
    next
  }

  sub(/\?.*$/, "", request)
  if (ignore_path(request)) {
    next
  }

  route_id = best_route(request)
  if (route_id == "") {
    next
  }

  status = kv["status"]
  method = kv["method"]
  upstream = kv["upstream_addr"]
  req_time = parse_numeric(kv["request_time"])
  upstream_rt = parse_numeric(kv["upstream_response_time"])
  upstream_conn = parse_numeric(kv["upstream_connect_time"])
  cache_status = toupper(kv["upstream_cache_status"])
  bytes_sent = parse_numeric(kv["body_bytes_sent"])
  if (bytes_sent == "") {
    bytes_sent = parse_numeric(kv["bytes_sent"])
  }
  client_ip = kv["client_ip"]
  tls = kv["ssl_protocol"]
  hour_bucket = extract_hour()

  counts[route_id]++
  if (status + 0 >= 400) {
    errors[route_id]++
  }

  if (req_time != "") {
    latency_sum[route_id] += req_time
    if (req_time > latency_max[route_id]) {
      latency_max[route_id] = req_time
    }
    latency_values[route_id, ++latency_count[route_id]] = req_time
    endpoint_latency_sum[route_id SUBSEP request] += req_time
    endpoint_latency_count[route_id SUBSEP request]++
    if (req_time > endpoint_latency_max[route_id SUBSEP request]) {
      endpoint_latency_max[route_id SUBSEP request] = req_time
    }
  }

  if (upstream_rt != "") {
    upstream_rt_sum[route_id] += upstream_rt
    upstream_rt_count[route_id]++
  }
  if (upstream_conn != "") {
    upstream_conn_sum[route_id] += upstream_conn
    upstream_conn_count[route_id]++
  }
  if (bytes_sent != "") {
    bytes_sum[route_id] += bytes_sent
    bytes_count[route_id]++
  }

  if (hour_bucket != "") {
    hourly_count[route_id SUBSEP hour_bucket]++
    hourly_errors[route_id SUBSEP hour_bucket] += ((status + 0) >= 400 ? 1 : 0)
    if (req_time != "") {
      hourly_latency_sum[route_id SUBSEP hour_bucket] += req_time
      hourly_latency_count[route_id SUBSEP hour_bucket]++
      if (req_time > hourly_latency_max[route_id SUBSEP hour_bucket]) {
        hourly_latency_max[route_id SUBSEP hour_bucket] = req_time
      }
    }
  }

  if (method == "") method = "-"
  if (status == "") status = "-"
  if (upstream == "") upstream = "-"
  if (client_ip == "") client_ip = "-"
  if (tls == "") tls = "-"

  counters["endpoint" SUBSEP route_id SUBSEP request]++
  counters["method" SUBSEP route_id SUBSEP method]++
  counters["status" SUBSEP route_id SUBSEP status]++
  counters["upstream" SUBSEP route_id SUBSEP upstream]++
  counters["client" SUBSEP route_id SUBSEP client_ip]++
  counters["tls" SUBSEP route_id SUBSEP tls]++

  if (upstream != "-") {
    seen_upstream[route_id SUBSEP upstream] = 1
    upstream_total[route_id]++
  }

  if (cache_status == "HIT" || cache_status == "STALE" || cache_status == "REVALIDATED") {
    cache_hit[route_id]++
    cache_total[route_id]++
  } else if (cache_status == "MISS" || cache_status == "BYPASS" || cache_status == "EXPIRED" || cache_status == "UPDATING") {
    cache_miss[route_id]++
    cache_total[route_id]++
  }
}

END {
  for (route_id in counts) {
    avg = (latency_count[route_id] == 0 ? 0 : latency_sum[route_id] / latency_count[route_id])
    err_rate = (counts[route_id] == 0 ? 0 : (errors[route_id] / counts[route_id]) * 100)
    avg_upstream_rt = (upstream_rt_count[route_id] == 0 ? 0 : upstream_rt_sum[route_id] / upstream_rt_count[route_id])
    avg_upstream_conn = (upstream_conn_count[route_id] == 0 ? 0 : upstream_conn_sum[route_id] / upstream_conn_count[route_id])
    avg_bytes = (bytes_count[route_id] == 0 ? 0 : bytes_sum[route_id] / bytes_count[route_id])
    cache_hit_ratio = (cache_total[route_id] == 0 ? 0 : (cache_hit[route_id] / cache_total[route_id]) * 100)
    cache_miss_ratio = (cache_total[route_id] == 0 ? 0 : (cache_miss[route_id] / cache_total[route_id]) * 100)

    print route_id,
          counts[route_id],
          errors[route_id] + 0,
          sprintf("%.2f", err_rate),
          sprintf("%.4f", avg),
          sprintf("%.4f", latency_max[route_id] + 0),
          percentile(route_id, 0.50),
          percentile(route_id, 0.95),
          percentile(route_id, 0.99),
          sprintf("%.4f", avg_upstream_rt),
          sprintf("%.4f", avg_upstream_conn),
          top_value("endpoint", route_id),
          top_value("method", route_id),
          top_value("status", route_id),
          top_value("upstream", route_id),
          top_upstream_share(route_id),
          count_unique_upstreams(route_id),
          slowest_endpoint(route_id, "name"),
          slowest_endpoint(route_id, "avg"),
          sprintf("%.2f", cache_hit_ratio),
          sprintf("%.2f", cache_miss_ratio),
          sprintf("%.2f", avg_bytes),
          top_value("client", route_id),
          top_value("tls", route_id) >> metrics_out
  }

  for (key in endpoint_latency_count) {
    split(key, parts, SUBSEP)
    route_id = parts[1]
    endpoint = parts[2]
    print route_id,
          endpoint,
          endpoint_latency_count[key],
          sprintf("%.8f", endpoint_latency_sum[key]),
          sprintf("%.4f", endpoint_latency_max[key] + 0) >> overall_out
  }

  for (key in hourly_count) {
    split(key, parts, SUBSEP)
    route_id = parts[1]
    hour_bucket = parts[2]
    avg_hour = (hourly_latency_count[key] == 0 ? 0 : hourly_latency_sum[key] / hourly_latency_count[key])
    print route_id,
          hour_bucket,
          hourly_count[key],
          hourly_errors[key] + 0,
          sprintf("%.8f", hourly_latency_sum[key] + 0),
          hourly_latency_count[key] + 0,
          sprintf("%.4f", avg_hour),
          sprintf("%.4f", hourly_latency_max[key] + 0) >> hourly_out
  }
}
EOF
}

analyze_single_log() {
  local log_file="$1"
  local route_subset="$2"
  local staged_log="$3"

  [[ -r "$log_file" ]] || return

  if [[ "$TAIL_LINES" -gt 0 ]]; then
    tail -n "$TAIL_LINES" "$log_file" > "$staged_log"
  else
    cp "$log_file" "$staged_log"
  fi

  "$AWK_BIN" \
    -v route_file="$route_subset" \
    -v metrics_out="$RUNTIME_TSV" \
    -v overall_out="$OVERALL_ENDPOINT_RAW_TSV" \
    -v hourly_out="$HOURLY_RAW_TSV" \
    -f "$RUNTIME_AWK_SCRIPT" \
    "$staged_log"
}

analyze_logs() {
  : > "$RUNTIME_TSV"
  : > "$OVERALL_ENDPOINT_RAW_TSV"
  : > "$HOURLY_RAW_TSV"
  local unique_logs_file route_subset log_file
  unique_logs_file="$TMP_DIR/unique_logs.txt"
  create_runtime_awk_script

  "$AWK_BIN" -F'\t' '
    $10 != "-" && $7 != "regex" && $7 != "named" && $10 !~ /\$/ && $10 !~ /^syslog:/ {
      print $10
    }
  ' "$ROUTES_CATALOG" | sort -u > "$unique_logs_file"

  while IFS= read -r log_file; do
    [[ -n "$log_file" ]] || continue
    route_subset="$TMP_DIR/$(printf '%s' "$log_file" | tr '/:' '__').routes.tsv"
    "$AWK_BIN" -F'\t' -v target="$log_file" '
      BEGIN { OFS = "\t" }
      $10 == target && $7 != "regex" && $7 != "named" { print $1, $6 }
    ' "$ROUTES_CATALOG" > "$route_subset"
    analyze_single_log "$log_file" "$route_subset" "$TMP_DIR/$(printf '%s' "$log_file" | tr '/:' '__').stage.log"
  done < "$unique_logs_file"
}

active_probe() {
  local url="$1"
  local curl_args=(-sS -o /dev/null -w '%{http_code}\t%{http_version}\t%{time_namelookup}\t%{time_connect}\t%{time_appconnect}\t%{time_starttransfer}\t%{time_total}' -m "$TIMEOUT")
  if [[ "$INSECURE" -eq 1 ]]; then
    curl_args+=(-k)
  fi
  curl "${curl_args[@]}" "$url" 2>/dev/null || printf '000\tunknown\t0\t0\t0\t0\t0'
}

get_tls_profile() {
  local host="$1"
  local port="$2"
  local cache_key="$host:$port"

  if [[ -n "${HOST_TLS_VERSION_CACHE[$cache_key]:-}" ]]; then
    printf '%s\t%s' "${HOST_TLS_VERSION_CACHE[$cache_key]}" "${HOST_CIPHER_CACHE[$cache_key]}"
    return
  fi

  local result protocol cipher
  result="$(printf '' | openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null || true)"
  protocol="$("$AWK_BIN" -F': ' '/Protocol[[:space:]]*:/ { print $2; exit }' <<<"$result")"
  cipher="$("$AWK_BIN" -F': ' '/Cipher[[:space:]]*:/ { print $2; exit }' <<<"$result")"
  [[ -z "$protocol" ]] && protocol="unknown"
  [[ -z "$cipher" ]] && cipher="unknown"
  HOST_TLS_VERSION_CACHE["$cache_key"]="$protocol"
  HOST_CIPHER_CACHE["$cache_key"]="$cipher"
  printf '%s\t%s' "$protocol" "$cipher"
}

run_active_probes() {
  : > "$PROBE_TSV"

  if [[ "$SKIP_PROBES" -eq 1 ]]; then
    return
  fi

  local route_id env_name config_file server_names modifier location route_type backend real_backend access_log backend_host probe_host
  local url probe_data tls_profile probe_code http_version dns_t connect_t tls_t ttfb_t total_t tls_version cipher

  while IFS=$'\t' read -r route_id env_name config_file server_names modifier location route_type backend real_backend access_log backend_host probe_host; do
    probe_code="000"
    http_version="unknown"
    dns_t="0"
    connect_t="0"
    tls_t="0"
    ttfb_t="0"
    total_t="0"
    tls_version="unknown"
    cipher="unknown"

    if [[ -n "$probe_host" && "$route_type" != "regex" && "$route_type" != "named" ]]; then
      url="${PROBE_SCHEME}://$probe_host"
      if [[ -n "$PROBE_PORT" ]]; then
        url="${PROBE_SCHEME}://$probe_host:$PROBE_PORT"
      fi
      url="${url}$(join_url_path "$location" "")"

      probe_data="$(active_probe "$url")"
      IFS=$'\t' read -r probe_code http_version dns_t connect_t tls_t ttfb_t total_t <<< "$probe_data"

      if [[ "$PROBE_SCHEME" == "https" ]]; then
        tls_profile="$(get_tls_profile "$probe_host" "${PROBE_PORT:-443}")"
        IFS=$'\t' read -r tls_version cipher <<< "$tls_profile"
      fi
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$route_id" \
      "$probe_code" \
      "$http_version" \
      "$dns_t" \
      "$connect_t" \
      "$tls_t" \
      "$ttfb_t" \
      "$total_t" \
      "$tls_version" \
      "$cipher" \
      >> "$PROBE_TSV"
  done < "$ROUTES_CATALOG"
}

build_route_report_tsv() {
  "$AWK_BIN" -F'\t' -v runtime_file="$RUNTIME_TSV" -v probe_file="$PROBE_TSV" '
    function append_reason(current, addition) {
      if (addition == "") {
        return current
      }
      if (current == "") {
        return addition
      }
      return current ";" addition
    }

    function risk_score(route_type, request_count, error_rate, p95, p99, avg_upstream_connect, top_upstream_share, upstream_nodes, cache_miss_ratio, probe_total, top_status, probe_code,    score, reasons) {
      score = 0
      reasons = ""

      if ((p95 + 0) >= 1.5000) {
        score += 25
        reasons = append_reason(reasons, "high_p95")
      } else if ((p95 + 0) >= 0.7500) {
        score += 10
        reasons = append_reason(reasons, "elevated_p95")
      }

      if ((p99 + 0) >= 3.0000) {
        score += 15
        reasons = append_reason(reasons, "high_p99")
      }

      if ((error_rate + 0) >= 5.00) {
        score += 25
        reasons = append_reason(reasons, "high_error_rate")
      } else if ((error_rate + 0) >= 1.00) {
        score += 10
        reasons = append_reason(reasons, "elevated_error_rate")
      }

      if ((avg_upstream_connect + 0) >= 0.2000) {
        score += 10
        reasons = append_reason(reasons, "slow_upstream_connect")
      }

      if ((upstream_nodes + 0) > 1 && (top_upstream_share + 0) >= 80.00) {
        score += 15
        reasons = append_reason(reasons, "upstream_imbalance")
      }

      if ((probe_total + 0) >= 1.5000) {
        score += 10
        reasons = append_reason(reasons, "slow_probe_total")
      }

      if (top_status ~ /^5/ || probe_code ~ /^5/) {
        score += 20
        reasons = append_reason(reasons, "server_errors")
      }

      if (route_type != "api" && (cache_miss_ratio + 0) >= 95.00 && (request_count + 0) >= 50) {
        score += 5
        reasons = append_reason(reasons, "cache_miss_heavy")
      }

      if (score > 100) {
        score = 100
      }

      if (reasons == "") {
        reasons = "none"
      }
      return score "\t" reasons
    }

    BEGIN {
      OFS = "\t"
    }

    FILENAME == runtime_file {
      runtime[$1] = $2 FS $3 FS $4 FS $5 FS $6 FS $7 FS $8 FS $9 FS $10 FS $11 FS $12 FS $13 FS $14 FS $15 FS $16 FS $17 FS $18 FS $19 FS $20 FS $21 FS $22 FS $23 FS $24
      next
    }

    FILENAME == probe_file {
      probe[$1] = $2 FS $3 FS $4 FS $5 FS $6 FS $7 FS $8 FS $9 FS $10
      next
    }

    {
      rid = $1
      env_name = $2
      server_name = $4
      location = $6
      route_type = $7
      backend = $8
      real_backend = $9
      access_log = $10

      split(runtime[rid], rt, FS)
      split(probe[rid], pp, FS)

      if (rt[1] == "") {
        rt[1] = 0
        rt[2] = 0
        rt[3] = "0.00"
        rt[4] = "0.0000"
        rt[5] = "0.0000"
        rt[6] = "0.0000"
        rt[7] = "0.0000"
        rt[8] = "0.0000"
        rt[9] = "0.0000"
        rt[10] = "0.0000"
        rt[11] = "-"
        rt[12] = "-"
        rt[13] = "-"
        rt[14] = "-"
        rt[15] = "0.00"
        rt[16] = 0
        rt[17] = "-"
        rt[18] = "0.0000"
        rt[19] = "0.00"
        rt[20] = "0.00"
        rt[21] = "0.00"
        rt[22] = "-"
        rt[23] = "-"
      }

      if (pp[1] == "") {
        pp[1] = "000"
        pp[2] = "unknown"
        pp[3] = "0"
        pp[4] = "0"
        pp[5] = "0"
        pp[6] = "0"
        pp[7] = "0"
        pp[8] = "unknown"
        pp[9] = "unknown"
      }

      split(risk_score(route_type, rt[1], rt[3], rt[7], rt[8], rt[10], rt[15], rt[16], rt[20], pp[7], rt[13], pp[1]), risk_parts, FS)

      print rid,
            env_name,
            server_name,
            location,
            route_type,
            backend,
            real_backend,
            access_log,
            rt[1],
            rt[2],
            rt[3],
            rt[4],
            rt[5],
            rt[6],
            rt[7],
            rt[8],
            rt[9],
            rt[10],
            rt[11],
            rt[12],
            rt[13],
            rt[14],
            rt[15],
            rt[16],
            rt[17],
            rt[18],
            rt[19],
            rt[20],
            rt[21],
            rt[22],
            rt[23],
            pp[1],
            pp[2],
            pp[3],
            pp[4],
            pp[5],
            pp[6],
            pp[7],
            pp[8],
            pp[9],
            risk_parts[1],
            risk_parts[2]
    }
  ' "$RUNTIME_TSV" "$PROBE_TSV" "$ROUTES_CATALOG" > "$ROUTE_REPORT_TSV"
}

write_final_csv() {
  "$AWK_BIN" -F'\t' '
    BEGIN {
      OFS = ","
      print "Environment,ServerName,Location,RouteType,Backend,RealBackend,AccessLog,RequestCount,ErrorCount,ErrorRate,AvgResponseTime,MaxResponseTime,P50ResponseTime,P95ResponseTime,P99ResponseTime,AvgUpstreamResponseTime,AvgUpstreamConnectTime,TopEndpoint,TopMethod,TopStatus,TopUpstream,TopUpstreamShare,UpstreamNodeCount,SlowestEndpoint,SlowestEndpointAvg,CacheHitRatio,CacheMissRatio,AvgBytesSent,TopClientIP,TopTLS,ProbeHTTPCode,ProbeHTTPVersion,ProbeDNS,ProbeConnect,ProbeTLSHandshake,ProbeTTFB,ProbeTotal,TLSVersion,Cipher,RiskScore,RiskReasons"
    }

    {
      print csv($2),
            csv($3),
            csv($4),
            csv($5),
            csv($6),
            csv($7),
            csv($8),
            csv($9),
            csv($10),
            csv($11),
            csv($12),
            csv($13),
            csv($14),
            csv($15),
            csv($16),
            csv($17),
            csv($18),
            csv($19),
            csv($20),
            csv($21),
            csv($22),
            csv($23),
            csv($24),
            csv($25),
            csv($26),
            csv($27),
            csv($28),
            csv($29),
            csv($30),
            csv($31),
            csv($32),
            csv($33),
            csv($34),
            csv($35),
            csv($36),
            csv($37),
            csv($38),
            csv($39),
            csv($40),
            csv($41),
            csv($42)
    }

    function csv(value, tmp) {
      tmp = value
      gsub(/\r/, " ", tmp)
      gsub(/\n/, " ", tmp)
      gsub(/"/, "\"\"", tmp)
      return "\"" tmp "\""
    }
  ' "$ROUTE_REPORT_TSV" > "$OUTPUT_FILE"
}

build_overall_slow_report() {
  "$AWK_BIN" -F'\t' '
    FNR == NR {
      route_meta[$1] = $2 FS $4 FS $6 FS $7
      next
    }

    {
      key = $1 SUBSEP $2
      count[key] += $3
      latency_sum[key] += $4
      if (($5 + 0) > (latency_max[key] + 0)) {
        latency_max[key] = $5
      }
    }

    END {
      for (key in count) {
        split(key, parts, SUBSEP)
        rid = parts[1]
        endpoint = parts[2]
        split(route_meta[rid], meta, FS)
        avg = (count[key] == 0 ? 0 : latency_sum[key] / count[key])
        print sprintf("%.8f", avg),
              sprintf("%.4f", latency_max[key] + 0),
              count[key],
              meta[1],
              meta[2],
              meta[3],
              meta[4],
              endpoint
      }
    }
  ' "$ROUTES_CATALOG" "$OVERALL_ENDPOINT_RAW_TSV" | sort -t $'\t' -k1,1nr -k2,2nr > "$OVERALL_ENDPOINT_TSV"

  if [[ -n "$OVERALL_SLOW_FILE" ]]; then
    {
      printf 'Environment,ServerName,Location,RouteType,Endpoint,RequestCount,AvgResponseTime,MaxResponseTime\n'
      "$AWK_BIN" -F'\t' -v limit="$SLOW_TOP_N" '
        NR <= limit {
          print csv($4) "," csv($5) "," csv($6) "," csv($7) "," csv($8) "," csv($3) "," csv($1) "," csv($2)
        }

        function csv(value, tmp) {
          tmp = value
          gsub(/\r/, " ", tmp)
          gsub(/\n/, " ", tmp)
          gsub(/"/, "\"\"", tmp)
          return "\"" tmp "\""
        }
      ' "$OVERALL_ENDPOINT_TSV"
    } > "$OVERALL_SLOW_FILE"
  fi
}

build_hourly_trend_report() {
  "$AWK_BIN" -F'\t' '
    FNR == NR {
      route_meta[$1] = $2 FS $4 FS $6 FS $7
      next
    }

    {
      key = $1 SUBSEP $2
      count[key] += $3
      errors[key] += $4
      latency_sum[key] += $5
      latency_count[key] += $6
      if (($8 + 0) > (latency_max[key] + 0)) {
        latency_max[key] = $8
      }
    }

    END {
      for (key in count) {
        split(key, parts, SUBSEP)
        rid = parts[1]
        hour_bucket = parts[2]
        split(route_meta[rid], meta, FS)
        avg = (latency_count[key] == 0 ? 0 : latency_sum[key] / latency_count[key])
        err_rate = (count[key] == 0 ? 0 : (errors[key] / count[key]) * 100)
        print hour_bucket,
              meta[1],
              meta[2],
              meta[3],
              meta[4],
              count[key],
              errors[key],
              sprintf("%.2f", err_rate),
              sprintf("%.4f", avg),
              sprintf("%.4f", latency_max[key] + 0)
      }
    }
  ' "$ROUTES_CATALOG" "$HOURLY_RAW_TSV" | sort -t $'\t' -k1,1 -k2,2 -k3,3 -k4,4 > "$HOURLY_TREND_TSV"

  if [[ -n "$HOURLY_TREND_FILE" ]]; then
    {
      printf 'HourBucket,Environment,ServerName,Location,RouteType,RequestCount,ErrorCount,ErrorRate,AvgResponseTime,MaxResponseTime\n'
      "$AWK_BIN" -F'\t' '
        {
          print csv($1) "," csv($2) "," csv($3) "," csv($4) "," csv($5) "," csv($6) "," csv($7) "," csv($8) "," csv($9) "," csv($10)
        }

        function csv(value, tmp) {
          tmp = value
          gsub(/\r/, " ", tmp)
          gsub(/\n/, " ", tmp)
          gsub(/"/, "\"\"", tmp)
          return "\"" tmp "\""
        }
      ' "$HOURLY_TREND_TSV"
    } > "$HOURLY_TREND_FILE"
  fi
}

write_json_export() {
  python - "$ROUTE_REPORT_TSV" "$OVERALL_ENDPOINT_TSV" "$HOURLY_TREND_TSV" "$JSON_OUTPUT_FILE" "$OUTPUT_FILE" "$OVERALL_SLOW_FILE" "$HOURLY_TREND_FILE" "$GENERATED_AT" "$SLOW_TOP_N" <<'PY'
import csv
import json
import sys

route_report, overall_tsv, hourly_tsv, json_out, csv_out, overall_csv, hourly_csv, generated_at, slow_top_n = sys.argv[1:]
slow_top_n = int(slow_top_n)

route_fields = [
    "route_id", "environment", "server_name", "location", "route_type", "backend",
    "real_backend", "access_log", "request_count", "error_count", "error_rate",
    "avg_response_time", "max_response_time", "p50_response_time", "p95_response_time",
    "p99_response_time", "avg_upstream_response_time", "avg_upstream_connect_time",
    "top_endpoint", "top_method", "top_status", "top_upstream", "top_upstream_share",
    "upstream_node_count", "slowest_endpoint", "slowest_endpoint_avg", "cache_hit_ratio",
    "cache_miss_ratio", "avg_bytes_sent", "top_client_ip", "top_tls", "probe_http_code",
    "probe_http_version", "probe_dns", "probe_connect", "probe_tls_handshake",
    "probe_ttfb", "probe_total", "tls_version", "cipher", "risk_score", "risk_reasons"
]

def load_tsv(path, fields=None, limit=None):
    rows = []
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh, delimiter="\t")
        for idx, row in enumerate(reader):
            if not row:
                continue
            if limit is not None and idx >= limit:
                break
            if fields is None:
                rows.append(row)
            else:
                rows.append({fields[i]: row[i] if i < len(row) else "" for i in range(len(fields))})
    return rows

routes = load_tsv(route_report, route_fields)
overall_rows = load_tsv(overall_tsv, [
    "avg_response_time", "max_response_time", "request_count", "environment",
    "server_name", "location", "route_type", "endpoint"
], slow_top_n)
hourly_rows = load_tsv(hourly_tsv, [
    "hour_bucket", "environment", "server_name", "location", "route_type",
    "request_count", "error_count", "error_rate", "avg_response_time", "max_response_time"
])

payload = {
    "metadata": {
        "generated_at": generated_at,
        "main_csv": csv_out,
        "overall_slow_csv": overall_csv,
        "hourly_trend_csv": hourly_csv,
        "overall_slow_limit": slow_top_n,
    },
    "routes": routes,
    "top_slow_endpoints_overall": overall_rows,
    "hourly_trends": hourly_rows,
}

with open(json_out, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, ensure_ascii=False, indent=2)
PY
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config)
        [[ $# -lt 2 ]] && die "Missing value for --config"
        MAIN_CONFIG="$2"
        shift 2
        ;;
      --env)
        [[ $# -lt 2 ]] && die "Missing value for --env"
        ENVIRONMENT="$2"
        shift 2
        ;;
      --output)
        [[ $# -lt 2 ]] && die "Missing value for --output"
        OUTPUT_FILE="$2"
        shift 2
        ;;
      --json-output)
        [[ $# -lt 2 ]] && die "Missing value for --json-output"
        JSON_OUTPUT_FILE="$2"
        shift 2
        ;;
      --overall-slow)
        [[ $# -lt 2 ]] && die "Missing value for --overall-slow"
        OVERALL_SLOW_FILE="$2"
        shift 2
        ;;
      --hourly-trend)
        [[ $# -lt 2 ]] && die "Missing value for --hourly-trend"
        HOURLY_TREND_FILE="$2"
        shift 2
        ;;
      --slow-top)
        [[ $# -lt 2 ]] && die "Missing value for --slow-top"
        SLOW_TOP_N="$2"
        shift 2
        ;;
      --probe-host)
        [[ $# -lt 2 ]] && die "Missing value for --probe-host"
        PROBE_HOST_OVERRIDE="$2"
        shift 2
        ;;
      --scheme)
        [[ $# -lt 2 ]] && die "Missing value for --scheme"
        PROBE_SCHEME="$2"
        shift 2
        ;;
      --port)
        [[ $# -lt 2 ]] && die "Missing value for --port"
        PROBE_PORT="$2"
        shift 2
        ;;
      --timeout)
        [[ $# -lt 2 ]] && die "Missing value for --timeout"
        TIMEOUT="$2"
        shift 2
        ;;
      --tail-lines)
        [[ $# -lt 2 ]] && die "Missing value for --tail-lines"
        TAIL_LINES="$2"
        shift 2
        ;;
      --skip-probes)
        SKIP_PROBES=1
        shift
        ;;
      --secure)
        INSECURE=0
        shift
        ;;
      --verbose)
        VERBOSE=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
  done

  [[ -n "$MAIN_CONFIG" ]] || die "--config is required"
  [[ -f "$MAIN_CONFIG" ]] || die "Config file not found: $MAIN_CONFIG"
  [[ "$PROBE_SCHEME" == "http" || "$PROBE_SCHEME" == "https" ]] || die "--scheme must be http or https"
  [[ "$TAIL_LINES" =~ ^[0-9]+$ ]] || die "--tail-lines must be a non-negative integer"
  [[ "$SLOW_TOP_N" =~ ^[0-9]+$ ]] || die "--slow-top must be a non-negative integer"
}

prepare_workspace() {
  TMP_DIR="$(mktemp -d)"
  ROUTES_RAW="$TMP_DIR/routes_raw.tsv"
  ROUTES_CATALOG="$TMP_DIR/routes_catalog.tsv"
  RUNTIME_TSV="$TMP_DIR/runtime.tsv"
  PROBE_TSV="$TMP_DIR/probe.tsv"
  ROUTE_REPORT_TSV="$TMP_DIR/route_report.tsv"
  OVERALL_ENDPOINT_RAW_TSV="$TMP_DIR/overall_endpoint_raw.tsv"
  OVERALL_ENDPOINT_TSV="$TMP_DIR/overall_endpoint.tsv"
  HOURLY_RAW_TSV="$TMP_DIR/hourly_raw.tsv"
  HOURLY_TREND_TSV="$TMP_DIR/hourly_trend.tsv"
  CONFIG_LIST="$TMP_DIR/config_files.txt"
}

main() {
  parse_args "$@"

  need_bin bash
  need_bin gawk
  need_bin sed
  need_bin grep
  need_bin sort
  need_bin tail
  need_bin tr
  need_bin cp
  need_bin date
  need_bin curl
  need_bin openssl
  need_bin mktemp
  if [[ -n "$JSON_OUTPUT_FILE" ]]; then
    need_bin python
  fi

  prepare_workspace
  GENERATED_AT="$(date '+%Y-%m-%dT%H:%M:%S%z')"

  log "Resolving nginx config tree from $MAIN_CONFIG"
  collect_config_files "$MAIN_CONFIG"

  log "Parsing nginx routes, upstreams and access_log bindings"
  parse_nginx_config

  log "Building performance route catalog"
  build_routes_catalog
  [[ -s "$ROUTES_CATALOG" ]] || die "No reverse proxy locations with proxy_pass were found in the provided nginx config tree"

  log "Analyzing access logs for latency, percentiles and upstream balance"
  analyze_logs

  log "Running active probes"
  run_active_probes

  log "Building route performance report with risk scoring"
  build_route_report_tsv

  log "Writing single export to $OUTPUT_FILE"
  write_final_csv

  if [[ -n "$OVERALL_SLOW_FILE" || -n "$JSON_OUTPUT_FILE" ]]; then
    log "Building overall slow endpoints report"
    build_overall_slow_report
  fi

  if [[ -n "$HOURLY_TREND_FILE" || -n "$JSON_OUTPUT_FILE" ]]; then
    log "Building hourly trend report"
    build_hourly_trend_report
  fi

  if [[ -n "$JSON_OUTPUT_FILE" ]]; then
    log "Writing JSON export to $JSON_OUTPUT_FILE"
    write_json_export
  fi

  printf 'Export complete: %s\n' "$OUTPUT_FILE"
  [[ -n "$OVERALL_SLOW_FILE" ]] && printf 'Overall slow endpoints: %s\n' "$OVERALL_SLOW_FILE"
  [[ -n "$HOURLY_TREND_FILE" ]] && printf 'Hourly trend export: %s\n' "$HOURLY_TREND_FILE"
  [[ -n "$JSON_OUTPUT_FILE" ]] && printf 'JSON export: %s\n' "$JSON_OUTPUT_FILE"
}

main "$@"
