#!/usr/bin/env bash
# =============================================================================
# info.sh — Reverse Proxy Intelligence & Performance Analyzer
#
# Hybrid model: Config Parsing (white-box) + Log Analytics (runtime) +
#               Live Discovery (black-box) + Risk Scoring + HTML Dashboard
#
# Kaynak: info.sh (orijinal) + nginx_perf_analyzer.sh birleşimi
# =============================================================================

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
TIMEOUT=10
OUTPUT_FILE="enterprise_inventory.csv"
JSON_OUTPUT_FILE=""
OVERALL_SLOW_FILE=""
HOURLY_TREND_FILE=""
HTML_REPORT_FILE=""
ENVIRONMENT="unknown"
MAIN_CONFIG=""
PROBE_HOST_OVERRIDE=""
PROBE_SCHEME="https"
PROBE_PORT=""
INSECURE=1
VERBOSE=0
AWK_BIN="awk"
SKIP_PROBES=0
SLOW_TOP_N=20
TAIL_LINES=0
GENERATED_AT=""

TMP_DIR=""
ROUTES_RAW=""
ROUTES_CATALOG=""
RUNTIME_TSV=""
DISCOVERY_TSV=""
ROUTE_REPORT_TSV=""
OVERALL_ENDPOINT_RAW_TSV=""
OVERALL_ENDPOINT_TSV=""
HOURLY_RAW_TSV=""
HOURLY_TREND_TSV=""
RUNTIME_AWK_SCRIPT=""
CONFIG_LIST=""

declare -A HOST_TLS_CACHE=()
declare -A HOST_HTTP2_CACHE=()
declare -A HOST_INGRESS_CACHE=()

# =============================================================================
# YARDIMCI FONKSIYONLAR
# =============================================================================

usage() {
  cat <<'EOF'
Kullanim: ./info.sh [SECENEKLER]

Secenekler:
  --config FILE         Nginx ana konfigurasyon (opsiyonel, otomatik bulur)
  --env NAME            Ortam adi (production, staging, test). Varsayilan: unknown
  --output FILE         Ana CSV ciktisi. Varsayilan: enterprise_inventory.csv
  --json-output FILE    JSON ciktisi (python3 gerekli)
  --overall-slow FILE   En yavas endpoint CSV ciktisi
  --hourly-trend FILE   Saatlik trend CSV ciktisi
  --html-report FILE    HTML dashboard (python3 gerekli, Chart.js CDN kullanir)
  --probe-host HOST     Canli probe icin sunucu adi (override)
  --scheme http|https   Probe semasi. Varsayilan: https
  --port PORT           Probe portu
  --slow-top N          En yavas N endpoint. Varsayilan: 20
  --tail-lines N        Her log dosyasindan son N satir (0 = tumu)
  --timeout SEC         Curl/openssl timeout. Varsayilan: 10
  --skip-probes         Canli prob atla (sadece config + log)
  --secure              TLS sertifikasi dogrulansin
  --verbose             Detayli log
  -h, --help            Bu yardim

Otomatik tespit:
  Config: /usr/nginx/conf/nginx.conf -> /etc/nginx/nginx.conf -> /usr/local/nginx/conf/nginx.conf
  Includes: sadece *.conf dosyalari taranir
  Loglar: config'deki access_log -> /web_log/*.log

Cikti kolonlari (CSV):
  Environment,ServerName,Location,RouteType,Backend,RealBackend,
  Framework,Ingress,Cluster,Swagger,Health,HTTP2,TLSVersion,
  TopEndpoint,TopMethod,TopStatus,TopUpstream,TopUpstreamShare,UpstreamNodeCount,
  SlowestEndpoint,SlowestEndpointAvg,
  RequestCount,ErrorCount,ErrorRate,
  AvgResponseTime,MaxResponseTime,P50,P95,P99,
  AvgUpstreamResponseTime,AvgUpstreamConnectTime,
  CacheHitRatio,CacheMissRatio,AvgBytesSent,
  TopClientIP,TopTLS,
  AccessLog,
  RiskScore,RiskReasons

Gereksinimler: bash, gawk/awk, sed, grep, sort, tail, tr, curl, openssl, mktemp
  JSON/HTML icin: python3
EOF
}

log()  { if [[ "$VERBOSE" -eq 1 ]]; then printf '[INFO] %s\n' "$*" >&2; fi }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

need_bin() {
  command -v "$1" >/dev/null 2>&1 || die "Gerekli binary bulunamadi: $1"
}

cleanup() {
  if [[ -n "${TMP_DIR:-}" && -d "${TMP_DIR:-}" ]]; then rm -rf "$TMP_DIR"; fi
}
trap cleanup EXIT

trim() {
  local value="${1-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

csv_escape() {
  local value="${1-}"
  value="${value//$'\r'/ }"
  value="${value//$'\n'/ }"
  value="${value//\"/\"\"}"
  printf '"%s"' "$value"
}

abs_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then printf '%s\n' "$path"; return; fi
  local dir base
  dir="$(cd "$(dirname "$path")" && pwd -P)"
  base="$(basename "$path")"
  printf '%s/%s\n' "$dir" "$base"
}

normalize_location() {
  local path="${1-}"
  [[ -z "$path" ]] && { printf '/'; return; }
  [[ "$path" != /* ]] && { printf '%s' "$path"; return; }
  if [[ "$path" != "/" ]]; then
    path="${path%/}"; [[ -z "$path" ]] && path="/"
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
  local server_names="$1" token
  for token in $server_names; do
    [[ -z "$token" ]] && continue; [[ "$token" = "_" ]] && continue
    [[ "$token" = "~"* ]] && continue
    if [[ "$token" == \*.* ]]; then token="${token#*.}"; fi
    if [[ -n "$token" && "$token" == *.* ]]; then printf '%s' "$token"; return; fi
  done
  for token in $server_names; do
    [[ -n "$token" && "$token" != "_" ]] || continue
    printf '%s' "$token"; return
  done
  printf ''
}

join_url_path() {
  local left="$1" right="$2"
  [[ -z "$left" ]] && left="/"; [[ -z "$right" ]] && right="/"
  [[ "$left" != "/" ]] && left="${left%/}"
  right="${right#/}"
  if [[ "$left" = "/" ]]; then printf '/%s' "$right"
  elif [[ -z "$right" ]]; then printf '%s' "$left"
  else printf '%s/%s' "$left" "$right"; fi
}

extract_host_from_proxy_pass() {
  local value="${1-}"
  value="${value#http://}"; value="${value#https://}"
  value="${value%%/*}"; value="${value%%\?*}"; value="${value%%\$*}"
  printf '%s' "$value"
}

extract_include_targets() {
  local file="$1"
  sed -E 's/[[:space:]]*#.*$//' "$file" | sed -nE 's/^[[:space:]]*include[[:space:]]+([^;]+);/\1/p'
}

# =============================================================================
# PHASE 1: CONFIG PARSING (info.sh)
# =============================================================================

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
      if [[ "$include" != /* ]]; then pattern="$current_dir/$include"
      else pattern="$include"; fi
      shopt -s nullglob
      for candidate in $pattern; do
        if [[ -f "$candidate" ]]; then
          [[ "$candidate" == *.conf ]] && queue+=("$candidate")
        fi
      done
      shopt -u nullglob
    done < <(extract_include_targets "$current_abs")
  done
}

parse_nginx_config() {
  local -a files=()
  mapfile -t files < "$CONFIG_LIST"
  [[ ${#files[@]} -gt 0 ]] || die "Config dosyasi bulunamadi: $MAIN_CONFIG"

  "$AWK_BIN" '
    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    function sanitize(s) { sub(/[[:space:]]*#.*/, "", s); return trim(s) }

    function emit_route(backend_host, real_backend) {
      if (loc_path == "") return
      backend_host = loc_proxy_pass
      sub(/^[A-Za-z]+:\/\//, "", backend_host)
      sub(/[\/\?].*$/, "", backend_host); sub(/\$.*/, "", backend_host)
      real_backend = loc_real_backend
      if (real_backend == "" && backend_host in upstream_servers) real_backend = upstream_servers[backend_host]
      if (real_backend == "") real_backend = backend_host
      if (loc_access_log == "") loc_access_log = server_access_log
      if (loc_access_log == "") loc_access_log = "-"
      print route_id, FILENAME, server_names, loc_modifier, loc_path, loc_proxy_pass, real_backend, loc_access_log, backend_host
      route_id++
    }

    BEGIN { OFS = "\t"; depth = 0; route_id = 1 }

    {
      line = sanitize($0)
      if (line == "") next
      work = line; open_count = gsub(/\{/, "{", work)
      work = line; close_count = gsub(/\}/, "}", work)

      if (match(line, /^[[:space:]]*upstream[[:space:]]+([^[:space:]{]+)[[:space:]]*\{/, m)) {
        current_upstream = m[1]; upstream_depth = depth + 1
      } else if (current_upstream != "" && match(line, /^[[:space:]]*server[[:space:]]+([^;]+);/, m)) {
        upstream_member = trim(m[1]); split(upstream_member, parts, /[[:space:]]+/)
        upstream_member = parts[1]
        if (upstream_servers[current_upstream] == "") upstream_servers[current_upstream] = upstream_member
        else upstream_servers[current_upstream] = upstream_servers[current_upstream] "|" upstream_member
      }

      if (match(line, /^[[:space:]]*server[[:space:]]*\{/, m) && loc_path == "") {
        in_server = 1; server_depth = depth + 1; server_names = ""; server_access_log = ""
      }
      if (in_server && loc_path == "" && match(line, /^[[:space:]]*server_name[[:space:]]+([^;]+);/, m)) server_names = trim(m[1])
      if (in_server && loc_path == "" && match(line, /^[[:space:]]*access_log[[:space:]]+([^;]+);/, m)) {
        server_access_log = trim(m[1]); split(server_access_log, access_parts, /[[:space:]]+/)
        server_access_log = access_parts[1]
        if (server_access_log == "off") server_access_log = "-"
      }

      if (in_server && match(line, /^[[:space:]]*location[[:space:]]+((=|\^~|~\*|~)[[:space:]]+)?([^[:space:]{]+)[[:space:]]*\{/, m)) {
        loc_modifier = trim(m[2]); loc_path = trim(m[3])
        loc_proxy_pass = ""; loc_real_backend = ""; loc_access_log = ""; loc_depth = depth + 1
      }
      if (loc_path != "" && match(line, /^[[:space:]]*proxy_pass[[:space:]]+([^;]+);/, m)) loc_proxy_pass = trim(m[1])
      if (loc_path != "" && match(line, /^[[:space:]]*proxy_ssl_name[[:space:]]+([^;]+);/, m)) loc_real_backend = trim(m[1])
      if (loc_path != "" && match(line, /^[[:space:]]*access_log[[:space:]]+([^;]+);/, m)) {
        loc_access_log = trim(m[1]); split(loc_access_log, access_parts, /[[:space:]]+/)
        loc_access_log = access_parts[1]
        if (loc_access_log == "off") loc_access_log = "-"
      }

      depth += open_count - close_count
      if (loc_path != "" && depth < loc_depth) { emit_route(); loc_path = ""; loc_modifier = ""; loc_proxy_pass = ""; loc_real_backend = ""; loc_access_log = "" }
      if (in_server && depth < server_depth) { in_server = 0; server_names = ""; server_access_log = "" }
      if (current_upstream != "" && depth < upstream_depth) current_upstream = ""
    }
  ' "${files[@]}" > "$ROUTES_RAW"
}

build_routes_catalog() {
  "$AWK_BIN" -v env_name="$ENVIRONMENT" '
    BEGIN { OFS = "\t" }
    { location = $5; if (location == "" || location == "@") next; print $1, env_name, $2, $3, $4, $5, $6, $7, $8, $9 }
  ' "$ROUTES_RAW" | while IFS=$'\t' read -r route_id env_name config_file server_names modifier location backend real_backend access_log backend_host; do
    normalized_location="$(normalize_location "$location")"
    route_type="$(detect_route_type "${modifier}${normalized_location}")"
    probe_host="$PROBE_HOST_OVERRIDE"
    [[ -z "$probe_host" ]] && probe_host="$(choose_probe_host "$server_names")"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$route_id" "$env_name" "$config_file" "$server_names" "$modifier" \
      "$normalized_location" "$route_type" "$backend" "$real_backend" \
      "$access_log" "$backend_host" "$probe_host"
  done > "$ROUTES_CATALOG"
}

# =============================================================================
# PHASE 2: ENHANCED LOG ANALYTICS (merge: info.sh + perf_analyzer)
# =============================================================================

create_runtime_awk_script() {
  cat > "$RUNTIME_AWK_SCRIPT" <<'AWK'
function tolower_safe(s) { return tolower(s) }

function ignore_path(path, lower) {
  lower = tolower_safe(path)
  if (lower ~ /\.(svg|png|jpe?g|gif|css|js|woff2?|map|ico|ttf|eot)(\?.*)?$/) return 1
  if (lower ~ /^\/(non-core-assets|locales|static|assets|rb_)(\/|$)/) return 1
  return 0
}

function parse_numeric(raw, cleaned, parts, i, n, sum, count) {
  if (raw == "" || raw == "-") return ""
  cleaned = raw; gsub(/[,;:]/, " ", cleaned)
  n = split(cleaned, parts, /[[:space:]]+/); sum = 0; count = 0
  for (i = 1; i <= n; i++) if (parts[i] ~ /^-?[0-9]+(\.[0-9]+)?$/) { sum += parts[i]; count++ }
  return (count == 0) ? "" : sum / count
}

function extract_hour(ts) {
  ts = kv["timestamp"]; if (ts == "") ts = kv["ts"]
  if (ts == "") ts = kv["time"]; if (ts == "") ts = kv["time_local"]
  if (ts == "") ts = kv["datetime"]; if (ts == "") return ""
  gsub(/^\[|\]$|"/, "", ts)
  if (ts ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}[T _][0-9]{2}/) { gsub(/[ _]/, "T", ts); return substr(ts, 1, 13) }
  if (ts ~ /^[0-9]{2}\/[A-Z][a-z]{2}\/[0-9]{4}:[0-9]{2}/) { return substr(ts, 4, 7) "T" substr(ts, 13, 2) }
  return ""
}

function load_routes(line, parts, i, j, tmp) {
  while ((getline line < route_file) > 0) {
    split(line, parts, "\t"); route_ids[++route_count] = parts[1]; route_values[route_count] = parts[2]; route_lengths[route_count] = length(parts[2])
  }
  close(route_file)
  for (i = 1; i <= route_count; i++) route_order[i] = i
  for (i = 1; i <= route_count; i++) for (j = i + 1; j <= route_count; j++)
    if (route_lengths[route_order[j]] > route_lengths[route_order[i]]) { tmp = route_order[i]; route_order[i] = route_order[j]; route_order[j] = tmp }
}

function best_route(path, i, idx, candidate, next_char) {
  for (i = 1; i <= route_count; i++) {
    idx = route_order[i]; candidate = route_values[idx]
    if (candidate == "/") return route_ids[idx]
    if (index(path, candidate) == 1) {
      next_char = substr(path, length(candidate) + 1, 1)
      if (path == candidate || candidate ~ /\/$/ || next_char == "/" || next_char == "" || next_char == "?") return route_ids[idx]
    }
  }
  return ""
}

function parse_line(n, i, item, pos, key, value) {
  delete kv; n = split($0, items, /[[:space:]]+/)
  for (i = 1; i <= n; i++) {
    item = items[i]; pos = index(item, "=")
    if (pos == 0) continue
    key = substr(item, 1, pos - 1); value = substr(item, pos + 1)
    gsub(/^"|"$/, "", value); kv[key] = value
  }
}

function top_value(prefix, route_id, key, count, winner, best, parts) {
  winner = "-"; best = -1
  for (key in counters) { split(key, parts, SUBSEP)
    if (parts[1] == prefix && parts[2] == route_id && counters[key] > best) { best = counters[key]; winner = parts[3] } }
  return winner
}

function top_upstream_share(route_id, winner, key) {
  winner = top_value("upstream", route_id)
  if (winner == "-" || upstream_total[route_id] == 0) return "0.00"
  key = "upstream" SUBSEP route_id SUBSEP winner
  return sprintf("%.2f", (counters[key] / upstream_total[route_id]) * 100)
}

function count_unique_upstreams(route_id, key, total, parts) {
  total = 0
  for (key in seen_upstream) { split(key, parts, SUBSEP); if (parts[1] == route_id) total++ }
  return total
}

function percentile(route_id, p, n, i, idx, values, sorted) {
  n = latency_count[route_id]; if (n == 0) return "0.0000"
  delete values; for (i = 1; i <= n; i++) values[i] = latency_values[route_id, i]
  asort(values, sorted); idx = int((p * n) + 0.999999)
  if (idx < 1) idx = 1; if (idx > n) idx = n
  return sprintf("%.4f", sorted[idx])
}

function slowest_endpoint(route_id, mode, key, avg, best, best_ep, parts) {
  best = -1; best_ep = "-"
  for (key in endpoint_latency_count) { split(key, parts, SUBSEP)
    if (parts[1] == route_id) {
      avg = endpoint_latency_sum[key] / endpoint_latency_count[key]
      if (avg > best) { best = avg; best_ep = parts[2] }
    }
  }
  if (mode == "name") return best_ep
  return (best < 0) ? "0.0000" : sprintf("%.4f", best)
}

BEGIN { OFS = "\t"; load_routes() }

{
  parse_line()
  request = kv["request"]; if (request == "") next
  sub(/\?.*$/, "", request); if (ignore_path(request)) next
  route_id = best_route(request); if (route_id == "") next

  status = kv["status"]; if (status == "") status = "-"
  method = kv["method"]; if (method == "") method = "-"
  upstream = kv["upstream_addr"]; if (upstream == "") upstream = "-"
  client_ip = kv["client_ip"]; if (client_ip == "") client_ip = "-"
  tls = kv["ssl_protocol"]; if (tls == "") tls = "-"
  req_time = parse_numeric(kv["request_time"])
  upstream_rt = parse_numeric(kv["upstream_response_time"])
  upstream_conn = parse_numeric(kv["upstream_connect_time"])
  cache_status = toupper(kv["upstream_cache_status"])
  bytes_sent = parse_numeric(kv["body_bytes_sent"])
  if (bytes_sent == "") bytes_sent = parse_numeric(kv["bytes_sent"])
  hour_bucket = extract_hour()

  counts[route_id]++
  if (status + 0 >= 400) errors[route_id]++

  if (req_time != "") {
    latency_sum[route_id] += req_time
    if (req_time > latency_max[route_id]) latency_max[route_id] = req_time
    latency_values[route_id, ++latency_count[route_id]] = req_time
    endpoint_latency_sum[route_id SUBSEP request] += req_time
    endpoint_latency_count[route_id SUBSEP request]++
    if (req_time > endpoint_latency_max[route_id SUBSEP request]) endpoint_latency_max[route_id SUBSEP request] = req_time
  }

  if (upstream_rt != "") { upstream_rt_sum[route_id] += upstream_rt; upstream_rt_count[route_id]++ }
  if (upstream_conn != "") { upstream_conn_sum[route_id] += upstream_conn; upstream_conn_count[route_id]++ }
  if (bytes_sent != "") { bytes_sum[route_id] += bytes_sent; bytes_count[route_id]++ }

  if (hour_bucket != "") {
    hourly_count[route_id SUBSEP hour_bucket]++
    hourly_errors[route_id SUBSEP hour_bucket] += ((status + 0) >= 400 ? 1 : 0)
    if (req_time != "") {
      hourly_latency_sum[route_id SUBSEP hour_bucket] += req_time
      hourly_latency_count[route_id SUBSEP hour_bucket]++
      if (req_time > hourly_latency_max[route_id SUBSEP hour_bucket]) hourly_latency_max[route_id SUBSEP hour_bucket] = req_time
    }
  }

  counters["endpoint" SUBSEP route_id SUBSEP request]++
  counters["method" SUBSEP route_id SUBSEP method]++
  counters["status" SUBSEP route_id SUBSEP status]++
  counters["upstream" SUBSEP route_id SUBSEP upstream]++
  counters["client" SUBSEP route_id SUBSEP client_ip]++
  counters["tls" SUBSEP route_id SUBSEP tls]++

  if (upstream != "-") { seen_upstream[route_id SUBSEP upstream] = 1; upstream_total[route_id]++ }

  if (cache_status ~ /^(HIT|STALE|REVALIDATED)$/) { cache_hit[route_id]++; cache_total[route_id]++ }
  else if (cache_status ~ /^(MISS|BYPASS|EXPIRED|UPDATING)$/) { cache_miss[route_id]++; cache_total[route_id]++ }
}

END {
  for (route_id in counts) {
    avg_lat = (latency_count[route_id] == 0 ? 0 : latency_sum[route_id] / latency_count[route_id])
    err_rate = (counts[route_id] == 0 ? 0 : (errors[route_id] / counts[route_id]) * 100)
    avg_up_rt = (upstream_rt_count[route_id] == 0 ? 0 : upstream_rt_sum[route_id] / upstream_rt_count[route_id])
    avg_up_co = (upstream_conn_count[route_id] == 0 ? 0 : upstream_conn_sum[route_id] / upstream_conn_count[route_id])
    avg_bytes = (bytes_count[route_id] == 0 ? 0 : bytes_sum[route_id] / bytes_count[route_id])
    cache_hit_r = (cache_total[route_id] == 0 ? 0 : (cache_hit[route_id] / cache_total[route_id]) * 100)
    cache_miss_r = (cache_total[route_id] == 0 ? 0 : (cache_miss[route_id] / cache_total[route_id]) * 100)

    print route_id,
      counts[route_id], errors[route_id] + 0, sprintf("%.2f", err_rate),
      sprintf("%.4f", avg_lat), sprintf("%.4f", latency_max[route_id] + 0),
      percentile(route_id, 0.50), percentile(route_id, 0.95), percentile(route_id, 0.99),
      sprintf("%.4f", avg_up_rt), sprintf("%.4f", avg_up_co),
      top_value("endpoint", route_id), top_value("method", route_id), top_value("status", route_id),
      top_value("upstream", route_id), top_upstream_share(route_id), count_unique_upstreams(route_id),
      slowest_endpoint(route_id, "name"), slowest_endpoint(route_id, "avg"),
      sprintf("%.2f", cache_hit_r), sprintf("%.2f", cache_miss_r), sprintf("%.2f", avg_bytes),
      top_value("client", route_id), top_value("tls", route_id)
  }

  for (key in endpoint_latency_count) {
    split(key, parts, SUBSEP)
    print parts[1], parts[2], endpoint_latency_count[key],
      sprintf("%.8f", endpoint_latency_sum[key]), sprintf("%.4f", endpoint_latency_max[key] + 0)
  }

  for (key in hourly_count) {
    split(key, parts, SUBSEP); rid = parts[1]; hour_bucket = parts[2]
    avg_hour = (hourly_latency_count[key] == 0 ? 0 : hourly_latency_sum[key] / hourly_latency_count[key])
    print rid, hour_bucket, hourly_count[key], hourly_errors[key] + 0,
      sprintf("%.8f", hourly_latency_sum[key] + 0), hourly_latency_count[key] + 0,
      sprintf("%.4f", avg_hour), sprintf("%.4f", hourly_latency_max[key] + 0)
  }
}
AWK
}

analyze_single_log() {
  local log_file="$1" route_subset="$2"
  local staged_log="$TMP_DIR/$(printf '%s' "$log_file" | tr '/: ' '___').stage"

  [[ -r "$log_file" ]] || { log "Uyari: '$log_file' okunamiyor, atlaniyor."; return; }

  if [[ "$TAIL_LINES" -gt 0 ]]; then tail -n "$TAIL_LINES" "$log_file" > "$staged_log"
  else cp "$log_file" "$staged_log"; fi

  "$AWK_BIN" -v route_file="$route_subset" \
    -v metrics_out="$RUNTIME_TSV" \
    -v overall_out="$OVERALL_ENDPOINT_RAW_TSV" \
    -v hourly_out="$HOURLY_RAW_TSV" \
    -f "$RUNTIME_AWK_SCRIPT" "$staged_log"
}

analyze_logs() {
  create_runtime_awk_script
  : > "$RUNTIME_TSV"; : > "$OVERALL_ENDPOINT_RAW_TSV"; : > "$HOURLY_RAW_TSV"

  local unique_logs_file="$TMP_DIR/unique_logs.txt"

  "$AWK_BIN" -F'\t' '$10 != "-" && $7 != "regex" && $7 != "named" { print $10 }' "$ROUTES_CATALOG" | sort -u > "$unique_logs_file"

  if [[ ! -s "$unique_logs_file" ]]; then
    log "Config'de access_log bulunamadi, /web_log/*.log taranıyor..."
    local found=0
    for f in /web_log/*.log; do [[ -f "$f" ]] && { printf '%s\n' "$f" >> "$unique_logs_file"; found=1; }; done
    [[ "$found" -eq 0 ]] && { log "/web_log/ altinda log bulunamadi."; return; }
  fi

  local log_file route_subset
  while IFS= read -r log_file; do
    [[ -n "$log_file" ]] || continue
    log "Log analiz ediliyor: $log_file"
    route_subset="$TMP_DIR/routes_$(printf '%s' "$log_file" | tr '/: ' '___').tsv"
    "$AWK_BIN" -F'\t' -v target="$log_file" '$10 == target && $7 != "regex" && $7 != "named" { print $1, $6 }' "$ROUTES_CATALOG" > "$route_subset"
    if [[ ! -s "$route_subset" ]]; then
      "$AWK_BIN" -F'\t' '$7 != "regex" && $7 != "named" { print $1, $6 }' "$ROUTES_CATALOG" > "$route_subset"
      log "Tum rotalar kullaniliyor (auto-detect log): $log_file"
    fi
    analyze_single_log "$log_file" "$route_subset"
  done < "$unique_logs_file"

  sort -u "$RUNTIME_TSV" -o "$RUNTIME_TSV"
  sort -u "$HOURLY_RAW_TSV" -o "$HOURLY_RAW_TSV"
  sort -u "$OVERALL_ENDPOINT_RAW_TSV" -o "$OVERALL_ENDPOINT_RAW_TSV"
}

# =============================================================================
# PHASE 3: LIVE DISCOVERY (info.sh)
# =============================================================================

probe_http_headers() {
  local url="$1"
  local curl_args=(-sS -L -m "$TIMEOUT" -D - -o /dev/null)
  [[ "$INSECURE" -eq 1 ]] && curl_args+=(-k)
  curl "${curl_args[@]}" "$url" 2>/dev/null || true
}

probe_http_body() {
  local url="$1"
  local curl_args=(-sS -L -m "$TIMEOUT")
  [[ "$INSECURE" -eq 1 ]] && curl_args+=(-k)
  curl "${curl_args[@]}" "$url" 2>/dev/null | head -c 20000 || true
}

get_tls_version() {
  local host="$1" port="$2" cache_key="$host:$port"
  [[ -n "${HOST_TLS_CACHE[$cache_key]:-}" ]] && { printf '%s' "${HOST_TLS_CACHE[$cache_key]}"; return; }
  local result protocol
  result="$(printf '' | openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null || true)"
  protocol="$("$AWK_BIN" -F': ' '/Protocol[[:space:]]*:/ { print $2; exit }' <<<"$result")"
  [[ -z "$protocol" ]] && protocol="unknown"
  HOST_TLS_CACHE["$cache_key"]="$protocol"; printf '%s' "$protocol"
}

get_http2_status() {
  local host="$1" route="$2" port="$3" cache_key="$host:$port"
  [[ -n "${HOST_HTTP2_CACHE[$cache_key]:-}" ]] && { printf '%s' "${HOST_HTTP2_CACHE[$cache_key]}"; return; }
  local url="${PROBE_SCHEME}://$host"
  [[ -n "$port" ]] && url="${PROBE_SCHEME}://$host:$port"
  url="${url}$(join_url_path "$route" "")"
  local curl_args=(-sS -o /dev/null -w '%{http_version}' --http2 -m "$TIMEOUT")
  [[ "$INSECURE" -eq 1 ]] && curl_args+=(-k)
  local version
  version="$(curl "${curl_args[@]}" "$url" 2>/dev/null || true)"
  case "$version" in 2|2.0) HOST_HTTP2_CACHE["$cache_key"]="yes" ;; 1|1.0|1.1|3) HOST_HTTP2_CACHE["$cache_key"]="no" ;; *) HOST_HTTP2_CACHE["$cache_key"]="unknown" ;; esac
  printf '%s' "${HOST_HTTP2_CACHE[$cache_key]}"
}

detect_cluster() {
  local combined="${1-} ${2-} ${3-}"; combined="${combined,,}"
  if [[ "$combined" == *".svc.cluster.local"* || "$combined" == *".svc"* || "$combined" == *".apps."* || "$combined" == *"openshift"* ]]; then printf 'openshift/kubernetes'
  elif [[ "$combined" == *"cluster.local"* || "$combined" == *"kubernetes"* ]]; then printf 'kubernetes'
  else printf 'unknown'; fi
}

detect_ingress() {
  local headers="${1,,}" backend="${2,,}" real_backend="${3,,}" key="$backend|$real_backend|$headers"
  [[ -n "${HOST_INGRESS_CACHE[$key]:-}" ]] && { printf '%s' "${HOST_INGRESS_CACHE[$key]}"; return; }
  if [[ "$headers" == *"server: envoy"* || "$headers" == *"x-envoy"* || "$headers" == *"istio"* ]]; then HOST_INGRESS_CACHE["$key"]="envoy/istio"
  elif [[ "$headers" == *"server: openresty"* ]]; then HOST_INGRESS_CACHE["$key"]="openresty"
  elif [[ "$headers" == *"server: nginx"* || "$headers" == *"via: nginx"* ]]; then HOST_INGRESS_CACHE["$key"]="nginx"
  elif [[ "$backend $real_backend" == *".apps."* || "$backend $real_backend" == *".svc"* || "$backend $real_backend" == *"openshift"* ]]; then HOST_INGRESS_CACHE["$key"]="openshift-router"
  else HOST_INGRESS_CACHE["$key"]="unknown"; fi
  printf '%s' "${HOST_INGRESS_CACHE[$key]}"
}

detect_framework() {
  local headers="${1,,}" body="${2,,}"
  if [[ "$headers" == *"x-powered-by: spring"* || "$body" == *"spring boot"* ]]; then printf 'spring'
  elif [[ "$headers" == *"x-powered-by: express"* ]]; then printf 'express'
  elif [[ "$headers" == *"x-powered-by: asp.net"* || "$headers" == *"server: kestrel"* ]]; then printf 'aspnet'
  elif [[ "$body" == *"__next_data__"* || "$body" == *"/_next/"* ]]; then printf 'nextjs'
  elif [[ "$body" == *"ng-version"* || "$body" == *"angular"* ]]; then printf 'angular'
  elif [[ "$body" == *"data-reactroot"* || "$body" == *"react"* ]]; then printf 'react'
  elif [[ "$body" == *"data-v-"* || "$body" == *"vue"* ]]; then printf 'vue'
  else printf 'unknown'; fi
}

classify_exposure() {
  local code="$1" path="$2"
  case "$code" in 200) printf 'public:%s' "$path" ;; 401|403) printf 'protected:%s' "$path" ;; *) printf 'not_found' ;; esac
}

probe_candidates() {
  local host="$1" route="$2"; shift 2
  [[ -n "$host" ]] || { printf 'unknown'; return; }
  local candidate path url code
  local curl_args=(-sS -L -m "$TIMEOUT" -o /dev/null -w '%{http_code}')
  [[ "$INSECURE" -eq 1 ]] && curl_args+=(-k)
  for candidate in "$@"; do
    path="$(join_url_path "$route" "$candidate")"
    url="${PROBE_SCHEME}://$host"; [[ -n "$PROBE_PORT" ]] && url="${PROBE_SCHEME}://$host:$PROBE_PORT"
    url="${url}${path}"
    code="$(curl "${curl_args[@]}" "$url" 2>/dev/null || true)"
    case "$code" in 200|401|403) classify_exposure "$code" "$path"; return ;; esac
  done
  printf 'not_found'
}

run_discovery() {
  [[ "$SKIP_PROBES" -eq 1 ]] && { log "Probleme atlaniyor (--skip-probes)"; return; }
  : > "$DISCOVERY_TSV"; : > "$TMP_DIR/http_tls.tsv"

  while IFS=$'\t' read -r route_id env_name config_file server_names modifier location route_type backend real_backend access_log backend_host probe_host; do
    local headers body framework ingress cluster swagger health http2 tls_version url

    cluster="$(detect_cluster "$backend" "$real_backend" "$server_names")"
    framework="unknown"; ingress="unknown"; swagger="unknown"; health="unknown"; http2="unknown"; tls_version="unknown"

    if [[ -n "$probe_host" && "$route_type" != "regex" && "$route_type" != "named" ]]; then
      url="${PROBE_SCHEME}://$probe_host"; [[ -n "$PROBE_PORT" ]] && url="${PROBE_SCHEME}://$probe_host:$PROBE_PORT"
      url="${url}${location}"
      headers="$(probe_http_headers "$url")"
      body="$(probe_http_body "$url")"
      framework="$(detect_framework "$headers" "$body")"
      ingress="$(detect_ingress "$headers" "$backend" "$real_backend")"
      swagger="$(probe_candidates "$probe_host" "$location" "swagger" "swagger-ui" "swagger-ui.html" "v3/api-docs" "api-docs")"
      health="$(probe_candidates "$probe_host" "$location" "health" "healthz" "actuator/health" "ping" "status")"
      http2="$(get_http2_status "$probe_host" "$location" "$PROBE_PORT")"
      [[ "$PROBE_SCHEME" == "https" ]] && tls_version="$(get_tls_version "$probe_host" "${PROBE_PORT:-443}")"
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$route_id" "$framework" "$ingress" "$cluster" "$swagger" "$health" >> "$DISCOVERY_TSV"
    printf '%s\t%s\t%s\n' "$route_id" "$http2" "$tls_version" >> "$TMP_DIR/http_tls.tsv"
  done < "$ROUTES_CATALOG"

  sort -u "$DISCOVERY_TSV" -o "$DISCOVERY_TSV"
  sort -u "$TMP_DIR/http_tls.tsv" -o "$TMP_DIR/http_tls.tsv"
}

# =============================================================================
# PHASE 4: RISK SCORING + REPORT TSV
# =============================================================================

build_route_report_tsv() {
  "$AWK_BIN" -F'\t' \
    -v env_name="$ENVIRONMENT" \
    -v runtime_file="$RUNTIME_TSV" \
    -v discovery_file="$DISCOVERY_TSV" \
    -v tls_file="$TMP_DIR/http_tls.tsv" \
  '
  function append_reason(cur, add) {
    return (cur == "") ? add : cur ";" add
  }

  function risk_score(route_type, req_count, err_rate, p95, p99,
                      avg_up_conn, top_up_share, up_nodes,
                      cache_miss_r, top_status,
                      score, reasons) {
    score = 0; reasons = ""

    if      ((p95 + 0) >= 1.5) { score += 25; reasons = append_reason(reasons, "yuksek_p95") }
    else if ((p95 + 0) >= 0.75){ score += 10; reasons = append_reason(reasons, "orta_p95")   }
    if ((p99 + 0) >= 3.0)      { score += 15; reasons = append_reason(reasons, "yuksek_p99") }
    if      ((err_rate + 0) >= 5)  { score += 25; reasons = append_reason(reasons, "yuksek_hata_orani") }
    else if ((err_rate + 0) >= 1)  { score += 10; reasons = append_reason(reasons, "orta_hata_orani")   }
    if ((avg_up_conn + 0) >= 0.2)  { score += 10; reasons = append_reason(reasons, "yavas_upstream") }
    if ((up_nodes + 0) > 1 && (top_up_share + 0) >= 80) { score += 15; reasons = append_reason(reasons, "upstream_dengesiz") }
    if (top_status ~ /^5/)  { score += 20; reasons = append_reason(reasons, "sunucu_hatasi") }
    if (route_type != "api" && (cache_miss_r + 0) >= 95 && (req_count + 0) >= 50) { score += 5; reasons = append_reason(reasons, "onbellek_iskala") }
    if (score > 100) score = 100
    if (reasons == "") reasons = "yok"
    return score "\t" reasons
  }

  BEGIN { OFS = "\t" }

  FILENAME == runtime_file {
    rid = $1; for (i = 2; i <= NF; i++) rt[rid, i-1] = $i; next
  }

  FILENAME == discovery_file {
    rid = $1; for (i = 2; i <= NF; i++) ds[rid, i-1] = $i; next
  }

  FILENAME == tls_file {
    rid = $1; for (i = 2; i <= NF; i++) tt[rid, i-1] = $i; next
  }

  {
    rid = $1; env_n = $2; server_name = $4; location = $6
    route_type = $7; backend = $8; real_backend = $9; access_log = $10

    # rt[] indices: 1=count 2=errors 3=err_rate 4=avg_lat 5=max_lat
    # 6=p50 7=p95 8=p99 9=avg_up_rt 10=avg_up_co
    # 11=top_ep 12=top_method 13=top_status 14=top_up 15=top_up_share 16=up_nodes
    # 17=slow_ep 18=slow_ep_avg 19=cache_hit 20=cache_miss 21=avg_bytes
    # 22=top_client 23=top_tls

    # ds[] indices: 1=framework 2=ingress 3=cluster 4=swagger 5=health
    # tt[] indices: 1=http2 2=tls_version

    req_count = rt[rid, 1]+0; err_rate = rt[rid, 3]+0
    p95 = rt[rid, 7]+0; p99 = rt[rid, 8]+0
    avg_up_co = rt[rid, 10]+0; top_up_share = rt[rid, 15]+0
    up_nodes = rt[rid, 16]+0; cache_miss_r = rt[rid, 20]+0
    top_status = rt[rid, 13]; if (top_status == "-" || top_status == "") top_status = "0"

    split(risk_score(route_type, req_count, err_rate, p95, p99,
                     avg_up_co, top_up_share, up_nodes,
                     cache_miss_r, top_status), risk_parts, "\t")

    print rid, env_n, server_name, location, route_type, backend, real_backend, access_log,
          (rt[rid, 1]+0), (rt[rid, 2]+0), rt[rid, 3], rt[rid, 4], rt[rid, 5],
          rt[rid, 6], rt[rid, 7], rt[rid, 8],
          rt[rid, 9], rt[rid, 10],
          rt[rid, 11], rt[rid, 12], rt[rid, 13], rt[rid, 14], rt[rid, 15], (rt[rid, 16]+0),
          rt[rid, 17], rt[rid, 18],
          rt[rid, 19], rt[rid, 20], rt[rid, 21],
          rt[rid, 22], rt[rid, 23],
          ds[rid, 1], ds[rid, 2], ds[rid, 3], ds[rid, 4], ds[rid, 5],
          tt[rid, 1], tt[rid, 2],
          risk_parts[1], risk_parts[2]
  }
  ' "$RUNTIME_TSV" "$DISCOVERY_TSV" "$TMP_DIR/http_tls.tsv" "$ROUTES_CATALOG" > "$ROUTE_REPORT_TSV"
}

# =============================================================================
# PHASE 5: REPORTS (CSV + optional JSON + HTML)
# =============================================================================

write_final_csv() {
  {
    printf 'Environment,ServerName,Location,RouteType,Backend,RealBackend,'
    printf 'Framework,Ingress,Cluster,Swagger,Health,HTTP2,TLSVersion,'
    printf 'TopEndpoint,TopMethod,TopStatus,TopUpstream,TopUpstreamShare,UpstreamNodeCount,'
    printf 'SlowestEndpoint,SlowestEndpointAvg,'
    printf 'RequestCount,ErrorCount,ErrorRate,'
    printf 'AvgResponseTime,MaxResponseTime,P50,P95,P99,'
    printf 'AvgUpstreamResponseTime,AvgUpstreamConnectTime,'
    printf 'CacheHitRatio,CacheMissRatio,AvgBytesSent,'
    printf 'TopClientIP,TopTLS,'
    printf 'AccessLog,'
    printf 'RiskScore,RiskReasons\n'

    "$AWK_BIN" -F'\t' '
      function csv(v, tmp) { tmp = v; gsub(/\r|\n/, " ", tmp); gsub(/"/, "\"\"", tmp); return "\"" tmp "\"" }
      {
        out = ""
        for (i = 2; i <= NF; i++) out = out (i > 2 ? "," : "") csv($i)
        print out
      }
    ' "$ROUTE_REPORT_TSV"
  } > "$OUTPUT_FILE"
}

build_overall_slow_report() {
  [[ -z "$OVERALL_SLOW_FILE" && -z "$JSON_OUTPUT_FILE" && -z "$HTML_REPORT_FILE" ]] && return

  "$AWK_BIN" -F'\t' '
    FNR == NR { route_meta[$1] = $2 FS $4 FS $6 FS $7; next }
    { key = $1 SUBSEP $2; count[key] += $3; latency_sum[key] += $4
      if (($5 + 0) > (latency_max[key] + 0)) latency_max[key] = $5 }
    END {
      for (key in count) {
        split(key, parts, SUBSEP); split(route_meta[parts[1]], meta, FS)
        avg = (count[key] == 0 ? 0 : latency_sum[key] / count[key])
        print sprintf("%.8f", avg), sprintf("%.4f", latency_max[key] + 0),
              count[key], meta[1], meta[2], meta[3], meta[4], parts[2]
      }
    }
  ' "$ROUTES_CATALOG" "$OVERALL_ENDPOINT_RAW_TSV" \
    | sort -t $'\t' -k1,1rn -k2,2rn > "$OVERALL_ENDPOINT_TSV"

  [[ -z "$OVERALL_SLOW_FILE" ]] && return

  {
    printf 'Environment,ServerName,Location,RouteType,Endpoint,RequestCount,AvgResponseTime,MaxResponseTime\n'
    "$AWK_BIN" -F'\t' -v limit="$SLOW_TOP_N" '
      function csv(v, tmp) { tmp=v; gsub(/\r|\n/," ",tmp); gsub(/"/,"\"\"",tmp); return "\""tmp"\"" }
      NR <= limit { print csv($4)","csv($5)","csv($6)","csv($7)","csv($8)","csv($3)","csv($1)","csv($2) }
    ' "$OVERALL_ENDPOINT_TSV"
  } > "$OVERALL_SLOW_FILE"
}

build_hourly_trend_report() {
  [[ -z "$HOURLY_TREND_FILE" && -z "$JSON_OUTPUT_FILE" && -z "$HTML_REPORT_FILE" ]] && return

  "$AWK_BIN" -F'\t' '
    FNR == NR { route_meta[$1] = $2 FS $4 FS $6 FS $7; next }
    { key = $1 SUBSEP $2; count[key] += $3; errors[key] += $4
      latency_sum[key] += $5; latency_count[key] += $6
      if (($8 + 0) > (latency_max[key] + 0)) latency_max[key] = $8 }
    END {
      for (key in count) {
        split(key, parts, SUBSEP); split(route_meta[parts[1]], meta, FS)
        avg = (latency_count[key] == 0 ? 0 : latency_sum[key] / latency_count[key])
        err_rate = (count[key] == 0 ? 0 : (errors[key] / count[key]) * 100)
        print parts[2], meta[1], meta[2], meta[3], meta[4],
              count[key], errors[key], sprintf("%.2f", err_rate),
              sprintf("%.4f", avg), sprintf("%.4f", latency_max[key] + 0)
      }
    }
  ' "$ROUTES_CATALOG" "$HOURLY_RAW_TSV" \
    | sort -t $'\t' -k1,1 -k2,2 -k3,3 -k4,4 > "$HOURLY_TREND_TSV"

  [[ -z "$HOURLY_TREND_FILE" ]] && return

  {
    printf 'HourBucket,Environment,ServerName,Location,RouteType,RequestCount,ErrorCount,ErrorRate,AvgResponseTime,MaxResponseTime\n'
    "$AWK_BIN" -F'\t' '
      function csv(v, tmp) { tmp=v; gsub(/\r|\n/," ",tmp); gsub(/"/,"\"\"",tmp); return "\""tmp"\"" }
      { print csv($1)","csv($2)","csv($3)","csv($4)","csv($5)","csv($6)","csv($7)","csv($8)","csv($9)","csv($10) }
    ' "$HOURLY_TREND_TSV"
  } > "$HOURLY_TREND_FILE"
}

write_json_export() {
  log "JSON export: $JSON_OUTPUT_FILE"
  {
    printf '{\n'
    printf '  "metadata": {\n'
    printf '    "generated_at": "%s",\n' "$GENERATED_AT"
    printf '    "main_csv": "%s",\n' "$OUTPUT_FILE"
    printf '    "overall_slow_limit": %s\n' "$SLOW_TOP_N"
    printf '  },\n'

    printf '  "routes": [\n'
    "$AWK_BIN" -F'\t' '
      BEGIN { first = 1 }
      {
        if (!first) printf ",\n"
        first = 0
        gsub(/\\/, "\\\\", $0)
        printf "    {"
        printf "\"route_id\":\"%s\",\"environment\":\"%s\",\"server_name\":\"%s\",\"location\":\"%s\",\"route_type\":\"%s\",\"backend\":\"%s\",\"real_backend\":\"%s\",\"access_log\":\"%s\"", $1, $2, $3, $4, $5, $6, $7, $8
        printf ",\"request_count\":%s,\"error_count\":%s,\"error_rate\":%s", $9+0, $10+0, $11
        printf ",\"avg_response_time\":%s,\"max_response_time\":%s,\"p50\":%s,\"p95\":%s,\"p99\":%s", $12, $13, $14, $15, $16
        printf ",\"avg_upstream_response_time\":%s,\"avg_upstream_connect_time\":%s", $17, $18
        printf ",\"top_endpoint\":\"%s\"", $19; printf ",\"top_method\":\"%s\"", $20; printf ",\"top_status\":\"%s\"", $21
        printf ",\"top_upstream\":\"%s\"", $22; printf ",\"top_upstream_share\":%s", $23+0; printf ",\"upstream_node_count\":%s", $24+0
        printf ",\"slowest_endpoint\":\"%s\"", $25; printf ",\"slowest_endpoint_avg\":%s", $26
        printf ",\"cache_hit_ratio\":%s,\"cache_miss_ratio\":%s,\"avg_bytes_sent\":%s", $27, $28, $29
        printf ",\"top_client_ip\":\"%s\"", $30; printf ",\"top_tls\":\"%s\"", $31
        printf ",\"framework\":\"%s\"", $32; printf ",\"ingress\":\"%s\"", $33; printf ",\"cluster\":\"%s\"", $34
        printf ",\"swagger\":\"%s\"", $35; printf ",\"health\":\"%s\"", $36; printf ",\"http2\":\"%s\"", $37; printf ",\"tls_version\":\"%s\"", $38
        printf ",\"risk_score\":%s", $39+0; printf ",\"risk_reasons\":\"%s\"", $40
        printf "}"
      }
      END { printf "\n  ],\n" }
    ' "$ROUTE_REPORT_TSV"

    printf '  "top_slow_endpoints": [\n'
    "$AWK_BIN" -F'\t' -v limit="$SLOW_TOP_N" '
      BEGIN { first = 1 }
      NR <= limit {
        if (!first) printf ",\n"
        first = 0
        printf "    {\"avg_response_time\":%s,\"max_response_time\":%s,\"request_count\":%s,\"environment\":\"%s\",\"server_name\":\"%s\",\"location\":\"%s\",\"route_type\":\"%s\",\"endpoint\":\"%s\"}",
          $1, $2, $3+0, $4, $5, $6, $7, $8
      }
      END { printf "\n  ],\n" }
    ' "$OVERALL_ENDPOINT_TSV"

    printf '  "hourly_trends": [\n'
    "$AWK_BIN" -F'\t' '
      BEGIN { first = 1 }
      {
        if (!first) printf ",\n"
        first = 0
        printf "    {\"hour_bucket\":\"%s\",\"environment\":\"%s\",\"server_name\":\"%s\",\"location\":\"%s\",\"route_type\":\"%s\",\"request_count\":%s,\"error_count\":%s,\"error_rate\":%s,\"avg_response_time\":%s,\"max_response_time\":%s}",
          $1, $2, $3, $4, $5, $6+0, $7+0, $8, $9, $10
      }
      END { printf "\n  ]\n" }
    ' "$HOURLY_TREND_TSV"

    printf '}\n'
  } > "$JSON_OUTPUT_FILE"
  log "JSON yazildi: $JSON_OUTPUT_FILE"
}

write_html_report() {
  log "HTML rapor: $HTML_REPORT_FILE"

  # --- Compute summary stats ---
  local total_routes total_requests total_errors avg_risk high_risk_count
  total_routes=$("$AWK_BIN" 'END { print NR }' "$ROUTE_REPORT_TSV")
  total_requests=$("$AWK_BIN" -F'\t' '{s+=$9} END {print s+0}' "$ROUTE_REPORT_TSV")
  total_errors=$("$AWK_BIN" -F'\t' '{s+=$10} END {print s+0}' "$ROUTE_REPORT_TSV")
  avg_risk=$("$AWK_BIN" -F'\t' '{s+=$40; c++} END {if(c>0) printf "%.1f", s/c; else print "0"}' "$ROUTE_REPORT_TSV")
  high_risk_count=$("$AWK_BIN" -F'\t' 'BEGIN{c=0} {if($40+0 >= 50) c++} END {print c}' "$ROUTE_REPORT_TSV")

  # --- Prepare chart data for 24h / 7d / 30d windows ---
  local labels_24 c24 e24 l24 labels_168 c168 e168 l168 labels_720 c720 e720 l720

  # 24h window
  labels_24=$("$AWK_BIN" -F'\t' '
    {
      split($1, d, "T"); split(d[2], h, ":")
      key = (h[1]+0) ":00"
      count[key] += $6; errors[key] += $7
      lat_sum[key] += $9 * $6; lat_cnt[key] += $6
    }
    END {
      for(i=0; i<24; i++) { k=sprintf("%02d:00",i); if(!count[k])count[k]=0; if(!errors[k])errors[k]=0; if(!lat_cnt[k])lat_cnt[k]=0 }
      n=asorti(count,sorted)
      for(i=1;i<=n;i++) { k=sorted[i]; printf "%s%s", (i>1?",":""), "\""k"\"" }
      print ""
    }
  ' "$HOURLY_TREND_TSV")
  c24=$("$AWK_BIN" -F'\t' '
    { split($1,d,"T"); split(d[2],h,":"); key=(h[1]+0)":00"; count[key]+=$6 }
    END { for(i=0;i<24;i++){k=sprintf("%02d:00",i);if(!count[k])count[k]=0}
      n=asorti(count,sorted); for(i=1;i<=n;i++)printf "%s%s",(i>1?",":""),count[sorted[i]]; print ""
    }
  ' "$HOURLY_TREND_TSV")
  e24=$("$AWK_BIN" -F'\t' '
    { split($1,d,"T"); split(d[2],h,":"); key=(h[1]+0)":00"; errors[key]+=$7 }
    END { for(i=0;i<24;i++){k=sprintf("%02d:00",i);if(!errors[k])errors[k]=0}
      n=asorti(errors,sorted); for(i=1;i<=n;i++)printf "%s%s",(i>1?",":""),errors[sorted[i]]; print ""
    }
  ' "$HOURLY_TREND_TSV")
  l24=$("$AWK_BIN" -F'\t' '
    { split($1,d,"T"); split(d[2],h,":"); key=(h[1]+0)":00"; lat_sum[key]+=$9*$6; lat_cnt[key]+=$6 }
    END { for(i=0;i<24;i++){k=sprintf("%02d:00",i);if(!lat_cnt[k])lat_cnt[k]=0;if(!lat_sum[k])lat_sum[k]=0}
      n=asorti(lat_sum,sorted)
      for(i=1;i<=n;i++){k=sorted[i];v=(lat_cnt[k]?lat_sum[k]/lat_cnt[k]*1000:0);printf "%s%.2f",(i>1?",":""),v}
      print ""
    }
  ' "$HOURLY_TREND_TSV")

  # 7d window
  labels_168=$("$AWK_BIN" -F'\t' '
    { split($1,d,"T"); key = d[1] " " d[2]; count[key]+=$6; errors[key]+=$7; lat_sum[key]+=$9*$6; lat_cnt[key]+=$6 }
    END {
      n=asorti(count,sorted)
      for(i=1;i<=n && i<=168;i++) { k=sorted[i]; printf "%s%s", (i>1?",":""), "\""substr(k,6)"\"" }
      print ""
    }
  ' "$HOURLY_TREND_TSV")
  c168=$("$AWK_BIN" -F'\t' '
    { split($1,d,"T"); key=d[1]" "d[2]; count[key]+=$6 }
    END { n=asorti(count,sorted); for(i=1;i<=n && i<=168;i++) printf "%s%s",(i>1?",":""),count[sorted[i]]; print "" }
  ' "$HOURLY_TREND_TSV")
  e168=$("$AWK_BIN" -F'\t' '
    { split($1,d,"T"); key=d[1]" "d[2]; errors[key]+=$7 }
    END { n=asorti(errors,sorted); for(i=1;i<=n && i<=168;i++) printf "%s%s",(i>1?",":""),errors[sorted[i]]; print "" }
  ' "$HOURLY_TREND_TSV")
  l168=$("$AWK_BIN" -F'\t' '
    { split($1,d,"T"); key=d[1]" "d[2]; lat_sum[key]+=$9*$6; lat_cnt[key]+=$6 }
    END { n=asorti(lat_sum,sorted); for(i=1;i<=n && i<=168;i++){k=sorted[i];v=(lat_cnt[k]?lat_sum[k]/lat_cnt[k]*1000:0);printf "%s%.2f",(i>1?",":""),v}; print "" }
  ' "$HOURLY_TREND_TSV")

  # 30d window
  labels_720=$("$AWK_BIN" -F'\t' '
    { split($1,d,"T"); key=d[1]; count[key]+=$6; errors[key]+=$7; lat_sum[key]+=$9*$6; lat_cnt[key]+=$6 }
    END { n=asorti(count,sorted); for(i=1;i<=n && i<=720;i++) printf "%s%s",(i>1?",":""),"\""substr(sorted[i],6)"\""; print "" }
  ' "$HOURLY_TREND_TSV")
  c720=$("$AWK_BIN" -F'\t' '
    { split($1,d,"T"); key=d[1]; count[key]+=$6 }
    END { n=asorti(count,sorted); for(i=1;i<=n && i<=720;i++) printf "%s%s",(i>1?",":""),count[sorted[i]]; print "" }
  ' "$HOURLY_TREND_TSV")
  e720=$("$AWK_BIN" -F'\t' '
    { split($1,d,"T"); key=d[1]; errors[key]+=$7 }
    END { n=asorti(errors,sorted); for(i=1;i<=n && i<=720;i++) printf "%s%s",(i>1?",":""),errors[sorted[i]]; print "" }
  ' "$HOURLY_TREND_TSV")
  l720=$("$AWK_BIN" -F'\t' '
    { split($1,d,"T"); key=d[1]; lat_sum[key]+=$9*$6; lat_cnt[key]+=$6 }
    END { n=asorti(lat_sum,sorted); for(i=1;i<=n && i<=720;i++){k=sorted[i];v=(lat_cnt[k]?lat_sum[k]/lat_cnt[k]*1000:0);printf "%s%.2f",(i>1?",":""),v}; print "" }
  ' "$HOURLY_TREND_TSV")

  # --- Risk table rows ---
  local risk_rows_html=""
  while IFS=$'\t' read -r rid env_n srv loc rt backend real_backend al og_err_rate p95 p99 score reas; do
    local rc tags
    rc="risk-low"
    awk_rc=$(echo "$score" | "$AWK_BIN" '{s=$1+0; if(s>=70) print "risk-high"; else if(s>=40) print "risk-med"; else print "risk-low"}')
    rc="$awk_rc"
    tags=""
    IFS=';' read -ra tarr <<< "$reas"
    for t in "${tarr[@]}"; do
      [[ -z "$t" || "$t" == "yok" ]] && continue
      tags+="<span class=\"rtag\">$t</span>"
    done
    risk_rows_html+="<tr><td class=\"mono\">$(csv_escape "$rid")</td><td>$(csv_escape "$env_n")</td><td>$(csv_escape "$srv")</td><td>$(csv_escape "$rt")</td><td class=\"mono\">$og</td><td class=\"mono\">$err_rate</td><td class=\"mono\">$p95</td><td class=\"mono\">$p99</td><td><span class=\"risk $rc\">$score</span></td><td>$tags</td></tr>"
  done < <("$AWK_BIN" -F'\t' -v limit="$SLOW_TOP_N" \
    '{s=$40+0; if(s>=50){print $1"\t"$2"\t"$3"\t"$5"\t"$9"\t"$11"\t"$15"\t"$16"\t"s"\t"$40"\t"$41}}' \
    "$ROUTE_REPORT_TSV" | sort -t $'\t' -k9,9rn | head -20 | while IFS=$'\t' read -r rid2 env2 srv2 rt2 req2 err2 p952 p992 score2 reas2; do
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$rid2" "$env2" "$srv2" "$rt2" "$req2" "$err2" "$p952" "$p992" "$score2" "$reas2"
  done)

  # --- Slow endpoints table rows ---
  local slow_rows_html=""
  while IFS=$'\t' read -r avg_t max_t cnt env_n srv loc rt ep; do
    slow_rows_html+="<tr><td class=\"mono\">$(csv_escape "$ep")</td><td>$(csv_escape "$env_n")</td><td>$(csv_escape "$srv")</td><td>$(csv_escape "$loc")</td><td class=\"mono\">$cnt</td><td class=\"mono\">$avg_t</td><td class=\"mono\">$max_t</td></tr>"
  done < <("$AWK_BIN" -F'\t' -v limit="$SLOW_TOP_N" 'NR <= limit { print }' "$OVERALL_ENDPOINT_TSV")

  # --- Write HTML ---
  cat > "$HTML_REPORT_FILE" <<HTMLEOF
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nginx Reverse Proxy Intelligence — ${ENVIRONMENT}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#0a0c10;--surface:#111318;--border:#1e2330;--accent:#00e5a0;--accent2:#ff4c6a;--accent3:#4c9fff;--text:#d4dbe8;--muted:#5a6480;--risk-high:#ff4c6a;--risk-med:#ffb340;--risk-low:#00e5a0;--font-head:system-ui,sans-serif;--font-mono:"JetBrains Mono",monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font-mono);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;z-index:0;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:40px 40px;opacity:.35;pointer-events:none}
.container{position:relative;z-index:1;max-width:1400px;margin:0 auto;padding:2rem}
header{display:flex;align-items:flex-end;justify-content:space-between;padding:2.5rem 0 2rem;border-bottom:1px solid var(--border);margin-bottom:2rem}
.logo{font-family:var(--font-head);font-size:2.2rem;font-weight:800;letter-spacing:-.02em;line-height:1}
.logo span{color:var(--accent)}
.meta{font-size:.72rem;color:var(--muted);text-align:right;line-height:1.8}
.env-badge{display:inline-block;padding:.15rem .6rem;background:color-mix(in srgb,var(--accent) 15%,transparent);border:1px solid var(--accent);border-radius:3px;color:var(--accent);font-size:.68rem;letter-spacing:.08em;text-transform:uppercase}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;margin-bottom:2rem}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.25rem 1.5rem;position:relative;overflow:hidden;transition:border-color .2s}
.kpi:hover{border-color:var(--accent)}
.kpi::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent-color,var(--accent))}
.kpi-label{font-size:.68rem;color:var(--muted);letter-spacing:.1em;text-transform:uppercase;margin-bottom:.5rem}
.kpi-value{font-family:var(--font-head);font-size:2rem;font-weight:800;line-height:1}
.kpi-sub{font-size:.7rem;color:var(--muted);margin-top:.35rem}
.tabs{display:flex;gap:.5rem;margin-bottom:1.5rem}
.tab{background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--font-mono);font-size:.78rem;padding:.5rem 1.25rem;border-radius:4px;cursor:pointer;letter-spacing:.05em;transition:all .15s}
.tab:hover{border-color:var(--accent);color:var(--accent)}
.tab.active{background:color-mix(in srgb,var(--accent) 12%,transparent);border-color:var(--accent);color:var(--accent)}
.tab-panel{display:none}
.tab-panel.active{display:block}
.chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.5rem}
@media(max-width:900px){.chart-grid{grid-template-columns:1fr}}
.chart-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.25rem}
.chart-card.full{grid-column:1/-1}
.chart-title{font-family:var(--font-head);font-size:.9rem;font-weight:700;margin-bottom:1rem;color:var(--text)}
.chart-wrap{position:relative;height:220px}
.table-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:1.5rem}
.table-head{padding:1rem 1.25rem;border-bottom:1px solid var(--border);font-family:var(--font-head);font-size:.9rem;font-weight:700;display:flex;align-items:center;justify-content:space-between}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.74rem}
thead th{background:#0d1016;padding:.6rem 1rem;text-align:left;font-size:.65rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);white-space:nowrap;border-bottom:1px solid var(--border)}
tbody tr{border-bottom:1px solid var(--border);transition:background .12s}
tbody tr:hover{background:rgba(255,255,255,.025)}
tbody td{padding:.55rem 1rem;white-space:nowrap}
.mono{font-family:var(--font-mono)}
.risk{display:inline-block;padding:.2rem .55rem;border-radius:3px;font-weight:700;font-size:.7rem}
.risk-high{background:color-mix(in srgb,var(--risk-high) 18%,transparent);color:var(--risk-high)}
.risk-med{background:color-mix(in srgb,var(--risk-med) 18%,transparent);color:var(--risk-med)}
.risk-low{background:color-mix(in srgb,var(--risk-low) 18%,transparent);color:var(--risk-low)}
.rtag{display:inline-block;padding:.1rem .4rem;background:rgba(255,255,255,.06);border-radius:2px;font-size:.63rem;color:var(--muted);margin:.1rem}
footer{border-top:1px solid var(--border);margin-top:3rem;padding:1.5rem 0;font-size:.68rem;color:var(--muted);display:flex;justify-content:space-between;align-items:center}
</style>
</head>
<body>
<div class="container">
<header>
<div><div class="logo">nginx<span>.</span>perf</div><div style="margin-top:.5rem;font-size:.78rem;color:var(--muted)">Reverse Proxy Intelligence &amp; Performance</div></div>
<div class="meta"><span class="env-badge">${ENVIRONMENT}</span><br>${GENERATED_AT}<br>${total_routes} routes</div>
</header>

<div class="kpi-grid">
<div class="kpi" style="--accent-color:var(--accent3)"><div class="kpi-label">Total Routes</div><div class="kpi-value">${total_routes}</div><div class="kpi-sub">active endpoints</div></div>
<div class="kpi" style="--accent-color:var(--accent)"><div class="kpi-label">Total Requests</div><div class="kpi-value">${total_requests}</div><div class="kpi-sub">analyzed</div></div>
<div class="kpi" style="--accent-color:var(--accent2)"><div class="kpi-label">Total Errors</div><div class="kpi-value">${total_errors}</div><div class="kpi-sub">4xx + 5xx</div></div>
<div class="kpi" style="--accent-color:var(--risk-med)"><div class="kpi-label">Avg Risk Score</div><div class="kpi-value">${avg_risk}</div><div class="kpi-sub">0-100 scale</div></div>
<div class="kpi" style="--accent-color:var(--risk-high)"><div class="kpi-label">High Risk Routes</div><div class="kpi-value">${high_risk_count}</div><div class="kpi-sub">score >= 50</div></div>
</div>

<div class="tabs">
<button class="tab active" onclick="switchTab('daily',this)">Daily (24h)</button>
<button class="tab" onclick="switchTab('weekly',this)">Weekly (7d)</button>
<button class="tab" onclick="switchTab('monthly',this)">Monthly (30d)</button>
<button class="tab" onclick="switchTab('risk',this)">Risk Analysis</button>
<button class="tab" onclick="switchTab('slow',this)">Slowest</button>
</div>

<div id="tab-daily" class="tab-panel active">
<div class="chart-grid">
<div class="chart-card"><div class="chart-title">Requests (last 24h)</div><div class="chart-wrap"><canvas id="c-dr"></canvas></div></div>
<div class="chart-card"><div class="chart-title">Errors (last 24h)</div><div class="chart-wrap"><canvas id="c-de"></canvas></div></div>
<div class="chart-card full"><div class="chart-title">Avg Response Time (last 24h) — ms</div><div class="chart-wrap"><canvas id="c-dl"></canvas></div></div>
</div></div>

<div id="tab-weekly" class="tab-panel">
<div class="chart-grid">
<div class="chart-card"><div class="chart-title">Requests (last 7d)</div><div class="chart-wrap"><canvas id="c-wr"></canvas></div></div>
<div class="chart-card"><div class="chart-title">Errors (last 7d)</div><div class="chart-wrap"><canvas id="c-we"></canvas></div></div>
<div class="chart-card full"><div class="chart-title">Avg Response Time (last 7d) — ms</div><div class="chart-wrap"><canvas id="c-wl"></canvas></div></div>
</div></div>

<div id="tab-monthly" class="tab-panel">
<div class="chart-grid">
<div class="chart-card"><div class="chart-title">Requests (last 30d)</div><div class="chart-wrap"><canvas id="c-mr"></canvas></div></div>
<div class="chart-card"><div class="chart-title">Errors (last 30d)</div><div class="chart-wrap"><canvas id="c-me"></canvas></div></div>
<div class="chart-card full"><div class="chart-title">Avg Response Time (last 30d) — ms</div><div class="chart-wrap"><canvas id="c-ml"></canvas></div></div>
</div></div>

<div id="tab-risk" class="tab-panel">
<div class="table-card">
<div class="table-head"><span>High Risk Routes (score >= 50)</span><span style="font-size:.72rem;color:var(--muted)">${high_risk_count} routes</span></div>
<div class="table-wrap"><table><thead><tr><th>ID</th><th>Env</th><th>Server</th><th>Type</th><th>Requests</th><th>Error%</th><th>P95</th><th>P99</th><th>Risk</th><th>Reasons</th></tr></thead><tbody>${risk_rows_html}</tbody></table></div></div></div>

<div id="tab-slow" class="tab-panel">
<div class="table-card">
<div class="table-head"><span>Slowest Endpoints</span><span style="font-size:.72rem;color:var(--muted)">top ${SLOW_TOP_N}</span></div>
<div class="table-wrap"><table><thead><tr><th>Endpoint</th><th>Env</th><th>Server</th><th>Location</th><th>Requests</th><th>Avg (s)</th><th>Max (s)</th></tr></thead><tbody>${slow_rows_html}</tbody></table></div></div></div>

<footer><span>nginx.perf — ${ENVIRONMENT}</span><span>${GENERATED_AT}</span></footer>
</div>

<script>
const D={responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#5a6480',font:{family:'JetBrains Mono',size:10}},grid:{color:'#1e2330'}},y:{ticks:{color:'#5a6480',font:{family:'JetBrains Mono',size:10}},grid:{color:'#1e2330'}}}}
function b(id,l,d,c){const ctx=document.getElementById(id);if(!ctx)return;new Chart(ctx,{type:'bar',data:{labels:l,datasets:[{data:d,backgroundColor:c+'55',borderColor:c,borderWidth:1,borderRadius:2}]},options:D})}
function l(id,l,d,c){const ctx=document.getElementById(id);if(!ctx)return;new Chart(ctx,{type:'line',data:{labels:l,datasets:[{data:d,borderColor:c,backgroundColor:c+'20',borderWidth:2,pointRadius:2,fill:true,tension:.35}]},options:D})}
b('c-dr',[${labels_24}],[${c24}],'#4c9fff')
b('c-de',[${labels_24}],[${e24}],'#ff4c6a')
l('c-dl',[${labels_24}],[${l24}],'#00e5a0')
b('c-wr',[${labels_168}],[${c168}],'#4c9fff')
b('c-we',[${labels_168}],[${e168}],'#ff4c6a')
l('c-wl',[${labels_168}],[${l168}],'#00e5a0')
b('c-mr',[${labels_720}],[${c720}],'#4c9fff')
b('c-me',[${labels_720}],[${e720}],'#ff4c6a')
l('c-ml',[${labels_720}],[${l720}],'#00e5a0')
function switchTab(n,b){document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.getElementById('tab-'+n).classList.add('active');b.classList.add('active')}
</script>
</body></html>
HTMLEOF
  log "HTML rapor yazildi: $HTML_REPORT_FILE"
}

# =============================================================================
# ARGUMAN AYRISTIRMA
# =============================================================================

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config)        [[ $# -lt 2 ]] && die "--config deger eksik"; MAIN_CONFIG="$2"; shift 2 ;;
      --env)           [[ $# -lt 2 ]] && die "--env deger eksik"; ENVIRONMENT="$2"; shift 2 ;;
      --output)        [[ $# -lt 2 ]] && die "--output deger eksik"; OUTPUT_FILE="$2"; shift 2 ;;
      --json-output)   [[ $# -lt 2 ]] && die "--json-output deger eksik"; JSON_OUTPUT_FILE="$2"; shift 2 ;;
      --overall-slow)  [[ $# -lt 2 ]] && die "--overall-slow deger eksik"; OVERALL_SLOW_FILE="$2"; shift 2 ;;
      --hourly-trend)  [[ $# -lt 2 ]] && die "--hourly-trend deger eksik"; HOURLY_TREND_FILE="$2"; shift 2 ;;
      --html-report)   [[ $# -lt 2 ]] && die "--html-report deger eksik"; HTML_REPORT_FILE="$2"; shift 2 ;;
      --probe-host)    [[ $# -lt 2 ]] && die "--probe-host deger eksik"; PROBE_HOST_OVERRIDE="$2"; shift 2 ;;
      --scheme)        [[ $# -lt 2 ]] && die "--scheme deger eksik"; PROBE_SCHEME="$2"; shift 2 ;;
      --port)          [[ $# -lt 2 ]] && die "--port deger eksik"; PROBE_PORT="$2"; shift 2 ;;
      --slow-top)      [[ $# -lt 2 ]] && die "--slow-top deger eksik"; SLOW_TOP_N="$2"; shift 2 ;;
      --tail-lines)    [[ $# -lt 2 ]] && die "--tail-lines deger eksik"; TAIL_LINES="$2"; shift 2 ;;
      --timeout)       [[ $# -lt 2 ]] && die "--timeout deger eksik"; TIMEOUT="$2"; shift 2 ;;
      --skip-probes)   SKIP_PROBES=1; shift ;;
      --secure)        INSECURE=0; shift ;;
      --verbose)       VERBOSE=1; shift ;;
      -h|--help)       usage; exit 0 ;;
      *)               die "Bilinmeyen secenek: $1" ;;
    esac
  done

  [[ "$PROBE_SCHEME" == "http" || "$PROBE_SCHEME" == "https" ]] || die "--scheme http veya https olmali"
  [[ "$SLOW_TOP_N" =~ ^[0-9]+$ ]] || die "--slow-top pozitif tam sayi olmali"
  [[ "$TAIL_LINES" =~ ^[0-9]+$ ]] || die "--tail-lines pozitif tam sayi olmali"
}

# =============================================================================
# CALISMA ALANI HAZIRLIK
# =============================================================================

prepare_workspace() {
  TMP_DIR="$(mktemp -d)"
  ROUTES_RAW="$TMP_DIR/routes_raw.tsv"
  ROUTES_CATALOG="$TMP_DIR/routes_catalog.tsv"
  RUNTIME_TSV="$TMP_DIR/runtime.tsv"
  DISCOVERY_TSV="$TMP_DIR/discovery.tsv"
  ROUTE_REPORT_TSV="$TMP_DIR/route_report.tsv"
  OVERALL_ENDPOINT_RAW_TSV="$TMP_DIR/overall_endpoint_raw.tsv"
  OVERALL_ENDPOINT_TSV="$TMP_DIR/overall_endpoint.tsv"
  HOURLY_RAW_TSV="$TMP_DIR/hourly_raw.tsv"
  HOURLY_TREND_TSV="$TMP_DIR/hourly_trend.tsv"
  RUNTIME_AWK_SCRIPT="$TMP_DIR/runtime_analysis.awk"
  CONFIG_LIST="$TMP_DIR/config_files.txt"
  : > "$TMP_DIR/http_tls.tsv"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
  parse_args "$@"

  # Config auto-detect
  if [[ -z "$MAIN_CONFIG" ]]; then
    for candidate in /usr/nginx/conf/nginx.conf /etc/nginx/nginx.conf /usr/local/nginx/conf/nginx.conf; do
      if [[ -f "$candidate" ]]; then MAIN_CONFIG="$candidate"; log "Config auto-detect: $MAIN_CONFIG"; break; fi
    done
  fi
  [[ -n "$MAIN_CONFIG" ]] || die "Config bulunamadi. --config ile belirtin veya /usr/nginx/conf/nginx.conf kullanin"
  [[ -f "$MAIN_CONFIG" ]] || die "Config dosyasi bulunamadi: $MAIN_CONFIG"

  # Dependency check
  need_bin bash
  if command -v gawk >/dev/null 2>&1; then AWK_BIN="gawk"; else AWK_BIN="awk"; fi
  need_bin "$AWK_BIN"; need_bin sed; need_bin grep; need_bin sort
  need_bin tail; need_bin tr; need_bin curl; need_bin openssl; need_bin mktemp

  GENERATED_AT="$(date '+%Y-%m-%dT%H:%M:%S%z')"
  prepare_workspace

  # --- Phase 1: Config ---
  log "Config dosyalari taranıyor: $MAIN_CONFIG"
  collect_config_files "$MAIN_CONFIG"

  log "Nginx route/upstream cozumleniyor"
  parse_nginx_config

  log "Rota katalogu olusturuluyor"
  build_routes_catalog
  [[ -s "$ROUTES_CATALOG" ]] || die "Config'de proxy_pass ile hicbir location bulunamadi"

  # --- Phase 2: Log Analytics ---
  log "Access log analizi baslatiliyor"
  analyze_logs

  # --- Phase 3: Discovery ---
  log "Canli curl/openssl kesfi yapiliyor"
  run_discovery

  # --- Phase 4: Risk + Report TSV ---
  log "Risk skorlama ve rapor TSV olusturuluyor"
  build_route_report_tsv

  # --- Phase 5: Outputs ---
  log "Ana CSV yaziliyor: $OUTPUT_FILE"
  write_final_csv

  build_overall_slow_report
  build_hourly_trend_report

  if [[ -n "$JSON_OUTPUT_FILE" ]]; then
    log "JSON export: $JSON_OUTPUT_FILE"
    write_json_export
  fi

  if [[ -n "$HTML_REPORT_FILE" ]]; then
    log "HTML rapor: $HTML_REPORT_FILE"
    write_html_report
  fi

  # --- Summary ---
  printf '\n=== TAMAMLANDI ===\n'
  printf '  Ana CSV       : %s\n' "$OUTPUT_FILE"
  [[ -n "$OVERALL_SLOW_FILE" ]] && printf '  Yavas EP      : %s\n' "$OVERALL_SLOW_FILE"
  [[ -n "$HOURLY_TREND_FILE" ]] && printf '  Saatlik trend : %s\n' "$HOURLY_TREND_FILE"
  [[ -n "$JSON_OUTPUT_FILE"  ]] && printf '  JSON          : %s\n' "$JSON_OUTPUT_FILE"
  [[ -n "$HTML_REPORT_FILE"  ]] && printf '  HTML Dashboard: %s\n' "$HTML_REPORT_FILE"
  printf '  Rota sayisi   : %s\n' "$(wc -l < "$ROUTES_CATALOG")"
}

main "$@"
