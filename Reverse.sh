#!/usr/bin/env bash

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
TIMEOUT=10
OUTPUT_FILE="enterprise_inventory.csv"
ENVIRONMENT="unknown"
MAIN_CONFIG=""
PROBE_HOST_OVERRIDE=""
PROBE_SCHEME="https"
PROBE_PORT=""
INSECURE=1
VERBOSE=0
AWK_BIN="awk"

TMP_DIR=""
ROUTES_RAW=""
ROUTES_CATALOG=""
RUNTIME_TSV=""
DISCOVERY_TSV=""
CONFIG_LIST=""

declare -A HOST_TLS_CACHE=()
declare -A HOST_HTTP2_CACHE=()
declare -A HOST_INGRESS_CACHE=()

usage() {
  cat <<'EOF'
Usage:
  ./info.sh [options]

Options:
  --config FILE         Main nginx config file (optional, auto-detects /usr/nginx/conf/nginx.conf)
  --env NAME            Environment label written to export. Default: unknown
  --output FILE         Final single CSV export. Default: enterprise_inventory.csv
  --probe-host HOST     Override server_name for live curl/openssl discovery
  --scheme http|https   Probe scheme for live discovery. Default: https
  --port PORT           Override probe port for live discovery
  --timeout SEC         Curl/openssl timeout. Default: 10
  --secure              Verify TLS certificates during live probes
  --verbose             Print progress logs
  -h, --help            Show help

Auto-detection paths:
  Config: /usr/nginx/conf/nginx.conf -> /etc/nginx/nginx.conf -> /usr/local/nginx/conf/nginx.conf
  Config includes: only *.conf files from include directives
  Logs:    access_log from config -> /web_log/*.log fallback

Notes:
  - Three-layer hybrid model:
       1. Config parsing  (route -> backend mapping)
       2. Access log analytics (runtime stats per route)
       3. Live discovery with curl + openssl (TLS, swagger, health, framework)
  - Temporary files cleaned automatically. Single CSV export only.
  - Requires: bash, awk, sed, grep, sort, curl, openssl, mktemp
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
    printf '/%s' "$right"
  elif [[ -z "$right" ]]; then
    printf '%s' "$left"
  else
    printf '%s/%s' "$left" "$right"
  fi
}

extract_host_from_proxy_pass() {
  local value="${1-}"
  value="${value#http://}"
  value="${value#https://}"
  value="${value%%/*}"
  value="${value%%\?*}"
  value="${value%%\$*}"
  printf '%s' "$value"
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
      if (loc_path == "") {
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

analyze_single_log() {
  local log_file="$1"
  local route_subset="$2"
  local out_file="$3"

  if [[ ! -r "$log_file" ]]; then
    return
  fi

  "$AWK_BIN" -v route_file="$route_subset" '
    function tolower_safe(s) {
      return tolower(s)
    }

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

    function load_routes(   line, parts, order_count, key) {
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

    function best_route(path,   i, idx, candidate, next_char) {
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

    function parse_line(   n, i, item, pos, key, value) {
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
      return 1
    }

    function top_value(prefix, route_id,   key, count, winner, best) {
      winner = ""
      best = -1
      for (key in counters) {
        split(key, k, SUBSEP)
        if (k[1] == prefix && k[2] == route_id) {
          count = counters[key]
          if (count > best) {
            best = count
            winner = k[3]
          }
        }
      }
      if (winner == "") {
        return "-"
      }
      return winner
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

      status = kv["status"] + 0
      method = kv["method"]
      upstream = kv["upstream_addr"]
      req_time = kv["request_time"] + 0
      client_ip = kv["client_ip"]
      tls = kv["ssl_protocol"]

      counts[route_id]++
      errors[route_id] += (status >= 400 ? 1 : 0)
      latency_sum[route_id] += req_time

      if (method == "") {
        method = "-"
      }
      if (upstream == "") {
        upstream = "-"
      }
      if (client_ip == "") {
        client_ip = "-"
      }
      if (tls == "") {
        tls = "-"
      }

      counters["endpoint" SUBSEP route_id SUBSEP request]++
      counters["method" SUBSEP route_id SUBSEP method]++
      counters["upstream" SUBSEP route_id SUBSEP upstream]++
      counters["client" SUBSEP route_id SUBSEP client_ip]++
      counters["tls" SUBSEP route_id SUBSEP tls]++
    }

    END {
      for (route_id in counts) {
        avg = (counts[route_id] == 0 ? 0 : latency_sum[route_id] / counts[route_id])
        err_rate = (counts[route_id] == 0 ? 0 : (errors[route_id] / counts[route_id]) * 100)
        print route_id,
              top_value("endpoint", route_id),
              top_value("method", route_id),
              top_value("upstream", route_id),
              counts[route_id],
              errors[route_id],
              sprintf("%.2f", err_rate),
              sprintf("%.4f", avg),
              top_value("client", route_id),
              top_value("tls", route_id)
      }
    }
  ' "$log_file" >> "$out_file"
}

analyze_logs() {
  : > "$RUNTIME_TSV"
  local unique_logs_file route_subset log_file
  unique_logs_file="$TMP_DIR/unique_logs.txt"

  "$AWK_BIN" -F'\t' '$10 != "-" && $7 != "regex" && $7 != "named" { print $10 }' "$ROUTES_CATALOG" | sort -u > "$unique_logs_file"

  if [[ ! -s "$unique_logs_file" ]]; then
    log "No access_log found in config, trying /web_log/*.log"
    local found=0
    for f in /web_log/*.log; do
      if [[ -f "$f" ]]; then
        printf '%s\n' "$f" >> "$unique_logs_file"
        found=1
      fi
    done
    if [[ "$found" -eq 0 ]]; then
      log "No log files found in /web_log/"
      return
    fi
  fi

  while IFS= read -r log_file; do
    [[ -n "$log_file" ]] || continue
    route_subset="$TMP_DIR/$(printf '%s' "$log_file" | tr '/:' '__').routes.tsv"
    "$AWK_BIN" -F'\t' -v target="$log_file" 'BEGIN { OFS = "\t" } $10 == target && $7 != "regex" && $7 != "named" { print $1, $6 }' "$ROUTES_CATALOG" > "$route_subset"
    if [[ ! -s "$route_subset" ]]; then
      "$AWK_BIN" -F'\t' '$7 != "regex" && $7 != "named" { print $1, $6 }' "$ROUTES_CATALOG" > "$route_subset"
      log "Using all routes for auto-detected log: $log_file"
    fi
    analyze_single_log "$log_file" "$route_subset" "$RUNTIME_TSV"
  done < "$unique_logs_file"
}

probe_http_headers() {
  local url="$1"
  local curl_args=(-sS -L -m "$TIMEOUT" -D - -o /dev/null)

  if [[ "$INSECURE" -eq 1 ]]; then
    curl_args+=(-k)
  fi

  curl "${curl_args[@]}" "$url" 2>/dev/null || true
}

probe_http_body() {
  local url="$1"
  local curl_args=(-sS -L -m "$TIMEOUT")

  if [[ "$INSECURE" -eq 1 ]]; then
    curl_args+=(-k)
  fi

  curl "${curl_args[@]}" "$url" 2>/dev/null | head -c 20000 || true
}

get_tls_version() {
  local host="$1"
  local port="$2"
  local cache_key="$host:$port"

  if [[ -n "${HOST_TLS_CACHE[$cache_key]:-}" ]]; then
    printf '%s' "${HOST_TLS_CACHE[$cache_key]}"
    return
  fi

  local result protocol
  result="$(printf '' | openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null || true)"
  protocol="$("$AWK_BIN" -F': ' '/Protocol[[:space:]]*:/ { print $2; exit }' <<<"$result")"
  [[ -z "$protocol" ]] && protocol="unknown"
  HOST_TLS_CACHE["$cache_key"]="$protocol"
  printf '%s' "$protocol"
}

get_http2_status() {
  local host="$1"
  local route="$2"
  local port="$3"
  local cache_key="$host:$port"

  if [[ -n "${HOST_HTTP2_CACHE[$cache_key]:-}" ]]; then
    printf '%s' "${HOST_HTTP2_CACHE[$cache_key]}"
    return
  fi

  local url version curl_args
  url="${PROBE_SCHEME}://$host"
  if [[ -n "$port" ]]; then
    url="${PROBE_SCHEME}://$host:$port"
  fi
  url="${url}$(join_url_path "$route" "")"

  curl_args=(-sS -o /dev/null -w '%{http_version}' --http2 -m "$TIMEOUT")
  if [[ "$INSECURE" -eq 1 ]]; then
    curl_args+=(-k)
  fi

  version="$(curl "${curl_args[@]}" "$url" 2>/dev/null || true)"
  case "$version" in
    2|2.0) HOST_HTTP2_CACHE["$cache_key"]="yes" ;;
    1|1.0|1.1|3) HOST_HTTP2_CACHE["$cache_key"]="no" ;;
    *) HOST_HTTP2_CACHE["$cache_key"]="unknown" ;;
  esac

  printf '%s' "${HOST_HTTP2_CACHE[$cache_key]}"
}

detect_cluster() {
  local combined="${1-} ${2-} ${3-}"
  combined="${combined,,}"
  if [[ "$combined" == *".svc.cluster.local"* || "$combined" == *".svc"* || "$combined" == *".apps."* || "$combined" == *"openshift"* ]]; then
    printf 'openshift/kubernetes'
  elif [[ "$combined" == *"cluster.local"* || "$combined" == *"kubernetes"* ]]; then
    printf 'kubernetes'
  else
    printf 'unknown'
  fi
}

detect_ingress() {
  local headers="${1,,}"
  local backend="${2,,}"
  local real_backend="${3,,}"
  local key="$backend|$real_backend|$headers"

  if [[ -n "${HOST_INGRESS_CACHE[$key]:-}" ]]; then
    printf '%s' "${HOST_INGRESS_CACHE[$key]}"
    return
  fi

  if [[ "$headers" == *"server: envoy"* || "$headers" == *"x-envoy"* || "$headers" == *"istio"* ]]; then
    HOST_INGRESS_CACHE["$key"]="envoy/istio"
  elif [[ "$headers" == *"server: openresty"* ]]; then
    HOST_INGRESS_CACHE["$key"]="openresty"
  elif [[ "$headers" == *"server: nginx"* || "$headers" == *"via: nginx"* ]]; then
    HOST_INGRESS_CACHE["$key"]="nginx"
  elif [[ "$backend $real_backend" == *".apps."* || "$backend $real_backend" == *".svc"* || "$backend $real_backend" == *"openshift"* ]]; then
    HOST_INGRESS_CACHE["$key"]="openshift-router"
  else
    HOST_INGRESS_CACHE["$key"]="unknown"
  fi

  printf '%s' "${HOST_INGRESS_CACHE[$key]}"
}

detect_framework() {
  local headers="${1,,}"
  local body="${2,,}"

  if [[ "$headers" == *"x-powered-by: spring"* || "$body" == *"spring boot"* ]]; then
    printf 'spring'
  elif [[ "$headers" == *"x-powered-by: express"* ]]; then
    printf 'express'
  elif [[ "$headers" == *"x-powered-by: asp.net"* || "$headers" == *"server: kestrel"* ]]; then
    printf 'aspnet'
  elif [[ "$body" == *"__next_data__"* || "$body" == *"/_next/"* ]]; then
    printf 'nextjs'
  elif [[ "$body" == *"ng-version"* || "$body" == *"angular"* ]]; then
    printf 'angular'
  elif [[ "$body" == *"data-reactroot"* || "$body" == *"react"* ]]; then
    printf 'react'
  elif [[ "$body" == *"data-v-"* || "$body" == *"vue"* ]]; then
    printf 'vue'
  else
    printf 'unknown'
  fi
}

classify_exposure() {
  local code="$1"
  local path="$2"
  case "$code" in
    200) printf 'public:%s' "$path" ;;
    401|403) printf 'protected:%s' "$path" ;;
    *) printf 'not_found' ;;
  esac
}

probe_candidates() {
  local host="$1"
  local route="$2"
  shift 2

  [[ -n "$host" ]] || {
    printf 'unknown'
    return
  }

  local candidate path url code curl_args
  curl_args=(-sS -L -m "$TIMEOUT" -o /dev/null -w '%{http_code}')
  if [[ "$INSECURE" -eq 1 ]]; then
    curl_args+=(-k)
  fi

  for candidate in "$@"; do
    path="$(join_url_path "$route" "$candidate")"
    url="${PROBE_SCHEME}://$host"
    if [[ -n "$PROBE_PORT" ]]; then
      url="${PROBE_SCHEME}://$host:$PROBE_PORT"
    fi
    url="${url}${path}"
    code="$(curl "${curl_args[@]}" "$url" 2>/dev/null || true)"
    case "$code" in
      200|401|403)
        classify_exposure "$code" "$path"
        return
        ;;
    esac
  done

  printf 'not_found'
}

run_discovery() {
  : > "$DISCOVERY_TSV"

  while IFS=$'\t' read -r route_id env_name config_file server_names modifier location route_type backend real_backend access_log backend_host probe_host; do
    local headers body framework ingress cluster swagger health http2 tls_version url

    framework="unknown"
    ingress="unknown"
    cluster="$(detect_cluster "$backend" "$real_backend" "$server_names")"
    swagger="unknown"
    health="unknown"
    http2="unknown"
    tls_version="unknown"

    if [[ -n "$probe_host" && "$route_type" != "regex" && "$route_type" != "named" ]]; then
      url="${PROBE_SCHEME}://$probe_host"
      if [[ -n "$PROBE_PORT" ]]; then
        url="${PROBE_SCHEME}://$probe_host:$PROBE_PORT"
      fi
      url="${url}${location}"

      headers="$(probe_http_headers "$url")"
      body="$(probe_http_body "$url")"
      framework="$(detect_framework "$headers" "$body")"
      ingress="$(detect_ingress "$headers" "$backend" "$real_backend")"
      swagger="$(probe_candidates "$probe_host" "$location" "swagger" "swagger-ui" "swagger-ui.html" "v3/api-docs" "api-docs")"
      health="$(probe_candidates "$probe_host" "$location" "health" "healthz" "actuator/health" "ping" "status")"
      http2="$(get_http2_status "$probe_host" "$location" "$PROBE_PORT")"
      if [[ "$PROBE_SCHEME" == "https" ]]; then
        tls_version="$(get_tls_version "$probe_host" "${PROBE_PORT:-443}")"
      fi
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$route_id" \
      "$framework" \
      "$ingress" \
      "$cluster" \
      "$swagger" \
      "$health" \
      >> "$DISCOVERY_TSV"

    printf '%s\t%s\t%s\n' \
      "$route_id" \
      "$http2" \
      "$tls_version" \
      >> "$TMP_DIR/http_tls.tsv"
  done < "$ROUTES_CATALOG"

  sort -u "$DISCOVERY_TSV" -o "$DISCOVERY_TSV"
  sort -u "$TMP_DIR/http_tls.tsv" -o "$TMP_DIR/http_tls.tsv"
}

write_final_csv() {
  "$AWK_BIN" -F'\t' -v runtime_file="$RUNTIME_TSV" -v discovery_file="$DISCOVERY_TSV" -v tls_file="$TMP_DIR/http_tls.tsv" '
    BEGIN {
      OFS = ","
      print "Environment,ServerName,Location,RouteType,Backend,RealBackend,Framework,Ingress,Cluster,Swagger,Health,HTTP2,TLSVersion,TopEndpoint,TopMethod,TopUpstream,RequestCount,ErrorCount,ErrorRate,AvgResponseTime,TopClientIP,TopTLS,AccessLog"
    }

    FILENAME == runtime_file {
      runtime[$1] = $2 FS $3 FS $4 FS $5 FS $6 FS $7 FS $8 FS $9 FS $10
      next
    }

    FILENAME == discovery_file {
      discovery[$1] = $2 FS $3 FS $4 FS $5 FS $6
      next
    }

    FILENAME == tls_file {
      tls[$1] = $2 FS $3
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
      split(discovery[rid], ds, FS)
      split(tls[rid], tt, FS)

      if (rt[1] == "") {
        rt[1] = "-"
        rt[2] = "-"
        rt[3] = "-"
        rt[4] = 0
        rt[5] = 0
        rt[6] = "0.00"
        rt[7] = "0.0000"
        rt[8] = "-"
        rt[9] = "-"
      }

      if (ds[1] == "") {
        ds[1] = "unknown"
        ds[2] = "unknown"
        ds[3] = "unknown"
        ds[4] = "unknown"
        ds[5] = "unknown"
      }

      if (tt[1] == "") {
        tt[1] = "unknown"
        tt[2] = "unknown"
      }

      print csv(env_name),
            csv(server_name),
            csv(location),
            csv(route_type),
            csv(backend),
            csv(real_backend),
            csv(ds[1]),
            csv(ds[2]),
            csv(ds[3]),
            csv(ds[4]),
            csv(ds[5]),
            csv(tt[1]),
            csv(tt[2]),
            csv(rt[1]),
            csv(rt[2]),
            csv(rt[3]),
            csv(rt[4]),
            csv(rt[5]),
            csv(rt[6]),
            csv(rt[7]),
            csv(rt[8]),
            csv(rt[9]),
            csv(access_log)
    }

    function csv(value, tmp) {
      tmp = value
      gsub(/\r/, " ", tmp)
      gsub(/\n/, " ", tmp)
      gsub(/"/, "\"\"", tmp)
      return "\"" tmp "\""
    }
  ' "$RUNTIME_TSV" "$DISCOVERY_TSV" "$TMP_DIR/http_tls.tsv" "$ROUTES_CATALOG" > "$OUTPUT_FILE"
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

  [[ "$PROBE_SCHEME" == "http" || "$PROBE_SCHEME" == "https" ]] || die "--scheme must be http or https"
}

prepare_workspace() {
  TMP_DIR="$(mktemp -d)"
  ROUTES_RAW="$TMP_DIR/routes_raw.tsv"
  ROUTES_CATALOG="$TMP_DIR/routes_catalog.tsv"
  RUNTIME_TSV="$TMP_DIR/runtime.tsv"
  DISCOVERY_TSV="$TMP_DIR/discovery.tsv"
  CONFIG_LIST="$TMP_DIR/config_files.txt"
  : > "$TMP_DIR/http_tls.tsv"
}

main() {
  parse_args "$@"

  if [[ -z "$MAIN_CONFIG" ]]; then
    for candidate in /usr/nginx/conf/nginx.conf /etc/nginx/nginx.conf /usr/local/nginx/conf/nginx.conf; do
      if [[ -f "$candidate" ]]; then
        MAIN_CONFIG="$candidate"
        log "Auto-detected config: $MAIN_CONFIG"
        break
      fi
    done
  fi

  [[ -n "$MAIN_CONFIG" ]] || die "Config not found. Use --config or place config at /usr/nginx/conf/nginx.conf"
  [[ -f "$MAIN_CONFIG" ]] || die "Config file not found: $MAIN_CONFIG"

  need_bin bash
  if command -v gawk >/dev/null 2>&1; then
    AWK_BIN="gawk"
  else
    AWK_BIN="awk"
  fi
  need_bin "$AWK_BIN"
  need_bin sed
  need_bin grep
  need_bin sort
  need_bin curl
  need_bin openssl
  need_bin mktemp
  need_bin tr

  prepare_workspace

  log "Resolving nginx config tree from $MAIN_CONFIG"
  collect_config_files "$MAIN_CONFIG"

  log "Parsing nginx routes, upstreams and access_log bindings"
  parse_nginx_config

  log "Building route catalog for correlation"
  build_routes_catalog
  [[ -s "$ROUTES_CATALOG" ]] || die "No reverse proxy locations with proxy_pass were found in the provided nginx config tree"

  log "Analyzing runtime access logs"
  analyze_logs

  log "Running live curl/openssl discovery"
  run_discovery

  log "Writing single export to $OUTPUT_FILE"
  write_final_csv

  printf 'Export complete: %s\n' "$OUTPUT_FILE"
}

main "$@"