#!/usr/bin/env bash

set -uo pipefail

SCRIPT_NAME="$(basename "$0")"
OUTPUT_MODE="json"
declare -a CONTEXTS=()

require_bin() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "Missing required dependency: $bin" >&2
    exit 1
  fi
}

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [--context <name>]... [--output json|pretty]

Collect OpenShift application and cluster metrics from the current context
or from the contexts provided with --context.

Requirements:
  - oc
  - jq

Examples:
  $SCRIPT_NAME
  $SCRIPT_NAME --context prod-cluster --context dr-cluster --output pretty
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --context)
      [[ $# -lt 2 ]] && { echo "Missing value for --context" >&2; exit 1; }
      CONTEXTS+=("$2")
      shift 2
      ;;
    --output)
      [[ $# -lt 2 ]] && { echo "Missing value for --output" >&2; exit 1; }
      OUTPUT_MODE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

require_bin oc
require_bin jq

if [[ ${#CONTEXTS[@]} -eq 0 ]]; then
  current_context="$(oc config current-context 2>/dev/null || true)"
  if [[ -z "$current_context" ]]; then
    echo "Could not determine current oc context. Use --context." >&2
    exit 1
  fi
  CONTEXTS=("$current_context")
fi

json_escape() {
  jq -Rn --arg v "${1-}" '$v'
}

safe_num() {
  local value="${1-}"
  if [[ -z "$value" || "$value" == "null" ]]; then
    echo "null"
  else
    jq -Rn --arg v "$value" '$v | tonumber? // $v'
  fi
}

sum_lines() {
  awk 'NF {s+=$1} END {if (NR==0) print 0; else print s}'
}

prom_query() {
  local context="$1"
  local query="$2"
  local encoded
  encoded="$(jq -rn --arg q "$query" '$q|@uri')"

  oc --context "$context" get --raw \
    "/api/v1/namespaces/openshift-monitoring/services/https:thanos-querier:9091/proxy/api/v1/query?query=${encoded}" \
    2>/dev/null || true
}

prom_scalar() {
  local context="$1"
  local query="$2"
  local response value

  response="$(prom_query "$context" "$query")"
  value="$(jq -r '.data.result[0].value[1] // empty' <<<"$response" 2>/dev/null || true)"

  if [[ -z "$value" ]]; then
    echo "null"
  else
    jq -Rn --arg v "$value" '$v | tonumber? // $v'
  fi
}

prom_sum() {
  local context="$1"
  local query="$2"
  local response

  response="$(prom_query "$context" "$query")"
  jq -r '
    if (.data.result | length) == 0 then
      "null"
    else
      ([.data.result[].value[1] | tonumber] | add)
    end
  ' <<<"$response" 2>/dev/null || echo "null"
}

build_json_array() {
  jq -cs '.'
}

collect_context() {
  local context="$1"
  local cluster_name server
  local nodes_json pods_json pvs_json pvcs_json namespaces_json resourcequotas_json
  local services_json routes_json scc_json secrets_json serviceaccounts_json rolebindings_json
  local pods_top nodes_top
  local total_nodes ready_nodes not_ready_nodes total_pods running_pods pending_pods failed_pods
  local cluster_cpu_allocatable cluster_memory_allocatable cluster_cpu_usage cluster_memory_usage
  local pvc_total_count pvc_capacity_bytes pv_available pv_bound service_count route_count
  local secret_count active_service_accounts role_bindings_count
  local cluster_up failed_auth_attempts ingress_request_rate

  cluster_name="$context"
  server="$(oc --context "$context" config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)"

  if ! oc --context "$context" whoami >/dev/null 2>&1; then
    jq -n \
      --arg context "$context" \
      --arg cluster_name "$cluster_name" \
      --arg server "$server" '
      {
        context: $context,
        cluster_name: $cluster_name,
        server: $server,
        cluster_metrics: { cluster_up: 0 },
        error: "oc login failed or context is not reachable"
      }'
    return
  fi

  cluster_up=1

  nodes_json="$(oc --context "$context" get nodes -o json 2>/dev/null || echo '{"items":[]}')"
  pods_json="$(oc --context "$context" get pods -A -o json 2>/dev/null || echo '{"items":[]}')"
  pvs_json="$(oc --context "$context" get pv -o json 2>/dev/null || echo '{"items":[]}')"
  pvcs_json="$(oc --context "$context" get pvc -A -o json 2>/dev/null || echo '{"items":[]}')"
  namespaces_json="$(oc --context "$context" get ns -o json 2>/dev/null || echo '{"items":[]}')"
  resourcequotas_json="$(oc --context "$context" get resourcequota -A -o json 2>/dev/null || echo '{"items":[]}')"
  services_json="$(oc --context "$context" get svc -A -o json 2>/dev/null || echo '{"items":[]}')"
  routes_json="$(oc --context "$context" get routes.route.openshift.io -A -o json 2>/dev/null || echo '{"items":[]}')"
  secrets_json="$(oc --context "$context" get secrets -A -o json 2>/dev/null || echo '{"items":[]}')"
  serviceaccounts_json="$(oc --context "$context" get sa -A -o json 2>/dev/null || echo '{"items":[]}')"
  rolebindings_json="$(oc --context "$context" get rolebindings.rbac.authorization.k8s.io -A -o json 2>/dev/null || echo '{"items":[]}')"
  pods_top="$(oc --context "$context" adm top pods -A --no-headers 2>/dev/null || true)"
  nodes_top="$(oc --context "$context" adm top nodes --no-headers 2>/dev/null || true)"

  total_nodes="$(jq '[.items[]] | length' <<<"$nodes_json")"
  ready_nodes="$(jq '[.items[] | select(any(.status.conditions[]?; .type=="Ready" and .status=="True"))] | length' <<<"$nodes_json")"
  not_ready_nodes="$(( total_nodes - ready_nodes ))"

  total_pods="$(jq '[.items[]] | length' <<<"$pods_json")"
  running_pods="$(jq '[.items[] | select(.status.phase=="Running")] | length' <<<"$pods_json")"
  pending_pods="$(jq '[.items[] | select(.status.phase=="Pending")] | length' <<<"$pods_json")"
  failed_pods="$(jq '[.items[] | select(.status.phase=="Failed")] | length' <<<"$pods_json")"

  cluster_cpu_allocatable="$(jq -r '[.items[].status.allocatable.cpu | sub("m$"; "") | tonumber?] | add // 0' <<<"$nodes_json")"
  cluster_memory_allocatable="$(jq -r '
    def mem_to_bytes:
      if test("Ki$") then sub("Ki$";"") | tonumber * 1024
      elif test("Mi$") then sub("Mi$";"") | tonumber * 1024 * 1024
      elif test("Gi$") then sub("Gi$";"") | tonumber * 1024 * 1024 * 1024
      elif test("Ti$") then sub("Ti$";"") | tonumber * 1024 * 1024 * 1024 * 1024
      else tonumber? // 0 end;
    [.items[].status.allocatable.memory | mem_to_bytes] | add // 0
  ' <<<"$nodes_json")"

  cluster_cpu_usage="$(awk 'NF {gsub("m","",$3); s+=$3} END {if (NR==0) print "null"; else print s}' <<<"$nodes_top")"
  cluster_memory_usage="$(awk '
    function to_bytes(v) {
      if (v ~ /Ki$/) { sub(/Ki$/, "", v); return v * 1024 }
      if (v ~ /Mi$/) { sub(/Mi$/, "", v); return v * 1024 * 1024 }
      if (v ~ /Gi$/) { sub(/Gi$/, "", v); return v * 1024 * 1024 * 1024 }
      if (v ~ /Ti$/) { sub(/Ti$/, "", v); return v * 1024 * 1024 * 1024 * 1024 }
      return v + 0
    }
    NF {s+=to_bytes($5)} END {if (NR==0) print "null"; else print s}
  ' <<<"$nodes_top")"

  pvc_total_count="$(jq '[.items[]] | length' <<<"$pvcs_json")"
  pvc_capacity_bytes="$(jq -r '
    def storage_to_bytes:
      if test("Ki$") then sub("Ki$";"") | tonumber * 1024
      elif test("Mi$") then sub("Mi$";"") | tonumber * 1024 * 1024
      elif test("Gi$") then sub("Gi$";"") | tonumber * 1024 * 1024 * 1024
      elif test("Ti$") then sub("Ti$";"") | tonumber * 1024 * 1024 * 1024 * 1024
      else tonumber? // 0 end;
    [.items[].status.capacity.storage? | select(.) | storage_to_bytes] | add // 0
  ' <<<"$pvcs_json")"
  pv_available="$(jq '[.items[] | select(.status.phase=="Available")] | length' <<<"$pvs_json")"
  pv_bound="$(jq '[.items[] | select(.status.phase=="Bound")] | length' <<<"$pvs_json")"

  service_count="$(jq '[.items[]] | length' <<<"$services_json")"
  route_count="$(jq '[.items[]] | length' <<<"$routes_json")"
  secret_count="$(jq '[.items[]] | length' <<<"$secrets_json")"
  active_service_accounts="$(jq '[.items[]] | length' <<<"$serviceaccounts_json")"
  role_bindings_count="$(jq '[.items[]] | length' <<<"$rolebindings_json")"

  ingress_request_rate="$(prom_scalar "$context" 'sum(rate(haproxy_backend_http_responses_total[5m]))')"
  failed_auth_attempts="$(prom_scalar "$context" 'sum(increase(oauth_server_login_failures_total[5m]))')"

  jq -n \
    --arg context "$context" \
    --arg cluster_name "$cluster_name" \
    --arg server "$server" \
    --argjson cluster_up "$cluster_up" \
    --argjson total_nodes "$total_nodes" \
    --argjson ready_nodes "$ready_nodes" \
    --argjson not_ready_nodes "$not_ready_nodes" \
    --argjson total_pods "$total_pods" \
    --argjson running_pods "$running_pods" \
    --argjson pending_pods "$pending_pods" \
    --argjson failed_pods "$failed_pods" \
    --argjson cluster_cpu_allocatable "$(safe_num "$cluster_cpu_allocatable")" \
    --argjson cluster_memory_allocatable "$(safe_num "$cluster_memory_allocatable")" \
    --argjson cluster_cpu_usage "$(safe_num "$cluster_cpu_usage")" \
    --argjson cluster_memory_usage "$(safe_num "$cluster_memory_usage")" \
    --argjson pvc_total_count "$pvc_total_count" \
    --argjson pvc_capacity_bytes "$(safe_num "$pvc_capacity_bytes")" \
    --argjson pv_available "$pv_available" \
    --argjson pv_bound "$pv_bound" \
    --argjson service_count "$service_count" \
    --argjson route_count "$route_count" \
    --argjson secret_count "$secret_count" \
    --argjson active_service_accounts "$active_service_accounts" \
    --argjson role_bindings_count "$role_bindings_count" \
    --argjson ingress_request_rate "$ingress_request_rate" \
    --argjson failed_auth_attempts "$failed_auth_attempts" \
    --argjson node_metrics "$(jq -n \
      --argjson nodes "$nodes_json" \
      --arg top "$nodes_top" '
      def mem_to_bytes:
        if test("Ki$") then sub("Ki$";"") | tonumber * 1024
        elif test("Mi$") then sub("Mi$";"") | tonumber * 1024 * 1024
        elif test("Gi$") then sub("Gi$";"") | tonumber * 1024 * 1024 * 1024
        elif test("Ti$") then sub("Ti$";"") | tonumber * 1024 * 1024 * 1024 * 1024
        else tonumber? // 0 end;
      def cpu_to_m:
        if test("m$") then sub("m$";"") | tonumber
        else (tonumber? // 0) * 1000 end;
      def top_map:
        ($top
          | split("\n")
          | map(select(length > 0))
          | map(capture("^(?<name>\\S+)\\s+(?<cpu>\\S+)\\s+\\S+\\s+(?<mem>\\S+)"))
          | map({
              key: .name,
              value: {
                cpu_m: (.cpu | sub("m$";"") | tonumber?),
                memory_bytes: (.mem | mem_to_bytes)
              }
            })
          | from_entries);
      (top_map) as $tm
      | $nodes.items
      | map({
          node: .metadata.name,
          node_status: (if any(.status.conditions[]?; .type=="Ready" and .status=="True") then "Ready" else "NotReady" end),
          node_cpu_capacity: ((.status.capacity.cpu // "0") | cpu_to_m),
          node_cpu_usage: ($tm[.metadata.name].cpu_m // null),
          node_memory_capacity: ((.status.capacity.memory // "0") | mem_to_bytes),
          node_memory_usage: ($tm[.metadata.name].memory_bytes // null),
          node_disk_usage: null,
          node_disk_io: null,
          node_network_rx: null,
          node_network_tx: null,
          node_pod_count: 0
        })
    ')" \
    --argjson namespace_metrics "$(jq -n \
      --argjson namespaces "$namespaces_json" \
      --argjson pods "$pods_json" \
      --argjson resourcequotas "$resourcequotas_json" '
      def cpu_to_m:
        if . == null then null
        elif test("m$") then sub("m$";"") | tonumber
        else (tonumber? // 0) * 1000 end;
      def mem_to_bytes:
        if . == null then null
        elif test("Ki$") then sub("Ki$";"") | tonumber * 1024
        elif test("Mi$") then sub("Mi$";"") | tonumber * 1024 * 1024
        elif test("Gi$") then sub("Gi$";"") | tonumber * 1024 * 1024 * 1024
        elif test("Ti$") then sub("Ti$";"") | tonumber * 1024 * 1024 * 1024 * 1024
        else tonumber? // 0 end;
      def rq_for_ns($ns):
        ($resourcequotas.items
          | map(select(.metadata.namespace == $ns))
          | {
              cpu: ([.[].status.hard.requests.cpu? | select(.) | cpu_to_m] | add // null),
              memory: ([.[].status.hard.requests.memory? | select(.) | mem_to_bytes] | add // null),
              limits_cpu: ([.[].status.used.limits.cpu? | select(.) | cpu_to_m] | add // null),
              hard_limits_cpu: ([.[].status.hard.limits.cpu? | select(.) | cpu_to_m] | add // null),
              limits_memory: ([.[].status.used.limits.memory? | select(.) | mem_to_bytes] | add // null),
              hard_limits_memory: ([.[].status.hard.limits.memory? | select(.) | mem_to_bytes] | add // null)
            });
      $namespaces.items
      | map(.metadata.name as $ns | (rq_for_ns($ns)) as $rq | {
          namespace: $ns,
          namespace_cpu_request: ([ $pods.items[]
            | select(.metadata.namespace == $ns)
            | .spec.containers[]?.resources.requests.cpu? | select(.)
            | cpu_to_m ] | add // 0),
          namespace_cpu_usage: null,
          namespace_memory_request: ([ $pods.items[]
            | select(.metadata.namespace == $ns)
            | .spec.containers[]?.resources.requests.memory? | select(.)
            | mem_to_bytes ] | add // 0),
          namespace_memory_usage: null,
          namespace_pod_count: ([ $pods.items[] | select(.metadata.namespace == $ns) ] | length),
          namespace_resource_quota_cpu: $rq.cpu,
          namespace_resource_quota_memory: $rq.memory,
          namespace_limit_usage_ratio:
            (if $rq.hard_limits_memory != null and $rq.hard_limits_memory > 0 and $rq.limits_memory != null
             then ($rq.limits_memory / $rq.hard_limits_memory)
             elif $rq.hard_limits_cpu != null and $rq.hard_limits_cpu > 0 and $rq.limits_cpu != null
             then ($rq.limits_cpu / $rq.hard_limits_cpu)
             else null end)
        })
    ')" \
    --argjson pod_metrics "$(jq -n \
      --argjson pods "$pods_json" '
      def cpu_to_m:
        if . == null then null
        elif test("m$") then sub("m$";"") | tonumber
        else (tonumber? // 0) * 1000 end;
      def mem_to_bytes:
        if . == null then null
        elif test("Ki$") then sub("Ki$";"") | tonumber * 1024
        elif test("Mi$") then sub("Mi$";"") | tonumber * 1024 * 1024
        elif test("Gi$") then sub("Gi$";"") | tonumber * 1024 * 1024 * 1024
        elif test("Ti$") then sub("Ti$";"") | tonumber * 1024 * 1024 * 1024 * 1024
        else tonumber? // 0 end;
      $pods.items
      | map({
          namespace: .metadata.namespace,
          pod: .metadata.name,
          workload: (.metadata.ownerReferences[0].name // null),
          pod_status: (.status.phase // "Unknown"),
          pod_restart_count: ([.status.containerStatuses[]?.restartCount] | add // 0),
          pod_cpu_usage: null,
          pod_memory_usage: null,
          pod_cpu_request: ([.spec.containers[]?.resources.requests.cpu? | select(.) | cpu_to_m] | add // 0),
          pod_memory_request: ([.spec.containers[]?.resources.requests.memory? | select(.) | mem_to_bytes] | add // 0),
          pod_age_seconds: (
            if .metadata.creationTimestamp
            then ((now - (.metadata.creationTimestamp | fromdateiso8601)) | floor)
            else null
            end
          ),
          container_restarts_total: ([.status.containerStatuses[]?.restartCount] | add // 0)
        })
    ')" \
    --argjson storage_metrics "$(jq -n \
      --argjson pvcs "$pvcs_json" '
      {
        pvc_total_count: $pvc_total_count,
        pvc_used_bytes: null,
        pvc_capacity_bytes: $pvc_capacity_bytes,
        pv_available: $pv_available,
        pv_bound: $pv_bound,
        storage_usage_percent: null
      }
    ')" \
    --argjson network_metrics "$(jq -n '
      {
        pod_network_rx_bytes: null,
        pod_network_tx_bytes: null,
        service_count: $service_count,
        route_count: $route_count,
        ingress_request_rate: $ingress_request_rate
      }
    ')" \
    --argjson security_metrics "$(jq -n '
      {
        active_service_accounts: $active_service_accounts,
        role_bindings_count: $role_bindings_count,
        secret_count: $secret_count,
        failed_auth_attempts: $failed_auth_attempts
      }
    ')" '
    {
      context: $context,
      cluster_name: $cluster_name,
      server: $server,
      collected_at: (now | todateiso8601),
      cluster_metrics: {
        cluster_up: $cluster_up,
        total_nodes: $total_nodes,
        ready_nodes: $ready_nodes,
        not_ready_nodes: $not_ready_nodes,
        total_pods: $total_pods,
        running_pods: $running_pods,
        pending_pods: $pending_pods,
        failed_pods: $failed_pods,
        cluster_cpu_allocatable: $cluster_cpu_allocatable,
        cluster_memory_allocatable: $cluster_memory_allocatable,
        cluster_cpu_usage: $cluster_cpu_usage,
        cluster_memory_usage: $cluster_memory_usage
      },
      node_metrics: (
        $node_metrics
        | map(.node as $name | . + {
          node_pod_count: ([ $pod_metrics[] | select(.pod != null and .namespace != null) ] | length)
        })
      ),
      namespace_metrics: $namespace_metrics,
      pod_metrics: $pod_metrics,
      storage_metrics: $storage_metrics,
      network_metrics: $network_metrics,
      security_metrics: $security_metrics
    }'
}

results="$(
  for context in "${CONTEXTS[@]}"; do
    collect_context "$context"
  done | build_json_array
)"

if [[ "$OUTPUT_MODE" == "pretty" ]]; then
  jq '.' <<<"$results"
else
  jq -c '.' <<<"$results"
fi
