#!/usr/bin/env bash
set -uo pipefail

out="json"
declare -a ctxs=()
server=""
username=""
password=""
token=""
insecure="false"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }; }
num() { [[ -z "${1-}" || "${1-}" == "null" ]] && echo null || jq -Rn --arg v "$1" '$v|tonumber? // null'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --context) [[ $# -lt 2 ]] && { echo "Missing value for --context" >&2; exit 1; }; ctxs+=("$2"); shift 2 ;;
    --output) [[ $# -lt 2 ]] && { echo "Missing value for --output" >&2; exit 1; }; out="$2"; shift 2 ;;
    --server) [[ $# -lt 2 ]] && { echo "Missing value for --server" >&2; exit 1; }; server="$2"; shift 2 ;;
    --username) [[ $# -lt 2 ]] && { echo "Missing value for --username" >&2; exit 1; }; username="$2"; shift 2 ;;
    --password) [[ $# -lt 2 ]] && { echo "Missing value for --password" >&2; exit 1; }; password="$2"; shift 2 ;;
    --token) [[ $# -lt 2 ]] && { echo "Missing value for --token" >&2; exit 1; }; token="$2"; shift 2 ;;
    --insecure-skip-tls-verify) insecure="true"; shift ;;
    -h|--help)
      cat <<'EOF'
Usage: collect_openshift_metrics.sh [--context <name>]... [--output json|pretty]
       [--server <api-url>] [--username <user> --password <pass> | --token <token>]
       [--insecure-skip-tls-verify]
Requires: oc, jq
EOF
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

need oc
need jq

if [[ -n "$server" ]]; then
  login_args=(login "$server")
  [[ "$insecure" == "true" ]] && login_args+=(--insecure-skip-tls-verify=true)

  if [[ -n "$token" ]]; then
    login_args+=(--token="$token")
  elif [[ -n "$username" && -n "$password" ]]; then
    login_args+=(--username="$username" --password="$password")
  else
    echo "When --server is used, provide either --token or both --username and --password." >&2
    exit 1
  fi

  oc "${login_args[@]}" >/dev/null 2>&1 || {
    echo "oc login failed for $server" >&2
    exit 1
  }
fi

[[ ${#ctxs[@]} -eq 0 ]] && ctxs=("$(oc config current-context 2>/dev/null)")
[[ -z "${ctxs[0]:-}" ]] && { echo "No active oc context" >&2; exit 1; }

pq() {
  local c="$1" q enc
  q="$2"
  enc="$(jq -rn --arg q "$q" '$q|@uri')"
  oc --context "$c" get --raw "/api/v1/namespaces/openshift-monitoring/services/https:thanos-querier:9091/proxy/api/v1/query?query=${enc}" 2>/dev/null || true
}

pscalar() {
  local v
  v="$(jq -r '.data.result[0].value[1] // empty' <<<"$(pq "$1" "$2")" 2>/dev/null || true)"
  num "$v"
}

collect() {
  local c="$1" server nodes pods pvs pvcs nss rqs svcs routes sas rbs secrets ntop ptop
  local tn rn nr tp rp pp fp cpua mema cpuu memu pvcn pvcc pva pvb svcn routen sac rbn secretn

  server="$(oc --context "$c" config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)"
  if ! oc --context "$c" whoami >/dev/null 2>&1; then
    jq -n --arg c "$c" --arg s "$server" '{context:$c,server:$s,cluster_metrics:{cluster_up:0},error:"oc login/context unreachable"}'
    return
  fi

  nodes="$(oc --context "$c" get nodes -o json 2>/dev/null || echo '{"items":[]}')"
  pods="$(oc --context "$c" get pods -A -o json 2>/dev/null || echo '{"items":[]}')"
  pvs="$(oc --context "$c" get pv -o json 2>/dev/null || echo '{"items":[]}')"
  pvcs="$(oc --context "$c" get pvc -A -o json 2>/dev/null || echo '{"items":[]}')"
  nss="$(oc --context "$c" get ns -o json 2>/dev/null || echo '{"items":[]}')"
  rqs="$(oc --context "$c" get resourcequota -A -o json 2>/dev/null || echo '{"items":[]}')"
  svcs="$(oc --context "$c" get svc -A -o json 2>/dev/null || echo '{"items":[]}')"
  routes="$(oc --context "$c" get routes.route.openshift.io -A -o json 2>/dev/null || echo '{"items":[]}')"
  sas="$(oc --context "$c" get sa -A -o json 2>/dev/null || echo '{"items":[]}')"
  rbs="$(oc --context "$c" get rolebindings.rbac.authorization.k8s.io -A -o json 2>/dev/null || echo '{"items":[]}')"
  secrets="$(oc --context "$c" get secrets -A -o json 2>/dev/null || echo '{"items":[]}')"
  ntop="$(oc --context "$c" adm top nodes --no-headers 2>/dev/null || true)"
  ptop="$(oc --context "$c" adm top pods -A --no-headers 2>/dev/null || true)"

  tn="$(jq '[.items[]]|length' <<<"$nodes")"
  rn="$(jq '[.items[]|select(any(.status.conditions[]?; .type=="Ready" and .status=="True"))]|length' <<<"$nodes")"
  nr="$(( tn - rn ))"
  tp="$(jq '[.items[]]|length' <<<"$pods")"
  rp="$(jq '[.items[]|select(.status.phase=="Running")]|length' <<<"$pods")"
  pp="$(jq '[.items[]|select(.status.phase=="Pending")]|length' <<<"$pods")"
  fp="$(jq '[.items[]|select(.status.phase=="Failed")]|length' <<<"$pods")"
  cpua="$(jq -r 'def c: if test("m$") then sub("m$";"")|tonumber else (tonumber?//0)*1000 end; [.items[].status.allocatable.cpu|c]|add//0' <<<"$nodes")"
  mema="$(jq -r 'def m: if test("Ki$") then sub("Ki$";"")|tonumber*1024 elif test("Mi$") then sub("Mi$";"")|tonumber*1048576 elif test("Gi$") then sub("Gi$";"")|tonumber*1073741824 elif test("Ti$") then sub("Ti$";"")|tonumber*1099511627776 else tonumber?//0 end; [.items[].status.allocatable.memory|m]|add//0' <<<"$nodes")"
  cpuu="$(awk 'NF{gsub(/m$/,"",$3);s+=$3}END{if(NR==0)print"null";else print s}' <<<"$ntop")"
  memu="$(awk 'function b(v){if(v~/Ki$/){sub(/Ki$/,"",v);return v*1024} if(v~/Mi$/){sub(/Mi$/,"",v);return v*1048576} if(v~/Gi$/){sub(/Gi$/,"",v);return v*1073741824} if(v~/Ti$/){sub(/Ti$/,"",v);return v*1099511627776} return v+0} NF{s+=b($5)} END{if(NR==0)print"null";else print s}' <<<"$ntop")"
  pvcn="$(jq '[.items[]]|length' <<<"$pvcs")"
  pvcc="$(jq -r 'def s: if test("Ki$") then sub("Ki$";"")|tonumber*1024 elif test("Mi$") then sub("Mi$";"")|tonumber*1048576 elif test("Gi$") then sub("Gi$";"")|tonumber*1073741824 elif test("Ti$") then sub("Ti$";"")|tonumber*1099511627776 else tonumber?//0 end; [.items[].status.capacity.storage?|select(.)|s]|add//0' <<<"$pvcs")"
  pva="$(jq '[.items[]|select(.status.phase=="Available")]|length' <<<"$pvs")"
  pvb="$(jq '[.items[]|select(.status.phase=="Bound")]|length' <<<"$pvs")"
  svcn="$(jq '[.items[]]|length' <<<"$svcs")"
  routen="$(jq '[.items[]]|length' <<<"$routes")"
  sac="$(jq '[.items[]]|length' <<<"$sas")"
  rbn="$(jq '[.items[]]|length' <<<"$rbs")"
  secretn="$(jq '[.items[]]|length' <<<"$secrets")"

  local ingress authfail pvcused netrx nettx
  ingress="$(pscalar "$c" 'sum(rate(haproxy_backend_http_responses_total[5m]))')"
  authfail="$(pscalar "$c" 'sum(increase(oauth_server_login_failures_total[5m]))')"
  pvcused="$(pscalar "$c" 'sum(kubelet_volume_stats_used_bytes)')"
  netrx="$(pscalar "$c" 'sum(rate(container_network_receive_bytes_total{pod!=""}[5m]))')"
  nettx="$(pscalar "$c" 'sum(rate(container_network_transmit_bytes_total{pod!=""}[5m]))')"

  local podm nodem nsm storagem networkm securitym
  podm="$(jq -n --argjson pods "$pods" --arg top "$ptop" '
    def c: if .==null then null elif test("m$") then sub("m$";"")|tonumber else (tonumber?//0)*1000 end;
    def m: if .==null then null elif test("Ki$") then sub("Ki$";"")|tonumber*1024 elif test("Mi$") then sub("Mi$";"")|tonumber*1048576 elif test("Gi$") then sub("Gi$";"")|tonumber*1073741824 elif test("Ti$") then sub("Ti$";"")|tonumber*1099511627776 else tonumber?//0 end;
    def tm: ($top|split("\n")|map(select(length>0))|map(capture("^(?<ns>\\S+)\\s+(?<pod>\\S+)\\s+(?<cpu>\\S+)\\s+(?<mem>\\S+)"))|map({key:(.ns+"/"+.pod),value:{cpu:(.cpu|c),mem:(.mem|m)}})|from_entries);
    (tm) as $t | $pods.items | map(. as $p | ($p.metadata.namespace+"/"+$p.metadata.name) as $k | {
      namespace:$p.metadata.namespace,pod:$p.metadata.name,node:($p.spec.nodeName//null),workload:($p.metadata.ownerReferences[0].name//null),
      pod_status:($p.status.phase//"Unknown"),pod_restart_count:([$p.status.containerStatuses[]?.restartCount]|add//0),
      pod_cpu_usage:($t[$k].cpu//null),pod_memory_usage:($t[$k].mem//null),
      pod_cpu_request:([$p.spec.containers[]?.resources.requests.cpu?|select(.)|c]|add//0),
      pod_memory_request:([$p.spec.containers[]?.resources.requests.memory?|select(.)|m]|add//0),
      pod_age_seconds:(if $p.metadata.creationTimestamp then ((now-($p.metadata.creationTimestamp|fromdateiso8601))|floor) else null end),
      container_restarts_total:([$p.status.containerStatuses[]?.restartCount]|add//0)
    })')"

  nodem="$(jq -n --argjson nodes "$nodes" --argjson podm "$podm" --arg top "$ntop" '
    def c: if test("m$") then sub("m$";"")|tonumber else (tonumber?//0)*1000 end;
    def m: if test("Ki$") then sub("Ki$";"")|tonumber*1024 elif test("Mi$") then sub("Mi$";"")|tonumber*1048576 elif test("Gi$") then sub("Gi$";"")|tonumber*1073741824 elif test("Ti$") then sub("Ti$";"")|tonumber*1099511627776 else tonumber?//0 end;
    def tm: ($top|split("\n")|map(select(length>0))|map(capture("^(?<n>\\S+)\\s+(?<cpu>\\S+)\\s+\\S+\\s+(?<mem>\\S+)"))|map({key:.n,value:{cpu:(.cpu|c),mem:(.mem|m)}})|from_entries);
    (tm) as $t | $nodes.items | map(. as $n | {
      node:$n.metadata.name,node_status:(if any($n.status.conditions[]?; .type=="Ready" and .status=="True") then "Ready" else "NotReady" end),
      node_cpu_capacity:(($n.status.capacity.cpu//"0")|c),node_cpu_usage:($t[$n.metadata.name].cpu//null),
      node_memory_capacity:(($n.status.capacity.memory//"0")|m),node_memory_usage:($t[$n.metadata.name].mem//null),
      node_disk_usage:null,node_disk_io:null,node_network_rx:null,node_network_tx:null,
      node_pod_count:([$podm[]|select(.node==$n.metadata.name)]|length)
    })')"

  nsm="$(jq -n --argjson nss "$nss" --argjson rqs "$rqs" --argjson podm "$podm" '
    def rq($ns): ($rqs.items|map(select(.metadata.namespace==$ns))|first//{} );
    def c($v): if $v==null then null elif ($v|test("m$")) then ($v|sub("m$";"")|tonumber) else (($v|tonumber?//0)*1000) end;
    def m($v): if $v==null then null elif ($v|test("Ki$")) then ($v|sub("Ki$";"")|tonumber*1024) elif ($v|test("Mi$")) then ($v|sub("Mi$";"")|tonumber*1048576) elif ($v|test("Gi$")) then ($v|sub("Gi$";"")|tonumber*1073741824) elif ($v|test("Ti$")) then ($v|sub("Ti$";"")|tonumber*1099511627776) else ($v|tonumber?//0) end;
    $nss.items|map(.metadata.name as $ns | (rq($ns)) as $rq | {
      namespace:$ns,
      namespace_cpu_request:([$podm[]|select(.namespace==$ns)|.pod_cpu_request]|add//0),
      namespace_cpu_usage:([$podm[]|select(.namespace==$ns)|.pod_cpu_usage//empty]|add//null),
      namespace_memory_request:([$podm[]|select(.namespace==$ns)|.pod_memory_request]|add//0),
      namespace_memory_usage:([$podm[]|select(.namespace==$ns)|.pod_memory_usage//empty]|add//null),
      namespace_pod_count:([$podm[]|select(.namespace==$ns)]|length),
      namespace_resource_quota_cpu:c($rq.status.hard.requests.cpu),
      namespace_resource_quota_memory:m($rq.status.hard.requests.memory),
      namespace_limit_usage_ratio:
        (if m($rq.status.hard.limits.memory)!=null and m($rq.status.hard.limits.memory)>0 and m($rq.status.used.limits.memory)!=null then (m($rq.status.used.limits.memory)/m($rq.status.hard.limits.memory))
         elif c($rq.status.hard.limits.cpu)!=null and c($rq.status.hard.limits.cpu)>0 and c($rq.status.used.limits.cpu)!=null then (c($rq.status.used.limits.cpu)/c($rq.status.hard.limits.cpu))
         else null end)
    })')"

  storagem="$(jq -n --argjson pvcn "$pvcn" --argjson used "$pvcused" --argjson cap "$(num "$pvcc")" --argjson pva "$pva" --argjson pvb "$pvb" '
    {pvc_total_count:$pvcn,pvc_used_bytes:$used,pvc_capacity_bytes:$cap,pv_available:$pva,pv_bound:$pvb,storage_usage_percent:(if $used==null or $cap==null or $cap==0 then null else ($used/$cap*100) end)}')"
  networkm="$(jq -n --argjson rx "$netrx" --argjson tx "$nettx" --argjson sc "$svcn" --argjson rc "$routen" --argjson ir "$ingress" '{pod_network_rx_bytes:$rx,pod_network_tx_bytes:$tx,service_count:$sc,route_count:$rc,ingress_request_rate:$ir}')"
  securitym="$(jq -n --argjson sa "$sac" --argjson rb "$rbn" --argjson sec "$secretn" --argjson fa "$authfail" '{active_service_accounts:$sa,role_bindings_count:$rb,secret_count:$sec,failed_auth_attempts:$fa}')"

  jq -n \
    --arg c "$c" --arg s "$server" \
    --argjson tn "$tn" --argjson rn "$rn" --argjson nr "$nr" --argjson tp "$tp" --argjson rp "$rp" --argjson pp "$pp" --argjson fp "$fp" \
    --argjson cpua "$(num "$cpua")" --argjson mema "$(num "$mema")" --argjson cpuu "$(num "$cpuu")" --argjson memu "$(num "$memu")" \
    --argjson nodem "$nodem" --argjson nsm "$nsm" --argjson podm "$podm" --argjson storagem "$storagem" --argjson networkm "$networkm" --argjson securitym "$securitym" '
    {context:$c,cluster_name:$c,server:$s,collected_at:(now|todateiso8601),
     cluster_metrics:{cluster_up:1,total_nodes:$tn,ready_nodes:$rn,not_ready_nodes:$nr,total_pods:$tp,running_pods:$rp,pending_pods:$pp,failed_pods:$fp,cluster_cpu_allocatable:$cpua,cluster_memory_allocatable:$mema,cluster_cpu_usage:$cpuu,cluster_memory_usage:$memu},
     node_metrics:$nodem,namespace_metrics:$nsm,pod_metrics:$podm,storage_metrics:$storagem,network_metrics:$networkm,security_metrics:$securitym}
  '
}

res="$(
  for c in "${ctxs[@]}"; do
    collect "$c"
  done | jq -cs '.'
)"

if [[ "$out" == "pretty" ]]; then jq '.' <<<"$res"; else jq -c '.' <<<"$res"; fi
