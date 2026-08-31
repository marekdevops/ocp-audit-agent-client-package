#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/overlays/generated"

default_image="${AUDIT_DEFAULT_IMAGE:-example.com/example-org/ocp-audit-agent:latest}"
default_pull_secret_name="${AUDIT_DEFAULT_PULL_SECRET_NAME:-registry-credentials}"
configured_pull_secret_registry="${AUDIT_DEFAULT_PULL_SECRET_REGISTRY:-}"

print_banner() {
  cat <<'EOF'
                                 
                            #####   
        ##########        ######### 
       ############      ###########
       #############     ###########
      ###############      #########
     #################       #######
    ########  #########    ######## 
   ########    ######### ########   
  #########     ########   ####     
 ########        ########           
#########         ########          
########           ########         
                                                                                                                                                

                         NETOLOGY
                    NETO KUBE AUDITOR

  Read-only auditing for Kubernetes, RKE2, OpenShift and OKD.
  Collects cluster state, detects risks and exposes findings,
  history and anonymized reports through a lightweight WebUI.

EOF
}

ask() {
  local prompt="$1"
  local default="$2"
  local value
  read -r -p "${prompt} [${default}]: " value
  printf '%s' "${value:-$default}"
}

ask_bool() {
  local prompt="$1"
  local default="$2"
  local value
  while true; do
    read -r -p "${prompt} [${default}]: " value
    value="${value:-$default}"
    case "${value,,}" in
      y|yes|true|t|1) printf 'true'; return ;;
      n|no|false|f|0) printf 'false'; return ;;
      *) echo "Answer yes/no." ;;
    esac
  done
}

ask_secret() {
  local prompt="$1"
  local value
  read -r -s -p "${prompt}: " value
  echo >&2
  printf '%s' "${value}"
}

registry_from_image() {
  local reference="$1"
  local first_segment
  first_segment="${reference%%/*}"
  if [[ "${reference}" != */* ]]; then
    printf 'index.docker.io'
  elif [[ "${first_segment}" == *.* || "${first_segment}" == *:* || "${first_segment}" == "localhost" ]]; then
    printf '%s' "${first_segment}"
  else
    printf 'index.docker.io'
  fi
}

validate_tagged_image() {
  local reference="$1"
  local last_segment
  local tag

  if [[ -z "${reference}" || "${reference}" =~ [[:space:]] ]]; then
    echo "Image reference cannot be empty or contain whitespace." >&2
    return 1
  fi
  if [[ "${reference}" == *"://"* ]]; then
    echo "Image reference must not include a URL scheme. Use example.com/project/image:tag." >&2
    return 1
  fi
  if [[ "${reference}" == *@* ]]; then
    echo "Image digests are not supported in generated client manifests. Use a tagged image, for example example.com/project/image:1.0.0." >&2
    return 1
  fi

  last_segment="${reference##*/}"
  if [[ "${last_segment}" == *:* ]]; then
    tag="${last_segment##*:}"
    if [[ ! "${tag}" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
      echo "Invalid image tag '${tag}'." >&2
      return 1
    fi
  fi
}

validate_registry_server() {
  local server="$1"
  if [[ -z "${server}" || "${server}" =~ [[:space:]] || "${server}" == *"://"* || "${server}" == */* ]]; then
    echo "Registry server must use host[:port] format without a URL scheme or repository path." >&2
    return 1
  fi
}

choose_cli() {
  if command -v kubectl >/dev/null 2>&1; then
    printf 'kubectl'
  elif command -v oc >/dev/null 2>&1; then
    printf 'oc'
  else
    echo "kubectl or oc is required" >&2
    exit 1
  fi
}

choose_python() {
  if command -v python3 >/dev/null 2>&1; then
    printf 'python3'
  elif command -v python >/dev/null 2>&1; then
    printf 'python'
  elif command -v py >/dev/null 2>&1; then
    printf 'py -3'
  else
    echo "python3 or python is required when creating an image pull secret" >&2
    exit 1
  fi
}

require_cluster_connection() {
  local cli="$1"
  if ! "${cli}" version --request-timeout=5s >/dev/null 2>&1; then
    echo "Cannot reach Kubernetes API with '${cli}'. Check kubeconfig/current context before uninstalling." >&2
    exit 1
  fi
}

usage() {
  cat <<'EOF'
Usage:
  scripts/deploy.sh
  scripts/deploy.sh --uninstall
  scripts/deploy.sh --help

Without flags, the script generates and optionally applies a cluster-specific
Kustomize overlay for Neto Kube Auditor.

Options:
  --uninstall   Remove Neto Kube Auditor resources from the selected namespace.
  --help        Show this help.
EOF
}

uninstall() {
  echo "Neto Kube Auditor uninstall"
  echo

  cli="$(choose_cli)"
  require_cluster_connection "${cli}"
  namespace="$(ask "Namespace" "ocp-audit")"
  delete_namespace="$(ask_bool "Delete namespace '${namespace}' after removing resources" "no")"

  if [[ -f "${OUT_DIR}/kustomization.yaml" ]]; then
    echo "Deleting resources from generated overlay: ${OUT_DIR}"
    "${cli}" delete -k "${OUT_DIR}" --ignore-not-found=true || true
  else
    echo "Generated overlay not found, deleting known resources by name."
  fi

  echo "Deleting Secret audit RBAC."
  "${cli}" delete clusterrolebinding ocp-audit-agent-secret-audit-risk --ignore-not-found=true || true
  "${cli}" delete clusterrole ocp-audit-agent-secret-audit-risk --ignore-not-found=true || true
  echo "Deleting Pod log audit RBAC."
  "${cli}" delete clusterrolebinding ocp-audit-agent-pod-logs-risk --ignore-not-found=true || true
  "${cli}" delete clusterrole ocp-audit-agent-pod-logs-risk --ignore-not-found=true || true

  echo "Deleting namespaced resources."
  "${cli}" delete deployment ocp-audit-agent-server ocp-audit-agent-watcher -n "${namespace}" --ignore-not-found=true || true
  "${cli}" delete statefulset ocp-audit-postgres -n "${namespace}" --ignore-not-found=true || true
  "${cli}" delete cronjob ocp-audit-agent-snapshot -n "${namespace}" --ignore-not-found=true || true
  "${cli}" delete service ocp-audit-agent -n "${namespace}" --ignore-not-found=true || true
  "${cli}" delete configmap ocp-audit-agent-config -n "${namespace}" --ignore-not-found=true || true
  "${cli}" delete pvc ocp-audit-data -n "${namespace}" --ignore-not-found=true || true
  "${cli}" delete pvc ocp-audit-postgres -n "${namespace}" --ignore-not-found=true || true
  "${cli}" delete service ocp-audit-postgres -n "${namespace}" --ignore-not-found=true || true
  "${cli}" delete secret ocp-audit-postgres -n "${namespace}" --ignore-not-found=true || true
  "${cli}" delete serviceaccount ocp-audit-agent -n "${namespace}" --ignore-not-found=true || true
  "${cli}" delete role ocp-audit-agent -n "${namespace}" --ignore-not-found=true || true
  "${cli}" delete rolebinding ocp-audit-agent -n "${namespace}" --ignore-not-found=true || true
  "${cli}" delete networkpolicy ocp-audit-agent -n "${namespace}" --ignore-not-found=true || true
  "${cli}" delete route ocp-audit-agent -n "${namespace}" --ignore-not-found=true >/dev/null 2>&1 || true

  echo "Deleting cluster-wide read-only RBAC."
  "${cli}" delete clusterrolebinding ocp-audit-agent --ignore-not-found=true || true
  "${cli}" delete clusterrole ocp-audit-agent --ignore-not-found=true || true

  if [[ "${delete_namespace}" == "true" ]]; then
    echo "Deleting namespace ${namespace}."
    "${cli}" delete namespace "${namespace}" --ignore-not-found=true || true
  else
    echo "Namespace ${namespace} left in place."
  fi

  echo "Uninstall completed."
}

main() {
  print_banner

  case "${1:-}" in
    --uninstall)
      uninstall
      return
      ;;
    --help|-h)
      usage
      return
      ;;
    "")
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac

  echo "Deployment configurator"
  echo

  cli="$(choose_cli)"
  namespace="$(ask "Namespace" "ocp-audit")"
  image="$(ask "Image" "${default_image}")"
  validate_tagged_image "${image}" || exit 2
  inferred_pull_secret_registry="$(registry_from_image "${image}")"
  default_pull_secret_registry="${configured_pull_secret_registry:-${inferred_pull_secret_registry}}"
  cluster_kind="$(ask "Cluster type: openshift/okd/kubernetes/rke2" "kubernetes")"
  storage_mode="$(ask "Storage mode: pvc/emptydir" "pvc")"
  storage_class=""
  if [[ "${storage_mode,,}" == "pvc" ]]; then
    storage_class="$(ask "StorageClass name, empty for cluster default" "")"
    if [[ -n "${storage_class}" ]] && { [[ ${#storage_class} -gt 253 ]] || [[ ! "${storage_class}" =~ ^[a-z0-9]([-.a-z0-9]*[a-z0-9])?$ ]]; }; then
      echo "Invalid StorageClass name '${storage_class}'. Use a valid lowercase DNS subdomain name." >&2
      exit 2
    fi
  fi
  node_port="$(ask "NodePort for WebUI, empty for auto-assigned" "30800")"
  pull_secret_mode="$(ask "Image pull secret: none/existing/create" "none")"
  pull_secret_name=""
  pull_secret_registry=""
  pull_secret_username=""
  pull_secret_password=""
  pull_secret_email=""
  case "${pull_secret_mode,,}" in
    none|"")
      pull_secret_mode="none"
      ;;
    existing)
      pull_secret_name="$(ask "Existing imagePullSecret name" "${default_pull_secret_name}")"
      ;;
    create)
      pull_secret_name="$(ask "New imagePullSecret name" "${default_pull_secret_name}")"
      pull_secret_registry="$(ask "Registry server (host[:port], without https://)" "${default_pull_secret_registry}")"
      validate_registry_server "${pull_secret_registry}" || exit 2
      pull_secret_username="$(ask "Registry username or robot account" "")"
      pull_secret_password="$(ask_secret "Registry password, token or robot secret")"
      pull_secret_email="$(ask "Registry email" "unused@example.local")"
      ;;
    *)
      echo "Unknown image pull secret mode '${pull_secret_mode}', using none."
      pull_secret_mode="none"
      ;;
  esac
  anonymize="$(ask_bool "Enable output anonymization by default" "no")"
  allow_deanon="$(ask_bool "Allow WebUI anonymization toggle" "yes")"
  # Kubernetes RBAC cannot restrict Secret reads to metadata. Keep this
  # high-risk permission optional even though values are redacted by the app.
  secret_audit="$(ask_bool "Enable optional Secret audit RBAC (grants Secret data read access)" "no")"
  pod_log_audit="$(ask_bool "Enable read-only Pod log audit RBAC" "yes")"

  enable_openshift="false"
  include_route="false"
  case "${cluster_kind,,}" in
    openshift|ocp|okd)
      enable_openshift="true"
      include_route="$(ask_bool "Also create OpenShift Route" "no")"
      ;;
    kubernetes|k8s|rke2)
      enable_openshift="false"
      ;;
    *)
      echo "Unknown cluster type '${cluster_kind}', using Kubernetes mode."
      enable_openshift="false"
      ;;
  esac
  deploy_now="$(ask_bool "Apply generated manifests now" "yes")"

  rm -rf "${OUT_DIR}"
  mkdir -p "${OUT_DIR}/patches"

  cat > "${OUT_DIR}/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- ../../deploy
EOF

  if [[ "${pull_secret_mode}" == "create" ]]; then
    cat >> "${OUT_DIR}/kustomization.yaml" <<EOF
- pull-secret/image-pull-secret.yaml
EOF
  fi
  if [[ "${pod_log_audit}" == "true" ]]; then
    cat >> "${OUT_DIR}/kustomization.yaml" <<EOF
- pod-logs-rbac/clusterrole-pod-logs-risk.yaml
- pod-logs-rbac/clusterrolebinding-pod-logs-risk.yaml
EOF
    mkdir -p "${OUT_DIR}/pod-logs-rbac"
    cp "${ROOT_DIR}/deploy/clusterrole-pod-logs-risk.yaml" "${OUT_DIR}/pod-logs-rbac/"
    cp "${ROOT_DIR}/deploy/clusterrolebinding-pod-logs-risk.yaml" "${OUT_DIR}/pod-logs-rbac/"
  fi

  if [[ "${secret_audit}" == "true" ]]; then
    cat >> "${OUT_DIR}/kustomization.yaml" <<EOF
- secret-rbac/clusterrole-with-secrets-metadata-risk.yaml
- secret-rbac/clusterrolebinding-with-secrets-metadata-risk.yaml
EOF
  fi

  if [[ "${include_route}" != "true" ]]; then
    cat >> "${OUT_DIR}/kustomization.yaml" <<EOF
patches:
- target:
    version: v1
    kind: Namespace
    name: ocp-audit
  path: patches/namespace.yaml
- path: patches/delete-route.yaml
- path: patches/delete-networkpolicy.yaml
- path: patches/configmap.yaml
- path: patches/service-nodeport.yaml
EOF
  else
    cat >> "${OUT_DIR}/kustomization.yaml" <<EOF
patches:
- target:
    version: v1
    kind: Namespace
    name: ocp-audit
  path: patches/namespace.yaml
- path: patches/delete-networkpolicy.yaml
- path: patches/configmap.yaml
- path: patches/service-nodeport.yaml
EOF
  fi

  if [[ "${pull_secret_mode}" != "none" ]]; then
    cat >> "${OUT_DIR}/kustomization.yaml" <<EOF
- target:
    version: v1
    kind: ServiceAccount
    name: ocp-audit-agent
  path: patches/serviceaccount-imagepullsecret.yaml
EOF
  fi

  if [[ "${storage_mode,,}" == "emptydir" ]]; then
    cat >> "${OUT_DIR}/kustomization.yaml" <<EOF
- path: patches/delete-pvc.yaml
- target:
    group: apps
    version: v1
    kind: Deployment
    name: ocp-audit-agent-server
  path: patches/emptydir-server.yaml
- target:
    group: apps
    version: v1
    kind: Deployment
    name: ocp-audit-agent-watcher
  path: patches/emptydir-watcher.yaml
- target:
    group: batch
    version: v1
    kind: CronJob
    name: ocp-audit-agent-snapshot
  path: patches/emptydir-cronjob-snapshot.yaml
- target:
    version: v1
    kind: PersistentVolumeClaim
    name: ocp-audit-postgres
  path: patches/delete-postgres-pvc.yaml
- target:
    group: apps
    version: v1
    kind: StatefulSet
    name: ocp-audit-postgres
  path: patches/emptydir-postgres.yaml
EOF
  fi

  if [[ -n "${storage_class}" ]]; then
    cat >> "${OUT_DIR}/kustomization.yaml" <<EOF
- target:
    version: v1
    kind: PersistentVolumeClaim
    name: ocp-audit-data
  path: patches/pvc-storageclass.yaml
EOF
  fi

  image_name="${image}"
  image_tag=""
  if [[ "${image##*/}" == *:* ]]; then
    image_name="${image%:*}"
    image_tag="${image##*:}"
  else
    image_tag="latest"
  fi

  cat >> "${OUT_DIR}/kustomization.yaml" <<EOF
namespace: ${namespace}
images:
- name: quay.io/example/ocp-audit-agent
  newName: ${image_name}
  newTag: ${image_tag}
EOF

  cat > "${OUT_DIR}/patches/delete-route.yaml" <<'EOF'
$patch: delete
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: ocp-audit-agent
  namespace: ocp-audit
EOF

  cat > "${OUT_DIR}/patches/delete-pvc.yaml" <<'EOF'
$patch: delete
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ocp-audit-data
  namespace: ocp-audit
EOF

  cat > "${OUT_DIR}/patches/delete-postgres-pvc.yaml" <<'EOF'
$patch: delete
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ocp-audit-postgres
  namespace: ocp-audit
EOF

  cat > "${OUT_DIR}/patches/delete-networkpolicy.yaml" <<'EOF'
$patch: delete
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ocp-audit-agent
  namespace: ocp-audit
EOF

  cat > "${OUT_DIR}/patches/namespace.yaml" <<EOF
- op: replace
  path: /metadata/name
  value: ${namespace}
EOF

  if [[ -n "${storage_class}" ]]; then
    cat > "${OUT_DIR}/patches/pvc-storageclass.yaml" <<EOF
- op: add
  path: /spec/storageClassName
  value: ${storage_class}
EOF
  fi

  cat > "${OUT_DIR}/patches/configmap.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: ocp-audit-agent-config
  namespace: ocp-audit
data:
  AUDIT_NAMESPACE: ${namespace}
  AUDIT_ENABLE_OPENSHIFT: "${enable_openshift}"
  AUDIT_ENABLE_SECRET_AUDIT: "${secret_audit}"
  AUDIT_ANONYMIZE_OUTPUT: "${anonymize}"
  AUDIT_ALLOW_UI_DEANONYMIZE: "${allow_deanon}"
  AUDIT_COLLECT_POD_LOGS: "${pod_log_audit}"
EOF

  if [[ "${pull_secret_mode}" != "none" ]]; then
    cat > "${OUT_DIR}/patches/serviceaccount-imagepullsecret.yaml" <<EOF
- op: add
  path: /imagePullSecrets
  value:
  - name: ${pull_secret_name}
EOF
  fi

  if [[ -n "${node_port}" ]]; then
    cat > "${OUT_DIR}/patches/service-nodeport.yaml" <<EOF
apiVersion: v1
kind: Service
metadata:
  name: ocp-audit-agent
  namespace: ocp-audit
spec:
  type: NodePort
  ports:
  - name: http
    port: 8080
    targetPort: 8080
    nodePort: ${node_port}
EOF
  else
    cat > "${OUT_DIR}/patches/service-nodeport.yaml" <<EOF
apiVersion: v1
kind: Service
metadata:
  name: ocp-audit-agent
  namespace: ocp-audit
spec:
  type: NodePort
  ports:
  - name: http
    port: 8080
    targetPort: 8080
EOF
  fi

  if [[ "${storage_mode,,}" == "emptydir" ]]; then
    cat > "${OUT_DIR}/patches/emptydir-server.yaml" <<'EOF'
- op: replace
  path: /spec/template/spec/volumes/0
  value:
    name: data
    emptyDir: {}
EOF
    cat > "${OUT_DIR}/patches/emptydir-watcher.yaml" <<'EOF'
- op: replace
  path: /spec/template/spec/volumes/0
  value:
    name: data
    emptyDir: {}
EOF
    cat > "${OUT_DIR}/patches/emptydir-cronjob-snapshot.yaml" <<'EOF'
- op: replace
  path: /spec/jobTemplate/spec/template/spec/volumes/0
  value:
    name: data
    emptyDir: {}
EOF
    cat > "${OUT_DIR}/patches/emptydir-postgres.yaml" <<'EOF'
- op: replace
  path: /spec/template/spec/volumes/0
  value:
    name: postgres-data
    emptyDir: {}
EOF
  fi

  if [[ "${secret_audit}" == "true" ]]; then
    mkdir -p "${OUT_DIR}/secret-rbac"
    cat > "${OUT_DIR}/secret-rbac/clusterrole-with-secrets-metadata-risk.yaml" <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ocp-audit-agent-secret-audit-risk
  annotations:
    audit.openshift.io/risk: "Kubernetes RBAC cannot grant metadata-only Secret reads; this permits Secret data reads. The application redacts Secret data before storage."
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get","list","watch"]
EOF
    cat > "${OUT_DIR}/secret-rbac/clusterrolebinding-with-secrets-metadata-risk.yaml" <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ocp-audit-agent-secret-audit-risk
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ocp-audit-agent-secret-audit-risk
subjects:
- kind: ServiceAccount
  name: ocp-audit-agent
  namespace: ${namespace}
EOF
  fi

  if [[ "${pull_secret_mode}" == "create" ]]; then
    mkdir -p "${OUT_DIR}/pull-secret"
    python_bin="$(choose_python)"
    export PULL_SECRET_NAME="${pull_secret_name}"
    export PULL_SECRET_NAMESPACE="${namespace}"
    export PULL_SECRET_REGISTRY="${pull_secret_registry}"
    export PULL_SECRET_USERNAME="${pull_secret_username}"
    export PULL_SECRET_PASSWORD="${pull_secret_password}"
    export PULL_SECRET_EMAIL="${pull_secret_email}"
    ${python_bin} - <<'PY' > "${OUT_DIR}/pull-secret/image-pull-secret.yaml"
import base64
import json
import os

name = os.environ["PULL_SECRET_NAME"]
namespace = os.environ["PULL_SECRET_NAMESPACE"]
registry = os.environ["PULL_SECRET_REGISTRY"]
username = os.environ["PULL_SECRET_USERNAME"]
password = os.environ["PULL_SECRET_PASSWORD"]
email = os.environ["PULL_SECRET_EMAIL"]
auth = base64.b64encode(f"{username}:{password}".encode()).decode()
dockerconfig = {
    "auths": {
        registry: {
            "username": username,
            "password": password,
            "email": email,
            "auth": auth,
        }
    }
}
encoded = base64.b64encode(json.dumps(dockerconfig, separators=(",", ":")).encode()).decode()
print("apiVersion: v1")
print("kind: Secret")
print("metadata:")
print(f"  name: {name}")
print(f"  namespace: {namespace}")
print("type: kubernetes.io/dockerconfigjson")
print("data:")
print(f"  .dockerconfigjson: {encoded}")
PY
    unset PULL_SECRET_NAME PULL_SECRET_NAMESPACE PULL_SECRET_REGISTRY PULL_SECRET_USERNAME PULL_SECRET_PASSWORD PULL_SECRET_EMAIL
  fi

  echo
  echo "Generated overlay: ${OUT_DIR}"
  "${cli}" kustomize "${OUT_DIR}" >/dev/null

  if [[ "${deploy_now}" == "true" ]]; then
    require_cluster_connection "${cli}"
    "${cli}" create namespace "${namespace}" --dry-run=client -o yaml | "${cli}" apply -f -
    if ! "${cli}" get secret ocp-audit-postgres -n "${namespace}" >/dev/null 2>&1; then
      postgres_password="$(cat /proc/sys/kernel/random/uuid)$(cat /proc/sys/kernel/random/uuid)"
      "${cli}" create secret generic ocp-audit-postgres -n "${namespace}" --from-literal=password="${postgres_password}"
    fi
    "${cli}" apply -k "${OUT_DIR}"
    # A delete patch prevents creation, but `kubectl apply` does not prune an
    # object left behind by an older overlay. Remove these explicitly.
    "${cli}" delete networkpolicy ocp-audit-agent -n "${namespace}" --ignore-not-found=true
    if [[ "${include_route}" != "true" ]]; then
      "${cli}" delete route ocp-audit-agent -n "${namespace}" --ignore-not-found=true >/dev/null 2>&1 || true
    fi
    "${cli}" rollout status "statefulset/ocp-audit-postgres" -n "${namespace}" || true
    "${cli}" rollout restart "deploy/ocp-audit-agent-server" -n "${namespace}" || true
    "${cli}" rollout status "deploy/ocp-audit-agent-server" -n "${namespace}" || true
  else
    echo "Create the required PostgreSQL password Secret if it does not exist:"
    echo "  ${cli} create secret generic ocp-audit-postgres -n ${namespace} --from-literal=password='<strong-random-password>'"
    echo "Apply later with:"
    echo "  ${cli} apply -k ${OUT_DIR}"
    echo "  ${cli} delete networkpolicy ocp-audit-agent -n ${namespace} --ignore-not-found=true"
  fi

  echo
  echo "WebUI service:"
  echo "  ${cli} get svc ocp-audit-agent -n ${namespace}"
  echo "If nodes are reachable, use http://<node-ip>:<nodePort>"
  echo "Fallback access:"
  echo "  ${cli} port-forward -n ${namespace} svc/ocp-audit-agent 8080:8080"
}

main "$@"
