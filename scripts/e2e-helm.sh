#!/usr/bin/env bash
# Copyright 2026 k8s-enc-image-operator authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# End-to-end test of the helm installation of the key sync daemonset,
# including running an encrypted image with a synced key. It runs against one
# of two container runtimes (E2E_RUNTIME):
#
#   containerd  kind cluster, image decryption with imgcrypt's ctd-decoder
#   cri-o       minikube cluster (--container-runtime=cri-o), CRI-O's built-in
#               image decryption
#
# Steps:
#
#   1. creates the cluster, sets up image decryption on the nodes and a local
#      registry
#   2. builds the keysync image from the current source and loads it into the
#      cluster
#   3. installs the helm chart using that image, with keysDir inside the
#      runtime's decryption keys directory
#   4. builds a test image with a unique layer and pushes it encrypted (JWE)
#      to the local registry
#   5. checks that a pod using the encrypted image cannot be started without
#      the decryption key
#   6. creates a decryption key secret (type=key) and checks that the key file
#      is synced to the keys directory on every node running the daemonset
#      (and that secrets of other types are ignored)
#   7. checks that a pod using the encrypted image now runs
#   8. deletes the secret and checks that the key file is removed
#   9. uninstalls the chart
#
# The cluster is created if it does not exist yet (and deleted at the end in
# that case, unless KEEP_CLUSTER=true). An existing cluster must have been
# created by this script. The script uses its own kubeconfig file, the
# default kubeconfig (~/.kube/config) is not modified.
#
# Configuration via environment variables:
#
#   E2E_RUNTIME          containerd or cri-o (default: containerd)
#   CLUSTER_NAME         kind cluster / minikube profile to use
#                        (default: enc-key-sync-e2e-<runtime>)
#   KEEP_CLUSTER         keep a cluster created by this script (default: false)
#   CONTAINER_TOOL       docker or podman (default: docker)
#   MINIKUBE_START_ARGS  additional arguments for minikube start (e.g. --memory=2g)
#   IMAGE                image name used for the locally built keysync image
#                        (default: localhost/keysync:e2e)
#   NAMESPACE            namespace to install the chart into (default: enc-key-sync)
#   KEYS_DIR             keysDir chart value, must be inside the runtime's
#                        decryption keys directory (default: <keys dir>/enc-key-sync)
#   TIMEOUT              seconds to wait for keys/pods (default: 120)

set -euo pipefail

E2E_RUNTIME=${E2E_RUNTIME:-containerd}
CLUSTER_NAME=${CLUSTER_NAME:-enc-key-sync-e2e-${E2E_RUNTIME}}
KEEP_CLUSTER=${KEEP_CLUSTER:-false}
CONTAINER_TOOL=${CONTAINER_TOOL:-docker}
MINIKUBE_START_ARGS=${MINIKUBE_START_ARGS:-}
IMAGE=${IMAGE:-localhost/keysync:e2e}
NAMESPACE=${NAMESPACE:-enc-key-sync}
TIMEOUT=${TIMEOUT:-120}

IMGCRYPT_VERSION=v2.0.3
SKOPEO_IMAGE=quay.io/skopeo/stable:v1.22.3
REGISTRY_IMAGE=docker.io/library/registry:3.1.1
BASE_IMAGE=docker.io/library/busybox:1.37.0

RELEASE=k8s-enc-image-operator
CHART_DIR=helm-operator/helm-charts/enckeysync
DAEMONSET=enc-key-sync
KEY_SECRET=e2e-decryption-key
KEY_FILE=e2e-priv-key.pem
OTHER_SECRET=e2e-not-a-key
REGISTRY_NAME="${CLUSTER_NAME}-registry"
REGISTRY="${REGISTRY_NAME}:5000"

# Unique per run, so that the encrypted image always has a layer that has
# never been unpacked on the nodes (container runtimes reuse unpacked layers
# without decrypting them again).
RUN_ID="$(date +%s)-${RANDOM}"
PLAIN_TEST_IMAGE="localhost/enc-e2e-plain:${RUN_ID}"
ENC_TEST_IMAGE="${REGISTRY}/enc-e2e:${RUN_ID}"

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${ROOT_DIR}"

WORK_DIR=$(mktemp -d)
CREATED_CLUSTER=false
CREATED_REGISTRY=false
INSTALLED=false

# Never touch the user's default kubeconfig.
export KUBECONFIG="${WORK_DIR}/kubeconfig"

ct() { "${CONTAINER_TOOL}" "$@"; }
log() { echo "==> $*"; }
fail() {
    echo "FAIL: $*" >&2
    exit 1
}

########################################################################
# containerd runtime: kind cluster with imgcrypt's ctd-decoder
########################################################################

containerd_init() {
    REQUIRED_TOOLS="kind curl tar"
    # Directory where ctd-decoder looks (recursively) for decryption keys;
    # this is the default of containerd 2.x.
    DECRYPTION_KEYS_ROOT=/etc/containerd/ocicrypt/keys
    KUBE_CONTEXT="kind-${CLUSTER_NAME}"
    CLUSTER_NETWORK=kind
    if [[ "${CONTAINER_TOOL}" == "podman" ]]; then
        export KIND_EXPERIMENTAL_PROVIDER=podman
    fi
}

containerd_cluster_exists() {
    kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"
}

containerd_cluster_create() {
    cat >"${WORK_DIR}/kind-config.yaml" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry]
    config_path = "/etc/containerd/certs.d"
EOF
    kind create cluster --name "${CLUSTER_NAME}" \
        --config "${WORK_DIR}/kind-config.yaml" --wait 120s
}

containerd_cluster_kubeconfig() {
    kind export kubeconfig --name "${CLUSTER_NAME}"
}

containerd_kubeconfig_hint() {
    echo "kind export kubeconfig --name ${CLUSTER_NAME}"
}

containerd_cluster_delete() {
    kind delete cluster --name "${CLUSTER_NAME}"
}

containerd_cluster_nodes() {
    kind get nodes --name "${CLUSTER_NAME}"
}

containerd_load_image() {
    kind load image-archive "$1" --name "${CLUSTER_NAME}"
}

containerd_setup_decryption() {
    local node config
    log "Checking containerd image decryption and registry config on the nodes"
    for node in ${ALL_NODES}; do
        config=$(ct exec "${node}" containerd config dump 2>/dev/null)
        grep -q "io.containerd.ocicrypt.decoder.v1.tar.gzip" <<<"${config}" ||
            fail "containerd on ${node} has no ocicrypt stream processor configured"
        grep -Eq "key_model = ['\"]node['\"]" <<<"${config}" ||
            fail "containerd on ${node} does not use the node key model for image decryption"
        grep -Eq "config_path = ['\"]/etc/containerd/certs.d['\"]" <<<"${config}" ||
            fail "containerd on ${node} has no registry config_path; was the cluster created by this script?"
    done

    log "Building ctd-decoder ${IMGCRYPT_VERSION} (linux/${NODE_ARCH})"
    curl -sSfL "https://github.com/containerd/imgcrypt/archive/refs/tags/${IMGCRYPT_VERSION}.tar.gz" |
        tar -xz -C "${WORK_DIR}"
    (
        cd "${WORK_DIR}/imgcrypt-${IMGCRYPT_VERSION#v}/cmd"
        CGO_ENABLED=0 GOOS=linux GOARCH="${NODE_ARCH}" go build -o "${WORK_DIR}/ctd-decoder" ./ctd-decoder
    )

    log "Installing ctd-decoder and registry config on the nodes"
    for node in ${ALL_NODES}; do
        ct cp "${WORK_DIR}/ctd-decoder" "${node}:/usr/local/bin/ctd-decoder"
        ct exec "${node}" mkdir -p "/etc/containerd/certs.d/${REGISTRY}"
        printf 'server = "http://%s"\n\n[host."http://%s"]\n  capabilities = ["pull", "resolve"]\n' \
            "${REGISTRY}" "${REGISTRY}" |
            ct exec -i "${node}" sh -c "cat > '/etc/containerd/certs.d/${REGISTRY}/hosts.toml'"
    done
}

########################################################################
# cri-o runtime: minikube cluster, CRI-O decrypts images natively
########################################################################

cri-o_init() {
    REQUIRED_TOOLS="minikube"
    # CRI-O's default decryption_keys_path (searched recursively).
    DECRYPTION_KEYS_ROOT=/etc/crio/keys
    KUBE_CONTEXT="${CLUSTER_NAME}"
    # The docker/podman drivers create a network named after the profile.
    CLUSTER_NETWORK="${CLUSTER_NAME}"
}

cri-o_cluster_exists() {
    # Only the first line: minikube prints warnings about the (not yet
    # configured) kubeconfig to stdout as well.
    local host
    host=$(minikube -p "${CLUSTER_NAME}" status --format '{{.Host}}' 2>/dev/null | head -n1) || true
    [[ "${host}" == "Running" ]]
}

cri-o_cluster_create() {
    local args=(--driver="${CONTAINER_TOOL}" --container-runtime=cri-o --wait=all)
    if [[ "${CONTAINER_TOOL}" == "podman" &&
        "$(podman info --format '{{.Host.Security.Rootless}}')" == "true" ]]; then
        args+=(--rootless)
    fi
    # shellcheck disable=SC2206 # intentionally split into separate arguments
    args+=(${MINIKUBE_START_ARGS})
    minikube start -p "${CLUSTER_NAME}" "${args[@]}"
}

cri-o_cluster_kubeconfig() {
    minikube -p "${CLUSTER_NAME}" update-context
}

cri-o_kubeconfig_hint() {
    echo "minikube -p ${CLUSTER_NAME} update-context"
}

cri-o_cluster_delete() {
    minikube delete -p "${CLUSTER_NAME}"
}

# The node names are the names of the node containers.
cri-o_cluster_nodes() {
    minikube -p "${CLUSTER_NAME}" node list | cut -f1
}

cri-o_load_image() {
    minikube -p "${CLUSTER_NAME}" image load "$1"
}

cri-o_setup_decryption() {
    local node keys_path
    log "Checking CRI-O image decryption config and adding the registry on the nodes"
    for node in ${ALL_NODES}; do
        keys_path=$(ct exec "${node}" crio status config 2>/dev/null |
            sed -n 's/^ *decryption_keys_path *= *"\(.*\)"/\1/p')
        [[ "${keys_path%/}" == "${DECRYPTION_KEYS_ROOT}" ]] ||
            fail "CRI-O on ${node} uses decryption_keys_path '${keys_path}', expected ${DECRYPTION_KEYS_ROOT}"
        printf '[[registry]]\nlocation = "%s"\ninsecure = true\n' "${REGISTRY}" |
            ct exec -i "${node}" sh -c "cat > /etc/containers/registries.conf.d/50-e2e-registry.conf"
        # CRI-O reloads the registries configuration on SIGHUP.
        ct exec "${node}" systemctl reload crio
    done
}

########################################################################
# Helpers
########################################################################

runtime() {
    local fn="${E2E_RUNTIME}_$1"
    shift
    "${fn}" "$@"
}

kc() { kubectl --context "${KUBE_CONTEXT}" "$@"; }
hc() { helm --kube-context "${KUBE_CONTEXT}" "$@"; }

dump_diagnostics() {
    local node
    log "Diagnostics"
    kc get nodes -o wide || true
    kc -n "${NAMESPACE}" get all,secrets -o wide || true
    kc -n "${NAMESPACE}" describe daemonset "${DAEMONSET}" || true
    kc -n "${NAMESPACE}" describe pods || true
    kc -n "${NAMESPACE}" logs -l name="${DAEMONSET}" --all-containers --tail=200 || true
    for node in ${ALL_NODES:-}; do
        echo "--- ${node}:${DECRYPTION_KEYS_ROOT}"
        ct exec "${node}" ls -laR "${DECRYPTION_KEYS_ROOT}" || true
        echo "--- ${node}: images"
        ct exec "${node}" crictl images || true
    done
}

cleanup() {
    local rc=$?
    if [[ ${rc} -ne 0 ]]; then
        echo "E2E TEST FAILED (exit code ${rc})" >&2
        dump_diagnostics
    fi
    if [[ "${CREATED_CLUSTER}" == "true" && "${KEEP_CLUSTER}" != "true" ]]; then
        log "Deleting ${E2E_RUNTIME} cluster ${CLUSTER_NAME}"
        runtime cluster_delete || true
    elif [[ "${CREATED_CLUSTER}" == "true" ]]; then
        log "Keeping ${E2E_RUNTIME} cluster ${CLUSTER_NAME}, context: ${KUBE_CONTEXT}"
        log "To access it, export its kubeconfig with: $(runtime kubeconfig_hint)"
    elif [[ "${INSTALLED}" == "true" ]]; then
        kc delete namespace "${NAMESPACE}" --ignore-not-found --wait=false || true
    fi
    if [[ "${CREATED_REGISTRY}" == "true" && "${KEEP_CLUSTER}" != "true" ]]; then
        ct rm -f "${REGISTRY_NAME}" >/dev/null 2>&1 || true
    fi
    ct rmi "${PLAIN_TEST_IMAGE}" >/dev/null 2>&1 || true
    rm -rf "${WORK_DIR}"
    exit ${rc}
}

# wait_until <description> <command...> polls the command until it succeeds
# or TIMEOUT expires.
wait_until() {
    local desc=$1
    shift
    local deadline=$((SECONDS + TIMEOUT))
    until "$@"; do
        if [[ ${SECONDS} -ge ${deadline} ]]; then
            fail "timed out after ${TIMEOUT}s waiting for: ${desc}"
        fi
        sleep 2
    done
}

# Nodes on which a key sync pod is running.
daemonset_nodes() {
    kc -n "${NAMESPACE}" get pods -l name="${DAEMONSET}" \
        -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' | sort -u
}

on_all_nodes() {
    local node
    for node in ${NODES}; do
        ct exec "${node}" "$@" || return 1
    done
}

# Starts a pod running the encrypted test image, always pulling it.
run_encrypted_pod() {
    kc -n "${NAMESPACE}" run "$1" \
        --image="${ENC_TEST_IMAGE}" \
        --image-pull-policy=Always \
        --restart=Never
}

# Succeeds once the pod's container is waiting because the image could not be
# decrypted.
pod_fails_decryption() {
    local msg
    msg=$(kc -n "${NAMESPACE}" get pod "$1" \
        -o jsonpath='{.status.containerStatuses[0].state.waiting.message}' 2>/dev/null) || return 1
    grep -qi "decrypt" <<<"${msg}"
}

# skopeo runs in the cluster network to reach the registry; the public key is
# passed via the environment and the image archive via stdin.
push_encrypted_image() {
    # shellcheck disable=SC2016 # expanded inside the skopeo container
    ct run --rm -i \
        --network "${CLUSTER_NETWORK}" -e ENC_PUB_KEY --entrypoint sh "${SKOPEO_IMAGE}" -c '
            set -e
            printf "%s\n" "${ENC_PUB_KEY}" > /tmp/pub.pem
            cat > /tmp/image.tar
            skopeo copy --format oci --dest-tls-verify=false \
                --encryption-key jwe:/tmp/pub.pem \
                docker-archive:/tmp/image.tar "docker://$1"
        ' sh "${ENC_TEST_IMAGE}" <"${WORK_DIR}/test-image.tar"
}

########################################################################
# Test
########################################################################

case "${E2E_RUNTIME}" in
    containerd | cri-o) runtime init ;;
    *) fail "unsupported E2E_RUNTIME '${E2E_RUNTIME}', must be containerd or cri-o" ;;
esac
KEYS_DIR=${KEYS_DIR:-${DECRYPTION_KEYS_ROOT}/enc-key-sync}

trap cleanup EXIT

# shellcheck disable=SC2086 # REQUIRED_TOOLS is a list
for tool in kubectl helm openssl go ${REQUIRED_TOOLS} "${CONTAINER_TOOL}"; do
    command -v "${tool}" >/dev/null || fail "${tool} is required but not installed"
done
[[ "${KEYS_DIR}/" == "${DECRYPTION_KEYS_ROOT}/"* ]] ||
    fail "KEYS_DIR (${KEYS_DIR}) must be inside ${DECRYPTION_KEYS_ROOT}"

log "Linting helm chart"
helm lint "${CHART_DIR}"

if runtime cluster_exists; then
    log "Using existing ${E2E_RUNTIME} cluster ${CLUSTER_NAME}"
    runtime cluster_kubeconfig
else
    log "Creating ${E2E_RUNTIME} cluster ${CLUSTER_NAME}"
    CREATED_CLUSTER=true
    runtime cluster_create
fi

ALL_NODES=$(runtime cluster_nodes)
FIRST_NODE=$(head -n1 <<<"${ALL_NODES}")
case "$(ct exec "${FIRST_NODE}" uname -m)" in
    x86_64) NODE_ARCH=amd64 ;;
    aarch64 | arm64) NODE_ARCH=arm64 ;;
    *) fail "unsupported node architecture" ;;
esac

runtime setup_decryption

log "Starting local registry ${REGISTRY}"
ct rm -f "${REGISTRY_NAME}" >/dev/null 2>&1 || true
ct run -d --name "${REGISTRY_NAME}" --network "${CLUSTER_NETWORK}" "${REGISTRY_IMAGE}" >/dev/null
CREATED_REGISTRY=true

log "Building keysync image ${IMAGE}"
# Built into a separate context so a host (e.g. darwin) binary in bin/ is never used.
CGO_ENABLED=0 GOOS=linux GOARCH="${NODE_ARCH}" go build -o "${WORK_DIR}/bin/keysync" main_keysync.go
ct build --platform "linux/${NODE_ARCH}" -f Dockerfile.keysync -t "${IMAGE}" "${WORK_DIR}"

log "Loading image into ${E2E_RUNTIME} cluster ${CLUSTER_NAME}"
ct save "${IMAGE}" -o "${WORK_DIR}/image.tar"
runtime load_image "${WORK_DIR}/image.tar"

log "Installing helm chart into namespace ${NAMESPACE}"
kc create namespace "${NAMESPACE}"
INSTALLED=true
hc install "${RELEASE}" "${CHART_DIR}" \
    --namespace "${NAMESPACE}" \
    --set image.repository="${IMAGE%:*}" \
    --set image.tag="${IMAGE##*:}" \
    --set image.pullPolicy=Never \
    --set keysDir="${KEYS_DIR}" \
    --wait --timeout 3m

kc -n "${NAMESPACE}" rollout status daemonset/"${DAEMONSET}" --timeout=3m
hc -n "${NAMESPACE}" status "${RELEASE}"

NODES=$(daemonset_nodes)
[[ -n "${NODES}" ]] || fail "no key sync pods are running"
log "Key sync running on nodes: ${NODES//$'\n'/ }"

log "Building encrypted test image ${ENC_TEST_IMAGE}"
openssl genrsa -out "${WORK_DIR}/${KEY_FILE}" 2048 2>/dev/null
openssl rsa -in "${WORK_DIR}/${KEY_FILE}" -pubout -out "${WORK_DIR}/pub.pem" 2>/dev/null
mkdir -p "${WORK_DIR}/test-image"
echo "${RUN_ID}" >"${WORK_DIR}/test-image/e2e-id"
cat >"${WORK_DIR}/test-image/Dockerfile" <<EOF
FROM ${BASE_IMAGE}
COPY e2e-id /e2e-id
CMD ["cat", "/e2e-id"]
EOF
ct build --platform "linux/${NODE_ARCH}" -t "${PLAIN_TEST_IMAGE}" "${WORK_DIR}/test-image"
ct save "${PLAIN_TEST_IMAGE}" -o "${WORK_DIR}/test-image.tar"

ENC_PUB_KEY="$(cat "${WORK_DIR}/pub.pem")"
export ENC_PUB_KEY
wait_until "encrypted image to be pushed" push_encrypted_image

manifest=$(ct run --rm --network "${CLUSTER_NETWORK}" "${SKOPEO_IMAGE}" \
    inspect --raw --tls-verify=false "docker://${ENC_TEST_IMAGE}")
layer_types=$(grep -o '"mediaType": *"application/vnd\.oci\.image\.layer[^"]*"' <<<"${manifest}" || true)
[[ -n "${layer_types}" ]] || fail "no layers found in the manifest of ${ENC_TEST_IMAGE}"
if grep -v -q "+encrypted" <<<"${layer_types}"; then
    fail "not all layers of ${ENC_TEST_IMAGE} are encrypted: ${layer_types}"
fi

log "Checking that the encrypted image cannot be run without the key"
kc -n "${NAMESPACE}" create secret generic "${OTHER_SECRET}" \
    --from-file="${WORK_DIR}/${KEY_FILE}"
run_encrypted_pod enc-workload-nokey
wait_until "pull of the encrypted image to fail decryption" pod_fails_decryption enc-workload-nokey
kc -n "${NAMESPACE}" delete pod enc-workload-nokey --wait=false
log "Image pull failed with a decryption error as expected"

log "Creating decryption key secret ${KEY_SECRET}"
kc -n "${NAMESPACE}" create secret generic "${KEY_SECRET}" \
    --type=key \
    --from-file="${WORK_DIR}/${KEY_FILE}"

# Synced key files are named <md5 of key>-<namespace>-<secret>-<file>
KEY_MD5=$(openssl dgst -md5 -r "${WORK_DIR}/${KEY_FILE}" | cut -d' ' -f1)
SYNCED_KEY="${KEYS_DIR}/${KEY_MD5}-${NAMESPACE}-${KEY_SECRET}-${KEY_FILE}"

log "Waiting for ${SYNCED_KEY} on all nodes"
wait_until "key file to be synced" on_all_nodes test -f "${SYNCED_KEY}"

for node in ${NODES}; do
    ct exec "${node}" cat "${SYNCED_KEY}" | cmp -s - "${WORK_DIR}/${KEY_FILE}" ||
        fail "content of ${SYNCED_KEY} on ${node} does not match the secret"
    perms=$(ct exec "${node}" stat -c '%a' "${SYNCED_KEY}")
    [[ "${perms}" == "600" ]] || fail "${SYNCED_KEY} on ${node} has permissions ${perms}, expected 600"
    listing=$(ct exec "${node}" ls "${KEYS_DIR}")
    if grep -q -- "-${OTHER_SECRET}-" <<<"${listing}"; then
        fail "secret ${OTHER_SECRET} without type=key was synced on ${node}"
    fi
done
log "Key file synced with correct content and permissions"

log "Checking that the encrypted image runs with the synced key"
run_encrypted_pod enc-workload
kc -n "${NAMESPACE}" wait pod/enc-workload \
    --for=jsonpath='{.status.phase}'=Succeeded --timeout="${TIMEOUT}s"
output=$(kc -n "${NAMESPACE}" logs enc-workload)
[[ "${output}" == "${RUN_ID}" ]] ||
    fail "unexpected output from the encrypted image: '${output}', expected '${RUN_ID}'"
log "Encrypted image was decrypted and ran successfully"

log "Deleting decryption key secret ${KEY_SECRET}"
kc -n "${NAMESPACE}" delete secret "${KEY_SECRET}"
wait_until "key file to be removed" on_all_nodes test ! -e "${SYNCED_KEY}"
log "Key file removed after secret deletion"

log "Uninstalling helm chart"
hc uninstall "${RELEASE}" --namespace "${NAMESPACE}" --wait --timeout 3m
INSTALLED=false
kc delete namespace "${NAMESPACE}" --wait --timeout=3m

log "E2E TEST PASSED ($E2E_RUNTIME)"
