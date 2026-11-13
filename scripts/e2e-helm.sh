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

# End-to-end test of the helm installation of the key sync daemonset on a
# kind cluster:
#
#   1. builds the keysync image from the current source and loads it into kind
#   2. installs the helm chart using that image
#   3. creates a decryption key secret (type=key) and checks that the key file
#      is synced to the keys directory on every node running the daemonset
#   4. checks that secrets of other types are ignored
#   5. deletes the secret and checks that the key file is removed
#   6. uninstalls the chart
#
# The kind cluster is created if it does not exist yet (and deleted at the end
# in that case). Configuration via environment variables:
#
#   KIND_CLUSTER_NAME  kind cluster to use (default: kind)
#   CONTAINER_TOOL     docker or podman (default: docker)
#   IMAGE              image name used for the locally built image (default: localhost/keysync:e2e)
#   NAMESPACE          namespace to install the chart into (default: enc-key-sync)
#   KEYS_DIR           keysDir chart value (default: /etc/crio/keys/enc-key-sync)
#   TIMEOUT            seconds to wait for keys to be synced/removed (default: 120)

set -euo pipefail

KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-kind}
CONTAINER_TOOL=${CONTAINER_TOOL:-docker}
IMAGE=${IMAGE:-localhost/keysync:e2e}
NAMESPACE=${NAMESPACE:-enc-key-sync}
KEYS_DIR=${KEYS_DIR:-/etc/crio/keys/enc-key-sync}
TIMEOUT=${TIMEOUT:-120}

RELEASE=k8s-enc-image-operator
CHART_DIR=helm-operator/helm-charts/enckeysync
DAEMONSET=enc-key-sync
KEY_SECRET=e2e-decryption-key
KEY_FILE=e2e-priv-key.pem
OTHER_SECRET=e2e-not-a-key

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${ROOT_DIR}"

# Always talk to the kind cluster explicitly, never to the current context.
KUBE_CONTEXT="kind-${KIND_CLUSTER_NAME}"
kc() { kubectl --context "${KUBE_CONTEXT}" "$@"; }
hc() { helm --kube-context "${KUBE_CONTEXT}" "$@"; }

if [[ "${CONTAINER_TOOL}" == "podman" ]]; then
    export KIND_EXPERIMENTAL_PROVIDER=podman
fi

WORK_DIR=$(mktemp -d)
CREATED_CLUSTER=false
INSTALLED=false

log() { echo "==> $*"; }

dump_diagnostics() {
    log "Diagnostics"
    kc get nodes -o wide || true
    kc -n "${NAMESPACE}" get all,secrets -o wide || true
    kc -n "${NAMESPACE}" describe daemonset "${DAEMONSET}" || true
    kc -n "${NAMESPACE}" describe pods -l name="${DAEMONSET}" || true
    kc -n "${NAMESPACE}" logs -l name="${DAEMONSET}" --all-containers --tail=200 || true
    for node in $(kind get nodes --name "${KIND_CLUSTER_NAME}" 2>/dev/null); do
        echo "--- ${node}:${KEYS_DIR}"
        "${CONTAINER_TOOL}" exec "${node}" ls -la "${KEYS_DIR}" || true
    done
}

cleanup() {
    local rc=$?
    if [[ ${rc} -ne 0 ]]; then
        echo "E2E TEST FAILED (exit code ${rc})" >&2
        dump_diagnostics
    fi
    if [[ "${CREATED_CLUSTER}" == "true" ]]; then
        log "Deleting kind cluster ${KIND_CLUSTER_NAME}"
        kind delete cluster --name "${KIND_CLUSTER_NAME}" || true
    elif [[ "${INSTALLED}" == "true" ]]; then
        kc delete namespace "${NAMESPACE}" --ignore-not-found --wait=false || true
    fi
    rm -rf "${WORK_DIR}"
    exit ${rc}
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
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
        "${CONTAINER_TOOL}" exec "${node}" "$@" || return 1
    done
}

for tool in kind kubectl helm openssl "${CONTAINER_TOOL}"; do
    command -v "${tool}" >/dev/null || fail "${tool} is required but not installed"
done

log "Linting helm chart"
helm lint "${CHART_DIR}"

if ! kind get clusters | grep -qx "${KIND_CLUSTER_NAME}"; then
    log "Creating kind cluster ${KIND_CLUSTER_NAME}"
    kind create cluster --name "${KIND_CLUSTER_NAME}" --wait 120s
    CREATED_CLUSTER=true
fi

log "Building keysync image ${IMAGE}"
# Built into a separate context so a host (e.g. darwin) binary in bin/ is never used.
CGO_ENABLED=0 GOOS=linux go build -o "${WORK_DIR}/bin/keysync" main_keysync.go
"${CONTAINER_TOOL}" build -f Dockerfile.keysync -t "${IMAGE}" "${WORK_DIR}"

log "Loading image into kind cluster ${KIND_CLUSTER_NAME}"
"${CONTAINER_TOOL}" save "${IMAGE}" -o "${WORK_DIR}/image.tar"
kind load image-archive "${WORK_DIR}/image.tar" --name "${KIND_CLUSTER_NAME}"

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

log "Creating decryption key secret ${KEY_SECRET}"
openssl genrsa -out "${WORK_DIR}/${KEY_FILE}" 2048 2>/dev/null
kc -n "${NAMESPACE}" create secret generic "${KEY_SECRET}" \
    --type=key \
    --from-file="${WORK_DIR}/${KEY_FILE}"
kc -n "${NAMESPACE}" create secret generic "${OTHER_SECRET}" \
    --from-file="${WORK_DIR}/${KEY_FILE}"

# Synced key files are named <md5 of key>-<namespace>-<secret>-<file>
KEY_MD5=$(openssl dgst -md5 -r "${WORK_DIR}/${KEY_FILE}" | cut -d' ' -f1)
SYNCED_KEY="${KEYS_DIR}/${KEY_MD5}-${NAMESPACE}-${KEY_SECRET}-${KEY_FILE}"

log "Waiting for ${SYNCED_KEY} on all nodes"
wait_until "key file to be synced" on_all_nodes test -f "${SYNCED_KEY}"

for node in ${NODES}; do
    "${CONTAINER_TOOL}" exec "${node}" cat "${SYNCED_KEY}" | cmp -s - "${WORK_DIR}/${KEY_FILE}" ||
        fail "content of ${SYNCED_KEY} on ${node} does not match the secret"
    perms=$("${CONTAINER_TOOL}" exec "${node}" stat -c '%a' "${SYNCED_KEY}")
    [[ "${perms}" == "600" ]] || fail "${SYNCED_KEY} on ${node} has permissions ${perms}, expected 600"
    listing=$("${CONTAINER_TOOL}" exec "${node}" ls "${KEYS_DIR}")
    if grep -q -- "-${OTHER_SECRET}-" <<<"${listing}"; then
        fail "secret ${OTHER_SECRET} without type=key was synced on ${node}"
    fi
done
log "Key file synced with correct content and permissions"

log "Deleting decryption key secret ${KEY_SECRET}"
kc -n "${NAMESPACE}" delete secret "${KEY_SECRET}"
wait_until "key file to be removed" on_all_nodes test ! -e "${SYNCED_KEY}"
log "Key file removed after secret deletion"

log "Uninstalling helm chart"
hc uninstall "${RELEASE}" --namespace "${NAMESPACE}" --wait --timeout 3m
INSTALLED=false
kc delete namespace "${NAMESPACE}" --wait --timeout=3m

log "E2E TEST PASSED"
