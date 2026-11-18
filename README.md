# Kubernetes Encrypted Images Operator

This operator provides facility to sync decryption keys required for Encrypted Container Images through the use of Kubernetes secrets.

NOTE: If you are using the operator from Operatorhub.io, please look at this [README](helm-operator/README.md) instead.
NOTE: If you are looking for Keyprotect specific details, please look at this [KEYPROTECT.md](KEYPROTECT.md) instead.

# Requirements

- Kubernetes with a container runtime that supports image decryption:
  - CRI-O (>= 1.17), which supports it out of the box
  - containerd (>= 1.4) with [imgcrypt](https://github.com/containerd/imgcrypt)
    configured
- Optional: Helm (>= 3)

The [end-to-end tests](#end-to-end-tests) run against Kubernetes v1.37 with
CRI-O 1.35 (minikube v1.39) and with containerd 2.x and imgcrypt v2.0.3 (kind).

For this README, we will use CRI-O as a runtime as it has default configuration
set up. This can be done either using OpenShift (which uses CRI-O) or using
minikube with this command:

```
$ minikube start --container-runtime=cri-o
```
<details>
<summary>containerd configuration</summary>

With additional configuration, it can be used with the containerd runtime:
imgcrypt's `ctd-decoder` has to be installed on the nodes and configured as
stream processor for encrypted layers. For more info, please refer to the
[imgcrypt docs](https://github.com/containerd/imgcrypt). The
[end-to-end test](scripts/e2e-helm.sh) sets this up for a kind cluster; there,
containerd looks for decryption keys in `/etc/containerd/ocicrypt/keys`.
</details>

## Install the operator

There are currently two ways to install the operator, one is via deploying
the resources directly into the kubernetes cluster, and to do it via Helm.

## If deploying directly:

Deploy the operator on the cluster with `kubectl`. By default, it will install
the operator in the `enc-key-sync` namespace.
```
$ kubectl apply -f deploy/deploy.yaml
```

## If deploying via helm:

Deploy the operator on the cluster with `helm`. 
```
$ kubectl create namespace enc-key-sync
$ helm install --namespace=enc-key-sync k8s-enc-image-operator ./helm-operator/helm-charts/enckeysync/
```

On OpenShift, add `--set isOpenShift=true`: SELinux only allows the key sync
pods to write to the keys directory on the host when they run privileged.
`deploy/deploy.yaml` does not set this up.

<details>
<summary>containerd configuration</summary>

## If deploying for containerd:

Deploy the operator on the cluster with `helm`, and change the value of the keys
directory to a dedicated subdirectory of the keys directory of the containerd
configuration. For example, if the keys directory is set to `/path/to/keys`,
then the value of `keysDir` can be set to `/path/to/keys/enc-key-sync`.

```
$ kubectl create namespace enc-key-sync
$ helm install --namespace=enc-key-sync --set keysDir=/path/to/keys/enc-key-sync k8s-enc-image-operator ./helm-operator/helm-charts/enckeysync/
```

</details>

## The keys directory

The operator owns the key files it writes to `keysDir`, and removes them once
the corresponding secrets are deleted. Key files of a secret whose processing
fails temporarily (e.g. the unwrapping service is unreachable) are kept, see
[KEYPROTECT.md](KEYPROTECT.md#revoking-access-and-key-protect-failures) for
Key Protect. Use a directory dedicated to the
operator: while other files in it are not removed, keys from other sources
are best kept elsewhere.

<details>
<summary>Key file names</summary>

Key files are named `<md5 of the key>_<namespace>_<secret name>_<secret entry>`.
Namespace and secret names cannot contain underscores, so every key file
belongs to exactly one secret. Only files following this format, and temporary
files starting with `.keysync-tmp-` left behind by an interrupted write, are
removed by the operator.

Previous versions named key files
`<md5 of the key>-<namespace>-<secret name>-<secret entry>`. Such files are
removed and written again in the current format by the first sync after an
upgrade. As the secret they belong to is ambiguous, they are not kept for a
secret whose processing fails temporarily, so upgrade while the unwrapping
service is reachable to avoid failing image pulls.

</details>

# Try out an example

In the following example, we will add a key to the cluster, and run an encrypted
image that we have created using the key.

## Configure a key

Create the private key file on disk
```
$ cat > my-priv-key.pem <<EOF
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAv8Ny7dCWQ8Pdq1ddYSwkQOCB3lUEZVEyj9StX3jnISF/rxIs
UZzJfbOrQN0fGkm+1sCCtltgQdztTjito8FhDGflqQBSmV40XP3iZnNUJDrHuAol
463Z/BuxxFXL3ry6rTosLGfrRwdQjxp8RSsnWyIIO2rmcqXZYe4SCtiMjMejLlTI
DWLIMdYL3d6hA4DpgDLoh6EPmhKMVVwRt5b0ew5eMLcDuq6ButOM5yv4zYVHNraj
Y41NK+abSlFb6wzMg2AUDiC/MxV1LRq6mpyZGJllx3LS1M1j7fDO3pmh/M0X7yD/
4RgHwFaW4/4CQBw3fyxrOv0pZzZay+o/pyMMWwIDAQABAoIBAQC8HV2HEZH21BOG
W+PMyWKfCh4cHsZ7JZY2JmoVOCN0CsqY0XkMboPyfehHbyNtxF4jiSIxBZ59vd5F
V7Bu7eroIpvWl+xva0xu1NfdrNEj4U2+qqXUnd0zRW+zrH6b+AQgnupqfV7+hJxw
ZYj2yYiIC/CLaSi72xpOyR6F6TyndBVRFePoktfCsPcevQDTVeYEbTr9q52vwK3d
nROr3bV+J2y5Glce/4A6yTknJoDNWcDFvy3Ai//5bpV2x38E+FNRRb1BfZN56/7M
3bEvwLyJ2bvnEqAQ+7Z8+307aMiMr01s1IQLYvi5Z1fvNewoaj1yxjxfawPvcMtB
YDg6soDRAoGBAOA8zv/a48WD+dCb9WFk4YtRqg3ZjwSRKT3Afsfkd5lGz8yRlGP4
HXCP8nQ7c2TUEjqiQmtyxrq7yi5dacIzzZXAlS8ORA5BxCfrxzUBvuPKgGoxeozC
/Xef7mJ6Si+JDIjY2GKwO8I66JgxScTi7JWlyXmQ26rY4/0Yg8f6Au8XAoGBANrt
FPYVXn4S6VdAdhFzkx85ymQ+uX6yflRIUcmP5sySKMCPD1GSrVujDIgj485sEmH2
h57gDWzFWLmEU6PDsG2Bpsi29w5MMibr4y7Ez6y1rNd9eor5lDIhKi2sJRA0Ftj1
tBl31rhkJfCnzVIRn3Q+ZuvgTca7J9oUnCFBlfddAoGAUih1f3Dnu1qbkT9TLJgV
u0H0mJZ5vCajgaihywN+fn5fbIh6YhZqUu+q2cNeiDbbZvhEdbHb9lcPwOUg9rKc
RJ4HCvKjJMYb5LSSjG1TT4rGeiIe0Kwwyj+izBoaTEhee1VYEvCXNJb42apVaPnr
zPitVQkqMvK8teLhhceog4kCgYA2M/C2pL/KcyA2rA0PcRAB8Sr8+tKuXb8NWwJ0
5x37lExmsITYa3pkb9AQfOJQH03F12Xongx027+F3w9eQnsSAcGrfDFa5t6b6FdN
IwlP94Mdr0GB2x0n9DIfMLnUczEc8mhuzc7pxFHobYNWSGq0Oyb8S4K2K2xIgEXP
rg9VOQKBgQCvZXPe7uRyfeFxH9uexhPOZEYNpF8/SxeFnTmxoyDNgfTaT6wC0Vwt
jALXNbZLiYen9cUBfusELk8chLna1tCvLDUTT0m/Y80d8p+S80EsZ20ja1A3HdBv
h1TW/ep4aPeI0UE0ZNOifUB37IGXETO5fohbzm799dH8jtAkE02pww==
-----END RSA PRIVATE KEY-----
EOF
```

Install a key by creating a generic secret in the `enc-key-sync` namespace,
with `--type=key`:

```
$ kubectl create -n enc-key-sync secret generic \
    --type=key \
    --from-file=my-priv-key.pem \
    my-decryption-key
```

## Running an encrypted image

Create the encrypted container workload. We will use a sample application that
has been encrypted by the above key's public key.
```
$ kubectl run enc-workload --image=docker.io/lumjjb/sample-enc-app
```

# Developing

Building requires Go 1.26.4 or later (see [go.mod](go.mod)). See
[CONTRIBUTING.md](CONTRIBUTING.md) for the tools needed by the checks.

## End-to-end tests

The helm installation is tested end-to-end with both supported container
runtimes (this also runs in CI):

```
$ make e2e-helm-containerd   # kind cluster with containerd
$ make e2e-helm-crio         # minikube cluster with --container-runtime=cri-o
```

These require `kubectl`, `helm`, `go`, `openssl` and `docker` or `podman`, as
well as `kind`, `curl` and `tar` (containerd) or `minikube` (CRI-O).

This builds the keysync image from source, installs the helm chart, and checks
that keys from `type=key` secrets are synced to (and removed from) the nodes.
It also sets up image decryption on the nodes (with [imgcrypt](https://github.com/containerd/imgcrypt)
for containerd, built into CRI-O) and a local registry, and checks that an
encrypted image cannot be run without the key, but runs once the key has been
synced by the operator. Finally, it checks the cleanup of the keys directory:
stale key files (also in the legacy name format) are removed, files not
written by the operator are kept, and so are the keys of a secret whose
handler fails transiently (also across a restart of the key sync pods), but
not those of a secret whose handler fails permanently.

The script creates (and deletes) its own cluster and uses its own kubeconfig,
so your default kubeconfig is not modified; set `KEEP_CLUSTER=true` to keep
the cluster for debugging. See [scripts/e2e-helm.sh](scripts/e2e-helm.sh) for
the other supported environment variables (e.g. `CONTAINER_TOOL=podman`).
