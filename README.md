# Kubernetes Encrypted Images Operator

This operator provides facility to sync decryption keys required for Encrypted Container Images through the use of Kubernetes secrets.

NOTE: If you are using the operator from Operatorhub.io, please look at this [README](enc-key-sync-operator/README.md)  instead.
NOTE: If you are looking for Keyprotect specific details, please look at this [KEYPROTECT.md](KEYPROTECT.md) instead.

# Requirements

Currently this will only work out of the box with:
- Kubernetes (>= 1.17) with cri-o runtime (>=1.17) or containerd (>=1.4)
- Optional: Helm (>= 3)

For this README, we will use cri-o as a runtime as it has default configuration
set up.

This can be done either using OpenShift 4.4 and above or using minikube v1.12.0
with this command:

```
$ minikube start \
    --network-plugin=cni \
    --enable-default-cni \
    --container-runtime=cri-o \
    --bootstrapper=kubeadm
```
<details>
<summary>containerd configuration</summary>

With additional configuration, it can be used with containerd runtime (>=1.4).
For more info, please refer to the [containerd/cri docs](https://github.com/containerd/cri/blob/master/docs/decryption.md).
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

<details>
<summary>containerd configuration</summary>

## If deploying for containerd:

Deploy the operator on the cluster with `helm`, and change the value of the keys
directory to the directory or subdirectory of the containerd configuration. For
example, if the keys directory is set to `/path/to/keys`, then the value of 
`keysDir` can be set to `/path/to/keys` or `/path/to/keys/subfolder`.

```
$ kubectl create namespace enc-key-sync
$ helm install --namespace=enc-key-sync --set keysDir=/path/to/keys k8s-enc-image-operator ./helm-operator/helm-charts/enckeysync/
```

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

We are using golang 1.19.12 or later, expect problems with earlier releases.
