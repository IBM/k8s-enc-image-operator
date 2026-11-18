# Encrypted Images Key Syncer Helm Operator

## Pre-requisites

For the following steps, we assume installation of the Encrypted Images Key Syncer Helm Operator from OperatorHub.io.

## Getting Started

After installing the operator, getting started with decrypting container 
images in your cluster is done in three simple steps

- Setup the key path on container runtimes on each node (optional if done by cloud provider)

- Initialize the operator with the key path

- Configuring decryption keys


### Setup the key path on container runtimes on each node

Depending on the runtime you use, they will look for decryption keys to
decrypt the container images in different directories. 

- cri-o (>=1.17) by default has keys in directory `/etc/crio/keys`.
  This is configurable in the runtime if required, please refer to the
  [cri-o decryption doc](https://github.com/cri-o/cri-o/blob/main/tutorials/decryption.md).

- containerd (>=1.4) requires some configuration of the runtime: imgcrypt's
  `ctd-decoder` has to be installed and configured for encrypted layers. For
  this, please refer to the [imgcrypt docs](https://github.com/containerd/imgcrypt).

For OpenShift (>=4.4), it is configured by default to use cri-o with path 
`/etc/crio/keys`

### Initialize the operator with the key path

From the previous step, we have gotten the key path, lets initialize the
operator by creating the `EncKeySync` custom resource. Replacing `keysDir`
with a subpath of the path obtained from the previous step. 

For example, if you have the path set as `/path/to/keys`, then set 
`keysDir: /path/to/keys/enc-key-sync`.

```yaml
apiVersion: oci.crypt/v1alpha1
kind: EncKeySync
metadata:
  name: example-enckeysync
spec:
  # Replace this line with your path if required
  keysDir: /etc/crio/keys/enc-key-sync
```

The default value of `keysDir` uses the default cri-o runtime path.

On OpenShift, also set `isOpenShift: true` in the spec: SELinux only allows the
key sync pods to write to the keys directory on the host when they run
privileged.

What the daemonset does is it syncs all keys that you will configure to this
path on every worker node's host file system.

### Configuring decryption keys

Great, now that we have the key syncer running, we can create our decryption
keys. This can be done by creating a kubernetes secret with `--type=key` in
the namespace of the `EncKeySync` resource, which is where the key sync
daemonset runs. For example

```
$ kubectl create -n enc-key-sync secret generic  \
  --type=key \
  --from-file=my-priv-key.pem \
  my-decryption-key
```

In this case, we created the `EncKeySync` resource in namespace `enc-key-sync`,
and have a private key locally with filename `my-priv-key.pem`. If you are
following this example, you can find the private key in the [README](/README.md#configure-a-key)

## Running an encrypted container

Great - we are done setting up the operator and configuring keys, now we can
run encrypted container images! If you followed along with the provided 
private key, you should be able to run the image `docker.io/lumjjb/sample-enc-app`

```
$ kubectl run enc-workload --image=docker.io/lumjjb/sample-enc-app
```

Great you have successfully run an encrypted container image!

# Contributing

## Requirements for development

1. operator-sdk (>=v0.17.2)
2. opm (>=1.12.3)


## Development

- `make build`  builds the operator container
- `make push`  pushes the operator container to a registry (REQUIRES CREDENTIALS)
- `make bundle`  creates and pushes the operator bundle container for OLM catalog and the corresponding catalog containers (REQUIRES CREDENTIALS)
