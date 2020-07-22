.PHONY: build push bundle

build: 
	operator-sdk build docker.io/lumjjb/enc-key-sync-operator:v0.0.1

push: build
	docker push docker.io/lumjjb/enc-key-sync-operator:v0.0.1

# Useful links:
# https://docs.openshift.com/container-platform/4.5/operators/operator_sdk/osdk-helm.html
# https://docs.openshift.com/container-platform/4.5/operators/operator_sdk/osdk-working-bundle-images.html#osdk-working-bundle-images
# https://docs.openshift.com/container-platform/4.5/operators/olm-managing-custom-catalogs.html#olm-managing-custom-catalogs-bundle-format
bundle:
	operator-sdk bundle create docker.io/lumjjb/enc-key-sync-operator-bundle:v0.0.1
	docker push docker.io/lumjjb/enc-key-sync-operator-bundle:v0.0.1
	operator-sdk bundle validate  docker.io/lumjjb/enc-key-sync-operator-bundle:v0.0.1
	opm index add \
	    -c docker \
		--bundles docker.io/lumjjb/enc-key-sync-operator-bundle:v0.0.1 \
		--tag docker.io/lumjjb/enc-key-sync-operator-catalog:v0.0.1
	docker push docker.io/lumjjb/enc-key-sync-operator-catalog:v0.0.1
