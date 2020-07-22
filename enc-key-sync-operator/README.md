# Requirements for development

1. operator-sdk (>=v0.17.2)
2. opm (>=1.12.3)


# Development

- `make build`  builds the operator container
- `make push`  pushes the operator container to a registry (REQUIRES CREDENTIALS)
- `make bundle`  creates and pushes the operator bundle container for OLM catalog and the corresponding catalog containers (REQUIRES CREDENTIALS)
