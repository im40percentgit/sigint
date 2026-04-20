# Running SIGINT in Containers

Works with both Docker and Podman. All commands below use `docker`; substitute `podman` and `podman-compose` if preferred.

## Quick Start (Docker)

```bash
docker-compose up -d
docker-compose exec ollama ollama pull llama3.2
# Open http://localhost:8080
```

## Quick Start (Podman)

```bash
podman-compose up -d
podman-compose exec ollama ollama pull llama3.2
# Open http://localhost:8080
```

## Build Only

```bash
# Docker
docker build -t sigint .
docker run -p 8080:8080 sigint

# Podman
podman build -t sigint .
podman run -p 8080:8080 sigint
```

## Environment

- SIGINT web UI: http://localhost:8080
- Ollama API: http://localhost:11434
- Data persisted in named volumes

## Custom Config

Mount your config file:
```bash
docker run -v ./my-config.toml:/root/.config/sigint/config.toml -p 8080:8080 sigint
podman run -v ./my-config.toml:/root/.config/sigint/config.toml:Z -p 8080:8080 sigint
```

Note: Podman requires `:Z` suffix on volume mounts for SELinux relabeling.

## With GPU (NVIDIA)

```bash
# Docker with NVIDIA runtime
docker run --gpus all -p 8080:8080 sigint

# Podman with NVIDIA CDI
podman run --device nvidia.com/gpu=all -p 8080:8080 sigint
```

## Rootless Podman

sigint's sandbox uses Linux user namespaces, which work in rootless Podman:
```bash
podman run --userns=keep-id -p 8080:8080 sigint
```

## Compose Compatibility

The `docker-compose.yml` uses the Compose Specification format (no `version` key), compatible with:
- Docker Compose v2+
- Podman Compose
- Podman with `podman compose` (requires `podman-compose` or `docker-compose` plugin)
