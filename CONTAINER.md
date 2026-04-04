# Running SIGINT in Docker

## Quick Start

docker-compose up -d
docker-compose exec ollama ollama pull llama3.2
# Open http://localhost:8080

## Build Only

docker build -t sigint .
docker run -p 8080:8080 sigint

## Environment

- SIGINT web UI: http://localhost:8080
- Ollama API: http://localhost:11434
- Data persisted in Docker volumes

## Custom Config

Mount your config:
docker run -v ./my-config.toml:/root/.config/sigint/config.toml -p 8080:8080 sigint

## With GPU (NVIDIA)

docker-compose -f docker-compose.yml -f docker-compose.gpu.yml up -d
