default:
    @echo "No default task specified."
    just --list

# Runs the Development Kit Container
dkc:
    docker pull ghcr.io/leoborai/dkc:latest
    docker run -it --rm \
        -v $(pwd):/app \
        -w /app \
        ghcr.io/leoborai/dkc:latest

# Unit and integration tests
test:
    cargo nextest run --workspace --no-tests=pass
