if [ -e .env ]; then
    source .env
fi

EXAMPLE=${1:-warp}
cargo run --example=$EXAMPLE