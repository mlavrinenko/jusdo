# Development recipes

# Run all checks (clippy + tests + file size)
check:
    cargo clippy --workspace --all-targets -q
    cargo test --workspace -q
    just check-file-size

# Run tests only
test *ARGS:
    cargo test --workspace {{ ARGS }}

# Run clippy only
clippy:
    cargo clippy --workspace --all-targets -q

# Auto-fix clippy warnings
clippy-fix:
    cargo clippy --fix --workspace --all-targets

# Build the project
build:
    cargo build --workspace -q

# Run coverage with tarpaulin
cover:
    cargo tarpaulin --workspace

# Format code
fmt:
    cargo fmt --all

# Format check (CI-friendly)
fmt-check:
    cargo fmt --all -- --check

# Count tests across workspace
count-tests:
    #!/usr/bin/env bash
    cargo test --workspace 2>&1 | grep "test result:" | awk '{sum += $4} END {print sum " tests"}'

# Show top 20 files by line count
file-sizes:
    #!/usr/bin/env bash
    find . -type f \( -name '*.rs' -o -name '*.md' \) ! -path './target/*' -exec wc -l {} + | sort -rn | head -20

# Check for oversized files (fails if any exceed limits)
check-file-size:
    #!/usr/bin/env bash
    set -euo pipefail

    RUST_LIMIT=500
    MARKDOWN_LIMIT=200

    # Add paths here to exempt specific files from size limits
    EXCEPTIONS=()

    failed=0

    while IFS= read -r file; do
        lines=$(wc -l < "$file")
        skip=0
        for exception in "${EXCEPTIONS[@]+"${EXCEPTIONS[@]}"}"; do
            if [[ "$file" == "./$exception" ]]; then
                skip=1
                break
            fi
        done

        if [[ $skip -eq 0 && $lines -gt $RUST_LIMIT ]]; then
            echo "--- $file: $lines lines (limit: $RUST_LIMIT)"
            failed=1
        fi
    done < <(find . -type f -name '*.rs' ! -path './target/*')

    while IFS= read -r file; do
        lines=$(wc -l < "$file")
        if [[ $lines -gt $MARKDOWN_LIMIT ]]; then
            echo "--- $file: $lines lines (limit: $MARKDOWN_LIMIT)"
            failed=1
        fi
    done < <(find . -type f -name '*.md' ! -path './target/*' ! -path './archive/*')

    if [[ $failed -eq 1 ]]; then
        echo ""
        echo "Some files exceed size limits. Consider refactoring."
        exit 1
    else
        echo "All files within size limits"
    fi
