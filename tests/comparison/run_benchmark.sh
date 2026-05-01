#!/usr/bin/env bash
# Security Tools Comparison Benchmark
# Executes multiple security analysis tools on the test corpus

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPARISON_DIR="$PROJECT_ROOT/tests/comparison"
RESULTS_DIR="$COMPARISON_DIR/results"
TEST_FILE="$COMPARISON_DIR/vulnerable_patterns.py"
RULES_DIR="$COMPARISON_DIR/rules"

mkdir -p "$RESULTS_DIR"

echo "=== Security Tools Comparison Benchmark ==="
echo "Test file: $TEST_FILE"
echo "Results directory: $RESULTS_DIR"
echo ""

# Tool 1: Falcon stubs (mypy type checking)
echo "1. Falcon stubs (mypy --strict)"
echo "   Running: uv run mypy --strict $TEST_FILE"
SECONDS=0
if uv run mypy --strict "$TEST_FILE" > "$RESULTS_DIR/mypy_output.txt" 2>&1; then
    MYPY_STATUS="PASS"
else
    MYPY_STATUS="FAIL"
fi
MYPY_TIME=$SECONDS
echo "   Status: $MYPY_STATUS, Time: ${MYPY_TIME}s"
echo ""

# Tool 2: Bandit
echo "2. Bandit (Python security linter)"
echo "   Running: uv run bandit -r $TEST_FILE -f json"
SECONDS=0
if uv run bandit -r "$TEST_FILE" -f json > "$RESULTS_DIR/bandit_raw.json" 2>&1; then
    # Extract JSON from output (skip log lines)
    grep -q '^\{' "$RESULTS_DIR/bandit_raw.json"
    if [ $? -eq 0 ]; then
        # Find start of JSON and extract it
        sed -n '/^{/,$p' "$RESULTS_DIR/bandit_raw.json" > "$RESULTS_DIR/bandit_results.json"
        BANDIT_STATUS="FOUND_ISSUES"
    else
        cp "$RESULTS_DIR/bandit_raw.json" "$RESULTS_DIR/bandit_results.json"
        BANDIT_STATUS="RUN_ERROR"
    fi
else
    BANDIT_STATUS="RUN_ERROR"
    uv run bandit -r "$TEST_FILE" -f json 2>&1 | sed -n '/^{/,$p' > "$RESULTS_DIR/bandit_results.json" || true
fi
BANDIT_TIME=$SECONDS
echo "   Status: $BANDIT_STATUS, Time: ${BANDIT_TIME}s"
echo ""

# Tool 3: Semgrep
echo "3. Semgrep (Static analysis with pattern matching)"
echo "   Running: uv run semgrep --config=$RULES_DIR $TEST_FILE --json --quiet"
SECONDS=0
if uv run semgrep --config="$RULES_DIR" "$TEST_FILE" --json --quiet > "$RESULTS_DIR/semgrep_results.json" 2>&1; then
    SEMGREP_STATUS="FOUND_FINDINGS"
else
    SEMGREP_STATUS="RUN_ERROR"
fi
SEMGREP_TIME=$SECONDS
echo "   Status: $SEMGREP_STATUS, Time: ${SEMGREP_TIME}s"
echo ""

# Tool 4: Ruff
echo "4. Ruff (Fast Python linter with security rules)"
echo "   Running: uv run ruff check $TEST_FILE --output-format=json"
SECONDS=0
if uv run ruff check "$TEST_FILE" --output-format=json > "$RESULTS_DIR/ruff_results.json" 2>&1; then
    RUFF_STATUS="FOUND_ISSUES"
else
    RUFF_STATUS="NO_ISSUES_OR_ERROR"
fi
RUFF_TIME=$SECONDS
echo "   Status: $RUFF_STATUS, Time: ${RUFF_TIME}s"
echo ""

# Summary
echo "=== Benchmark Summary ==="
echo "Tool                                | Status       | Time"
echo "------------------------------------|--------------|--------"
printf "%-35s | %-12s | %ds\n" "Falcon stubs (mypy)" "$MYPY_STATUS" "$MYPY_TIME"
printf "%-35s | %-12s | %ds\n" "Bandit" "$BANDIT_STATUS" "$BANDIT_TIME"
printf "%-35s | %-12s | %ds\n" "Semgrep" "$SEMGREP_STATUS" "$SEMGREP_TIME"
printf "%-35s | %-12s | %ds\n" "Ruff" "$RUFF_STATUS" "$RUFF_TIME"
echo ""
echo "Results saved to: $RESULTS_DIR/"
echo ""
echo "Next steps:"
echo "  cat $RESULTS_DIR/mypy_output.txt"
echo "  cat $RESULTS_DIR/bandit_results.json | jq"
echo "  cat $RESULTS_DIR/semgrep_results.json | jq"
echo "  cat $RESULTS_DIR/ruff_results.json | jq"
