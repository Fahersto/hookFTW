#!/bin/bash
set -e

# Usage function
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Test the injectable library with either a function name or hook address offset"
    echo ""
    echo "Options:"
    echo "  -f, --function-name NAME    Function name to hook (e.g., CalculateInput)"
    echo "  -o, --offset OFFSET         Hook address offset from base in hexadecimal (e.g., 0x1234)"
    echo "  -s, --skip-original         Skip original function call (default: false)"
    echo "  -h, --help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --function-name CalculateInput"
    echo "  $0 --function-name CalculateInput --skip-original"
    echo "  $0 --offset 0x1234"
    exit 1
}

# Parse command-line arguments
FUNCTION_NAME=""
HOOK_ADDRESS_OFFSET=""
SKIP_ORIGINAL="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--function-name)
            FUNCTION_NAME="$2"
            shift 2
            ;;
        -o|--offset)
            HOOK_ADDRESS_OFFSET="$2"
            shift 2
            ;;
        -s|--skip-original)
            SKIP_ORIGINAL="true"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Default to CalculateInput if no arguments provided
if [ -z "$FUNCTION_NAME" ] && [ -z "$HOOK_ADDRESS_OFFSET" ]; then
    echo "[test] No function name or hook address offset specified, defaulting to CalculateInput"
    FUNCTION_NAME="_Z14CalculateInputi"
fi

# Validate that only one mode is specified
if [ -n "$FUNCTION_NAME" ] && [ -n "$HOOK_ADDRESS_OFFSET" ]; then
    echo "[test] Error: Cannot specify both function name and hook address offset"
    usage
fi

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VICTIM_BIN="$SCRIPT_DIR/../cmake-build-debug/example/victim"
INJECTABLE_SO="$SCRIPT_DIR/../cmake-build-debug/injectable/libinjectable.so"
MAIN_CPP="$SCRIPT_DIR/main.cpp"

if [ ! -f "$VICTIM_BIN" ]; then
    echo "[test] Victim binary not found: $VICTIM_BIN"
    exit 1
fi
if [ ! -f "$MAIN_CPP" ]; then
    echo "[test] main.cpp not found: $MAIN_CPP"
    exit 1
fi

# Update main.cpp with the specified configuration
echo "[test] Updating main.cpp configuration..."

if [ -n "$FUNCTION_NAME" ]; then
    echo "[test] Mode: Function name = $FUNCTION_NAME"
    sed -i "s|std::string compileFlag_functionName = \".*\";|std::string compileFlag_functionName = \"$FUNCTION_NAME\";|" "$MAIN_CPP"
    sed -i 's|uintptr_t compileFlag_hookAddressOffset = .*;|uintptr_t compileFlag_hookAddressOffset = 0;|' "$MAIN_CPP"
elif [ -n "$HOOK_ADDRESS_OFFSET" ]; then
    echo "[test] Mode: Hook address offset = $HOOK_ADDRESS_OFFSET"
    sed -i 's|std::string compileFlag_functionName = ".*";|std::string compileFlag_functionName = "";|' "$MAIN_CPP"
    sed -i "s|uintptr_t compileFlag_hookAddressOffset = .*;|uintptr_t compileFlag_hookAddressOffset = $HOOK_ADDRESS_OFFSET;|" "$MAIN_CPP"
fi

echo "[test] Skip original function: $SKIP_ORIGINAL"
sed -i "s|bool compileFlag_skipOriginalFunction = .*;|bool compileFlag_skipOriginalFunction = $SKIP_ORIGINAL;|" "$MAIN_CPP"

# Rebuild the injectable library
echo "[test] Rebuilding injectable library..."
cd "$SCRIPT_DIR/../cmake-build-debug"
cmake --build . --target injectable -j$(nproc) > /dev/null 2>&1 || {
    echo "[test] Build failed!"
    exit 1
}

if [ ! -f "$INJECTABLE_SO" ]; then
    echo "[test] Injectable .so not found after build: $INJECTABLE_SO"
    exit 1
fi

echo "[test] Build successful!"
echo "[test] Running victim with LD_PRELOAD..."
echo "----------------------------------------"

export LD_PRELOAD="$INJECTABLE_SO"
"$VICTIM_BIN" 2>&1

echo "----------------------------------------"
echo "[test] Test complete!"

