#!/bin/bash
# Build script for ML-DSA and ML-KEM and randombytes
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SCRIPT_DIR"

if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
	SHARED_EXT="dll"
	CC="${CC:-gcc}"
elif [[ "$OSTYPE" == "darwin"* ]]; then
	SHARED_EXT="dylib"
	CC="${CC:-clang}"
else
	SHARED_EXT="so"
	CC="${CC:-gcc}"
fi

echo "Building for platform: $OSTYPE (shared lib: .$SHARED_EXT)"
echo "Compiler: $CC"

echo "Building randombytes..."
$CC -shared -fPIC -O2 -o "$SCRIPT_DIR/randombytes.$SHARED_EXT" "$PROJECT_ROOT/src/native/randombytes.c"

echo "Building ML-DSA..."
if [ ! -d "$SCRIPT_DIR/src/mldsa-native" ]; then
	git clone --depth 1 https://github.com/pq-code-package/mldsa-native.git "$SCRIPT_DIR/src/mldsa-native"
fi
cd "$SCRIPT_DIR/src/mldsa-native"
make clean 2>/dev/null || true
make EXTRA_CFLAGS="-fPIC -O2" build

echo "Creating ML-DSA shared libraries..."
for variant in 44 65 87; do
	ar -x test/build/libmldsa${variant}.a
	if [[ "$SHARED_EXT" == "dylib" ]]; then
		$CC -dynamiclib -o "$SCRIPT_DIR/libmldsa${variant}.$SHARED_EXT" *.o
	else
		$CC -shared -z noexecstack -o "$SCRIPT_DIR/libmldsa${variant}.$SHARED_EXT" *.o
	fi
	rm -f *.o
done

echo "Building ML-KEM..."
cd "$SCRIPT_DIR"
if [ ! -d "$SCRIPT_DIR/src/mlkem-native" ]; then
	git clone --depth 1 https://github.com/pq-code-package/mlkem-native.git "$SCRIPT_DIR/src/mlkem-native"
fi
cd "$SCRIPT_DIR/src/mlkem-native"
make clean 2>/dev/null || true
make EXTRA_CFLAGS="-fPIC -O2" build

echo "Creating ML-KEM shared libraries..."
for variant in 512 768 1024; do
	ar -x test/build/libmlkem${variant}.a
	if [[ "$SHARED_EXT" == "dylib" ]]; then
		$CC -dynamiclib -o "$SCRIPT_DIR/libmlkem${variant}.$SHARED_EXT" *.o
	else
		$CC -shared -z noexecstack -o "$SCRIPT_DIR/libmlkem${variant}.$SHARED_EXT" *.o
	fi
	rm -f *.o
done

echo ""
echo "Build complete! Libraries in $SCRIPT_DIR/:"
ls -lh "$SCRIPT_DIR"/libml*."$SHARED_EXT" "$SCRIPT_DIR"/randombytes.$SHARED_EXT 2>/dev/null ||
	ls -lh "$SCRIPT_DIR"/*."$SHARED_EXT"
