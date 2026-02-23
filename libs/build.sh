#!/bin/bash
# Build script for ML-DSA and ML-KEM and randombytes
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SCRIPT_DIR"

if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
	SHARED_EXT="dll"
	CC="${CC:-gcc}"
	NATIVE_ARCH="x86_64"
elif [[ "$OSTYPE" == "darwin"* ]]; then
	SHARED_EXT="dylib"
	CC="${CC:-clang}"
	NATIVE_ARCH="aarch64"
else
	SHARED_EXT="so"
	CC="${CC:-gcc}"
	NATIVE_ARCH="x86_64"
fi

echo "Building for platform: $OSTYPE (shared lib: .$SHARED_EXT)"
echo "Compiler: $CC"
echo "Target architecture: $NATIVE_ARCH"

echo "Building randombytes..."
if [[ "$OSTYPE" == "darwin"* ]]; then
	$CC -shared -fPIC -O2 -arch arm64 -o "$SCRIPT_DIR/randombytes.$SHARED_EXT" "$PROJECT_ROOT/src/native/randombytes.c"
else
	$CC -shared -fPIC -O2 -o "$SCRIPT_DIR/randombytes.$SHARED_EXT" "$PROJECT_ROOT/src/native/randombytes.c"
fi

echo "Building ML-DSA..."
if [ ! -d "$SCRIPT_DIR/src/mldsa-native" ]; then
	git clone --depth 1 https://github.com/pq-code-package/mldsa-native.git "$SCRIPT_DIR/src/mldsa-native"
fi
cd "$SCRIPT_DIR/src/mldsa-native"
make clean 2>/dev/null || true
if [[ "$OSTYPE" == "darwin"* ]]; then
	make EXTRA_CFLAGS="-fPIC -O2 -arch arm64" EXTRA_ASMFLAGS="-arch arm64" build
else
	make EXTRA_CFLAGS="-fPIC -O2" build
fi

echo "Creating ML-DSA shared libraries..."
for variant in 44 65 87; do
	mkdir -p "$SCRIPT_DIR/tmp_mldsa${variant}"
	cd "$SCRIPT_DIR/tmp_mldsa${variant}"
	cp "$SCRIPT_DIR/src/mldsa-native/test/build/mldsa${variant}/mldsa/src"/*.o .
	cp "$SCRIPT_DIR/src/mldsa-native/test/build/mldsa${variant}/mldsa/src/native/${NATIVE_ARCH}/src"/*.o .
	cp "$SCRIPT_DIR/src/mldsa-native/test/build/mldsa${variant}/mldsa/src/fips202"/*.o .
	cp "$SCRIPT_DIR/src/mldsa-native/test/build/mldsa${variant}/mldsa/src/fips202/native/${NATIVE_ARCH}/src"/*.o .
	if [[ "$SHARED_EXT" == "dylib" ]]; then
		$CC -dynamiclib -o "$SCRIPT_DIR/libmldsa${variant}.$SHARED_EXT" *.o "$SCRIPT_DIR/randombytes.$SHARED_EXT"
	else
		$CC -shared -z noexecstack -o "$SCRIPT_DIR/libmldsa${variant}.$SHARED_EXT" *.o "$SCRIPT_DIR/randombytes.$SHARED_EXT"
	fi
	cd "$SCRIPT_DIR"
	rm -rf "$SCRIPT_DIR/tmp_mldsa${variant}"
done

echo "Building ML-KEM..."
cd "$SCRIPT_DIR"
if [ ! -d "$SCRIPT_DIR/src/mlkem-native" ]; then
	git clone --depth 1 https://github.com/pq-code-package/mlkem-native.git "$SCRIPT_DIR/src/mlkem-native"
fi
cd "$SCRIPT_DIR/src/mlkem-native"
make clean 2>/dev/null || true
if [[ "$OSTYPE" == "darwin"* ]]; then
	make EXTRA_CFLAGS="-fPIC -O2 -arch arm64" EXTRA_ASMFLAGS="-arch arm64" build
else
	make EXTRA_CFLAGS="-fPIC -O2" build
fi

echo "Creating ML-KEM shared libraries..."
for variant in 512 768 1024; do
	mkdir -p "$SCRIPT_DIR/tmp_mlkem${variant}"
	cd "$SCRIPT_DIR/tmp_mlkem${variant}"
	cp "$SCRIPT_DIR/src/mlkem-native/test/build/mlkem${variant}/mlkem/src"/*.o .
	cp "$SCRIPT_DIR/src/mlkem-native/test/build/mlkem${variant}/mlkem/src/native/${NATIVE_ARCH}/src"/*.o .
	cp "$SCRIPT_DIR/src/mlkem-native/test/build/mlkem${variant}/mlkem/src/fips202"/*.o .
	cp "$SCRIPT_DIR/src/mlkem-native/test/build/mlkem${variant}/mlkem/src/fips202/native/${NATIVE_ARCH}/src"/*.o .
	if [[ "$SHARED_EXT" == "dylib" ]]; then
		$CC -dynamiclib -o "$SCRIPT_DIR/libmlkem${variant}.$SHARED_EXT" *.o "$SCRIPT_DIR/randombytes.$SHARED_EXT"
	else
		$CC -shared -z noexecstack -o "$SCRIPT_DIR/libmlkem${variant}.$SHARED_EXT" *.o "$SCRIPT_DIR/randombytes.$SHARED_EXT"
	fi
	cd "$SCRIPT_DIR"
	rm -rf "$SCRIPT_DIR/tmp_mlkem${variant}"
done

echo ""
echo "Build complete! Libraries in $SCRIPT_DIR/:"
ls -lh "$SCRIPT_DIR"/libml*."$SHARED_EXT" "$SCRIPT_DIR"/randombytes.$SHARED_EXT 2>/dev/null ||
	ls -lh "$SCRIPT_DIR"/*."$SHARED_EXT"
