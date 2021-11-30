pushd write_wrappers
  ../../afl-clang-fast -c wrapper.c
popd

pushd src
  ../../afl-clang-fast -c classify.c
popd

WRAP_FLAGS="-Wl,-wrap,printf -Wl,-wrap,fprintf -Wl,-wrap,vprintf -Wl,-wrap,vfprintf -Wl,-wrap,write -Wl,-wrap,puts -Wl,-wrap,fputs -Wl,-wrap,fwrite"
../afl-clang-fast $WRAP_FLAGS write_wrappers/wrapper.o src/classify.o -lc -o classify
