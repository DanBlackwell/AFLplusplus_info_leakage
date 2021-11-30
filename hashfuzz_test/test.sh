pushd write_wrappers
  gcc -c test_wrapper.c 
  gcc -c wrapper.c
  WRAP_FLAGS="-Wl,-wrap,printf -Wl,-wrap,fprintf -Wl,-wrap,vprintf -Wl,-wrap,vfprintf -Wl,-wrap,write -Wl,-wrap,puts -Wl,-wrap,fputs -Wl,-wrap,fwrite"
  gcc $WRAP_FLAGS wrapper.o test_wrapper.o -lc -o test
  ./test > expected_out.txt
popd
