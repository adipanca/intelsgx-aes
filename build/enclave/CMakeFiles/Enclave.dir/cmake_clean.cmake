file(REMOVE_RECURSE
  "libEnclave.pdb"
  "libEnclave.so"
)

# Per-language clean rules from dependency scanning.
foreach(lang C CXX)
  include(CMakeFiles/Enclave.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
