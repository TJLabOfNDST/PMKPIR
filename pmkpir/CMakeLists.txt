add_library(pir_pmkpir
    src/layout.cpp
    src/query_compiler.cpp
    src/protocol.cpp
    src/wide_keyword_codebook.cpp)

target_include_directories(pir_pmkpir PUBLIC include)
target_link_libraries(pir_pmkpir PUBLIC pir_common)
target_compile_features(pir_pmkpir PUBLIC cxx_std_20)
target_compile_options(pir_pmkpir PRIVATE -Wall -Wextra -Wpedantic -Werror)
