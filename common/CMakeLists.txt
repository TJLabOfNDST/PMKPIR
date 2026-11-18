add_library(pir_common
    src/types.cpp
    src/bfv.cpp
    src/dataset.cpp
    src/boolean_query.cpp
    src/hash.cpp
    src/persistence.cpp
    src/constant_weight.cpp
    src/keyword_database.cpp)

target_include_directories(pir_common PUBLIC include)
target_link_libraries(pir_common PUBLIC SEAL::seal OpenSSL::Crypto)
target_compile_features(pir_common PUBLIC cxx_std_20)
target_compile_options(pir_common PRIVATE -Wall -Wextra -Wpedantic -Werror)
