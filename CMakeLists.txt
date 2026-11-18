cmake_minimum_required(VERSION 3.20)
project(pmkpir VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(SEAL 4.1.2 REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

include(CTest)
add_subdirectory(common)
add_subdirectory(pmkpir)

# ---------------------------------------------------------------------------
# Example: an end-to-end private Boolean retrieval demo.
# ---------------------------------------------------------------------------
add_executable(pmkpir_example examples/basic_boolean_query.cpp)
target_link_libraries(pmkpir_example PRIVATE pir_pmkpir)
target_compile_options(pmkpir_example PRIVATE -Wall -Wextra -Wpedantic -Werror)

# ---------------------------------------------------------------------------
# Unit tests. Each executable doubles as a CTest case.
# ---------------------------------------------------------------------------
if(BUILD_TESTING)
    function(add_pir_test test_name library)
        add_executable(${test_name} tests/${test_name}.cpp)
        target_link_libraries(${test_name} PRIVATE ${library})
        target_compile_options(${test_name} PRIVATE -Wall -Wextra -Wpedantic -Werror)
        add_test(NAME ${test_name} COMMAND ${test_name})
    endfunction()

    add_pir_test(common_types_test pir_common)
    add_pir_test(dataset_test pir_common)
    add_pir_test(boolean_query_test pir_common)
    add_pir_test(constant_weight_test pir_common)
    add_pir_test(keyword_database_test pir_common)
    add_pir_test(persistence_test pir_common)

    add_pir_test(pmkpir_query_test pir_pmkpir)
    add_pir_test(pmkpir_protocol_test pir_pmkpir)
    add_pir_test(wide_keyword_codebook_test pir_pmkpir)
    add_pir_test(pmkpir_wide_domain_test pir_pmkpir)
endif()
