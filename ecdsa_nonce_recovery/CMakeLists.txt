cmake_minimum_required(VERSION 3.16)
project(ecdsa_nonce_recovery LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find dependencies
find_package(PkgConfig REQUIRED)

pkg_check_modules(GMP REQUIRED gmp)
pkg_check_modules(GMPXX REQUIRED gmpxx)
pkg_check_modules(FFTW3 REQUIRED fftw3)

# fplll
pkg_check_modules(FPLLL REQUIRED fplll)

find_package(Threads REQUIRED)

# Main executable
add_executable(ecdsa_nonce_recovery
    src/main.cpp
    src/parser.cpp
    src/pair_computation.cpp
    src/bias_profiler.cpp
    src/lattice_solver.cpp
    src/fft_solver.cpp
    src/recovery_engine.cpp
    src/telemetry.cpp
    src/verifier.cpp
    src/utils.cpp
    src/secp256k1.cpp
)

target_include_directories(ecdsa_nonce_recovery PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${GMP_INCLUDE_DIRS}
    ${GMPXX_INCLUDE_DIRS}
    ${FPLLL_INCLUDE_DIRS}
    ${FFTW3_INCLUDE_DIRS}
)

target_link_libraries(ecdsa_nonce_recovery PRIVATE
    ${GMP_LIBRARIES}
    ${GMPXX_LIBRARIES}
    ${FPLLL_LIBRARIES}
    ${FFTW3_LIBRARIES}
    Threads::Threads
)

target_compile_options(ecdsa_nonce_recovery PRIVATE
    -Wall -Wextra -Wpedantic
    ${GMP_CFLAGS_OTHER}
    ${FPLLL_CFLAGS_OTHER}
)

# Standalone fplll test binary
add_executable(fplll_sanity_test
    tests/fplll_sanity.cpp
)

target_include_directories(fplll_sanity_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${FPLLL_INCLUDE_DIRS}
    ${GMP_INCLUDE_DIRS}
)

target_link_libraries(fplll_sanity_test PRIVATE
    ${FPLLL_LIBRARIES}
    ${GMP_LIBRARIES}
    ${GMPXX_LIBRARIES}
)

# Fast, isolated unit tests (see tests/unit_tests.cpp for what these cover
# and why they're kept separate from the full e2e pipeline test).
add_executable(unit_tests
    tests/unit_tests.cpp
    src/utils.cpp
    src/secp256k1.cpp
    src/verifier.cpp
    src/lattice_solver.cpp
)

target_include_directories(unit_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${GMP_INCLUDE_DIRS}
    ${GMPXX_INCLUDE_DIRS}
    ${FPLLL_INCLUDE_DIRS}
)

target_link_libraries(unit_tests PRIVATE
    ${GMP_LIBRARIES}
    ${GMPXX_LIBRARIES}
    ${FPLLL_LIBRARIES}
)

# Install
install(TARGETS ecdsa_nonce_recovery DESTINATION bin)

# For testing convenience
enable_testing()
add_test(NAME unit_tests COMMAND unit_tests)
set_tests_properties(unit_tests PROPERTIES TIMEOUT 30)
add_test(NAME fplll_sanity COMMAND fplll_sanity_test)

# True end-to-end integration test: generates real biased/unbiased signature
# data with known ground truth, runs the actual compiled binary, and checks
# the reported recovery against that ground truth. See tests/e2e_recovery_test.sh
# for why this replaces trusting a component-level self-test.
add_test(
    NAME e2e_recovery
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e_recovery_test.sh
            $<TARGET_FILE:ecdsa_nonce_recovery>
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/generate_mock_signatures.py
)
set_tests_properties(e2e_recovery PROPERTIES TIMEOUT 600)
