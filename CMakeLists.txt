cmake_minimum_required(VERSION 3.16)
project(ecdsa_nonce_recovery LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(GMP REQUIRED gmp)
pkg_check_modules(GMPXX REQUIRED gmpxx)
pkg_check_modules(FPLLL REQUIRED fplll)
find_package(Threads REQUIRED)

# Strict warnings, applied uniformly to every first-party target. Previously
# only the CLI executable had these; the core library and the tests now get
# them too, so a warning regression can't hide in code the CLI doesn't compile.
set(ECDSA_WARNINGS -Wall -Wextra -Wpedantic)

# ---------------------------------------------------------------------------
# Core library: the single shared implementation of the recovery pipeline.
# The CLI and the unit tests both link this instead of each re-listing a
# hand-picked subset of sources (which drifted -- e.g. unit_tests used to omit
# parser.cpp). PUBLIC usage requirements propagate include dirs + link libs to
# anything that links the core.
# ---------------------------------------------------------------------------
add_library(ecdsa_recovery_core STATIC
    src/parser.cpp
    src/pair_computation.cpp
    src/bias_profiler.cpp
    src/lattice_solver.cpp
    src/recovery_engine.cpp
    src/telemetry.cpp
    src/verifier.cpp
    src/utils.cpp
    src/secp256k1.cpp
    src/sieve_estimator.cpp
)

target_include_directories(ecdsa_recovery_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${GMP_INCLUDE_DIRS}
    ${GMPXX_INCLUDE_DIRS}
    ${FPLLL_INCLUDE_DIRS}
)

target_link_libraries(ecdsa_recovery_core PUBLIC
    ${GMP_LIBRARIES}
    ${GMPXX_LIBRARIES}
    ${FPLLL_LIBRARIES}
    Threads::Threads
)

target_compile_options(ecdsa_recovery_core PRIVATE
    ${ECDSA_WARNINGS}
    ${GMP_CFLAGS_OTHER}
    ${FPLLL_CFLAGS_OTHER}
)

# ---------------------------------------------------------------------------
# CLI executable
# ---------------------------------------------------------------------------
add_executable(ecdsa_nonce_recovery src/main.cpp)
target_link_libraries(ecdsa_nonce_recovery PRIVATE ecdsa_recovery_core)
target_compile_options(ecdsa_nonce_recovery PRIVATE ${ECDSA_WARNINGS})

# ---------------------------------------------------------------------------
# Predicate shim: a shared library exposing the tool's secp256k1 pubkey check
# (bazooka_predicate) to the external g6k sieve worker via cffi. Links no
# lattice/sieve code. The static core must be PIC to link into a shared object.
# ---------------------------------------------------------------------------
set_property(TARGET ecdsa_recovery_core PROPERTY POSITION_INDEPENDENT_CODE ON)
add_library(bazooka_predicate SHARED src/predicate_shim.cpp)
target_link_libraries(bazooka_predicate PRIVATE ecdsa_recovery_core)
target_compile_options(bazooka_predicate PRIVATE ${ECDSA_WARNINGS})

# ---------------------------------------------------------------------------
# Standalone fplll sanity test (depends only on fplll/gmp, not the core lib)
# ---------------------------------------------------------------------------
add_executable(fplll_sanity_test tests/fplll_sanity.cpp)
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

# ---------------------------------------------------------------------------
# Fast, isolated unit tests -- link the SAME core library as the CLI, so the
# tests exercise exactly the code that ships (no separate source list to drift).
# ---------------------------------------------------------------------------
add_executable(unit_tests tests/unit_tests.cpp)
target_link_libraries(unit_tests PRIVATE ecdsa_recovery_core)
target_compile_options(unit_tests PRIVATE ${ECDSA_WARNINGS})

# Differential-test shim: prints d*G via this project's secp256k1 for the
# Python driver to compare against the trusted `ecdsa` library.
add_executable(ecc_diff_tool tests/ecc_diff_tool.cpp)
target_link_libraries(ecc_diff_tool PRIVATE ecdsa_recovery_core)
target_compile_options(ecc_diff_tool PRIVATE ${ECDSA_WARNINGS})

# Install
install(TARGETS ecdsa_nonce_recovery DESTINATION bin)

# For testing convenience
enable_testing()
add_test(NAME unit_tests COMMAND unit_tests)
set_tests_properties(unit_tests PROPERTIES TIMEOUT 30)
add_test(NAME fplll_sanity COMMAND fplll_sanity_test)

add_test(
    NAME cli_validation
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_validation_test.sh
            $<TARGET_FILE:ecdsa_nonce_recovery>
)

# Differential ECC test vs the trusted `ecdsa` Python library. Skips itself
# (exit 0) if that library isn't installed, so it never blocks a build that
# lacks the optional test dependency.
add_test(NAME ecc_differential
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tests/ecc_differential_test.py
            $<TARGET_FILE:ecc_diff_tool>)
set_tests_properties(ecc_differential PROPERTIES TIMEOUT 180)

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
