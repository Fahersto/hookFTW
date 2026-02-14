include(FetchContent)

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)

# For Windows: prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

enable_testing()

# Collect test sources
file(GLOB_RECURSE TEST_SOURCES LIST_DIRECTORIES false
    CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_LIST_DIR}/src/*.cpp
    ${CMAKE_CURRENT_LIST_DIR}/src/*.h
)

add_executable(hookftw_tests ${TEST_SOURCES})

target_include_directories(hookftw_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/library/src
)

target_link_libraries(hookftw_tests PRIVATE
    hookftw
    GTest::gtest
    GTest::gtest_main
)

target_compile_features(hookftw_tests PRIVATE cxx_std_17)

# Disable optimizations for test targets to prevent issues with hooking
if (MSVC)
    target_compile_options(hookftw_tests PRIVATE /Od /Ob0)
else()
    target_compile_options(hookftw_tests PRIVATE -O0)
endif()

include(GoogleTest)
gtest_discover_tests(hookftw_tests)
