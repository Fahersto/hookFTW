## Test
file(GLOB_RECURSE TEST_SOURCES LIST_DIRECTORIES true ./*.h ./*.cpp)

# Add test.exe
add_executable (test ${TEST_SOURCES})

# Add header files of hookftw.lib to search path (needed by test.exe)
include_directories(../library/src)

# Link hookftw.lib to example.dll
target_link_libraries(test hookftw)
# target_link_libraries(test dbghelp)