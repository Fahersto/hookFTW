cmake_minimum_required(VERSION "3.15")
project("hookftw")

# Enable CTest from the top-level so `ctest` picks up subdirectory tests.
include(CTest)

# Enable position-independent code for shared libraries
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

## Add Zydis dependency
option(ZYDIS_BUILD_TOOLS "" OFF)	# Disable build of tools
option(ZYDIS_BUILD_EXAMPLES "" OFF)	# Disable build of examples

#option(ZYDIS_STATIC_DEFINE "" ON)	
#option(ZYCORE_STATIC_DEFINE "" ON)	

add_subdirectory("deps/zydis")

if (WIN32)
    add_subdirectory(injector)
endif (WIN32)

add_subdirectory(example)
add_subdirectory(library)
add_subdirectory(test)
add_subdirectory(injectable)

