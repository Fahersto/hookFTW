cmake_minimum_required(VERSION "3.15")
project("hookftw")

## Add Zydis dependency
option(ZYDIS_BUILD_TOOLS "" OFF)	# Disable build of tools
option(ZYDIS_BUILD_EXAMPLES "" OFF)	# Disable build of examples

#option(ZYDIS_STATIC_DEFINE "" ON)	
#option(ZYCORE_STATIC_DEFINE "" ON)	

add_subdirectory("deps/zydis")

if (WIN32)
    add_subdirectory(example)
    add_subdirectory(injector)
endif (WIN32)


add_subdirectory(library)
#add_subdirectory(test)