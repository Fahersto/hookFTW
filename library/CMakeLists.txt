## hookftw library



# Add header and source files to library
file(GLOB_RECURSE LIBRARY_SOURCES LIST_DIRECTORIES true src/*.h src/*.cpp)

# Add hookftw.lib
add_library(hookftw STATIC ${LIBRARY_SOURCES})

# Link our project executable against Zydis.
target_link_libraries(hookftw PRIVATE Zydis)
target_compile_features(hookftw PRIVATE cxx_std_17)