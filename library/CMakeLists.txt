## hookftw library
# Add header and source files to library
file(GLOB_RECURSE LIBRARY_SOURCES LIST_DIRECTORIES true src/*.h src/*.cpp)
# Add hookftw.lib
add_library(hookftw ${LIBRARY_SOURCES})
# Link our project executable against Zydis.
target_link_libraries(hookftw PUBLIC Zydis) #public damit attacker auch included PRIVAT
target_compile_features(hookftw PRIVATE cxx_std_17)