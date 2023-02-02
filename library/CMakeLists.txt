## hookftw library



# Add header and source files to library
#file(GLOB_RECURSE LIBRARY_SOURCES LIST_DIRECTORIES true src/*.h src/*.cpp)



if (WIN32)
file(GLOB_RECURSE LIBRARY_SOURCES LIST_DIRECTORIES true 
    src/Decoder.h src/Decoder.cpp
    src/Detour.h src/Detour.cpp
    src/DbgSymbols.h src/DbgSymbols.cpp
    src/VEHHook.h src/VEHHook.cpp
    src/IATHook.h src/IATHook.cpp
    src/Memory.h src/Memory.cpp
    src/MidfunctionHook.h src/MidfunctionHook.cpp
    src/Registers.h
    src/Trampoline.h src/Trampoline.cpp
    src/VFTHook.h src/VFTHook.cpp
)

    # Add hookftw.lib
    add_library(hookftw STATIC ${LIBRARY_SOURCES})
endif (WIN32)

if (UNIX)
file(GLOB_RECURSE LIBRARY_SOURCES LIST_DIRECTORIES true 
    src/Decoder.h src/Decoder.cpp
    src/Detour.h src/Detour.cpp
    src/Memory.h src/Memory.cpp
    src/Registers.h
    src/Trampoline.h src/Trampoline.cpp
    src/VFTHook.h src/VFTHook.cpp
)
    add_library(hookftw STATIC ${LIBRARY_SOURCES})
endif (UNIX)

# Link our project executable against Zydis.
target_link_libraries(hookftw PRIVATE Zydis)
target_compile_features(hookftw PRIVATE cxx_std_17)