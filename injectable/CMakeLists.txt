file(GLOB_RECURSE LIBRARY_SOURCES LIST_DIRECTORIES true
        main.cpp
        HookUtility.h HookUtility.cpp
        ../library/src/Decoder.h ../library/src/Decoder.cpp
        ../library/src/Memory.h ../library/src/Memory.cpp
        ../library/src/MidfunctionHook.h ../library/src/MidfunctionHook.cpp
        ../library/src/Registers.h
        ../library/src/Trampoline.h ../library/src/Trampoline.cpp
)

include_directories(../library/src)
add_library(injectable SHARED ${LIBRARY_SOURCES})

# Link our project executable against Zydis.
target_link_libraries(injectable PRIVATE Zydis)
target_link_libraries(injectable PRIVATE hookftw)

# Link dbghelp on Windows for symbol resolution
if (WIN32)
    target_link_libraries(injectable PRIVATE dbghelp)
endif()

target_compile_features(injectable PRIVATE cxx_std_20)