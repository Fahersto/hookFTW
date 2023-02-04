if (WIN32)
    ## Attacker
    file(GLOB_RECURSE ATTACKER_SOURCES LIST_DIRECTORIES true windows/attacker/*.h windows/attacker/*.cpp)
    # Add example.dll
    add_library (example SHARED ${ATTACKER_SOURCES})
    # Add header files of hookftw.lib to search path (needed by example.dll)
    include_directories(../library/src)
    # Link hookftw.lib to example.dll
    target_link_libraries(example hookftw)
    target_link_libraries(example dbghelp)


    ## Victim
    file(GLOB_RECURSE VICTIM_SOURCES LIST_DIRECTORIES true windows/victim/*.h windows/victim/*.cpp)
    # Add victim.exe
    add_executable(victim ${VICTIM_SOURCES})
endif (WIN32)

if (UNIX)
    ## Attacker
    file(GLOB_RECURSE ATTACKER_SOURCES LIST_DIRECTORIES true linux/attacker/*.h linux/attacker/*.cpp)
    # Add example.dll
    add_library (example SHARED ${ATTACKER_SOURCES})
    # Add header files of hookftw.lib to search path (needed by example.dll)
    include_directories(../library/src)
    # Link hookftw.lib to example.dll
    target_link_libraries(example hookftw)


    ## Victim
    file(GLOB_RECURSE VICTIM_SOURCES LIST_DIRECTORIES true linux/victim/*.h linux/victim/*.cpp)
    # Add victim.exe
    add_executable(victim ${VICTIM_SOURCES})
endif (UNIX)