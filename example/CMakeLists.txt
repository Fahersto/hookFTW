## Attacker
file(GLOB_RECURSE ATTACKER_SOURCES LIST_DIRECTORIES true attacker/*.h attacker/*.cpp)
# Add example.dll
add_library (example SHARED ${ATTACKER_SOURCES})
# Add header files of hookftw.lib to search path (needed by example.dll)
include_directories(${CMAKE_SOURCE_DIR}/library/src)
# Link hookftw.lib to example.dll
target_link_libraries(example hookftw)
target_link_libraries(example dbghelp)


## Victim
file(GLOB_RECURSE VICTIM_SOURCES LIST_DIRECTORIES true victim/*.h victim/*.cpp)
# Add victim.exe
add_executable(victim ${VICTIM_SOURCES})