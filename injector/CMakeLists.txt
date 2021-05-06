file(GLOB_RECURSE INJECTOR_SOURCES LIST_DIRECTORIES true src/*.h src/*.cpp)
add_executable(injector ${INJECTOR_SOURCES})
target_compile_features(injector PRIVATE cxx_std_17) #compile with c++17 so we can use std::filesystem