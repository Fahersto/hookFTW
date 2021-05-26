## hookftw library



# Add header and source files to library
file(GLOB_RECURSE LIBRARY_SOURCES LIST_DIRECTORIES true src/*.h src/*.cpp)
# Add hookftw.lib
add_library(hookftw STATIC ${LIBRARY_SOURCES})

#set_target_properties(Zydis PROPERTIES LINK_FLAGS "/WHOLEARCHIVE")
#set_target_properties(hookftw PROPERTIES LINK_FLAGS "/WHOLEARCHIVE")

# Link our project executable against Zydis.
target_link_libraries(hookftw PRIVATE Zydis) #public damit attacker auch included PRIVAT
#target_link_libraries(hookftw PUBLIC "C:\\Users\\Fahersto\\source\\repos\\hookftw\\out\\build\\x86-Release\\deps\\zydis\\Zydis") #public damit attacker auch included PRIVAT
target_compile_features(hookftw PRIVATE cxx_std_17)
