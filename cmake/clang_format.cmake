## get all project files
find_package(ClangFormat)
   
if(NOT CLANG_FORMAT_FOUND)
  message("clang-format not found. Please install it to run 'make clangformat'")
endif()

file(GLOB SOURCE_FILES ${CMAKE_SOURCE_DIR}/src/*.cpp ${CMAKE_SOURCE_DIR}/src/*.c ${CMAKE_SOURCE_DIR}/src/inspectors/*.c ${CMAKE_SOURCE_DIR}/include/peafowl/*.h ${CMAKE_SOURCE_DIR}/include/peafowl/*.hpp ${CMAKE_SOURCE_DIR}/include/peafowl/inspectors/*.h)
 
add_custom_target(
        clangformat
        COMMAND ${CLANG_FORMAT_EXECUTABLE}
        -style=google
        -i
        ${SOURCE_FILES}
)