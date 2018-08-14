## get all project files
file(GLOB SOURCE_FILES ${CMAKE_SOURCE_DIR}/src/*.cpp ${CMAKE_SOURCE_DIR}/src/*.c ${CMAKE_SOURCE_DIR}/src/inspectors/*.c ${CMAKE_SOURCE_DIR}/include/peafowl/*.h ${CMAKE_SOURCE_DIR}/include/peafowl/*.hpp ${CMAKE_SOURCE_DIR}/include/peafowl/inspectors/*.h)

add_custom_target(
        clangformat
        COMMAND /usr/bin/clang-format
        -style=google
        -i
        ${SOURCE_FILES}
)