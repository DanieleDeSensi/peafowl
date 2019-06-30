## get all project files
find_package(ClangFormat)
   
if(NOT CLANG_FORMAT_FOUND)
  message("clang-format not found. Please install it to run 'make clangformat'")
endif()

file(GLOB SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/*.cpp ${PROJECT_SOURCE_DIR}/src/*.c ${PROJECT_SOURCE_DIR}/src/inspectors/*.c ${PROJECT_SOURCE_DIR}/include/peafowl/*.h ${PROJECT_SOURCE_DIR}/include/peafowl/*.hpp ${PROJECT_SOURCE_DIR}/include/peafowl/inspectors/*.h)
 
add_custom_target(
        clangformat
        COMMAND ${CLANG_FORMAT_EXECUTABLE}
        -style='{
                 AllowShortFunctionsOnASingleLine : None,
                 AllowShortIfStatementsOnASingleLine : false,
                 AllowShortLoopsOnASingleLine : false,
                 AlignOperands : true,
                 AllowShortCaseLabelsOnASingleLine : false,
                 AllowShortBlocksOnASingleLine : false,
                 BreakBeforeBinaryOperators : None,
                 BreakBeforeTernaryOperators : false,
                 SpaceAfterCStyleCast : true,
                 AlignAfterOpenBracket : true,
                 UseTab : Never}'
        -i
        ${SOURCE_FILES}
)