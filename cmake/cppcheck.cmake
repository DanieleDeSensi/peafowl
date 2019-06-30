# additional target to perform cppcheck run, requires cppcheck
find_package(cppcheck)

if(!CPPCHECK_FOUND)
  message("cppcheck not found. Please install it to run 'make cppcheck'")
endif()

add_custom_target(
        cppcheck
        COMMAND ${CPPCHECK_EXECUTABLE} --xml --xml-version=2 --enable=warning,performance,style --error-exitcode=1 --suppressions-list=${CMAKE_SOURCE_DIR}/test/cppcheck/suppressions-list.txt -UNN_EXPORT ${CMAKE_SOURCE_DIR} -i${CMAKE_SOURCE_DIR}/src/external -i${CMAKE_SOURCE_DIR}/demo/http_pattern_matching/pattern_matching_lib -i${CMAKE_SOURCE_DIR}/src/worker.cpp -itest -ibuild -icmake 2> cppcheck-report.xml || (cat cppcheck-report.xml && exit 2) 
)


