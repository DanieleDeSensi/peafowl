include_directories(${CMAKE_SOURCE_DIR}/include)

# Check if git is present
find_package(Git)
if(!GIT_FOUND)
  message("git not found. Please install it to run the tests.")
endif()

# Download and unpack googletest at configure time
configure_file(${CMAKE_SOURCE_DIR}/cmake/gtest_download.cmake.in googletest-download/CMakeLists.txt)

execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/test/googletest-download )
if(result)
  message(FATAL_ERROR "CMake step for googletest failed: ${result}")
endif()

execute_process(COMMAND ${CMAKE_COMMAND} --build .
  RESULT_VARIABLE result
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/test/googletest-download )
if(result)
  message(FATAL_ERROR "Build step for googletest failed: ${result}")
endif()

# Prevent overriding the parent project's compiler/linker
# settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Add googletest directly to our build. This defines
# the gtest and gtest_main targets.
add_subdirectory(${CMAKE_BINARY_DIR}/test/googletest-src
                 ${CMAKE_BINARY_DIR}/test/googletest-build
                 EXCLUDE_FROM_ALL)

# The gtest/gtest_main targets carry header search path
# dependencies automatically when using CMake 2.8.11 or
# later. Otherwise we have to add them here ourselves.
if (CMAKE_VERSION VERSION_LESS 2.8.11)
  include_directories("${gtest_SOURCE_DIR}/include")
endif()

file(GLOB TESTS "*.cpp")
list(REMOVE_ITEM TESTS "${CMAKE_SOURCE_DIR}/test/common.cpp")
foreach(TEST ${TESTS})
  set(TESTNAME ${TEST})
  string(REPLACE "${CMAKE_SOURCE_DIR}/test/" "" TESTNAME ${TESTNAME})
  string(REPLACE ".cpp" "" TESTNAME ${TESTNAME})
  add_executable(${TESTNAME} ${TEST} "${CMAKE_SOURCE_DIR}/test/common.cpp")
  target_link_libraries(${TESTNAME} peafowl_static gtest_main pcap)

  add_test(
    NAME ${TESTNAME}
    COMMAND ${TESTNAME}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/test
  )  
endforeach(TEST)

# Print full output of tests
#configure_file(${CMAKE_SOURCE_DIR}/cmake/CTestCustom.cmake ${CMAKE_BINARY_DIR}/CTestCustom.cmake)
