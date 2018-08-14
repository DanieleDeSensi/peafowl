########################
# Src and header files #
########################
include_directories(${CMAKE_SOURCE_DIR}/include)
file(GLOB SOURCES "*.cpp" "*.c" "inspectors/*.cpp" "inspectors/*.c")
list(REMOVE_ITEM SOURCES "${CMAKE_SOURCE_DIR}/src/worker.cpp" "${CMAKE_SOURCE_DIR}/src/mc_api.cpp")
add_definitions(-g)

####################
# Parallel version #
####################
if (ENABLE_PARALLEL)
  include_directories(external/fastflow) 
  list(APPEND SOURCES "${CMAKE_SOURCE_DIR}/src/worker.cpp" "${CMAKE_SOURCE_DIR}/src/mc_api.cpp")
  add_definitions(-DDPI_THREAD_SAFETY_ENABLED=1 -DFF_BOUNDED_BUFFER -DNO_DEFAULT_MAPPING)
endif (ENABLE_PARALLEL)
 
####################
# Library building #
####################
add_library(peafowl SHARED ${SOURCES})
add_library(peafowl_static STATIC ${SOURCES})

install(TARGETS peafowl DESTINATION /usr/lib)
install(TARGETS peafowl_static DESTINATION /usr/lib)

####################
# Uninstall target #
####################
if(NOT TARGET uninstall)
    configure_file(
        "${CMAKE_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/cmake/cmake_uninstall.cmake"
        IMMEDIATE @ONLY)

    add_custom_target(uninstall
        COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake/cmake_uninstall.cmake)
endif()
