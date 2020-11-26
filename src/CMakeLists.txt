########################
# Src and header files #
########################
include_directories(${CMAKE_SOURCE_DIR}/include)
file(GLOB SOURCES "*.cpp" "*.c" "inspectors/*.cpp" "inspectors/*.c" "external/md5.c")
list(REMOVE_ITEM SOURCES "${CMAKE_SOURCE_DIR}/src/worker.cpp" "${CMAKE_SOURCE_DIR}/src/peafowl_mc.cpp" "${CMAKE_SOURCE_DIR}/src/peafowl_py.cpp")

if (PCAP_FOUND)
  include_directories(${PCAP_INCLUDE_DIR})
  add_definitions(-DHAVE_PCAP)
endif(PCAP_FOUND)

if (OPENSSL_FOUND)
  include_directories(${OPENSSL_INCLUDE_DIR})
  link_libraries(${OPENSSL_LIBRARIES})
  add_definitions(-DHAVE_OPENSSL)
endif(OPENSSL_FOUND)

####################
# Parallel version #
####################
if (ENABLE_PARALLEL)
  find_package (Threads REQUIRED)
  list(APPEND SOURCES "${CMAKE_SOURCE_DIR}/src/worker.cpp" "${CMAKE_SOURCE_DIR}/src/peafowl_mc.cpp")
  add_definitions(-DPFWL_THREAD_SAFETY_ENABLED=1 -DFF_BOUNDED_BUFFER -DNO_DEFAULT_MAPPING)
endif (ENABLE_PARALLEL)
 
####################
# Library building #
####################
if (ENABLE_C)
    add_library(peafowl SHARED ${SOURCES})
    add_library(peafowl_static STATIC ${SOURCES})

    # Generate protocol fields names before building
    find_package(PythonInterp 2 REQUIRED)

    add_custom_target(
        generate_fields_names
        COMMAND ${PYTHON_EXECUTABLE} ${CMAKE_SOURCE_DIR}/src/generate_fields_enum.py
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    )
    add_dependencies(peafowl generate_fields_names)
    add_dependencies(peafowl_static generate_fields_names)

    if (ENABLE_PARALLEL)
      include_directories(${CMAKE_SOURCE_DIR}/include/peafowl/external/fastflow/)
      target_link_libraries(peafowl ${CMAKE_THREAD_LIBS_INIT})
    endif (ENABLE_PARALLEL)


    install(TARGETS peafowl 
            LIBRARY DESTINATION lib)

    install(TARGETS peafowl_static 
            ARCHIVE DESTINATION lib)

    install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/peafowl
            DESTINATION include)
endif(ENABLE_C)

##########
# Python #
##########
if (ENABLE_PYTHON)
    cmake_minimum_required(VERSION 2.8.12)
    execute_process(COMMAND git clone https://github.com/pybind/pybind11.git external/pybind11
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    add_subdirectory(external/pybind11)
    find_package(PythonLibs REQUIRED)
    pybind11_add_module(pypeafowl ${SOURCES} peafowl_py.cpp)
    target_include_directories(pypeafowl PUBLIC ${CMAKE_SOURCE_DIR}/src/external/pybind11/include/)
    target_include_directories(pypeafowl PUBLIC ${PYTHON_INCLUDE_DIRS})
endif (ENABLE_PYTHON)

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
