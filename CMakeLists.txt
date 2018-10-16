cmake_minimum_required(VERSION 3.5.1)
project(peafowl VERSION 1.0.0)
set (CMAKE_BUILD_TYPE Release)
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_C_STANDARD 11)
set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules/")

###########
# Options #
###########
option (ENABLE_TESTS "Enables testing" OFF)
option (ENABLE_CPPCHECK "Enables cppcheck checks" OFF)
option (ENABLE_CODECOV "Enables code coverage reports" OFF)
option (ENABLE_CLANGFORMAT "Enables clang-format formatting" OFF)
option (ENABLE_DOCS "Enables documentation generation" OFF)

add_compile_options(-Wall -finline-functions -g -O0)

find_package(PCAP)

# This must be the first thing done, since COVERAGE_COMPILER_FLAGS must be used by all the targets
###########
# codecov #
###########
if (ENABLE_CODECOV)
    set (CMAKE_BUILD_TYPE Debug)
    if (NOT ENABLE_TESTS)
        message (FATAL_ERROR "You need to define -DENABLE_TESTS=ON when you use -DENABLE_CODECOV=ON")
    endif()
    include(CodeCoverage)
    APPEND_COVERAGE_COMPILER_FLAGS()
endif (ENABLE_CODECOV)

###########
# Library #
###########
add_subdirectory(src)
add_subdirectory(demo)

############
# cppcheck #
############
if (ENABLE_CPPCHECK)
    include(cmake/cppcheck.cmake)
endif (ENABLE_CPPCHECK)

###########
# Testing #
###########
if (ENABLE_TESTS)
    if (NOT PCAP_FOUND)
        message(FATAL_ERROR "libpcap needs to be installed to run tests")
    else()
        enable_testing()
        add_subdirectory(test) 
    endif (NOT PCAP_FOUND)
endif (ENABLE_TESTS)

###########
# codecov #
###########
if (ENABLE_CODECOV)
    set(COVERAGE_GCOVR_EXCLUDES 'src/external/*' 'test/*' 'demo/*' 'experiments/*')
    SETUP_TARGET_FOR_COVERAGE_GCOVR_XML(
        NAME coverage
        EXECUTABLE make test
        DEPENDENCIES peafowl_static
    )
endif (ENABLE_CODECOV)

################
# clang-format #
################
if (ENABLE_CLANGFORMAT)
  include(cmake/clang_format.cmake)
endif (ENABLE_CLANGFORMAT)

#######
# Doc #
#######
if (ENABLE_DOCS)
    find_package(Doxygen)
    if (DOXYGEN_FOUND)
        # set input and output files
        set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile.in)
        set(DOXYGEN_OUT ${CMAKE_CURRENT_SOURCE_DIR}/docs/Doxyfile)

        # request to configure the file
        configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
        message("Doxygen build started")

        add_custom_target(docs 
            COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/docs
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM )
    else (DOXYGEN_FOUND)
      message(WARNING "Doxygen need to be installed to generate the doxygen documentation")
    endif (DOXYGEN_FOUND)
endif (ENABLE_DOCS)
