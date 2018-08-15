include_directories(${CMAKE_SOURCE_DIR}/include/peafowl/external/fastflow) 
file(GLOB PMLIB "pattern_matching_lib/*.cc")
add_executable(http_pm_seq http_pm_seq.cpp ${PMLIB})
target_link_libraries(http_pm_seq LINK_PUBLIC peafowl pcap)

if (ENABLE_PARALLEL)
    add_executable(http_pm_mc http_pm_mc.cpp ${PMLIB})
    target_link_libraries(http_pm_mc LINK_PUBLIC peafowl pcap)
endif (ENABLE_PARALLEL)