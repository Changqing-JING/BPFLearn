cmake_minimum_required(VERSION 3.5)

project(BPFLearn)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

add_subdirectory(socket_demo)

aux_source_directory(src/helper sourceHelpers)
add_library(libHelper ${sourceHelpers})

set(BPF_FLAG -target bpf -O1)

macro(add_bpf_target bpfName)
    add_custom_target(
        ${bpfName}_kern ALL
        COMMAND clang ${BPF_FLAG} -o ${CMAKE_CURRENT_BINARY_DIR}/${bpfName}_kern.o -c ${bpfName}_kern.c
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    add_executable(${bpfName} src/${bpfName}_user.cpp)
    target_link_libraries(${bpfName} PRIVATE libHelper bpf)
endmacro()

add_bpf_target(hello)