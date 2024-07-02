cmake_minimum_required(VERSION 3.28)
project(IndirectProxyCall)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static")
include_directories(include)

add_compile_options(
        -Os -s -fno-asynchronous-unwind-tables -fno-ident
        -falign-functions=1 -falign-jumps=1 -falign-labels=1
        -fpack-struct=8 -masm=intel -fpermissive
)

add_link_options(
        -Wl,-s,--no-seh
        -Wl,--as-needed,--no-whole-archive
)

add_executable(
        IndirectProxyCall
        src/Main.cpp
        src/Syscalls.c
        include/Syscalls.h
        include/ProxyCaller.h
)

set(ASM_SOURCE_FILES asm/x64/ProxyCaller.asm)

foreach(ASM_SRC IN LISTS ASM_SOURCE_FILES)
    get_filename_component(ASM_OBJ ${ASM_SRC} NAME_WE)
    set(ASM_OBJ ${CMAKE_CURRENT_BINARY_DIR}/${ASM_OBJ}.obj)
    add_custom_command(OUTPUT ${ASM_OBJ}
            COMMAND jwasm -win64 -coff -Fo${ASM_OBJ} ${CMAKE_CURRENT_SOURCE_DIR}/${ASM_SRC}
            DEPENDS ${ASM_SRC}
            COMMENT "Assembling ${ASM_SRC}")
    target_sources(IndirectProxyCall PRIVATE ${ASM_OBJ})
endforeach()