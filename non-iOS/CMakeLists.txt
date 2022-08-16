#--------------------------------------------------------------------------------------------------
#
#  File:       non-iOS/CMakeLists.txt
#
#  Project:    mdns_plusplus
#
#  Contains:   The non-iOS CMAKE definitions for the mdns_plusplus library.
#
#  Written by: Norman Jaffe
#
#  Copyright:  (c) 2022 by OpenDragon.
#
#              All rights reserved. Redistribution and use in source and binary forms, with or
#              without modification, are permitted provided that the following conditions are met:
#                * Redistributions of source code must retain the above copyright notice, this list
#                  of conditions and the following disclaimer.
#                * Redistributions in binary form must reproduce the above copyright notice, this
#                  list of conditions and the following disclaimer in the documentation and / or
#                  other materials provided with the distribution.
#                * Neither the name of the copyright holders nor the names of its contributors may
#                  be used to endorse or promote products derived from this software without
#                  specific prior written permission.
#
#              THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
#              EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#              OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
#              SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
#              INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
#              TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#              BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#              CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
#              ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
#              DAMAGE.
#
#  Created:    2022-03-21
#
#--------------------------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

set(PROJECT_NAME "mdns_plusplus")

if(APPLE)
    execute_process(COMMAND uname -m
                    OUTPUT_VARIABLE CPU_TYPE
                    OUTPUT_STRIP_TRAILING_WHITESPACE)

    set(CMAKE_OSX_ARCHITECTURES ${CPU_TYPE} CACHE STRING "Build architectures for Mac OSX")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.9" CACHE STRING "Deployment target for Mac OSX")
endif()

project(${PROJECT_NAME}
        HOMEPAGE_URL "https://github.com/opendragon/mdns_plusplus")

include(../mdns_plusplusCommonSettings.cmake NO_POLICY_SCOPE)

if(WIN32)
    set(CMAKE_CONFIGURATION_TYPES Debug Release CACHE INTERNAL "" FORCE)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Make some flags to control the build flags visibilities
mark_as_advanced(CLEAR BUILD_SHARED_LIBS)

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    set(LINUX ON)
    if(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "unknown")
        set(UNKNOWN_CPU ON)
    else()
        set(UNKNOWN_CPU OFF)
    endif()
else()
    set(LINUX OFF)
    set(UNKNOWN_CPU OFF)
endif()

if(APPLE)
    set(CMAKE_CXX_FLAGS "-Wall -Wextra" CACHE STRING "Fixes linking error for mdns_plusplus" FORCE)
    set(CMAKE_INSTALL_PREFIX "/opt/mdns_plusplus" CACHE STRING "Fixes install path for mdns_plusplus" FORCE)
# 'rpath' warning
#    cmake_policy(SET CMP0042 OLD)
elseif(LINUX)
    set(CMAKE_CXX_FLAGS "-Wall -Wextra" CACHE STRING "Fixes linking error for mdns_plusplus" FORCE)
    set(CMAKE_INSTALL_PREFIX "/opt/mdns_plusplus" CACHE STRING "Fixes install path for mdns_plusplus" FORCE)
endif()

set(CMAKE_USE_RELATIVE_PATHS ON CACHE BOOL "Always set file paths as relative")

if(WIN32)
    option(WIN64 "Build 64-bit binaries" ON)
else()
    set(WIN64 OFF)
endif()

option(mdns_plusplus_ChattyStart "Report the version numbers when launching an executable")

option(mdns_plusplus_DoExplicitCheckForOK "Check OK responses for validity")

# Add the IF target path so that IF can be found
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_INSTALL_PREFIX}")

list(APPEND CMAKE_PREFIX_PATH $ENV{CMAKE_PREFIX_PATH})

configure_file(${mdns_plusplus_CONFIG_DIR}/mdns_plusplusConfigVersion.cmake.in
               ${CMAKE_CURRENT_BINARY_DIR}/mdns_plusplusConfigVersion.cmake @ONLY)
configure_file("${mdns_plusplus_SOURCE_DIR}/mdns_plusplusConfig.h.in" "${mdns_plusplus_SOURCE_DIR}/mdns_plusplusConfig.h")

set(TARGET mdns_example)

add_executable(${TARGET}
            ${mdns_plusplus_SOURCE_DIR}/mdns.cpp)

target_include_directories(${TARGET} PUBLIC
                            $<BUILD_INTERFACE:${mdns_plusplus_SOURCE_DIR}> # for headers when building
                            $<INSTALL_INTERFACE:${INCLUDE_DEST}> # for client in install mode
                            )

install(TARGETS ${TARGET}
        EXPORT ${PROJECT_NAME})

install(FILES
        ${mdns_plusplus_SOURCE_DIR}/mdns.hpp
        ${mdns_plusplus_SOURCE_DIR}/mdns_plusplusConfig.h
        DESTINATION ${INCLUDE_DEST}
        COMPONENT headers)

install(FILES
        ${mdns_plusplus_CONFIG_DIR}/mdns_plusplusConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/mdns_plusplusConfigVersion.cmake
        DESTINATION ${LIB_DEST}
        COMPONENT scripts)

install(EXPORT ${PROJECT_NAME}
        DESTINATION ${LIB_DEST})

add_subdirectory(CPack)
