#--------------------------------------------------------------------------------------------------
#
#  File:       non-iOS/CPack/CMakeLists.txt
#
#  Project:    mdns_plusplus
#
#  Contains:   The non-iOS CPack CMAKE definitions for the mdns_plusplus library.
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

#General Packaging Stuff
set(CPACK_DISPLAY_NAME "OpenDragon mdns_plusplus Library")
set(CPACK_PACKAGE_CONTACT "turing@shaw.ca")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "mdns_plusplus Package")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "mdns_plusplus")
set(CPACK_PACKAGE_INSTALL_REGISTRY_KEY_ "mdns_plusplus")
set(CPACK_PACKAGE_NAME "mdns_plusplus")
set(CPACK_PACKAGE_VENDOR "OpenDragon")
set(CPACK_PACKAGE_VERSION "${mdns_plusplus_VERSION}")
set(CPACK_PACKAGE_VERSION_MAJOR "${mdns_plusplus_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${mdns_plusplus_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${mdns_plusplus_VERSION_PATCH}")
set(CPACK_RESOURCE_FILE_LICENSE "${mdns_plusplus_SOURCE_DIR}/../LICENSE")
set(CPACK_RESOURCE_FILE_README "${mdns_plusplus_SOURCE_DIR}/../README.md")

#display name for our components
set(CPACK_COMPONENT_HEADERS_DISPLAY_NAME "C++ Header Files")
set(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME "mdns_plusplus Libraries")

#descriptions for our components
set(CPACK_COMPONENT_HEADERS_DESCRIPTION "The header files required for new development")
set(CPACK_COMPONENT_LIBRARIES_DESCRIPTION "The fundamental files for an mdns_plusplus installation")

#set up dependencies
set(CPACK_COMPONENT_HEADERS_DEPENDS libraries)

#set up CPack groups
set(CPACK_COMPONENT_HEADERS_GROUP "Core")
set(CPACK_COMPONENT_LIBRARIES_GROUP "Core")

#set up CPack constraints
set(CPACK_COMPONENT_LIBRARIES_REQUIRED ON)

#CPack group descriptions
set(CPACK_COMPONENT_GROUP_CORE_DESCRIPTION "The core mdns_plusplus")
set(CPACK_COMPONENT_GROUP_CORE_BOLD_TITLE ON)

set(CPACK_COMPONENTS_ALL headers libraries)

#end General Packaging stuff

if(WIN32)
    #Windows specific install step
    set(CPACK_GENERATOR NSIS64)

    set(CPACK_NSIS_MODIFY_PATH ON)
    set(CPACK_NSIS_URL_INFO_ABOUT "http://www.github/opendragon/mdns_plusplus")

    #Finally, set some mdns_plusplus Environment variables (WINDOWS ONLY!)
    set(CPACK_NSIS_EXTRA_INSTALL_COMMANDS
        "
        WriteRegStr HKCU 'Environment' 'mdns_plusplus_ROOT' '$INSTDIR'
        ")

    #And, unset them when we uninstall!
    set(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS
        "
        DeleteRegValue HKCU 'Environment' 'mdns_plusplus_ROOT'
        ")
elseif(APPLE)
    #Macintosh specific install step
    set(CPACK_GENERATOR DragNDrop)
    set(CPACK_DMG_DISABLE_APPLICATIONS_SYMLINK ON)
    set(CPACK_DMG_FORMAT UDRO)
    set(CPACK_TOPLEVEL_TAG "/opt")
else()
    #Linux specific install step
    set(CPACK_GENERATOR RPM DEB)
    set(CPACK_TOPLEVEL_TAG "/opt")
    set(CPACK_RPM_PACKAGE_LICENSE "BSD")
endif()

include(CPack)
