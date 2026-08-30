cmake_minimum_required(VERSION 3.16)
project(objectstoremojo C)

# conda-forge's libcurl ships CURLConfig.cmake; CMake also has a bundled
# FindCURL module. Prefer the package config (exact version/target info) and
# fall back to the module, so this builds on both ubuntu and macos runners.
find_package(CURL CONFIG QUIET)
if(NOT CURL_FOUND)
    find_package(CURL REQUIRED)
endif()

add_library(objectstoremojo SHARED curl_wrapper.c)
# dladdr/dlopen: the shim takes a permanent reference to itself so that Mojo
# closing its OwnedDLHandle cannot unmap the pooled connections. On glibc >=
# 2.34 these live in libc, but CMAKE_DL_LIBS covers the platforms where they
# do not.
target_link_libraries(objectstoremojo PRIVATE ${CMAKE_DL_LIBS})
if(TARGET CURL::libcurl)
    target_link_libraries(objectstoremojo PRIVATE CURL::libcurl)
else()
    target_include_directories(objectstoremojo PRIVATE ${CURL_INCLUDE_DIRS})
    target_link_libraries(objectstoremojo PRIVATE ${CURL_LIBRARIES})
endif()

# _find_lib() in the Mojo package loads lib/libobjectstoremojo.so on every
# platform, macOS included — hence the forced .so suffix.
set_target_properties(objectstoremojo PROPERTIES SUFFIX ".so" PREFIX "lib")

install(TARGETS objectstoremojo LIBRARY DESTINATION lib)
