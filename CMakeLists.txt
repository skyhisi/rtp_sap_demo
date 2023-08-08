cmake_minimum_required(VERSION 3.15)
project(rtp_sap_demo VERSION 0.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
if (MSVC)
    add_compile_options(/W4)  # /WX
    add_compile_definitions(_WIN32_WINNT=0x0601)
else()
    add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

find_package(
    Boost REQUIRED
    COMPONENTS system program_options log log_setup
    HINTS "C:/Boost"
)

if (NOT MSVC)
    find_library(LIBURING uring REQUIRED)
endif()

add_executable(
    rtp_sap_demo
    announcement_handler.cpp
    announcement_handler.hpp
    main.cpp
    save_stream.cpp
    save_stream.hpp
    session_description.cpp
    session_description.hpp
    session_manager.cpp
    session_manager.hpp
)
target_link_libraries(
    rtp_sap_demo
    Boost::log
    Boost::log_setup
    Boost::program_options
    Boost::system
)
if (LIBURING)
    target_link_libraries(
        rtp_sap_demo
        ${LIBURING}
    )
    target_compile_definitions(
        rtp_sap_demo
        PRIVATE
        BOOST_ASIO_HAS_IO_URING
    )
endif()
