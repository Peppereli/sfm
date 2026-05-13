cmake_minimum_required(VERSION 3.16)

project(SFM_QT)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)
find_library(CRYPTOPP_LIB cryptopp REQUIRED)

add_executable(SFM_QT
    qtmain.cpp
    qtwindow.cpp

    core/functions.cpp
)

target_include_directories(SFM_QT PRIVATE
    ${CMAKE_SOURCE_DIR}
)

target_link_libraries(SFM_QT PRIVATE
    Qt6::Widgets
    ${CRYPTOPP_LIB}
)
