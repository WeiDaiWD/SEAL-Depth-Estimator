# Copyright (c) Wei Dai (weidai3141@gmail.com). All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

project(SEALDepthEstimator LANGUAGES CXX)

set(CMAKE_BUILD_TYPE "Release")

find_package(SEAL 4.1.1 REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

add_executable(seal_depth_estimator)

target_sources(seal_depth_estimator
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/seal_depth_estimator.cpp
)

if(TARGET SEAL::seal)
    target_link_libraries(seal_depth_estimator PRIVATE SEAL::seal)
elseif(TARGET SEAL::seal_shared)
    target_link_libraries(seal_depth_estimator PRIVATE SEAL::seal_shared)
else()
    message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
endif()