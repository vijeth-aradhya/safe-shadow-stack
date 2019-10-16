cmake_minimum_required(VERSION 3.0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -fno-stack-protector")
set(DynamoRIO_DIR "/home/vt-aradhya/Software/DynamoRIO-Linux-7.1.0-1/cmake")
find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif()

add_library(instrcalls SHARED instrcalls.c)

configure_DynamoRIO_client(instrcalls)
use_DynamoRIO_extension(instrcalls drmgr)