#!/bin/sh

mkdir -p build && cd build;
DYNAMORIO_HOME=/home/vt-aradhya/NUS/dynamorio/; 
cmake -DDynamoRIO_DIR=$DYNAMORIO_HOME/cmake ..;
make;