############################################################################
#  Filename: Makefile
#
#  Description: This file is used to compile the packet generator 
#              
############################################################################

BASE_DIR=$(PWD)
CC=gcc
CFLAGS=-Wall

INCLUDE_DIR=$(BASE_DIR)/include
OBJ_DIR=$(BASE_DIR)/obj
SRC_DIR=$(BASE_DIR)/src
BIN_DIR=$(BASE_DIR)/bin

CFLAGS+=-I$(INCLUDE_DIR)
DEPS= \
    $(INCLUDE_DIR)/pkt_hdrs.h \
    $(INCLUDE_DIR)/pkt_defn.h
    
OBJ_FILES=$(OBJ_DIR)/pkt_main.o\
          $(OBJ_DIR)/pkt_util.o
EXE_NAME=pktGen

exe: $(OBJ_FILES)
	@$(CC) $(CFLAGS) -o $(BIN_DIR)/$(EXE_NAME) $(OBJ_FILES)

$(OBJ_DIR)/pkt_main.o: $(SRC_DIR)/pkt_main.c $(DEPS)
	@$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/pkt_main.o $(SRC_DIR)/pkt_main.c $(INCLUDES)

$(OBJ_DIR)/pkt_util.o: $(SRC_DIR)/pkt_util.c $(DEPS)
	@$(CC) $(CFLAGS) -c -o $(OBJ_DIR)/pkt_util.o $(SRC_DIR)/pkt_util.c $(INCLUDES)

clean:
	@rm -rf $(OBJ_DIR)/*.o
	@rm -rf $(BIN_DIR)/$(EXE_NAME)
