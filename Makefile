CC=g++
EXEC=pump
CFLAGS=-Wall -Werror
CPPFLAGS=
LDFLAGS=-lpcap
OBJ_DIR=objs
OBJS=$(OBJ_DIR)/pump_traffic.o \
    $(OBJ_DIR)/socket.o

.PHONY: run

$(OBJ_DIR)/%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(EXEC): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(EXEC)

run:
	sudo $(EXEC)  1.1.1.137 1.1.1.56 5060 5060

all: $(EXEC)

clean:
	rm -rvf $(OBJ_DIR)/* $(EXEC)
