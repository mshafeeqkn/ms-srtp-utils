CC=g++
EXEC=pump
CFLAGS=-Wall -Werror
CPPFLAGS=
LDFLAGS=-lpcap
OBJ_DIR=objs
OBJS=$(OBJ_DIR)/pump_traffic.o \
    $(OBJ_DIR)/socket.o


$(OBJ_DIR)/%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(EXEC): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(EXEC)

run:
	sudo ./$(EXEC)
.PHONY: run

all: $(EXEC)

clean:
	rm -rvf $(OBJ_DIR)/* $(EXEC)
