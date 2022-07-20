CC=g++
EXEC=run
CFLAGS=
CPPFLAGS=
LDFLAGS=-lpcap
OBJ_DIR=objs
OBJS=$(OBJ_DIR)/pump_traffic.o \
    $(OBJ_DIR)/socket.o


$(OBJ_DIR)/%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(EXEC): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(EXEC)

all: $(EXEC)

clean:
	rm -rf $(OBJ_DIR)/* $(EXEC)
