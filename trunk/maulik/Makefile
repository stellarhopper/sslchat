CFLAGS =

CC = gcc
SRCS = client.c server.c

all: client server

client: 
	${CC} client.c -o client -lrt -lpthread -lcrypto -lssl

server:
	${CC} server.c -o server -lpthread -lcrypto -lssl

clean:
	rm client server
