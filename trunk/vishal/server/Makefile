CFLAGS =

CC = gcc
SRCS = server.c

all: server

client: 
	${CC} client.c -o client -lrt -lpthread -lssl -lcrypto -Wall

server:
	${CC} server.c -o server -lpthread -lssl -lcrypto -Wall

clean:
	rm server
