CFLAGS =

CC = gcc
SRCS = server.c

all: server

client: 
	${CC} client.c -o client -lrt -lpthread -Wall

server:
	${CC} server.c -o server -lpthread -Wall

clean:
	rm server
