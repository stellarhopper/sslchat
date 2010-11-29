CFLAGS =

CC = gcc
SRCS = client.c server.c

all: client server

client: 
	${CC} client.c -o client -lrt -lpthread

server:
	${CC} server.c -o server -lpthread

clean:
	rm client server
