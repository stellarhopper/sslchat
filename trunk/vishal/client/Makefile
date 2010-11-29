CFLAGS =

CC = gcc
SRCS = client.c server.c

all: client

client: 
	${CC} client.c -o client -lrt -lpthread -Wall

server:
	${CC} server.c -o server -lpthread -Wall

clean:
	rm client
