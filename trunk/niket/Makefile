CFLAGS =

CC = gcc
SRCS = client.c server.c

all: client server

client: 
	${CC} client.c -o client -lrt -lpthread -lssl -lcrypto

server:
	${CC} server.c -o server -lpthread -lssl -lcrypto

clean:
	rm client server
