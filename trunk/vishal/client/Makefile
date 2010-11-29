CFLAGS =

CC = gcc
SRCS = client.c server.c

all: client

client: 
	${CC} client.c -o client -lrt -lpthread -lssl -lcrypto -Wall

server:
	${CC} server.c -o server -lpthread -lssl -lcrypto -Wall

clean:
	rm client
