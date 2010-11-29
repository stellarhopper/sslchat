ReadMe:

go to the folder & type "make all"
This will compile both the files.

Now to start the server use:
./server <Server_port> <logFile>

To start Client
./client <user_id> <server_ip> <server_port> <Your_Private_Port> <status_msg>

Your private port is any other port that is allowed for client. It should be different for each client.

The following does exist in the code:
1. Clients are able to connect to the server via TCP
2. Clients are able to send and receive text messages
3. Clients send an exit messages when leaving the chat system
4. Server is able to add and remove members from a channel
5. Server correctly routes all text messages to the correct clients
6. Server gracefully handles clients that do not leave properly
7. Server correctly handles the special commands

Server Code:
The server start by listening at the server_port. It blocks on accept for clients to connect to them.
Then for each connected client it spawns a new thread. The thread has a bunch of conditional statements that decides what commands needs to be parsed. These statements are for the commands. The server maintains a list of connected clients & there sock details(IP & number). When the client asks for the details the server searches this list for the requested "@user" & passes on the parameters to the client.
In case of no special commands the server sends the message to all. the server also updates the list on special commands(like /status).
The server passes the entire list to the client requesting /display

Client Code:
The client code is a buck of threads. There is a main thread that spawns all the other threads. The main thread spawns two major thread. ONe thread connects to the server on its port & blocks on recv() function on the socket. this socket is for incoming communication with the server.
The second thread is listening for incoming connection on the <your_private_port> for any private connections via "@". The server has the info of which clients are listening on which <your_private_port>
The main thread is the one that accepts the user input. It waits on gets for user commands. After the command is received the code now parses the command info & takes action accordingly.
Now for every incoming connection via another client (using @) the code spawns another thread that waits on recv(). so in all there are two recv() blocks now. one blocked on the connection to the server while the second one blocked on the @ connection to another client. For every client connected a new thread is spawned. If the connection already exists then no threads are invoked. The client does not even ask the server for the remote client data in such case(the client have a connection database locally too).


