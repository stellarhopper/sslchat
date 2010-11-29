										Programming Assignment 3: ReadMe

Compilation:
go to the folder & type "make clean; make all"
This will compile both the files.

Usage:

To start server:
./server <Server_port> <logFile>

To start Client:
./client <user id> <server ip> <server port #> <status_msg>

The following functionality works flawlessly in the code:

Basic Functionality:
1. Clients are able to connect to the server via TCP
2. Clients are able to send and receive text messages
3. Clients send an exit messages when leaving the chat system
4. Server is able to add and remove members from a channel
5. Server correctly routes all text messages to the correct clients
6. Server gracefully handles clients that do not leave properly
7. Server correctly handles the special commands

Extra Credit:
8. Upon new connection with client, Server assigns an unused random port to each client to listen for private_message connections from the clients.
9. Client spawns a new thread to listen for the request from another clients want to send private_message
10. Client maintains connection once other client sends a connect request while @client command
11. Next time, both the clients communicate directly for private_message. (Not only one but any of these two clients can send private_message without interrupting server)
12. If the private connection of one client with other is broken accidentally, then both the clients handle the situation by removing each other from their private_client_connection list. The next time, it will ask the server if it wants to send a private_message to the same client.

TimeOut:
12. Server waits for any commands/messages from each client for exactly 120 seconds. If the server does not receive any data from particular client for 2 minters, that client will be removed from the chat room/list and all the other clients will be notified.

Log File:
- Creates and maintains log on the server side for each and every event with timestamp.


Server Code:

- Starts listening on the Port defined by #define LOCAL_PORT.
- Waits until it gets any connection request from other clients. (Blocking accept()).
- Once the connection is accepted, it adds that client to global client list, dawns a new thread, which will handle this client related recv() requests independently. (for e.g. handling different commands like /exit, /display etc. as well as maintaining timeout)
- Hence, two (or more than two) simultaneous operations on server: 1) Listening for new connection request 2) Handling each individual client in independent thread(s)

Client Code:
- Starts with requesting a connection on SERVER_PORT and SERVER_IP (provided as argument).
- Once the connection has been established, it accepts the Listen_Port no. on which it should listen for private_connection. Then, It spawns a new thread, which handles all private_connection request from other clients.
- Then, it continuously waits for user input.
- In the background, it will wait for any data receive event, and ISR (SIGIOHandler) will be invoked upon any data reception from server socket.
- Hence, three process in parallel: 1) wait for user input 2) Independent thread to accept() private_connection from other clients and 3) Data-Receive from server ISR (Interrupt driven)

The client maintains a global list of its private_connection with other clients in same manner as server does for all the clients. (i.e. add/remove private connection)
Once the user inputs '@client' command, it will first check if the client it wants to send private_message is already it its private_client_connection list. If not, then it will obtain an IP address and Listen_port of that client from server, and spawn a new thread for private_connection with that client.
If the client is already in list, then it will simply send the message to that client using the TCP socket handler which is already there, connected with that client.

 - Hence, four (or more than four) process in parallel: 1) wait for user input 2) Independent thread to accept() private_connection from other clients 3) Data-Receive from server ISR (Interrupt driven). and 4) Independent thread to handle Private_Connection with each client.

Thank you,
Niket

