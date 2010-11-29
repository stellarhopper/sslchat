/*
 * Example of client using TCP protocol.
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> 
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/signal.h>
#include <pthread.h>

#define MAXBUFSIZE 50
#define MAX_CONNECTS 50

struct sockaddr_in Listen_Sock_Addr;

void Init_Socket_SIGIO(int sock, pid_t pid);
void SIGIOHandler(int signalType);

void Initialize_Listen_Mode(int clsock,int Port_No);
void *Listen_Handler(void *sockcl);
int Check_For_User(char *U_ID);

int sock, Listen_Socket;
struct sockaddr_in server_addr;
volatile int exit_flag = 1;
volatile int recv_flag = 1;
char isr_data[30];



typedef struct New_User_List {
	char User_Name[20];
	int User_No;
	int Socket_ID;
	struct sockaddr_in client_addr;
	int Listen_Port;
}New_User_List;

//thread function declaration
void *connection(void *U_List);


//global variables
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

New_User_List User_List[MAX_CONNECTS];
int Free_List[MAX_CONNECTS];
int User_Count = 0;
int Free_Count = 0;
int Main_Count = 0;

int main(int argc, char *argv[])

{
	int bytes_recieved;  
	char send_data[1024],recv_data[1024];
	
	
	if (argc < 5)
	{
		printf("./client <user id> <server ip> <server port #> <status_msg>\n");
		exit(1);
	}
	
	
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Socket");
		exit(1);
	}
	
	server_addr.sin_family = AF_INET;     
	server_addr.sin_port = htons(atoi(argv[3]));    
	server_addr.sin_addr.s_addr = inet_addr(argv[2]);;
	bzero(&(server_addr.sin_zero),8); 
	
	if (connect(sock, (struct sockaddr *)&server_addr,
				sizeof(struct sockaddr)) == -1) 
	{
		perror("Error");
		exit(1);
	}
	
	bytes_recieved=recv(sock,recv_data,1024,0);
	recv_data[bytes_recieved] = '\0';
	
	if (recv_data[0] == 'U' && recv_data[1] == 'I' && recv_data[2] == 'D')		//'put' command identified. 
	{
		send(sock,argv[1],strlen(argv[1]), 0);
		
		bytes_recieved=recv(sock,recv_data,1024,0);
		recv_data[bytes_recieved] = '\0';
		
		if (recv_data[0] == 'S' && recv_data[1] == 'T' && recv_data[2] == 'M')		//'put' command identified. 
		{
			int length = 0, i = 0;
			length += sprintf(send_data + length,"%s",argv[4]);
			
			for(i=5;i<argc;i++)
				length += sprintf(send_data + length," %s",argv[i]);
			
			send(sock,send_data,strlen(send_data), 0);
			
			bytes_recieved=recv(sock,recv_data,1024,0);
			recv_data[bytes_recieved] = '\0';
			
			if(bytes_recieved>0)
			{
				printf("\nServer says: %s", recv_data);		//Print Server's Acknowledge.
				
				bytes_recieved=recv(sock,recv_data,1024,0);
				recv_data[bytes_recieved] = '\0';
				
				if (recv_data[0] == 'P' && recv_data[1] == 'R' && recv_data[2] == 'T')		//'put' command identified. 
				{
					printf("Port No. to Listen: %s\n",&recv_data[4]);
					Initialize_Listen_Mode(Listen_Socket,atoi(&recv_data[4]));
				}
				else
					exit(1);
			}
			else
				exit(1);
		}
		else
			exit(1);
	}
	
	Init_Socket_SIGIO(sock, getpid());	
	
	while(exit_flag)
	{	
		printf("Enter Command: ");
		fflush(stdout);
		bzero(send_data,MAXBUFSIZE);
		bzero(recv_data,MAXBUFSIZE);
		//fflush(stdin);
		fgets(send_data, MAXBUFSIZE, stdin);	//Get User Input to variable 'send_data'
		send_data[strlen(send_data)-1] = 0x00;	//Replace Last Character (CR+LF) with 0x00
		
		
		if(send_data[0] == '@')
		{
			
			char u_id[10], i_addr[16], port_no[5],pr_message[50];
			int char_cnt;
			
			for(char_cnt=0;char_cnt<strlen(send_data);char_cnt++)
			{
				if(send_data[char_cnt] == ' ')	break;
				else u_id[char_cnt] = send_data[char_cnt];
			}
			u_id[char_cnt] = '\0';			
			strcpy(pr_message,&send_data[strlen(u_id)+1]);
			
			int result = Check_For_User(u_id+1);
			//printf("\nResult: %d\n",result);
			
			if(result == -1)
			{
				
				send(sock,u_id,strlen(u_id), 0);
				
				bzero(isr_data,sizeof(isr_data));
				recv_flag = 1;
				while(recv_flag);
				recv_flag = 1;
				
				if(strcmp(isr_data,"User not Found.") == 0)
				{
					printf("User not Found\n");
					//break;
				}
				
				else 
				{
					for(char_cnt=0;char_cnt<strlen(isr_data);char_cnt++)
					{
						if(isr_data[char_cnt] == ' ')	break;
						else i_addr[char_cnt] = isr_data[char_cnt];
					}
					
					i_addr[char_cnt] = '\0';
					
					strcpy(port_no,&isr_data[char_cnt+1]);
					
					
					struct sockaddr_in client_addr;
					int sock2;
					
					if ((sock2 = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
					{
						perror("Client Socket Error\n");
						break;
					}
					
					client_addr.sin_family = AF_INET;     
					client_addr.sin_port = htons(atoi(port_no));    
					client_addr.sin_addr.s_addr = inet_addr(i_addr);;
					bzero(&(client_addr.sin_zero),8);
					
					if (connect(sock2, (struct sockaddr *)&client_addr,
								sizeof(struct sockaddr)) == -1) 
					{
						perror("Client Connection Error\n");
						break;
					}
					
					bytes_recieved=recv(sock2,recv_data,1024,0);
					recv_data[bytes_recieved] = '\0';
					
					if (recv_data[0] == 'U' && recv_data[1] == 'I' && recv_data[2] == 'D')		//'put' command identified. 
						send(sock2,argv[1],strlen(argv[1]), 0);
					
					
					bytes_recieved=recv(sock2,recv_data,1024,0);
					recv_data[bytes_recieved] = '\0';
					
					if (recv_data[0] == 'M' && recv_data[1] == 'S' && recv_data[2] == 'G')		//'put' command identified. 
						send(sock2,pr_message, strlen(pr_message),0);
					
					
					New_User_List Tmp_User;
					pthread_t th;
					
					memcpy(&Tmp_User.User_Name,u_id+1,strlen(u_id+1));
					Tmp_User.Socket_ID = sock2;
					Tmp_User.Listen_Port = atoi(port_no);
					Tmp_User.client_addr = client_addr;
					
					
					pthread_mutex_lock(&mutex);
					//now add your new user to your global list of users
					if(Free_Count>0)
					{
						Tmp_User.User_No = Free_List[Free_Count-1];
						memcpy(&User_List[Free_List[Free_Count-1]],&Tmp_User,sizeof(New_User_List));
						
						
						//now you need to start a thread to take care of the 
						//rest of the messages for that client
						int r = pthread_create(&th, 0, connection, (void *)(&User_List[Free_List[Free_Count-1]]));
						if (r != 0) { fprintf(stderr, "thread create failed\n"); }
						
						Free_List[Free_Count-1] = -1;
						Free_Count--;
						Main_Count++;
						printf("Empty Slot used\n");
					}
					else 
					{					
						Tmp_User.User_No = User_Count;
						memcpy(&User_List[User_Count],&Tmp_User,sizeof(New_User_List));
						User_Count++;
						Main_Count++;
						
						//now you need to start a thread to take care of the 
						//rest of the messages for that client
						int r = pthread_create(&th, 0, connection, (void *)(&User_List[User_Count-1]));
						if (r != 0) { fprintf(stderr, "thread create failed\n"); }
					}
					pthread_mutex_unlock(&mutex);		
				}
			}
			else 
			{
				pthread_mutex_lock(&mutex);
				send(User_List[result].Socket_ID,pr_message, strlen(pr_message),0);
				pthread_mutex_unlock(&mutex);
				//printf("\nAlready There.\n");
			}
			
		}
		else
		{			
			send(sock,send_data,strlen(send_data), 0);
		}
	}
	
	return 0;
}



void SIGIOHandler(int signalType)		//Socket Data Recv ISR
{	
	int nbytes = 0;
	char recv_data[1024];
	
	bzero(recv_data,sizeof(recv_data));
	
	while(1) 
	{	
		nbytes = recv(sock,recv_data, 1024, 0);
		
		if(nbytes < 0 && errno == EWOULDBLOCK)	break;
		
		else if(nbytes>0)
		{
			if(recv_data[0] == '/')	
			{
				strcpy(isr_data,&recv_data[1]);
				recv_flag = 0;
			}
			else
				printf("\n%s",recv_data);
		}
		else if(nbytes == 0)
		{
			printf("\nConnection with Server has been broken.\n");
			exit_flag = 0;
			exit(1);
		}
	}
	fflush(stdout);
}




void Init_Socket_SIGIO(int sock, pid_t pid)
{	
	struct sigaction handler;
	
	
	/* Set signal handler for SIGIO */
	handler.sa_handler = SIGIOHandler;
	/* Create mask that mask all signals */
	if (sigfillset(&handler.sa_mask) < 0) 
		printf("sigfillset() failed");
	/* No flags */
	handler.sa_flags = 0;
	
	if (sigaction(SIGIO, &handler, 0) < 0)
		printf("sigaction() failed for SIGIO");
	
	/* We must own the socket to receive the SIGIO message */
	if (fcntl(sock, F_SETOWN, pid) < 0)
		printf("Unable to set process owner to us");
	
	/* Arrange for nonblocking I/O and SIGIO delivery */
	if (fcntl(sock, F_SETFL, O_NONBLOCK | FASYNC) < 0)
		printf("Unable to put client sock into non-blocking/async mode");
}



void Initialize_Listen_Mode(int clsock,int Port_No)
{
    int true = 1;
	struct sockaddr_in clserver_addr;
	pthread_t th;
	
	
	/*
     * Open a TCP socket (an Internet stream socket).
     */
	
	if ((clsock = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
	{
		perror("Socket");
		exit(1);
	}
	
	if (setsockopt(clsock,SOL_SOCKET,SO_REUSEADDR,&true,sizeof(int)) == -1) 
	{
		perror("Setsockopt");
		exit(1);
	}
	
	/*
     * Bind our local address so that the client can send to us.
     */
	clserver_addr.sin_family = AF_INET;         
	clserver_addr.sin_port = htons(Port_No);     
	clserver_addr.sin_addr.s_addr = INADDR_ANY; 
	bzero(&(server_addr.sin_zero),8); 
	
	if (bind(clsock, (struct sockaddr *)&clserver_addr, sizeof(struct sockaddr)) == -1) 
	{
		perror("Unable to bind");
		exit(1);
	}
	
	
    /*
     * here you should listen() on your TCP socket
     */
	
	if (listen(clsock, 5) == -1) 
	{
		perror("Listen");
		exit(1);
	}
	
	pthread_create(&th, 0, Listen_Handler, (void *) clsock);
}



void *Listen_Handler(void *sockcl)
{
	New_User_List Tmp_User;
	char send_data [1024] , recv_data[1024];
	int newsockfd = 0, bytes_recieved, r;
	int exit_flag = 0;
	int sin_size = sizeof(struct sockaddr_in);
	pthread_t th;
	
	int Listen_Socket = (int) sockcl;
	
	while(1)
	{
		
		bzero(&Tmp_User,sizeof(New_User_List));
		
		//now that you're listening, check to see if anyone is trying 
		//to connect
		//hint:  select()
		
		//if someone is trying to connect, you'll have to accept() the connection
		
		
		newsockfd = accept(Listen_Socket, (struct sockaddr *)&Tmp_User.client_addr,&sin_size);
		
		if(newsockfd>0)
		{
			//printf("\n I got a connection from (%s , %d)", inet_ntoa(User_List[User_Count].client_addr.sin_addr),ntohs(User_List[User_Count].client_addr.sin_port));
			
			
			Tmp_User.Socket_ID = newsockfd;
			
			//if you've accepted the connection, you'll probably want to
			//check "select()" to see if they're trying to send data, 
			//like their chat name, and if so
			//recv() whatever they're trying to send
			
			sprintf(send_data,"UID");			
			send(newsockfd, send_data,strlen(send_data), 0);
			
			bytes_recieved = recv(newsockfd,recv_data,1024,0);
			recv_data[bytes_recieved] = '\0';
			
			if(bytes_recieved)
			{
				memcpy(&Tmp_User.User_Name[0],recv_data,bytes_recieved);
				
			}
			else {
				printf("Connection Broken before adding new client.\n");
				exit_flag = 1;
			}
			
			sprintf(send_data,"MSG");			
			send(newsockfd, send_data,strlen(send_data), 0);
			
			bytes_recieved = recv(newsockfd,recv_data,1024,0);
			recv_data[bytes_recieved] = '\0';
			
			printf("\n***** Private Message from %s: %s ******\n",Tmp_User.User_Name,recv_data);
			printf("\nEnter Command: ");
			fflush(stdout);
			
			if(exit_flag == 0)
			{
				pthread_mutex_lock(&mutex);
				//now add your new user to your global list of users
				if(Free_Count>0)
				{
					Tmp_User.User_No = Free_List[Free_Count-1];
					memcpy(&User_List[Free_List[Free_Count-1]],&Tmp_User,sizeof(New_User_List));
					
					
					//now you need to start a thread to take care of the 
					//rest of the messages for that client
					r = pthread_create(&th, 0, connection, (void *)(&User_List[Free_List[Free_Count-1]]));
					if (r != 0) { fprintf(stderr, "thread create failed\n"); }
					
					Free_List[Free_Count-1] = -1;
					Free_Count--;
					Main_Count++;
					//printf("Empty Slot used\n");
				}
				else 
				{					
					Tmp_User.User_No = User_Count;
					memcpy(&User_List[User_Count],&Tmp_User,sizeof(New_User_List));
					User_Count++;
					Main_Count++;
					
					//now you need to start a thread to take care of the 
					//rest of the messages for that client
					r = pthread_create(&th, 0, connection, (void *)(&User_List[User_Count-1]));
					if (r != 0) { fprintf(stderr, "thread create failed\n"); }
				}
				pthread_mutex_unlock(&mutex);	
				
				//printf("\n*****%s added*****\n",Tmp_User.User_Name);
				
			}
		}
	}
}

//-----------------------------------------------------------------------------
void *connection(void *U_List)
{
	New_User_List *User_Data = U_List;
	int s = User_Data->Socket_ID;
	
	char buffer[1000], send_data[1000];
	int rc = 0;
	
	pthread_detach(pthread_self());  //automatically clears the threads memory on exit
	
	
	/*
	 * Here we handle all of the incoming text from a particular client.
	 */
	while(1)
	{
		bzero(buffer,sizeof(buffer));
		bzero(send_data,sizeof(send_data));
		rc = recv(s,buffer,1024,0);
		buffer[rc] = '\0';
		if (rc > 0)
		{
			printf("\n***** Private Message from %s: %s ******\n",User_Data->User_Name,buffer);
			printf("\nEnter Command: ");
			fflush(stdout);
			
		}
		else if(rc == 0)
		{
			printf("\nPrivate Connection with Client: %s has been broken.\n",User_Data->User_Name);
			printf("\nEnter Command: ");
			pthread_mutex_lock(&mutex);
			//remove myself from the vector of active clients
			Free_List[Free_Count] = User_Data->User_No;
			bzero(&User_List[Free_List[Free_Count]],sizeof(New_User_List));
			User_List[Free_List[Free_Count]].Socket_ID = -1;
			Free_Count++;
			Main_Count--;			
			pthread_mutex_unlock(&mutex);
			close(s);
			pthread_exit(NULL);
			printf("Shouldn't see this!\n");
		}
		
	}
}

int Check_For_User(char *U_ID)
{
	int i = 0;
	
	pthread_mutex_lock(&mutex);
	for(i=0;i<MAX_CONNECTS;i++)
	{
		if(strncmp(U_ID,&User_List[i].User_Name[0],strlen(U_ID)) == 0)
		{
			pthread_mutex_unlock(&mutex);
			return i;
		}
	}
	pthread_mutex_unlock(&mutex);
	return (-1);
}