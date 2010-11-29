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
#include <pthread.h>


#define MAXBUFSIZE 2048
#define MAX_STATUS_SIZE 500
#define MAX_CONNECTS 50

char* client_id = NULL;
char statusMsg[MAX_STATUS_SIZE] = {0};
char recvBuf[MAXBUFSIZE] = {0};
char first_msg[MAXBUFSIZE] = {0};


void *listen_message_private(void *);
void *listen_messages(void *);
void *listen_accept_private(void *);
void *send_message_private(void *);

void transmit_message_private(int array_id);
void check_for_disconnect_msg(int buf_size, int del_sock);
void delete_entry(int sock_to_delete);


pthread_t th_listen_message_private;
pthread_t myth;
pthread_t th_listen_accept_private;
pthread_t th_send_message_private;

typedef struct
{
	char at_user_id[100];
	int sock_descriptor;
}mylist;

mylist connection_list[MAX_CONNECTS];

void init_struct()
{
	char temp_at_user_id[100]={0};
	int p;
	
	for(p=0;p<50;p++)
	{
		strcpy(connection_list[p].at_user_id, temp_at_user_id);
		connection_list[p].sock_descriptor = -1;	
	}

}

int main(int argc, char *argv[]) 
{
	int nbytes = 0;                             // number of bytes send by send()
	char buffer[MAXBUFSIZE] = {0};
	char cmd[MAXBUFSIZE] = {0};
	int i = 0;
	int j=0;
	int kill_flag = 0;
	int retval = 0;
	
	char my_private_port[7]={0};
	int sock, bytes_recieved;  
	char sendBuf[MAXBUFSIZE] = {0};
	char blank_space[1] = {' '};

	struct hostent *host;
	struct sockaddr_in server_addr;  
	int r=0;
	int ind=0;

	int int_my_priv_port=0;
	
	if (argc < 6) 
	{					//   0       1		   2            3                4					5
		printf("\nUSAGE:  ./client <user id> <server ip> <server port #> <Your Private Port> <status_msg>\n");
		exit(1);
	}
	
	for (i=5; i<argc ; i++) 
	{
		strcat(statusMsg,argv[i]);
		if(i != argc-1)
		   strcat(statusMsg," ");
	}
	i=0;
	
	client_id = (char*) malloc (strlen(argv[1]) + 1);
	strcpy(client_id, argv[1]);
	
	strcpy(my_private_port, argv[4]);	
	
	//====================Setup sockets=============================================================
	
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
	{
		perror("Socket");
		exit(1);
	}
	
	server_addr.sin_family = AF_INET;     
	server_addr.sin_port = htons(atoi(argv[3]));   
	server_addr.sin_addr.s_addr = inet_addr(argv[2]);
	bzero(&(server_addr.sin_zero),8); 

	retval=-1;
	
	//try to connect over & over till success
	while (retval == -1) 
	{
		retval = connect(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
		if (retval == -1) 
		{
			perror("Connection Request Sent");
			printf("Trying again in 5 seconds...\n\n");
			fflush(stdout);
			sleep(5);
		}		
	}
		
	printf("\nLOG: Connection established with server\n");
	
	init_struct();
	
	r = pthread_create(&myth, 0, listen_messages, (void *)sock);
	if (r != 0) 
	{ 
		fprintf(stderr, "Thread create failed\n"); 
	}
	
	
	bzero(sendBuf,MAXBUFSIZE);
	
	//send client_id
	strcpy(sendBuf, client_id);
	strcat(sendBuf," ");
	strcat(sendBuf,my_private_port);
	strcat(sendBuf," ");
	strcat(sendBuf,statusMsg);


	send(sock,sendBuf,strlen(sendBuf), 0);

	//====================create user terminal====================
	
	int_my_priv_port = atoi(my_private_port);
	r = pthread_create(&th_listen_accept_private, 0, listen_accept_private, (void *)int_my_priv_port);
	if (r != 0) 
	{ 
		fprintf(stderr, "Thread create failed\n"); 
	}

	//while cli is alive
	while (kill_flag == 0) 
	{
		printf ("\n%s : ",client_id);
		
		bzero(cmd,MAXBUFSIZE);
		fgets(cmd, MAXBUFSIZE, stdin);
		
		//put \0 in the end
		for (i=0; i<MAXBUFSIZE; i++) 
		{
			if(cmd[i] == 0x0a) 
				cmd[i] = 0x00;
		}
		

		if (strncmp(cmd, "/exit", 5) == 0)					//for exit command
		{
			
			strcpy(sendBuf, cmd);
			send(sock,sendBuf,strlen(sendBuf), 0);

			printf ("\nLOG: Exiting");
			fflush(stdout);
			kill_flag = 1;
			break;
		}
		else if(strncmp(cmd, "/display", 8) == 0)		//for display command
		{
			strcpy(sendBuf, cmd);
			send(sock,sendBuf,strlen(sendBuf), 0);

			printf ("\nDisplaying ChatRoom Participant List...\nFormat: {<Status ID>:< Status Message>}");
			fflush(stdout);
			continue;		
		}
		else if (strncmp(cmd, "/status", 7) == 0)		//for status command
		{
			for (i=0; cmd[i] != ' '; i++) 
			{
			}
			ind=0;
			i++;
			
			if (strlen(cmd) == 7)						//check for blank stat msg
			{
				printf("\nLOG: Status Message Cannot be blank");
				continue;
			}
			
			bzero(statusMsg,MAX_STATUS_SIZE);
			for(j=i;j<strlen(cmd);j++)
			{
				statusMsg[ind]=cmd[j];
				ind++;
			}
			statusMsg[ind+1]='\0';
			
			strcpy(sendBuf, cmd);
			send(sock,sendBuf,strlen(sendBuf), 0);
			
			printf ("\nLOG: Changing Status Message");
			fflush(stdout);
			continue;
		}
		else if (strncmp(cmd, "@", 1) == 0) 
		{
			
			char comp_id[100] = {0}; // = (char*) malloc (strlen(argv[1]) + 2);			
			strcat(comp_id,"@");
			strcat(comp_id,client_id);
			if (strncmp(cmd,comp_id,strlen(argv[1]) + 1) == 0) 
			{
				printf("\nERROR: Cannot Send Message to yourself");
				bzero(comp_id,100);
				bzero(cmd,MAXBUFSIZE);
				continue;
			}
			
			for (i=0; cmd[i] != ' '; i++)		//getting data till @stellar_hopper <data>
			{
				sendBuf[i]=cmd[i];
			}
			
			sendBuf[i]='\0';					//sendbuf has stellar_hopper
				
			ind=0;
			i++;
			
			for(j=i;j<strlen(cmd);j++)
			{
				first_msg[ind]=cmd[j];		//first_msg has the message to be sent
				ind++;
			}
			first_msg[j]='\0';
			
			int p,q;
			
			//search for the user_id in the list 
			for (p=0; p<MAX_CONNECTS; p++) 
			{
				if(strncmp(sendBuf, connection_list[p].at_user_id, strlen(sendBuf)) == 0)
				{
					if (connection_list[p].sock_descriptor != -1) 
					{
						printf("\nLOG: TCP connection with %s already exists. New connection will NOT be established",sendBuf);
						transmit_message_private(p);			//TRansmit this message in case the connection is already established
						break;
					}
					
				}
			}

			if(p == MAX_CONNECTS)
			{
					printf("\nLOG: user %s not connected. TCP conection to the client wil now be established.",sendBuf);
				
					for (q=0; q<MAX_CONNECTS; q++) 
					{
						if(connection_list[q].sock_descriptor == -1)
						{
							strcpy(connection_list[q].at_user_id , sendBuf);
						}
					}
					send(sock,sendBuf,strlen(sendBuf), 0);
					printf ("\nLOG: Requesting connection to client");
			}
			else 
			{
				
			}

			
			//strcpy(sendBuf, cmd);
			
			fflush(stdout);
			continue;
		}

		bzero(sendBuf,MAXBUFSIZE); 
		strcpy(sendBuf, cmd);
		send(sock,sendBuf,strlen(sendBuf), 0);
	}
    return 0;
}



void *listen_messages(void *sockid)		//this is the thread that receives the message from all
{
    int s = (int)sockid;
	int rc;
	
	pthread_detach(pthread_self());  //automatically clears the threads memory on exit

	while(1)
	{
		//printf("Waiting on recv\n");
		bzero(recvBuf,MAXBUFSIZE); 
		rc = recv(s, recvBuf, MAXBUFSIZE, 0);
		if(rc == 0)
		{
			printf("\nERROR: Connection Lost");
			exit(1);
			pthread_exit(NULL);
		}
		
		check_for_disconnect_msg(rc,s);
		
		if (! strncmp(recvBuf,"@",1)) 
		{
				struct sockaddr_in server_addr_priv;  
				int sock_priv=0;
			
			int exit_at_loop =0;
				//parse ip address & port number in the feilds at_ip & at_port
				char at_ip[20];
				char at_port[7];
				
				int x,y,myindex;
				myindex=0;
				
				//printf("@ type message: %s",recvBuf);
				if (recvBuf[1] == ':')
				{
					printf("\nLOG: Private Client not connected to server");
					//printf ("%s : ",client_id);
					fflush(stdout);
					exit_at_loop = 1;
					continue;
				}
			
				for(x=1 ; recvBuf[x] != ':'; x++)
				{
			
						exit_at_loop =0;
						at_ip[myindex]=recvBuf[x];
						myindex++;
				}
							
				at_ip[myindex]='\0';
				x++;
				myindex=0;
				
				for(y=x ; y<rc; y++)
				{
					at_port[myindex]=recvBuf[y];
					myindex++;
				}
			
				at_port[myindex]='\0';
				
				if ((sock_priv = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
				{
					perror("Socket");
					exit(1);
				}
				
				server_addr_priv.sin_family = AF_INET;     
				server_addr_priv.sin_port = htons(atoi(at_port));   
				server_addr_priv.sin_addr.s_addr = inet_addr(at_ip);
				bzero(&(server_addr_priv.sin_zero),8); 
				
					
				if ( connect(sock_priv, (struct sockaddr *)&server_addr_priv, sizeof(struct sockaddr)) == -1) 
				{
					printf("\nERROR: Establishing connection to the client %s at port %s",at_ip,at_port);
					perror("Connection Request Sent");
					fflush(stdout);
				}
				
				int q;
				for (q=0; q<MAX_CONNECTS; q++) 
				{
					if(connection_list[q].sock_descriptor == -1)
					{
						connection_list[q].sock_descriptor = sock_priv;
						break;
					}
				}
				printf("\nLOG: Connection established with client %s at port %s",at_ip,at_port);
			
				//pthread_create(&th_send_message_private, 0, send_message_private, (void *)sock_priv);
				transmit_message_private(q);
			printf ("\n%s : ",client_id);
			fflush(stdout);
			continue;
		}
		
		printf("\n%s",recvBuf);
		fflush(stdout);
		printf ("\n%s : ",client_id);
		fflush(stdout);
		
	}
}



void *listen_accept_private(void *t) 
{
    int port_to_listen = (int)t;
	
	pthread_detach(pthread_self());  //automatically clears the threads memory on exit
	
	struct sockaddr_in server_addr_p;
	struct sockaddr_in client_addr_p;
	socklen_t client_len = sizeof(client_addr_p);
	
	char recvBuf[MAXBUFSIZE] = {0};
	char sendBuf[MAXBUFSIZE] = {0};
	pthread_t th;

	int sz_recv = 0;
	int sz_send = 0;
	int true = 1;
	int sock_p=0;
	int sock_pi=0;
	int r=0;
	
	if ((sock_p = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
	{
		perror("Socket");
		exit(1);
	}
	
	if (setsockopt(sock_p,SOL_SOCKET,SO_REUSEADDR,&true,sizeof(int)) == -1) 
	{
		perror("Setsockopt");
		exit(1);
	}
	
	server_addr_p.sin_family = AF_INET;         
	server_addr_p.sin_port = htons(port_to_listen);     
	server_addr_p.sin_addr.s_addr = INADDR_ANY; 
	bzero(&(server_addr_p.sin_zero),8); 
	
	if (bind(sock_p, (struct sockaddr *)&server_addr_p, sizeof(struct sockaddr)) == -1) 
	{
		perror("Unable to bind");
		exit(1);
	}
	
	if (listen(sock_p, 5) == -1) 
	{
		perror("Listen");
		exit(1);
	}
	
	//init_struct();
	
	printf("\nLOG: Also waiting for private connection on port %d",port_to_listen);
	fflush(stdout);
	
	
	//start_connections
    for ( ; ; ) //endless loop
    {
		
		bzero(&client_addr_p, client_len);
		sock_pi = accept(sock_p, (struct sockaddr *)&client_addr_p,&client_len);
		
		//char* cIP = inet_ntoa(client_addr.sin_addr);
		//strcpy(cli_IP,cIP);

		if(sock_pi != -1)	
		{
			printf("\nLOG: Connection successfully established");
			fflush(stdout);

			r = pthread_create(&th_listen_message_private, 0, listen_message_private, (void *)sock_pi);
			if (r != 0) 
			{ 
				fprintf(stderr, "Thread create failed\n"); 
			}
		}
		
	}
}


void *listen_message_private(void *port_listen) 
{
	int sock_listen_priv = (int)port_listen;
	int rec_size;
	
	char recv_buf_priv[MAXBUFSIZE]={0};
	
	pthread_detach(pthread_self()); 
	
	printf("\nLOG: Listening for message");
	bzero(recv_buf_priv,MAXBUFSIZE); 
	
	while(1)
	{
		bzero(recv_buf_priv,MAXBUFSIZE);
		rec_size = recv(sock_listen_priv, recv_buf_priv, MAXBUFSIZE, 0);
		if(rec_size == 0)
		{
			printf("\nERROR: Connection Lost");
			//delete_entry(sock_listen_priv);
			shutdown(sock_listen_priv,2);
			pthread_exit(NULL);
		}
	
		printf("\n%s",recv_buf_priv);
		fflush(stdout);
		printf ("\n%s : ",client_id);
		fflush(stdout);
	}
}


void transmit_message_private(int array_id)
{
	fflush(stdout);
	char my_buffer[MAXBUFSIZE];
	
	pthread_detach(pthread_self()); 
	
	//printf("Val of array id is %d\n",array_id);
	bzero(my_buffer,MAXBUFSIZE);

	strcat(my_buffer,"@");
	strcat(my_buffer,client_id);
	strcat(my_buffer,":");
	strcat(my_buffer,first_msg);
	bzero(first_msg,MAXBUFSIZE);
	//printf("Sending from me: %s\n",my_buffer);
	fflush(stdout);
	
	send(connection_list[array_id].sock_descriptor , my_buffer, strlen(my_buffer), 0);
}

void check_for_disconnect_msg(int buf_size, int del_sock)
{
	char left_str[]="left";
	char removed_str[]="Removed.";
	int k=0;
	char *cptr = NULL;
	
	char *temp_ptr = NULL;
	

	
		if((strstr(recvBuf,left_str) != NULL) || (strstr(recvBuf,removed_str) != NULL))
		{
				//printf("Someone removed from the system\n");
			fflush(stdout);

				//printf("recvbuf = %s\n ",recvBuf);
			fflush(stdout);

				for (k=0; k < MAX_CONNECTS; k++) 
				{
					temp_ptr = connection_list[k].at_user_id;
					temp_ptr++;
					
					//printf(":: %s ::",temp_ptr);
					if(((cptr = strstr(recvBuf,temp_ptr)) != NULL) && (connection_list[k].sock_descriptor != -1))
					{
							//printf("%s Removed\n",cptr);
							fflush(stdout);
							delete_entry(connection_list[k].sock_descriptor);
					}
				}
		}
}


void delete_entry(int sock_to_delete)
{
	int k=0;
	//printf("Here to delete %d\n",sock_to_delete);
	
	for (k=0; k< MAX_CONNECTS; k++) 
	{
		if (connection_list[k].sock_descriptor == sock_to_delete) 
		{
			printf("\nLOG: Entry for %s successfully Deleted",connection_list[k].at_user_id);
			connection_list[k].sock_descriptor = -1;
			bzero(connection_list[k].at_user_id , 100);
			
		}
	}
	
	
}
