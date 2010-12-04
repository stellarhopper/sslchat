/*
 * Skeleton code of chat server using TCP protocol.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdlib.h>
#include <errno.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <openssl/x509.h>


#define MAX_CONNECTS 50
#define LOCAL_PORT 5655
#define CLIENT_TIMEOUT 120

#define MAX_FILE_SIZE 	1024
/*
 * You should use a globally declared linked list or an array to 
 * keep track of your connections.  Be sure to manage either properly
 */
typedef struct New_User_List {
	int User_No;
	char User_Name[20];
	char User_Status[50];
	int Socket_ID;
	struct sockaddr_in client_addr;
	int Listen_Port;
	BIO *sbio;
	SSL *ssl;
}New_User_List;

/* typedef struct File_Data{
 FILE *file_ptr;
 long file_size;
 char *file_path;
 char file_buffer[MAX_FILE_SIZE];
 }File_Data;
 
 File_Data CA_CRT;
 File_Data Server_CRT;
 File_Data Server_Private_Key; */


//thread / function declaration
void *connection(void *U_List);
SSL_CTX *Initialize_SSL_Context(char *Certificate, char *Private_Key, char *CA_Certificate);
int Verify_Peer(SSL *ssl, char *name);
//void File_Stat(File_Data *file_data);

//global variables
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

struct timeval currTime;
pthread_t th;
int r;
FILE *logFile;

char *log_file;
char *CA_CRT;
char *Server_CRT;
char *Server_Private_Key;



New_User_List User_List[MAX_CONNECTS];
int Free_List[MAX_CONNECTS];
int User_Count = 0;
int Free_Count = 0;
int Main_Count = 0;

struct timeval tv = {CLIENT_TIMEOUT, 0};						//Standard Unix Time Var Structure to Hold Socket Receive Timeout Period


int main(int argc,char *argv[])
{
	int sock, newsockfd = 0, bytes_recieved , true = 1;  
	int i = 0;
	char send_data [1024] , recv_data[1024]; 
	struct sockaddr_in server_addr;
	int sin_size = sizeof(struct sockaddr_in);
	int exit_flag = 0;
	
	SSL_CTX *ctx;
	
	
	bzero(User_List,sizeof(User_List));
	for(i=0;i<MAX_CONNECTS;i++)
		User_List[i].Socket_ID = -1;
	
	
    //check arguments here
    if (argc != 6)  
	{
		printf("usage is: ./pserver <port#> <logFile> <CA Certificate Path> <client_certificate_path> <client_private_key_path> \n");
		return 0;
    }
	
	log_file = argv[2];
    
	/* 	CA_CRT.file_path = argv[3];
	 Server_CRT.file_path = argv[4];
	 Server_Private_Key.file_path = argv[5];
	 
	 File_Stat(&CA_CRT);
	 File_Stat(&Server_CRT);
	 File_Stat(&Server_Private_Key);
	 
	 printf("%s\n\n\n",CA_CRT.file_buffer);
	 printf("%s\n\n\n",Server_CRT.file_buffer);
	 printf("%s\n\n\n",Server_Private_Key.file_buffer); */
    
    
	
	
	CA_CRT = argv[3];
	Server_CRT = argv[4];
	Server_Private_Key = argv[5];
	
	ctx = Initialize_SSL_Context(Server_CRT, Server_Private_Key, CA_CRT);
	//load_dh_params(ctx,DHFILE);
	
	pthread_mutex_lock(&log_mutex); 
	gettimeofday(&currTime,NULL);
	logFile = fopen(log_file,"w");
	fprintf(logFile,"Server started at <%ld.%06ld>\n", currTime.tv_sec, currTime.tv_usec);
	fclose(logFile);
	pthread_mutex_unlock(&log_mutex);
	
    /*
     * Open a TCP socket (an Internet stream socket).
     */
	
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
	{
		perror("Socket");
		exit(1);
	}
	
	if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&true,sizeof(int)) == -1) 
	{
		perror("Setsockopt");
		exit(1);
	}
	
	//tv.tv_sec = CLIENT_TIMEOUT;  	/* 4 Secs Timeout */
	//tv.tv_usec = 0;	
	
	//Configure Socket to be Blocking, but with Time-Out of 4 seconds.
	/*if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval)) != 0)
	 printf("Timeout Set Error No. %d. The Socket will now work in Blocking Mode.\n", errno);*/
	
	
	
    /*
     * Bind our local address so that the client can send to us.
     */
	server_addr.sin_family = AF_INET;         
	server_addr.sin_port = htons(atoi(argv[1]));     
	server_addr.sin_addr.s_addr = INADDR_ANY; 
	bzero(&(server_addr.sin_zero),8); 
	
	if (bind(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) 
	{
		perror("Unable to bind");
		exit(1);
	}
	
	
    /*
     * here you should listen() on your TCP socket
     */
	
	if (listen(sock, 5) == -1) 
	{
		perror("Listen");
		exit(1);
	}
	
	printf("TCPServer Waiting for client on port %s\n",argv[1]);
	fflush(stdout);
	
    for ( ; ; ) //endless loop
    {
		New_User_List Tmp_User;
		exit_flag = 0;
		bzero(&Tmp_User,sizeof(New_User_List));
		
		//now that you're listening, check to see if anyone is trying 
		//to connect
		//hint:  select()
		
		//if someone is trying to connect, you'll have to accept() the connection
		
		newsockfd = accept(sock, (struct sockaddr *)&Tmp_User.client_addr,&sin_size);
		
		//Configure Socket to be Blocking, but with Time-Out of 4 seconds.
		if(setsockopt(newsockfd, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval)) != 0)
			printf("Timeout Set Error No. %d. The Socket will now work in Blocking Mode.\n", errno);
		
		
		
		if(newsockfd>0)
		{
			//printf("\n I got a connection from (%s , %d)", inet_ntoa(User_List[User_Count].client_addr.sin_addr),ntohs(User_List[User_Count].client_addr.sin_port));
			
			Tmp_User.Socket_ID = newsockfd;
			exit_flag = 0;
			
			Tmp_User.sbio=BIO_new_socket(newsockfd,BIO_NOCLOSE);
			Tmp_User.ssl=SSL_new(ctx);
			SSL_set_bio(Tmp_User.ssl,Tmp_User.sbio,Tmp_User.sbio);
			
			if((SSL_accept(Tmp_User.ssl)<=0))
			{
				printf("\nSSL Handshake Error\n");
				ERR_print_errors_fp(stdout);
				exit_flag = 1;
			}
			
			sprintf(send_data,"UID");	
			//send(newsockfd, send_data,strlen(send_data), 0);
			SSL_write(Tmp_User.ssl,send_data,strlen(send_data));
			
			
			
			//bytes_recieved = recv(newsockfd,recv_data,1024,0);
			bytes_recieved = SSL_read(Tmp_User.ssl,recv_data,1024);
			
			if(bytes_recieved)
			{
				memcpy(&Tmp_User.User_Name[0],recv_data,bytes_recieved);
				
				if(Verify_Peer(Tmp_User.ssl, &Tmp_User.User_Name[0]) == 1)
				{
					
					sprintf(send_data,"STM");			
					//send(newsockfd, send_data,strlen(send_data), 0);
					SSL_write(Tmp_User.ssl, send_data,strlen(send_data));
					
					//bytes_recieved = recv(newsockfd,recv_data,1024,0);
					bytes_recieved = SSL_read(Tmp_User.ssl,recv_data,1024);
					
					if(bytes_recieved)
						memcpy(&Tmp_User.User_Status[0],recv_data,bytes_recieved);
					
					else {
						printf("Connection Broken before adding new client.\n");
						BIO_free_all(Tmp_User.sbio);
						//SSL_shutdown(Tmp_User.ssl);
						SSL_free(Tmp_User.ssl);
						close(newsockfd);
						exit_flag = 1;
					}
				}
				else{
					//printf("Connection Broken before adding new client.\n");
					BIO_free_all(Tmp_User.sbio);
					//SSL_shutdown(Tmp_User.ssl);
					SSL_free(Tmp_User.ssl);
					close(newsockfd);
					exit_flag = 1;
				}
			}
			else {
				printf("Connection Broken before adding new client.\n");
				exit_flag = 1;
			}
			
			if(exit_flag == 0)
			{
				//since you're talking nicely now.. probably a good idea send them
				//a message to welcome them to the chat room, and maybe log 
				//that they've arrived
				
				sprintf(send_data,"Welcome %s\n",&Tmp_User.User_Name[0]);			
				//send(newsockfd, send_data,strlen(send_data), 0);
				SSL_write(Tmp_User.ssl, send_data,strlen(send_data));
				
				//if there are others in the room, probably good to notify them
				//that someone else has joined.
				sprintf(send_data,"%s has joined the Room. Status: %s\n",&Tmp_User.User_Name[0],&Tmp_User.User_Status[0]);			
				for(i=0;i<MAX_CONNECTS;i++)
				{
					if(User_List[i].Socket_ID > 0)
						//send(User_List[i].Socket_ID, send_data,strlen(send_data), 0);
						SSL_write(User_List[i].ssl, send_data,strlen(send_data));
				}
				
				printf("%s",send_data);
				fflush(stdout);
				
				pthread_mutex_lock(&log_mutex); 
				gettimeofday(&currTime,NULL);
				logFile = fopen(log_file,"a");
				fprintf(logFile,"<Join> <%s> <%ld.%06ld>\n", &Tmp_User.User_Name[0], currTime.tv_sec, currTime.tv_usec);
				fclose(logFile);
				pthread_mutex_unlock(&log_mutex);
				
				
				pthread_mutex_lock(&mutex);
				//now add your new user to your global list of users
				if(Free_Count>0)
				{
					Tmp_User.User_No = Free_List[Free_Count-1];
					Tmp_User.Listen_Port = LOCAL_PORT + Free_List[Free_Count-1] + 50;
					memcpy(&User_List[Free_List[Free_Count-1]],&Tmp_User,sizeof(New_User_List));
					
					//now you need to start a thread to take care of the 
					//rest of the messages for that client
					r = pthread_create(&th, 0, connection, (void *)(&User_List[Free_List[Free_Count-1]]));
					if (r != 0) { fprintf(stderr, "thread create failed\n"); }
					
					Free_List[Free_Count-1] = -1;
					Free_Count--;
					Main_Count++;
					//printf("Empty Slot used: %d\n",Tmp_User.User_No);
				}
				else 
				{					
					Tmp_User.User_No = User_Count;
					Tmp_User.Listen_Port = LOCAL_PORT + User_Count + 50;
					memcpy(&User_List[User_Count],&Tmp_User,sizeof(New_User_List));
					User_Count++;
					Main_Count++;
					
					//now you need to start a thread to take care of the 
					//rest of the messages for that client
					r = pthread_create(&th, 0, connection, (void *)(&User_List[User_Count-1]));
					if (r != 0) { fprintf(stderr, "thread create failed\n"); }
				}
				pthread_mutex_unlock(&mutex);
				
				sprintf(send_data,"PRT %d",Tmp_User.Listen_Port);			
				//send(newsockfd, send_data,strlen(send_data), 0);
				SSL_write(Tmp_User.ssl, send_data,strlen(send_data));	
			}
		}
    }
}





//-----------------------------------------------------------------------------
void *connection(void *U_List)
{
	New_User_List *User_Data = U_List;
	int s = User_Data->Socket_ID;
	BIO *sbio;
	SSL *ssl;
	
	sbio =  User_Data->sbio;
	ssl =  User_Data->ssl;
	
    char buffer[1000], send_data[1000];
    struct timeval;
    int rc = 0;
	int i =0;
	
	pthread_detach(pthread_self());  //automatically clears the threads memory on exit
	
	
	
	
    /*
     * Here we handle all of the incoming text from a particular client.
     */
	while(1)
	{
		bzero(buffer,sizeof(buffer));
		bzero(send_data,sizeof(send_data));
		//rc = recv(s,buffer,1024,0);
		rc = SSL_read(ssl,buffer,1024);
		buffer[rc] = '\0';
		if (rc > 0)
		{
			if(buffer[0] == '/' || buffer[0] == '@')
			{
				if(strcasecmp(buffer,"/exit") == 0)//if I received an 'exit' message from this client
				{
					pthread_mutex_lock(&mutex);
					//remove myself from the vector of active clients
					sprintf(send_data,"%s has left the Room.\n",&User_Data->User_Name[0]);
					
					pthread_mutex_lock(&log_mutex); 
					gettimeofday(&currTime,NULL);
					logFile = fopen(log_file,"a");
					fprintf(logFile,"<Left> <%s> <%ld.%06ld>\n",&User_Data->User_Name[0], currTime.tv_sec, currTime.tv_usec);
					fclose(logFile);
					pthread_mutex_unlock(&log_mutex);
					
					Free_List[Free_Count] = User_Data->User_No;
					bzero(&User_List[Free_List[Free_Count]],sizeof(New_User_List));
					User_List[Free_List[Free_Count]].Socket_ID = -1;	
					Free_Count++;
					Main_Count--;
					for(i=0;i<MAX_CONNECTS;i++)
					{
						if(User_List[i].Socket_ID > 0 && User_List[i].Socket_ID != s)
							//send(User_List[i].Socket_ID, send_data,strlen(send_data), 0);
							SSL_write(User_List[i].ssl, send_data,strlen(send_data));
					}
					pthread_mutex_unlock(&mutex);
					printf("%s",send_data);
					fflush(stdout);
					
					BIO_free_all(sbio);
					//SSL_shutdown(ssl);
					SSL_free(ssl);
					close(s);
					
					pthread_exit(NULL);
					printf("Shouldn't see this!\n");
				}
				
				else if(strcasecmp(buffer,"/display") == 0)//if I received an 'exit' message from this client
				{
					int length = 0;
					length += sprintf(send_data + length,"List of Active Users: %d\n",Main_Count);
					
					pthread_mutex_lock(&mutex);
					for(i=0;i<MAX_CONNECTS;i++)
					{
						if(User_List[i].Socket_ID > 0)
							length += sprintf(send_data + length,"%s: %s\n",&User_List[i].User_Name[0],&User_List[i].User_Status[0]);	
					}
					pthread_mutex_unlock(&mutex);
					
					//send(s, send_data,strlen(send_data), 0);	
					SSL_write(ssl, send_data,strlen(send_data));
					printf("%s",send_data);
					fflush(stdout);
					
					pthread_mutex_lock(&log_mutex); 
					gettimeofday(&currTime,NULL);
					logFile = fopen(log_file,"a");
					fprintf(logFile,"<Command | /display> <%s> <%ld.%06ld>\n", &User_Data->User_Name[0], currTime.tv_sec, currTime.tv_usec);
					fclose(logFile);
					pthread_mutex_unlock(&log_mutex);				
				}
				
				else if(strncmp(buffer,"/status",7) == 0)//if I received an 'exit' message from this client
				{
					sprintf(send_data, "Status Changed to: %s\n",&buffer[8]);
					//send(s, send_data,strlen(send_data), 0);
					SSL_write(ssl, send_data,strlen(send_data));
					pthread_mutex_lock(&mutex);
					bzero(&User_Data->User_Status[0], strlen(User_Data->User_Status));
					memcpy(&User_Data->User_Status[0],&buffer[8],rc-8);
					sprintf(send_data,"%s has changed the status: %s\n",&User_Data->User_Name[0], &buffer[8]);
					for(i=0;i<MAX_CONNECTS;i++)
					{
						if(User_List[i].Socket_ID > 0 && User_List[i].Socket_ID != s)
							//send(User_List[i].Socket_ID, send_data,strlen(send_data), 0);
							SSL_write(User_List[i].ssl, send_data,strlen(send_data));
					}
					pthread_mutex_unlock(&mutex);
					printf("%s",send_data);
					fflush(stdout);
					
					pthread_mutex_lock(&log_mutex); 
					gettimeofday(&currTime,NULL);
					logFile = fopen(log_file,"a");
					fprintf(logFile,"<Command | /status> <%s> <%ld.%06ld>\n", &User_Data->User_Name[0], currTime.tv_sec, currTime.tv_usec);
					fclose(logFile);
					pthread_mutex_unlock(&log_mutex);
					
				}
				else if(buffer[0] == '@')//if I received an 'exit' message from this client
				{
					pthread_mutex_lock(&mutex);
					sprintf(send_data,"/User not Found.");
					for(i=0;i<MAX_CONNECTS;i++)
					{
						if(strcmp(&User_List[i].User_Name[0],&buffer[1]) == 0)
						{
							sprintf(send_data,"/%s %d",inet_ntoa(User_List[i].client_addr.sin_addr),User_List[i].Listen_Port);
							break;
						}
					}
					pthread_mutex_unlock(&mutex);
					//send(s, send_data,strlen(send_data), 0);
					SSL_write(ssl, send_data,strlen(send_data));					
					//printf("IP Addr: %s\n",send_data);
					
					pthread_mutex_lock(&log_mutex); 
					gettimeofday(&currTime,NULL);
					logFile = fopen(log_file,"a");
					fprintf(logFile,"<Command | @%s> <%s> <%ld.%06ld>\n", &buffer[1], &User_Data->User_Name[0], currTime.tv_sec, currTime.tv_usec);
					fclose(logFile);
					pthread_mutex_unlock(&log_mutex);
					
				}
				else 
				{
					sprintf(send_data,"%s: Invalid Command.\n",buffer);
					//send(s, send_data,strlen(send_data), 0);
					SSL_write(ssl, send_data,strlen(send_data));
					//printf("%s",send_data);
					
					pthread_mutex_lock(&log_mutex); 
					gettimeofday(&currTime,NULL);
					logFile = fopen(log_file,"a");
					fprintf(logFile,"<Command | Invalid> <%s> <<%ld.%06ld>>\n", &User_Data->User_Name[0], currTime.tv_sec, currTime.tv_usec);
					fclose(logFile);
					pthread_mutex_unlock(&log_mutex);
				}
			}
			else
			{
				//if I received anything else from this client
				//send what I received out to all other clients
				sprintf(send_data,"%s: %s\n",User_Data->User_Name,buffer);
				pthread_mutex_lock(&mutex);			
				for(i=0;i<MAX_CONNECTS;i++)
				{
					if(User_List[i].Socket_ID > 0 && User_List[i].Socket_ID != s)
						//send(User_List[i].Socket_ID, send_data,strlen(send_data), 0);
						SSL_write(User_List[i].ssl, send_data,strlen(send_data));
				}
				pthread_mutex_unlock(&mutex);
				
				printf("%s",send_data);
				fflush(stdout);
				
				pthread_mutex_lock(&log_mutex); 
				gettimeofday(&currTime,NULL);
				logFile = fopen(log_file,"a");
				fprintf(logFile,"<Message> <%s> <%ld.%06ld>\n",&User_Data->User_Name[0], currTime.tv_sec, currTime.tv_usec);
				fclose(logFile);
				pthread_mutex_unlock(&log_mutex);
			}
			
		}
		else if(rc == 0)
		{
			printf("Connection with Client: %s has been broken.\n",User_Data->User_Name);
			pthread_mutex_lock(&mutex);
			//remove myself from the vector of active clients
			fflush(stdout);
			sprintf(send_data,"%s has left the Room.\n",&User_Data->User_Name[0]);
			
			pthread_mutex_lock(&log_mutex); 
			gettimeofday(&currTime,NULL);
			logFile = fopen(log_file,"a");
			fprintf(logFile,"<Left> <%s> <%ld.%06ld>\n",&User_Data->User_Name[0], currTime.tv_sec, currTime.tv_usec);
			fclose(logFile);
			pthread_mutex_unlock(&log_mutex);
			
			Free_List[Free_Count] = User_Data->User_No;
			bzero(&User_List[Free_List[Free_Count]],sizeof(New_User_List));
			User_List[Free_List[Free_Count]].Socket_ID = -1;	
			Free_Count++;
			Main_Count--;
			for(i=0;i<MAX_CONNECTS;i++)
			{
				if(User_List[i].Socket_ID > 0)
					//send(User_List[i].Socket_ID, send_data,strlen(send_data), 0);
					SSL_write(User_List[i].ssl, send_data,strlen(send_data));
			}
			pthread_mutex_unlock(&mutex);
			
			BIO_free_all(sbio);
			//SSL_shutdown(ssl);
			SSL_free(ssl);
			close(s);
			
			pthread_exit(NULL);
			printf("Shouldn't see this!\n");
		}
		else if(rc < 0 && errno == EAGAIN)
		{
			printf("Connection Timed Out: %s has been removed from the Chat Room.\n",User_Data->User_Name);
			pthread_mutex_lock(&mutex);
			//remove myself from the vector of active clients
			fflush(stdout);
			sprintf(send_data,"%s has been removed from the Chat Room.\n",&User_Data->User_Name[0]);
			
			pthread_mutex_lock(&log_mutex); 
			gettimeofday(&currTime,NULL);
			logFile = fopen(log_file,"a");
			fprintf(logFile,"<TIMEOUT | LEFT> <%s> <%ld.%06ld>\n",&User_Data->User_Name[0], currTime.tv_sec, currTime.tv_usec);
			fclose(logFile);
			pthread_mutex_unlock(&log_mutex);
			
			Free_List[Free_Count] = User_Data->User_No;
			bzero(&User_List[Free_List[Free_Count]],sizeof(New_User_List));
			User_List[Free_List[Free_Count]].Socket_ID = -1;	
			Free_Count++;
			Main_Count--;
			for(i=0;i<MAX_CONNECTS;i++)
			{
				if(User_List[i].Socket_ID > 0)
					//send(User_List[i].Socket_ID, send_data,strlen(send_data), 0);
					SSL_write(User_List[i].ssl, send_data,strlen(send_data));
			}
			pthread_mutex_unlock(&mutex);
			
			BIO_free_all(sbio);
			//SSL_shutdown(ssl);
			SSL_free(ssl);
			close(s);
			
			pthread_exit(NULL);
			printf("Shouldn't see this!\n");
		}
	}
}

SSL_CTX *Initialize_SSL_Context(char *Certificate, char *Private_Key, char *CA_Certificate)
{
	SSL_CTX *ctx;
	
	/* Global system initialization*/
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_SSL_strings();
	OpenSSL_add_all_algorithms();
	
	printf("Attempting to create SSL context... ");
	ctx = SSL_CTX_new(SSLv23_server_method());
	if(ctx == NULL)
	{
		printf("Failed. Aborting.\n");
		return 0;
	}
	
	printf("\nLoading certificates...");	
	if(!SSL_CTX_use_certificate_file(ctx, Certificate, SSL_FILETYPE_PEM))
	{
		printf("\nUnable to load Certificate...\n");
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(ctx);
		exit (0);
	}
	
	printf("\nLoading Key File...");
	if(!SSL_CTX_use_PrivateKey_file(ctx, Private_Key, SSL_FILETYPE_PEM))
	{
		printf("Unable to load Private_Key File...\n");
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(ctx);
		exit (0);
	}
	
	printf("\nLoading TrustStore File...");
	if(!SSL_CTX_load_verify_locations(ctx, CA_Certificate, NULL))
	{
		printf("Unable to load CA Certificate...\n");
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(ctx);
		exit (0);
	}
	
	SSL_CTX_set_verify_depth(ctx,1);
	
	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,0);
	printf("\nSSL Initialization completed.\n");
	
	return ctx;
}

int Verify_Peer(SSL *ssl, char *name)
{
    X509 *peer;
    char peer_CN[256];
    int result;
	
	result = SSL_get_verify_result(ssl);
	
    
    if(result!=X509_V_OK)
	{
		printf("\nUnable to verify %s's Certificate. Verification Result: %d\n",name,result);
		ERR_print_errors_fp(stdout);
		return(-1);
	}
	
	/*Check the cert chain. The chain length
	 is automatically checked by OpenSSL when
	 we set the verify depth in the ctx */
	
    //Check the common name
    peer=SSL_get_peer_certificate(ssl);
	
    X509_NAME_get_text_by_NID
	(X509_get_subject_name(peer),
	 NID_commonName, peer_CN, 256);
	
	
    if(strcasecmp(peer_CN,name))
	{
		printf("\nUnable to verify client's name:%s name with Certificate Signature: %s.\n",name,peer_CN);
		ERR_print_errors_fp(stdout);
		return(-1);
	} 
	
	return (1);
}
