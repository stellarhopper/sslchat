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

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <openssl/x509.h>

#define MAX_CONNECTS 50
#define MAXBUFSIZE 2048
#define MAX_CLIENT_ID 100
#define MAXCLIENT_STATUS 500


/*
 * You should use a globally declared linked list or an array to 
 * keep track of your connections.  Be sure to manage either properly
 */

//thread function declaration
void *connection(void *);
SSL_CTX *Initialize_SSL_Context(char *Certificate, char *Private_Key, char *CA_Certificate);
int Verify_Peer(SSL *ssl, char *name);

char cli_IP[20];

//global variables
pthread_mutex_t mutex_log;
pthread_mutex_t mutex_list;
pthread_mutex_t mutex_global;

char temp_buf[500] = {0};
char file_name[100];
FILE *logFile;
char *CA_CRT;
char *Server_CRT;
char *Server_Private_Key;


typedef struct  
{
	int sock_id;
	char client_ip[20];
	char client_id[MAX_CLIENT_ID];
	char client_status[MAXCLIENT_STATUS];
	char my_private_port[7];
	SSL *ssl;

}my_list;

my_list client_list[MAX_CONNECTS]; 

int list_top;
int client_count;



typedef struct
{
	int temp_sock;
	SSL *temp_ssl;
}one_struct;

one_struct temp_struct;



void init_struct()
{
	int a=0;
	char temp_client_id[MAX_CLIENT_ID]= {0};
	char temp_client_status[MAXCLIENT_STATUS]= {0};
	char temp_private_port[7] = {0};

	client_count=0;
	list_top=0;
	
	for(a=0;a<MAX_CONNECTS;a++)
	{
		client_list[a].sock_id = -1;
		bzero(client_list[a].client_ip,20);
		strcpy(client_list[a].client_id,temp_client_id);
		strcpy(client_list[a].client_status,temp_client_status);
		strcpy(client_list[a].my_private_port , temp_private_port);
	}
}

void clear_struct_entry(int a)
{
	char temp_client_id[MAX_CLIENT_ID] = {0};
	char temp_client_status[MAXCLIENT_STATUS] = {0};
	char temp_private_port[7] = {0};
	
	client_list[a].sock_id = -1;
	bzero(client_list[a].client_ip,20);
	strcpy(client_list[a].client_id , temp_client_id);
	strcpy(client_list[a].client_status , temp_client_status);
	strcpy(client_list[a].my_private_port , temp_private_port);
	client_count--;
	printf("There are %d clients in the system\n",client_count);

}

void print_time(char *message)
{
	struct timeval tv;
	char time_buffer[40];
	time_t curtime;
	
	gettimeofday(&tv, NULL); 
	curtime=tv.tv_sec;
	
	strftime(time_buffer,40,"Date: %m-%d-%Y  Time: %T",localtime(&curtime));
	//printf("%s\n",time_buffer);
	
	pthread_mutex_lock(&mutex_log);
		logFile = fopen(file_name,"a+");
		fprintf(logFile,"%s : %s\n",time_buffer, message);
		fclose(logFile);
	pthread_mutex_unlock(&mutex_log);

}

void clear_file()
{
	logFile = fopen(file_name,"w");
	fclose(logFile);
}

int main(int argc,char *argv[])
{
    pthread_t th;
    int r;
    int sock_i = 0;
	int sock = 0;
	int true = 1;
	
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	int sin_size = 0;
	socklen_t client_len = sizeof(client_addr);
	
	char recvBuf[MAXBUFSIZE] = {0};
	char sendBuf[MAXBUFSIZE] = {0};

	int sz_recv = 0;
	int sz_send = 0;

	struct timeval timeout_tv;
	timeout_tv.tv_sec = 120;
	
	SSL_CTX *my_ctx;
	SSL *my_ssl;
	BIO *sbio;
	
    //check arguments here
	if (argc != 6)  
	{    	    
		//				0		1		  2
		//printf("USAGE: ./server <port#> <logFile>\n");
		//			     0         1		 2			3					4						5
		printf("USAGE: ./server <port #> <log file> <CA Certificate Path> <server_certificate_path> <server_private_key_path>\n");
		return 0;
	}	
	
	strcpy(file_name,argv[2]);
	clear_file();
	print_time("Server Started");
	//====================Setup sockets=============================================================
	
    	CA_CRT = argv[3];
	Server_CRT = argv[4];
	Server_Private_Key = argv[5];
	
	my_ctx = Initialize_SSL_Context(Server_CRT, Server_Private_Key, CA_CRT);

    
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
	
	server_addr.sin_family = AF_INET;         
	server_addr.sin_port = htons(atoi(argv[1]));     
	server_addr.sin_addr.s_addr = INADDR_ANY; 
	bzero(&(server_addr.sin_zero),8); 

	if (bind(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) 
	{
		perror("Unable to bind");
		exit(1);
	}

	if (listen(sock, 5) == -1) 
	{
		perror("Listen");
		exit(1);
	}
	
	init_struct();
	
	printf("TCPServer Waiting for client\n");
	print_time("TCPServer Waiting for client\n");

	fflush(stdout);
	
	//start_connections

    for ( ; ; ) //endless loop
    {
    		
	bzero(&client_addr, client_len);
	sock_i = accept(sock, (struct sockaddr *)&client_addr,&client_len);
		
		
		
	if (setsockopt(sock_i, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&timeout_tv,sizeof(struct timeval)) == -1) 
	{
		perror("Setsockopt");
		exit(1);
	}
		
	char* cIP = inet_ntoa(client_addr.sin_addr);
	strcpy(cli_IP,cIP);
		
	printf("Client IP:%s Sock:%d joined\n", cli_IP, sock_i);
		
	//Convert client IP & store in the sturct//
		
	sprintf(temp_buf,"Client %d joined", sock_i);
	print_time(temp_buf);	

	/*
	SSL_CTX *my_ctx;
	SSL *my_ssl;
	BIO *sbio;
	*/
	
	if(sock_i != -1)
	{
		printf("A\n");

		temp_struct.temp_sock = sock_i;
		sbio=BIO_new_socket(sock_i,BIO_NOCLOSE);
		printf("B %d\n",sbio);
		
		my_ssl = SSL_new(my_ctx);
		temp_struct.temp_ssl = my_ssl;
		
		printf("C\n");

		
		SSL_set_bio(temp_struct.temp_ssl , sbio , sbio);
		printf("D\n");
		
		if((SSL_accept(temp_struct.temp_ssl)<=0))
		{
			printf("\nSSL Handshake Error %d\n",errno);
			fflush(stdout);
			ERR_print_errors_fp(stdout);
			return 0;
		}

		printf("SSL sbio created & accepted. Thread for the client will now start\n");	
		r = pthread_create(&th, 0, connection, (void *)&temp_struct);
		if (r != 0) 
		{ 
			
			fprintf(stderr, "Thread create failed\n"); 
			print_time("Thread create failed\n");	
		}
	}
		

    }
	return 0;
}

//-----------------------------------------------------------------------------

void send_to_all(int my_index, char *sending_buffer )
{
	int i;
	
	pthread_mutex_lock(&mutex_list);
	//printf(":%s:\n", sending_buffer);

	for(i=0;i<MAX_CONNECTS;i++)
	{
		if ( (i == my_index) || (client_list[i].sock_id == -1) )
		{

		}
		else 
		{
			//send(client_list[i].sock_id , sending_buffer,strlen(sending_buffer), 0);
			SSL_write(client_list[i].ssl , sending_buffer,strlen(sending_buffer));

		}
		
	}
	pthread_mutex_unlock(&mutex_list);

	
}



void *connection(void *passed_struct) 
{
	one_struct *a_struct = (one_struct *)passed_struct;
	
	//int s = (int)sockid;
	int s = a_struct->temp_sock;
	SSL *ssl_connection= a_struct->temp_ssl;

	//int s = (int)sockid;
	
	char buffer[MAXBUFSIZE];
	char send_all_buffer[MAXBUFSIZE];

	char client_id[MAX_CLIENT_ID];
	char client_status[MAXCLIENT_STATUS];
	char priv_cli_id[MAX_CLIENT_ID];
	struct timeval curTime;
	int i, j,index, e, rc, rc_msg = 0;

	char zero_stat[MAXCLIENT_STATUS] = {0};
	char client_private_port[7]={0};
	int my_struct_index = 0;
	
	pthread_detach(pthread_self());  //automatically clears the threads memory on exit

	

	/*
	* Here we handle all of the incoming text from a particular client.
	*/

	//rc = recv(s, buffer, MAXBUFSIZE, 0);
	rc = SSL_read(ssl_connection, buffer, MAXBUFSIZE);


	if(rc > 1)
	{
		
	}
	else 
	{
		perror("Receive");
		printf("Connection Lost\n");
		printf("Thread exit\n");
		pthread_exit(NULL);
		
	}

	for (i=0; i<MAX_CONNECTS; i++) 
	{
		pthread_mutex_lock(&mutex_list);
			if(client_list[i].sock_id == -1)
			{
				my_struct_index = i;
				client_count++;
				printf("There are %d clients in the system\n",client_count);
				pthread_mutex_unlock(&mutex_list);
				break;
			}
		pthread_mutex_unlock(&mutex_list);

	}
		
	pthread_mutex_lock(&mutex_list);

		//int s  copy sock_id to struct//
		client_list[my_struct_index].ssl = ssl_connection;

		client_list[my_struct_index].sock_id = s;
		strcpy(client_list[my_struct_index].client_ip , cli_IP);
		printf("CLI_IP : %s \n",client_list[my_struct_index].client_ip);

	pthread_mutex_unlock(&mutex_list);
	
	for (i=0; buffer[i] != ' '; i++) 
	{
		//printf("i is %d\n",i);
		client_id[i]=buffer[i];
	}

	client_id[i]='\0';

	pthread_mutex_lock(&mutex_list);
		//copy client_id to struct//
		strcpy(client_list[my_struct_index].client_id , client_id);
	pthread_mutex_unlock(&mutex_list);

	index=0;
	i++;
	
	for(j=i;buffer[j] != ' ';j++)
	{
		client_private_port[index]=buffer[j];
		index++;

	}
	client_private_port[index+1]='\0';

	index=0;
	j++;
	
	for(i=j;i < rc;i++)
	{
		client_status[index]=buffer[i];
		
		index++;
	}
	client_status[index+1]='\0';
		
	pthread_mutex_lock(&mutex_list);
		//copy client_status to struct//
		strcpy(client_list[my_struct_index].client_status , client_status);
		strcpy(client_list[my_struct_index].my_private_port , client_private_port);
	pthread_mutex_unlock(&mutex_list);

	
	printf("****Client \"%s\" Joined with Status message \"%s\"****\n", client_id, client_status);
	sprintf(send_all_buffer,"****Client \"%s\" Joined with Status message \"%s\"****\n", client_id, client_status);
	
	send_to_all(my_struct_index,&send_all_buffer[0]);
	
	sprintf(temp_buf,"****Client \"%s\" Joined with Status message \"%s\"****", client_id, client_status);
	print_time(temp_buf);	
	
	fflush(stdout);
	
    while (1)
    {

		bzero(buffer,MAXBUFSIZE);
		//rc_msg = recv(s, buffer, MAXBUFSIZE, 0);
		rc_msg = SSL_read(ssl_connection, buffer, MAXBUFSIZE);

		if(rc_msg > 1)
		{
			
		}
		else 
		{
			sprintf(temp_buf,"****Client \"%s\" Connection Lost. Removed.****\n", client_id);
			print_time(temp_buf);	
			
			sprintf(send_all_buffer,"****Client \"%s\" Connection Lost. Removed.****\n", client_id);
			send_to_all(my_struct_index,&send_all_buffer[0]);

			pthread_mutex_lock(&mutex_list);
				clear_struct_entry(my_struct_index);
			pthread_mutex_unlock(&mutex_list);
			
			shutdown(s,2);
			printf("Thread exit on connection lost\n");
			pthread_exit(NULL);
			
		}
		
		printf("%s says %s \n", client_id,buffer);

		bzero(send_all_buffer,MAXBUFSIZE);
		sprintf(send_all_buffer,"%s : %s \n", client_id,buffer);
		fflush(stdout);

		if (!strncmp(buffer,"/exit",5)) 
		{
			printf("****Client \"%s\" is removed from chatroom****\n", client_id);

				sprintf(temp_buf,"****Client \"%s\" has left the chatroom****\n", client_id);
				print_time(temp_buf);	
			
			sprintf(send_all_buffer,"****Client \"%s\" has left the chatroom****\n", client_id);
			send_to_all(my_struct_index,&send_all_buffer[0]);

			pthread_mutex_lock(&mutex_list);
				clear_struct_entry(my_struct_index);
			pthread_mutex_unlock(&mutex_list);


			printf("Thread exit\n");
			pthread_exit(NULL);

		}
		
		if (!strncmp(buffer,"/status",7)) 
		{			
			for (i=0; buffer[i] != ' '; i++) 
			{
			}
						
			index=0;
			i++;
			j=0;
			for(j=i;j<rc;j++)
			{
				client_status[index]=buffer[j];
				index++;
			}
			client_status[index+1]='\0';
			strcpy(client_list[my_struct_index].client_status , zero_stat);
			strcpy(client_list[my_struct_index].client_status , client_status);
			
			printf("****Client \"%s\" Changed the Status Message to %s ****\n", client_id, client_list[my_struct_index].client_status);
			
			sprintf(temp_buf,"****Client \"%s\" Changed the Status Message to %s ****\n", client_id, client_list[my_struct_index].client_status);
			print_time(temp_buf);	
			
			sprintf(send_all_buffer,"****Client \"%s\" Changed the Status Message to %s ****\n", client_id, client_list[my_struct_index].client_status);
			send_to_all(my_struct_index,&send_all_buffer[0]);
			continue;

		}

		if (!strncmp(buffer,"/display",8)) 
		{			
			
			pthread_mutex_lock(&mutex_list);
			//printf(":%s:\n", sending_buffer);
			bzero(send_all_buffer,MAXBUFSIZE);

			for(i=0;i<MAX_CONNECTS;i++)
			{
				if (client_list[i].sock_id == -1)
				{
					//printf("i %d = my_struct_index %d\n",1, my_struct_index);
					//printf("client_list[my_struct_index].sock_id = %d\n",client_list[my_struct_index].sock_id);
					//printf("NOT Sending to client %d\n\n",i);
				}
				else 
				{
					//printf("client_list[my_struct_index].sock_id = %d\n",client_list[my_struct_index].sock_id);
					strcat(send_all_buffer,"{");
					strcat(send_all_buffer,client_list[i].client_id);
					strcat(send_all_buffer,":");
					strcat(send_all_buffer,client_list[i].client_status);
					strcat(send_all_buffer,"}\n");
				}
				
			}
			//send(client_list[my_struct_index].sock_id , send_all_buffer,strlen(send_all_buffer), 0);
			SSL_write(client_list[my_struct_index].ssl , send_all_buffer,strlen(send_all_buffer));

			pthread_mutex_unlock(&mutex_list);
			
			continue;
		}
		
		if (!strncmp(buffer,"@",1)) 
		{			
			for (i=1; i<rc; i++) 
			{
				//printf("i is %d\n",i);
				priv_cli_id[i-1]=buffer[i];
			}
			priv_cli_id[i-1]='\0';
			
			printf("private client ID : %s\n", priv_cli_id);
			
			
			pthread_mutex_lock(&mutex_list);
			//printf(":%s:\n", sending_buffer);
			
			for(i=0;i<MAX_CONNECTS;i++)
			{
					if(!strncmp(priv_cli_id , client_list[i].client_id , strlen(client_list[i].client_id) ))
					{
						bzero(send_all_buffer,MAXBUFSIZE);
						strcat(send_all_buffer,"@");
						strcat(send_all_buffer,client_list[i].client_ip);
						strcat(send_all_buffer,":");
						strcat(send_all_buffer,client_list[i].my_private_port);
						
						//send(client_list[my_struct_index].sock_id , send_all_buffer, strlen(send_all_buffer), 0);
						SSL_write(client_list[my_struct_index].ssl , send_all_buffer, strlen(send_all_buffer));

						fflush(stdout);

						pthread_mutex_unlock(&mutex_list);
						break;
					}
			}
			
			if(i == MAX_CONNECTS)
			{
				bzero(send_all_buffer,MAXBUFSIZE);
				strcat(send_all_buffer,"@");
				//strcat(send_all_buffer,"o");
				strcat(send_all_buffer,":");
				//strcat(send_all_buffer,"o");
				//send(client_list[my_struct_index].sock_id , send_all_buffer, strlen(send_all_buffer));

				SSL_write(client_list[my_struct_index].ssl , send_all_buffer, strlen(send_all_buffer));
			}
			pthread_mutex_unlock(&mutex_list);
			continue;
		}
		
		
		//bzero(temp_buf,MAXBUFSIZE);
		//printf("****Sending to %d all %d:  %s ****\n", my_struct_index, client_list[my_struct_index].sock_id ,send_all_buffer);
		
		sprintf(temp_buf,"****Sending to all: %s****\n", send_all_buffer);
		print_time(temp_buf);	
		
		send_to_all(my_struct_index,&send_all_buffer[0]);
		

    }

    //should probably never get here
	

    return 0;
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
		printf("\nUnable to load Certificate...");
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(ctx);
		return 0;
	}
	if(!SSL_CTX_use_PrivateKey_file(ctx, Private_Key, SSL_FILETYPE_PEM))
	{
		printf("Unable to load Private_Key File.\n");
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(ctx);
		return 0;
	}
	
	printf("\nLoading Key File...");
	if(!SSL_CTX_load_verify_locations(ctx, CA_Certificate, NULL))
	{
		printf("Unable to load CA Certificate\n");
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(ctx);
		return 0;
	}
	
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
	SSL_CTX_set_verify_depth(ctx,1);
#endif
	
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
		printf("\nUnable to verify %s Certificate. Verification Result: %d\n",name,result);
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
		printf("\nUnable to verify client's name:%s name with Certificate Signature: %s. Verification Result: %d\n",name,peer_CN,result);
		ERR_print_errors_fp(stdout);
		return(-1);
	} 
	return (1);
}


