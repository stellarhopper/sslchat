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

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <openssl/x509.h>

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

SSL_CTX *Initialize_SSL_Context(char *Certificate, char *Private_Key, char *CA_Certificate);
int Verify_Peer(SSL *ssl, char *name);
SSL_CTX *Initialize_SSL_Context_Server(char *Certificate, char *Private_Key, char *CA_Certificate);

pthread_t th_listen_message_private;
pthread_t myth;
pthread_t th_listen_accept_private;
pthread_t th_send_message_private;

char *CA_CRT;
char *Client_CRT;
char *Client_Private_Key;

BIO *sbio;
SSL_CTX *ctx;
SSL *ssl;

typedef struct
{
	char at_user_id[100];
	int sock_descriptor;
	SSL *ssl;
}mylist;

mylist connection_list[MAX_CONNECTS];


typedef struct
{
	int temp_sock;
	SSL *temp_ssl;
}one_struct;

one_struct *temp_struct;


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
	
	if (argc < 8) 
	{					//   0       1		   2            3                		4					5					6				7					8	
		printf("\nUSAGE:  ./client <user id> <server ip> <server port #> <Your Private Port>  <CA Certificate Path> <client_certificate_path> <client_private_key_path>  <status_msg>\n");
		exit(1);
	}
	
	for (i=8; i<argc ; i++) 
	{
		strcat(statusMsg,argv[i]);
		
		if(i != argc-1)
		   strcat(statusMsg," ");
	}
	
	i=0;
	
	client_id = (char*) malloc (strlen(argv[1]) + 1);
	strcpy(client_id, argv[1]);
	
	strcpy(my_private_port, argv[4]);	
	
	CA_CRT = argv[5];
	Client_CRT = argv[6];
	Client_Private_Key = argv[7];
	
	ctx = Initialize_SSL_Context(Client_CRT, Client_Private_Key, CA_CRT);


	init_struct();

	//====================Setup sockets=============================================================
	
	//Socket function called. Creat a socket to connect to server
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) 
	{
		perror("Socket");
		exit(1);
	}
	
	//fill struct for conencting to server
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
	
	/* Connect the SSL socket */
	ssl=SSL_new(ctx);
	sbio=BIO_new_socket(sock,BIO_NOCLOSE);
	SSL_set_bio(ssl,sbio,sbio);
	
	if(SSL_connect(ssl)<=0)
	{
		printf("\nSSL Handshake Error\n");
		ERR_print_errors_fp(stdout);
		fflush(stdout);
		BIO_free_all(sbio);
		SSL_shutdown(ssl);
		//SSL_free(ssl);
		close(sock);
		exit(1);
	}
	
	Verify_Peer(ssl, "server");
	
	printf("\nLOG: Connection established with server\n");
	
	temp_struct->temp_sock = sock;
	temp_struct->temp_ssl = ssl;
	
	//r = pthread_create(&myth, 0, listen_messages, (void *)sock);
	r = pthread_create(&myth, 0, listen_messages, (void *)temp_struct);		//left here A
	
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


	//send(sock,sendBuf,strlen(sendBuf), 0);
	SSL_write(ssl,sendBuf,strlen(sendBuf));
	
	//====================create user terminal====================
	
	int_my_priv_port = atoi(my_private_port);
	r = pthread_create(&th_listen_accept_private, 0, listen_accept_private, (void *)int_my_priv_port);	//back
	
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
			//send(sock,sendBuf,strlen(sendBuf), 0);
			SSL_write(ssl,sendBuf,strlen(sendBuf));
			
			printf ("\nLOG: Exiting");
			fflush(stdout);
			kill_flag = 1;
			break;
		}
		else if(strncmp(cmd, "/display", 8) == 0)		//for display command
		{
			strcpy(sendBuf, cmd);
			//send(sock,sendBuf,strlen(sendBuf), 0);
			SSL_write(ssl,sendBuf,strlen(sendBuf));

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
			//send(sock,sendBuf,strlen(sendBuf), 0);
			SSL_write(ssl,sendBuf,strlen(sendBuf));
			
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
					//send(sock,sendBuf,strlen(sendBuf), 0);
					SSL_write(ssl,sendBuf,strlen(sendBuf));

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
		//send(sock,sendBuf,strlen(sendBuf), 0);
		SSL_write(ssl,sendBuf,strlen(sendBuf));
		
	}
    return 0;
}


//DONE. 1 todo
void *listen_messages(void *passed_struct)		//this is the thread that receives the message from all
{
	one_struct *a_struct = (one_struct *)passed_struct;
	
	//int s = (int)sockid;
	int s = a_struct->temp_sock;
	SSL *ssl_listen_server= a_struct->temp_ssl;
		
	int rc;
	
	pthread_detach(pthread_self());  //automatically clears the threads memory on exit

	while(1)
	{
		//printf("Waiting on recv\n");
		bzero(recvBuf,MAXBUFSIZE); 
		//rc = recv(s, recvBuf, MAXBUFSIZE, 0);
		rc = SSL_read(ssl_listen_server, recvBuf, MAXBUFSIZE);

		if(rc == 0)
		{
			printf("\nERROR: Connection Lost");
			exit(1);
			pthread_exit(NULL);
		}
		
		check_for_disconnect_msg(rc,s);		// left here B
		
		if (! strncmp(recvBuf,"@",1)) 			//Server sends info in form of @maulik:127.0.0.1:5677
		{
				struct sockaddr_in server_addr_priv;  
				int sock_priv=0;
				int exit_at_loop =0;
			
				//parse ip address & port number in the feilds at_ip & at_port
				char at_ip[20];
				char at_port[7];
				
				int x,y,myindex;
				myindex=0;
			
				BIO *private_connect_sbio;
				SSL_CTX *private_connect_ctx;
				SSL *private_connect_ssl;
			
				
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
				
				private_connect_ctx = Initialize_SSL_Context(Client_CRT, Client_Private_Key, CA_CRT);		// Initialize_SSL_Context

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
				
				
					/* Connect the SSL socket */
				private_connect_ssl=SSL_new(private_connect_ctx);
				private_connect_sbio=BIO_new_socket(sock_priv,BIO_NOCLOSE);
				SSL_set_bio(private_connect_ssl,private_connect_sbio,private_connect_sbio);
				
				if(SSL_connect(private_connect_ssl)<=0)
				{
					printf("\nSSL Handshake Error\n");
					ERR_print_errors_fp(stdout);
					fflush(stdout);
					BIO_free_all(private_connect_sbio);
					SSL_shutdown(private_connect_ssl);
					//SSL_free(ssl);
					close(sock_priv);
					exit(1);
				}
	
				Verify_Peer(ssl, "server");		//<<<<<LOOK>>>>>

	
				int q;
				for (q=0; q<MAX_CONNECTS; q++) 
				{
					if(connection_list[q].sock_descriptor == -1)
					{
						connection_list[q].sock_descriptor = sock_priv;
						connection_list[q].ssl = private_connect_ssl;
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
	
	BIO *sbio_priv_listen;
	SSL *ssl_priv_listen;
	SSL_CTX *listen_priv_ctx;
	
	listen_priv_ctx = Initialize_SSL_Context_Server(Client_CRT, Client_Private_Key, CA_CRT);		//Acts as a server

	
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

			sbio_priv_listen = BIO_new_socket(sock_pi,BIO_NOCLOSE);
			ssl_priv_listen = SSL_new(listen_priv_ctx);
			SSL_set_bio(ssl_priv_listen,sbio_priv_listen,sbio_priv_listen);
		
			  if(SSL_connect(ssl_priv_listen)<=0)
			{
				printf("\nSSL Handshake Error\n");
				ERR_print_errors_fp(stdout);
				fflush(stdout);
				BIO_free_all(sbio_priv_listen);
				SSL_shutdown(ssl_priv_listen);
				//SSL_free(ssl);
				close(sock_pi);
				exit(1);
			}
	
			//Verify_Peer(ssl, "server");		//<<<<<LOOK>>>>>
	
			temp_struct->temp_sock = sock_pi;
			temp_struct->temp_ssl = ssl_priv_listen;
			
			r = pthread_create(&th_listen_message_private, 0, listen_message_private, (void *)temp_struct);
			if (r != 0) 
			{ 
				fprintf(stderr, "Thread create failed\n"); 
			}
		}
		
	}
}


void *listen_message_private(void *my_temp_struct) 
{
	one_struct *a_struct = (one_struct *) my_temp_struct;
	
	SSL *ssl_listen_priv = a_struct->temp_ssl;
	int sock_listen_priv = a_struct->temp_sock;
	
	int rec_size;
	char recv_buf_priv[MAXBUFSIZE]={0};
	
	pthread_detach(pthread_self()); 
	
	printf("\nLOG: Listening for message");
	bzero(recv_buf_priv,MAXBUFSIZE); 
	
	while(1)
	{
		bzero(recv_buf_priv,MAXBUFSIZE);
		//rec_size = recv(sock_listen_priv, recv_buf_priv, MAXBUFSIZE, 0);
		rec_size = SSL_read(ssl_listen_priv, recv_buf_priv, MAXBUFSIZE);

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
	
	
	//send(connection_list[array_id].sock_descriptor , my_buffer, strlen(my_buffer), 0);
	SSL_write(connection_list[array_id].ssl , my_buffer, strlen(my_buffer));

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
			connection_list[k].ssl = NULL;
			bzero(connection_list[k].at_user_id , 100);
			
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
	ctx = SSL_CTX_new(SSLv23_client_method());
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
		printf("\nUnable to verify client's name:%s  with Certificate Signature: %s. Verification Result: %d\n",name,peer_CN,result);
		ERR_print_errors_fp(stdout);
		return(-1);
	} 
	fflush(stdout);
	return (1);
}

SSL_CTX *Initialize_SSL_Context_Server(char *Certificate, char *Private_Key, char *CA_Certificate)
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
