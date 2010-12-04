#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>


#define MAX_CONNECTS 50
#define MAXBUFSIZE 2048
#define MAXUSERNAME 100
#define MAXSTATUS 2048


//Regular or thread functions

void *recvHandler(void *);
void *pm_acceptHandler(void *);
void *pm_recvHandler(void *);
void initAll(void);
int isInHist(char *usr);
int delFromHist(int id, char *user);
int addToHist(int id, char *ip, int port, char* user, SSL *ssl);
int sockToIdxHist(int sock);

//SSL functions
SSL_CTX *Initialize_SSL_Context(char *Certificate, char *Private_Key, char *CA_Certificate);
int Verify_Peer(SSL *ssl, char *name);
SSL_CTX *Initialize_SSL_Context_Server(char *Certificate, char *Private_Key, char *CA_Certificate);

//global variables

char* userId = NULL;
char* statusMsg = NULL;
char* cPort = NULL;
int killFlag = 0;

pthread_mutex_t myMutex;

struct sockaddr_in pm_server_addr;
int pm_listenSock;
char pm_sendBuf[MAXBUFSIZE] = {0};

typedef struct {
	int clientId;
	char clientIp[INET_ADDRSTRLEN];
	unsigned int listenPort;
	char username[MAXUSERNAME];
	BIO *sbio;
	SSL *ssl;
}clientInfo;

typedef struct {
	int pSock;
	SSL *pSsl;
}pInfo;

pInfo pObject;

clientInfo thisClient[MAX_CONNECTS];
int clientIdx = 0;

char *CA_CRT;
char *Client_CRT;
char *Client_Private_Key;

BIO *sbio;
SSL_CTX *ctx;
SSL *ssl;





int main(int argc, char *argv[]) {
	char cmd[MAXBUFSIZE] = {0};
	int i = 0;
	int retval = 0;
	unsigned int listenPort = 0;
	int true = 1;

	int sock;
	int pm_listenSock;
	char sendBuf[MAXBUFSIZE] = {0};
	struct sockaddr_in server_addr;
	pthread_t th;

	initAll();

	if (argc < 9) {	   //   0       1		   2            3                4							5						6							7				   8
		printf("USAGE: ./client <user id> <server ip> <server port #> <private listen port#> <CA Certificate Path> <client_certificate_path> <client_private_key_path> <status_msg>\n");
		exit(1);
	}

	cPort = (char*) malloc ((strlen(argv[4]) + 1) * sizeof(char));
	strcpy(cPort, argv[4]);

	userId = (char*) malloc ((strlen(argv[1]) + 1) * sizeof(char));
	strcpy(userId, argv[1]);

	//TODO: get all of status msg - this gets 1st word only
	statusMsg = (char*) malloc ((strlen(argv[8]) + 1) * sizeof(char));
	strcpy(statusMsg, argv[8]);

	listenPort = atoi(argv[4]);

	CA_CRT = argv[5];
	Client_CRT = argv[6];
	Client_Private_Key = argv[7];

	ctx = Initialize_SSL_Context(Client_CRT, Client_Private_Key, CA_CRT);

	//====================Setup sockets=============================================================

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Socket");
		exit(1);
	}
	if ((pm_listenSock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("PM Socket");
		exit(1);
	}

	if (setsockopt(pm_listenSock,SOL_SOCKET,SO_REUSEADDR,&true,sizeof(int)) == -1) {
		perror("Setsockopt");
		exit(1);
	}

	pm_server_addr.sin_family = AF_INET;
	pm_server_addr.sin_port = htons(atoi(argv[4]));
	pm_server_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(pm_server_addr.sin_zero),8);

	if (bind(pm_listenSock, (struct sockaddr *)&pm_server_addr, sizeof(struct sockaddr)) == -1) {
		perror("PM bind");
		exit(1);
	}

	if (listen(pm_listenSock, 5) == -1) {
		perror("PM Listen");
		exit(1);
	}

	printf("Passing listening sock %d\n",pm_listenSock);
	retval = pthread_create(&th, 0, pm_acceptHandler, (void *)pm_listenSock);
	if (retval != 0) {
		fprintf(stdout, "pm_acceptHandler thread create failed\n");
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(atoi(argv[3]));
	server_addr.sin_addr.s_addr = inet_addr(argv[2]);
	bzero(&(server_addr.sin_zero),8);

	do {
		retval = connect(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
		if (retval == -1) {
			perror("Connect");
			printf("Trying again...\n\n");
			fflush(stdout);
			sleep(1);
		}
		else {
			/* Connect the SSL socket */
			ssl=SSL_new(ctx);
			sbio=BIO_new_socket(sock,BIO_NOCLOSE);
			SSL_set_bio(ssl,sbio,sbio);
			if(SSL_connect(ssl)<=0) {
				printf("\nSSL Handshake Error\n");
				ERR_print_errors_fp(stdout);
				fflush(stdout);
				BIO_free_all(sbio);
				SSL_shutdown(ssl);
				//SSL_free(ssl);
				close(sock);
			}
			if (Verify_Peer(ssl, "server") < 0) {
				//invalid certificate, disconnect
				printf("Exiting because of invalid certificate from server\n");
				BIO_free_all(sbio);
				SSL_shutdown(ssl);
				//SSL_free(ssl);
				close(sock);
				close(pm_listenSock);
				exit(1);
			}
		}
	}while (retval == -1);

	sprintf(sendBuf, "%s %s %s", cPort, userId, statusMsg);
	//send(sock,sendBuf,strlen(sendBuf), 0);
	SSL_write(ssl,sendBuf,strlen(sendBuf));

	//====================create user terminal======================================================

	pObject.pSock = sock;
	pObject.pSsl = ssl;
	retval = pthread_create(&th, 0, recvHandler, (void *)&pObject);
	if (retval != 0) {
		fprintf(stdout, "thread create failed\n");
	}

	do {
		printf ("%s>", userId);
		bzero(cmd,MAXBUFSIZE);
		fgets(cmd, MAXBUFSIZE, stdin);
		//scanf("%s", cmd);

		for (i=0; i<MAXBUFSIZE; i++) {               //convert <CRLF> to <NULL>
			if(cmd[i] == 0x0a) cmd[i] = 0x00;
		}


		if (cmd[0] == '@') {
			char *tmp = NULL;
			char locUsr[100] = {0};
			char locMsg[MAXBUFSIZE] = {0};

			tmp = cmd + 1;
			i=0;
			while(tmp[i] != ' ') {
				locUsr[i] = tmp[i];
				i++;
				if (i == 99) break;
			}
			locUsr[i] = 0;
			if (i == 99) {
				printf("No message\n");
			}

			else {
				tmp += i+1;
				i=0;
				while(tmp[i] != 0) {
					locMsg[i] = tmp[i];
					i++;
					if (i==MAXBUFSIZE - 1) break;
				}
				locMsg[i] = 0;

				if (i == MAXBUFSIZE - 1) {
					printf("Bad message\n");
				}
				else {
					//printf("@ message decoded: user = %s, msg = %s\n", locUsr, locMsg);
					bzero(pm_sendBuf,MAXBUFSIZE);
					sprintf(pm_sendBuf, "%s PM to %s> %s", userId, locUsr, locMsg);
					bzero(sendBuf,MAXBUFSIZE);
					strcpy(sendBuf, cmd);

					retval = isInHist(locUsr);
					if (retval < 0) {					//user not in history, sent request to server
						//send(sock,sendBuf,strlen(sendBuf), 0);
						SSL_write(ssl,sendBuf,strlen(sendBuf));
					}
					else { 								//connection already exists, use directly.
						int loc_pm_sock = 0;

						printf("Client info for %s retrieved from database\n", locUsr);
						loc_pm_sock = retval;
						//send(loc_pm_sock, pm_sendBuf, strlen(pm_sendBuf), 0);
						SSL_write(thisClient[sockToIdxHist(loc_pm_sock)].ssl, pm_sendBuf, strlen(pm_sendBuf));
					}
				}
			}
		}

		else if (strncmp(cmd, "/exit", 5) == 0) {
			printf ("\nExiting...\n");
			fflush(stdout);
			bzero(sendBuf,MAXBUFSIZE);
			strcpy(sendBuf, cmd);
			//send(sock,sendBuf,strlen(sendBuf), 0);
			SSL_write(ssl,sendBuf,strlen(sendBuf));
			BIO_free_all(sbio);
			SSL_shutdown(ssl);
			//SSL_free(ssl);
			close(sock);
			killFlag = 1;
			break;
		}

		else if(!killFlag) {
			bzero(sendBuf,MAXBUFSIZE);
			strcpy(sendBuf, cmd);
			//send(sock,sendBuf,strlen(sendBuf), 0);
			SSL_write(ssl,sendBuf,strlen(sendBuf));
		}

	}while(killFlag == 0);

    return 0;
}



//====================Various threads=============================================================


void *recvHandler(void *pObj) {
	pInfo *pObjectL = (pInfo*)pObj;
	
	//int s = pObjectL->pSock;
	SSL *rec_ssl = pObjectL->pSsl;
	
	char recvBuf[MAXBUFSIZE];
	int sz_recv = 0;
	char *tmp = NULL;
	int i = 0;
	int retval = 0;
	
	BIO *pm_sbio;
	SSL_CTX *pm_ctx;
	SSL *pm_ssl;


	while(!killFlag) {
		bzero(recvBuf, MAXBUFSIZE);
		//sz_recv = recv(s, recvBuf, MAXBUFSIZE, 0);
		sz_recv = SSL_read(rec_ssl, recvBuf, MAXBUFSIZE);

		if(sz_recv == 0) {
			//connection lost; server died
			printf("Connection to server lost or kicked due to inactivity.\n");
			killFlag = 1;
			pthread_exit(NULL);
		}

		else if (recvBuf[0] == '@') {
			char locUsr[100] = {0};
			char locIp[20] = {0};
			char locPort[10] = {0};
			unsigned int connectPort = 0;

			int pm_connectSock = 0;
			struct sockaddr_in pm_client_addr;

			tmp = recvBuf + 1;
			i=0;
			while(tmp[i] != ' ') {
				locUsr[i] = tmp[i];
				i++;
			}
			locUsr[i] = 0;

			tmp += i+1;
			i=0;
			while(tmp[i] != ' ') {
				locIp[i] = tmp[i];
				i++;
			}
			locIp[i] = 0;

			tmp += i+1;
			i=0;
			while(tmp[i] != 0) {
				locPort[i] = tmp[i];
				i++;
			}
			locPort[i] = 0;
			connectPort = atoi(locPort);

			//printf("@ message from server: user = %s, ip = %s, port = %d\n", locUsr, locIp, connectPort);


			pm_client_addr.sin_family = AF_INET;
			pm_client_addr.sin_port = htons(connectPort);
			pm_client_addr.sin_addr.s_addr = inet_addr(locIp);
			bzero(&(pm_client_addr.sin_zero),8);

			if ((pm_connectSock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
				perror("Socket");
				exit(1);
			}

			retval = connect(pm_connectSock, (struct sockaddr *)&pm_client_addr, sizeof(struct sockaddr));
			if (retval == -1) {
				perror("Connect");
				printf("Error: %d s=%d\n", errno, pm_connectSock);
				fflush(stdout);
			}
			else {
			
				pm_ctx = Initialize_SSL_Context(Client_CRT, Client_Private_Key, CA_CRT);
				/* Connect the SSL socket */
				pm_ssl=SSL_new(pm_ctx);
				pm_sbio=BIO_new_socket(pm_connectSock, BIO_NOCLOSE);
				SSL_set_bio(pm_ssl, pm_sbio, pm_sbio);
				if(SSL_connect(pm_ssl)<=0)
				{
					printf("\nSSL Handshake Error\n");
					ERR_print_errors_fp(stdout);
					fflush(stdout);
					BIO_free_all(pm_sbio);
					SSL_shutdown(pm_ssl);
					//SSL_free(pm_ssl);
					close(pm_connectSock);
					exit(1);
				}
				if (Verify_Peer(pm_ssl, locUsr) < 0) {
					//invalid certificate, disconnect
					printf("Exiting because of invalid certificate wjile connecting to peer\n");
					BIO_free_all(pm_sbio);
					SSL_shutdown(pm_ssl);
					//SSL_free(pm_ssl);
					close(pm_connectSock);
				}
					
				//send the data
				//send(pm_connectSock, pm_sendBuf, strlen(pm_sendBuf), 0);
				SSL_write(pm_ssl, pm_sendBuf, strlen(pm_sendBuf));

				//save client info for future use
				retval = addToHist(pm_connectSock, locIp, connectPort, locUsr, pm_ssl);
				if(retval) {
					//printf("Client %s saved\n", locUsr);
				}
				else {
					printf("Unable to add %s to database, possibly out of space\n", locUsr);
				}
			}
		}

		else if (strstr(recvBuf, "ADMIN>") != NULL) {			//remove user 'x' from hist on admin msg
			printf("\n%s\n%s>", recvBuf, userId);
			fflush(stdout);
			if (strstr(recvBuf, "disconnected") != NULL) {
				if (strstr(recvBuf, "User") != NULL) {
					char *tmp = NULL;
					char *tail = NULL;
					tmp = strstr(recvBuf, "User");
					tail = strstr(recvBuf, "disconnected");
					tmp += 5;
					tail--;
					tail[0] = '\0';
					if (isInHist(tmp) != -1) {
						if (delFromHist(-1, tmp) < 0) {
							printf("Caution: Unable to remove %s from history\n", tmp);
						}
					}
				}
			}
		}

		else {
			printf("\n%s\n%s>", recvBuf, userId);
			fflush(stdout);
		}
	}
	return 0;
}


void *pm_acceptHandler(void *sockid) {
	int s = (int)sockid;
	int newsockfd=0;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	int retval = 0;
	pthread_t th;
	
	BIO *pm_sbio;
	SSL_CTX *pm_ctx;
	SSL *pm_ssl;
	
	pm_ctx = Initialize_SSL_Context(Client_CRT, Client_Private_Key, CA_CRT);

	printf("Ready for PM connection\n");

	while(!killFlag) {

		bzero( &client_addr, client_len );
		printf("NA: New Connection %d from %d\n", s, client_addr.sin_addr.s_addr);

		newsockfd = accept(s, (struct sockaddr *)&client_addr,&client_len);
		printf("New Connection %d from %d\n", newsockfd, client_addr.sin_addr.s_addr);
		fflush(stdout);
		
		pm_ssl = SSL_new(pm_ctx);
		pm_sbio = BIO_new_socket(newsockfd, BIO_NOCLOSE);
		SSL_set_bio(pm_ssl, pm_sbio, pm_sbio);
		if(SSL_accept(pm_ssl)<=0)	{
			printf("\nSSL Handshake Error\n");
			ERR_print_errors_fp(stdout);
			fflush(stdout);
			BIO_free_all(pm_sbio);
			SSL_shutdown(pm_ssl);
			//SSL_free(pm_ssl);
			close(newsockfd);
			exit(1);
		}
		
		pObject.pSock = newsockfd;
		pObject.pSsl = pm_ssl;
		
		retval = pthread_create(&th, 0, pm_recvHandler, (void *)&pObject);
		if (retval != 0) {
			fprintf(stdout, "pm_recvHandler thread create failed\n");
		}
	}
	return 0;
}

void *pm_recvHandler(void *pObj) {
	
	pInfo *pObjectL = (pInfo*)pObj;
	//int s = pObjectL->pSock;
	SSL *pm_ssl = pObjectL->pSsl;
	
	char recvBuf[MAXBUFSIZE];
	int sz_recv = 0;
	int flag_verified = 0;

	while(!killFlag) {
		bzero(recvBuf, MAXBUFSIZE);
		//sz_recv = recv(s, recvBuf, MAXBUFSIZE, 0);
		sz_recv = SSL_read(pm_ssl, recvBuf, MAXBUFSIZE);

		if(sz_recv == 0) {
			//connection lost; pm_client died
			//printf("Connection to pm_client lost.\n");
			pthread_exit(NULL);
		}
		
		if (flag_verified == 0) {
			char *tmp = NULL;
			int cnt = 0;
			char *uid;
			
			//printf("Will parse: %s\n", recvBuf);
			tmp = strpbrk(recvBuf, " ");
			//printf("Have: %s\n", tmp);
			do {
				tmp--;
				cnt ++;
			}while(tmp != recvBuf);
			
			//printf("stats: cnt = %d, tmp = %s\n", cnt, tmp);
			
			uid = (char*) malloc ((cnt+1)*sizeof(char));
			strncpy(uid, tmp, cnt);
			uid[cnt] = 0;
				
			if (Verify_Peer(pm_ssl, uid) < 0) {
				//invalid certificate, disconnect
				printf("Exiting because of invalid certificate: %s\n", uid);
				SSL_shutdown(pm_ssl);
				//SSL_free(pm_ssl);
				pthread_exit(NULL);
			}
			flag_verified = 1;
		}

		printf("\n%s\n%s>", recvBuf, userId);
		fflush(stdout);
	}
	return 0;
}



//===========================================================================================


void initAll() {
	int i = 0;

	pthread_mutex_lock(&(myMutex));

	for (i=0; i<MAX_CONNECTS; i++) {
		thisClient[i].clientId = -1;
	}
	clientIdx = 0;

	pthread_mutex_unlock(&(myMutex));
}

int sockToIdxHist(int sock) {
	int i = 0;
	int retval = -1;

	pthread_mutex_lock(&(myMutex));

	for (i=0; i<MAX_CONNECTS; i++) {
		if(thisClient[i].clientId == sock) {
			retval = i;
			break;
		}
	}

	pthread_mutex_unlock(&(myMutex));

	return retval;
}

int isInHist(char *usr) {
	int i = 0;
	int found = -1;

	pthread_mutex_lock(&(myMutex));

	for (i=0; i<MAX_CONNECTS; i++) {
		if(strcmp(thisClient[i].username, usr) == 0) {
			found = thisClient[i].clientId;
			break;
		}
	}

	pthread_mutex_unlock(&(myMutex));

	return found;
}

int delFromHist(int id, char *user) {
	int i = 0;
	int removed = -1;

	pthread_mutex_lock(&(myMutex));

	if(id > -1) {   //use id to delete
		for (i=0; i<MAX_CONNECTS; i++) {
			if(thisClient[i].clientId == id) {
				thisClient[i].clientId = -1;
				removed = 1;
				break;
			}
		}
	}
	else {          //use username to delete
		for (i=0; i<MAX_CONNECTS; i++) {
			printf("Removing User %s from database\n", thisClient[i].username);
			if(strcmp(thisClient[i].username, user) == 0 && thisClient[i].clientId != -1) {
				thisClient[i].clientId = -1;
				removed = 1;
				break;
			}
		}
	}

	pthread_mutex_unlock(&(myMutex));

	return removed;
}

int addToHist(int id, char *ip, int port, char *user, SSL *ssl) {
	int added = -1;
	int tries = 200;

	pthread_mutex_lock(&(myMutex));

	do {
		clientIdx++;
		tries--;
		if (clientIdx == MAX_CONNECTS - 1) {
			clientIdx = 0;
		}
		if(thisClient[clientIdx].clientId == -1) {		//try to find next free slot
			thisClient[clientIdx].clientId = id;
			bzero(thisClient[clientIdx].clientIp, strlen(thisClient[clientIdx].clientIp));
			strcpy(thisClient[clientIdx].clientIp, ip);
			thisClient[clientIdx].listenPort = port;
			bzero(thisClient[clientIdx].username, strlen(thisClient[clientIdx].username));
			strcpy(thisClient[clientIdx].username, user);
			thisClient[clientIdx].ssl = ssl;
			printf("Adding User to database %s\n", thisClient[clientIdx].username);
			added = 1;
			break;
		}
	}while (tries > 0);

	pthread_mutex_unlock(&(myMutex));

	return added;
}








SSL_CTX *Initialize_SSL_Context(char *Certificate, char *Private_Key, char *CA_Certificate) {
	SSL_CTX *ctx;
	
	/* Global system initialization*/
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_SSL_strings();
	OpenSSL_add_all_algorithms();
	
	printf("Attempting to create SSL context... ");
	ctx = SSL_CTX_new(SSLv23_method());
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

int Verify_Peer(SSL *ssl, char *name) {
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



