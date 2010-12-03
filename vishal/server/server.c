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

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#define MAX_CONNECTS 50
#define MAXBUFSIZE 2048
#define MAXUSERNAME 100
#define MAXSTATUS 2048

#define FLAG_SENDALL -10

void *connection(void *);
int sendAll (char*, int);
void connLost(int, char*);
void initAll(void);
void logMsg(char*);
int delFromHist(int id, char *user);
int addToHist(int id, char *ip, int port, char* user);

SSL_CTX *Initialize_SSL_Context(char *Certificate, char *Private_Key, char *CA_Certificate);
int Verify_Peer(SSL *ssl, char *name);


//global variables

pthread_mutex_t myMutex;
pthread_mutex_t logMutex;

char *CA_CRT;
char *Server_CRT;
char *Server_Private_Key;

typedef struct {
	int clientId;
	char clientIp[INET_ADDRSTRLEN];
	unsigned int listenPort;
	char username[MAXUSERNAME];
	char statusMsg[MAXSTATUS];
	BIO *sbio;
	SSL *ssl;
}clientInfo;

int clientIdx = 0;

clientInfo thisClient[MAX_CONNECTS] = {{0}};

typedef struct {
	int pSock;
	SSL *pSsl;
	BIO *pSbio;
}pInfo;

pInfo pObject;

char* fileName = NULL;
char logBuf[MAXBUFSIZE] = {0};
FILE *logFile;

struct timeval timeout_tv;

int main(int argc,char *argv[]) {

    pthread_t th;
    int retval;
	
    int newsockfd = 0;
	int sock = 0;
	int true = 1;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	
    //check arguments here
    if (argc < 7)  { // 	0      1 		2 				3 						4 						  5  
		printf("USAGE: ./server <port#> <logFile> <CA Certificate Path> <server_certificate_path> <server_private_key_path>\n");
		return 0;
    }
	
	
	fileName = (char*) malloc ((sizeof(char)) * ((strlen(argv[2])) + 1));
	strcpy(fileName, argv[2]);
	initAll();
	
	CA_CRT = argv[3];
	Server_CRT = argv[4];
	Server_Private_Key = argv[5];
	
	ctx = Initialize_SSL_Context(Server_CRT, Server_Private_Key, CA_CRT);

	
	
	//====================Setup sockets=============================================================
	
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Socket");
		exit(1);
	}

	if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&true,sizeof(int)) == -1) {
		perror("Setsockopt");
		exit(1);
	}
	
	server_addr.sin_family = AF_INET;         
	server_addr.sin_port = htons(atoi(argv[1]));     
	server_addr.sin_addr.s_addr = INADDR_ANY; 
	bzero(&(server_addr.sin_zero),8); 

	if (bind(sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
		perror("Unable to bind");
		exit(1);
	}

	if (listen(sock, 5) == -1) {
		perror("Listen");
		exit(1);
	}
	
	printf("TCPServer Waiting for client\n");
	bzero(logBuf, MAXBUFSIZE);
	sprintf(logBuf, "<TCPServer Waiting for client>");
	logMsg(logBuf);
	fflush(stdout);
	

	//====================Listen for conncetions=============================================================
	
    for (;;) {
		BIO newBio;
		SSL *newSsl;
		
		bzero( &client_addr, client_len );
		
		newsockfd = accept(sock, (struct sockaddr *)&client_addr,&client_len);
		char* clientIp = inet_ntoa(client_addr.sin_addr);
		//printf ("clientIp: %s\n", clientIp);

		if (setsockopt(newsockfd, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&timeout_tv,sizeof(struct timeval)) == -1) 
		{
		 perror("Setsockopt");
		 exit(1);
		}
		
		newBio = BIO_new_socket(newsockfd,BIO_NOCLOSE);
		newSsl = SSL_new(ctx);
		SSL_set_bio(newSsl, newBio, newBio);
		
		if((SSL_accept(newSsl) <= 0)) {
			printf("\nSSL Handshake Error\n");
			ERR_print_errors_fp(stdout);
			//exit_flag = 1;
		}
		else {
			retval = addToHist(newsockfd, clientIp, 0, "default", newSsl, newBio);
			pObject->pSock = newsockfd;
			pObject->pSsl = newSsl;
			
			retval = pthread_create(&th, 0, connection, (void *)pObject);
			if (retval != 0) { 
				fprintf(stdout, "thread create failed\n"); 
			}
		}
    }
	printf("should probably never get here - for loop\n");
	return 0;
}





//====================Threads for client connections====================================================


void *connection(void *pObj) {
	
	BIO *sbio;
	SSL *ssl;
	
	pInfo *pObjectL = (pInfo*)pObj;
	int s = pObjectL->pSock;
	sbio =  pObjectL->pSbio;
	ssl =  pObjectL->pSsl;
	
	
	char recvBuf[MAXBUFSIZE];
	char sendBuf[MAXBUFSIZE];
	char sendLst[MAXBUFSIZE];
	int sz_recv = 0;
	int sz_send = 0;
	char userId[MAXUSERNAME] = {0};
	char statusMsg[MAXSTATUS] = {0};
	char cPort[6] = {0};
	char* tmp = NULL;
	unsigned int listenPort = 0;
	int iSave[2] = {0};
	int i = 0;
	int j = 0;	
	int myClientIdx = 0;
	
    pthread_detach(pthread_self()); 
	
	for (i=0; i<MAX_CONNECTS; i++) {
		if (thisClient[i].clientId == s) {
			myClientIdx = i;
			break;
		}
	}
	
	bzero(recvBuf, MAXBUFSIZE);
	//sz_recv = recv(s, recvBuf, MAXBUFSIZE, 0);
	sz_recv = SSL_read(ssl, recvBuf, MAXBUFSIZE);
	
	if (sz_recv == 0 || sz_recv == -1) {
		//connection lost
		connLost(myClientIdx, userId);
		pthread_exit(NULL);	
	}
	
	for (i=0; i<sz_recv; i++) {
		if (recvBuf[i] == ' ') { 
			iSave[0] = i;
			break;
		}
	}
	for (j=i; j<sz_recv; j++) {
		if (recvBuf[j] == ' ') { 
			iSave[1] = j;
		}
	}
	//printf("recvBuf = %s, iSave0 = %d, iSave1 = %d\n", recvBuf, iSave[0], iSave[1]);
	
	
	//cPort = (char*) malloc ((iSave[0]+1) * sizeof(char));
	//userId = (char*) malloc ((iSave[1]-iSave[0]+1) * sizeof(char));
	//statusMsg = (char*) malloc ((sz_recv-iSave[1]+1) * sizeof(char));
	
	tmp = recvBuf;
	strncpy(cPort, tmp, iSave[0]);
	cPort[iSave[0]] = 0;
	listenPort = atoi(cPort);
	
	tmp += iSave[0]+1;
	strncpy(userId, tmp, iSave[1]-iSave[0]);
	userId[iSave[1]-iSave[0]-1] = 0;
	
	tmp += iSave[1]-iSave[0];
	strcpy(statusMsg, tmp);
	tmp = NULL;
	
	printf("%s joined port = %d: \"%s\"\n", userId, listenPort, statusMsg);
	fflush(stdout);
	
	thisClient[myClientIdx].listenPort = listenPort;
	strcpy(thisClient[myClientIdx].username, userId);
	strcpy(thisClient[myClientIdx].statusMsg, statusMsg);
	
	bzero(sendBuf, MAXBUFSIZE);
	sprintf(sendBuf, "ADMIN> User %s joined", userId);
	sendAll(sendBuf, FLAG_SENDALL);
	
	bzero(logBuf, MAXBUFSIZE);
	sprintf(logBuf, "<Join> <%s>", userId);
	logMsg(logBuf);
	
    while (1) {
		bzero(recvBuf, MAXBUFSIZE);
		//sz_recv = recv(s, recvBuf, MAXBUFSIZE, 0);
		sz_recv = SSL_read(ssl, recvBuf, MAXBUFSIZE);
		
		if (sz_recv == 0 || sz_recv == -1) {
			//connection lost
			connLost(myClientIdx, userId);
			printf("Exiting because recv returned bad\n");
			shutdown(s,2);
			pthread_exit(NULL);	
		}
	
		printf("%s(%d)> %s\n", userId, sz_recv, recvBuf);
		fflush(stdout);
		
		if ((strncmp(recvBuf, "/display", 8)) == 0) {
			bzero(sendBuf, MAXBUFSIZE);
			for (i=0; i<MAX_CONNECTS; i++) {
				if (thisClient[i].clientId != -1) {
					bzero(sendLst, MAXBUFSIZE);
					sprintf(sendLst, "%s: %s\n", thisClient[i].username, thisClient[i].statusMsg);
					strcat(sendBuf, sendLst);
				}
			}
			//sz_send = send(s, sendBuf, strlen(sendBuf), 0);
			sz_send = SSL_write(ssl, sendBuf, strlen(sendBuf));
			
			bzero(logBuf, MAXBUFSIZE);
			sprintf(logBuf, "<Display> <%s>", userId);
			logMsg(logBuf);
		}
		
		else if ((strncmp(recvBuf, "/status", 7)) == 0) {
			tmp = recvBuf + 8;
			strncpy(statusMsg, tmp, sz_recv-8);
			statusMsg[sz_recv-8] = 0;
			tmp = NULL;
			strcpy(thisClient[myClientIdx].statusMsg, statusMsg);
			printf("User %s changed status to \"%s\"\n", userId, statusMsg);
			bzero(sendBuf, MAXBUFSIZE);
			sprintf(sendBuf, "User %s changed status to \"%s\"\n", userId, statusMsg);
			sendAll(sendBuf, myClientIdx);
			
			bzero(logBuf, MAXBUFSIZE);
			sprintf(logBuf, "<Status: %s> <%s>", statusMsg, userId);
			logMsg(logBuf);
		}
		
		else if (recvBuf[0] == '@') {
			char locUsr[100] = {0};
			int pm_idx = 0;
			
			tmp = recvBuf + 1;
			i=0;
			while(tmp[i] != ' ') { 
				locUsr[i] = tmp[i];
				i++;
			}
			locUsr[i] = 0;
			tmp = NULL;
			//printf("@ message: user = %s\n", locUsr);
			
			for (i=0; i<MAX_CONNECTS; i++) {
				if (strcmp(locUsr, thisClient[i].username) == 0) {
					pm_idx = i;
					break;
				}
			}
			
			bzero(sendBuf, MAXBUFSIZE);
			sprintf(sendBuf, "@%s %s %d", thisClient[pm_idx].username, thisClient[pm_idx].clientIp, thisClient[pm_idx].listenPort);
			//sz_send = send(s, sendBuf, strlen(sendBuf), 0);
			sz_send = SSL_write(ssl, sendBuf, strlen(sendBuf));
			
			bzero(logBuf, MAXBUFSIZE);
			sprintf(logBuf, "<Private Message> <%s>", userId);
			logMsg(logBuf);
		}

		else if ((strncmp(recvBuf, "/exit", 5)) == 0) {
			connLost(myClientIdx, userId);
			printf("Exiting because exit msg\n");
			pthread_exit(NULL);	
		}
		
		else {
			bzero(sendBuf, MAXBUFSIZE);
			sprintf(sendBuf, "%s> %s", userId, recvBuf);
			sendAll(sendBuf, myClientIdx);
			
			bzero(logBuf, MAXBUFSIZE);
			sprintf(logBuf, "<Message : %s> <%s>", sendBuf, userId);
			logMsg(logBuf);
		}
    }
	

    printf("should probably never get here\n");
	
    return 0;
}

//----------------------------------------------------------------------------------------------------------

int sendAll (char *sendBuf, int self) {
	int ret = 0;
	int i = 0;
	
	for (i=0; i<MAX_CONNECTS; i++) {
		if (thisClient[i].clientId != -1 && i != self) {
			//ret = send(thisClient[i].clientId, sendBuf, strlen(sendBuf), 0);
			ret = SSL_write(thisClient[i].ssl, sendBuf, strlen(sendBuf));
			printf("Sent to client %d, %s, returned %d\n", thisClient[i].clientId, thisClient[i].username, ret);
		}
	}
	return ret;
}

void connLost(int id, char* user) {
	int i;
	char sendBuf[MAXBUFSIZE] = {0};
	int retval = 0;

	for (i=0; i<MAX_CONNECTS; i++) {
		if (thisClient[i].clientId != -1) {
			printf("Client %d present\n", thisClient[i].clientId);
		}
	}
	
	bzero(logBuf, MAXBUFSIZE);
	sprintf(logBuf, "<Leave> <%s>", thisClient[id].username);
	logMsg(logBuf);
	
	retval = delFromHist(-1, user);
	if (retval < 0) {
		printf("Caution: Unable to remove %s from history\n", user);
	}
	
	printf("User %s disconnected\n", user);
	fflush(stdout);
	sprintf(sendBuf, "ADMIN> User %s disconnected", user);
	sendAll(sendBuf, FLAG_SENDALL);
}


void logMsg(char *message)
{
	pthread_mutex_lock(&(logMutex));
	{
		struct timeval tv;
		char time_buffer[40];
		time_t curtime;

		gettimeofday(&tv, NULL); 
		curtime=tv.tv_sec;

		strftime(time_buffer,40,"%m-%d-%Y (%T)",localtime(&curtime));
		//printf("%s\n",time_buffer);

		logFile = fopen(fileName, "a+");
		fprintf(logFile,"%s <%s>\n", message, time_buffer);
		fclose(logFile);
	}
	pthread_mutex_unlock(&(logMutex));
}

void initAll() {
	int i = 0;
	
	pthread_mutex_lock(&(myMutex));
	for (i=0; i<MAX_CONNECTS; i++) {
		thisClient[i].clientId = -1;
	}
	clientIdx = 0;
	
	logFile = fopen(fileName, "w");
	fclose(logFile);
	
	timeout_tv.tv_sec = 120;
	
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

int addToHist(int id, char *ip, int port, char* user, SSL *ssl, BIO sbio) {
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
			thisClient[clientIdx].sbio = sbio;

			printf("Adding User %s, ie %s\n", thisClient[clientIdx].username, user);
			added = 1;
			break;
		}
	}while (tries > 0);
	
	pthread_mutex_unlock(&(myMutex));
	
	return added;
}


int delFromHist(int id, char *user) {
	int i = 0;
	int removed = -1;
	
	pthread_mutex_lock(&(myMutex));
	
	if(id > -1) {   //use id to delete
		for (i=0; i<MAX_CONNECTS; i++) {
			if(thisClient[i].clientId == id) {
				thisClient[i].clientId = -1;
				thisClient[i].listenPort = 0;
				bzero(thisClient[i].clientIp, INET_ADDRSTRLEN);
				bzero(thisClient[i].username, MAXUSERNAME);
				bzero(thisClient[i].statusMsg, MAXSTATUS);
				removed = 1;
				break;
			}
		}
	}
	else {          //use username to delete
		for (i=0; i<MAX_CONNECTS; i++) {
			//printf("In delFromHist: Comparing %s and %s\n", thisClient[i].username, user);
			if(strcmp(thisClient[i].username, user) == 0 && thisClient[i].clientId != -1) {
				thisClient[i].clientId = -1;
				thisClient[i].listenPort = 0;
				bzero(thisClient[i].clientIp, INET_ADDRSTRLEN);
				bzero(thisClient[i].username, MAXUSERNAME);
				bzero(thisClient[i].statusMsg, MAXSTATUS);
				removed = 1;
				break;
			}
		}
	}
	
	pthread_mutex_unlock(&(myMutex));
	
	return removed;
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
	
	SSL_CTX_set_verify_depth(ctx,1);
	
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





