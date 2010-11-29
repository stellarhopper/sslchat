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


#define MAX_CONNECTS 50
#define MAXBUFSIZE 2048
#define MAXUSERNAME 100
#define MAXSTATUS 2048

void *recvHandler(void *);
void *pm_acceptHandler(void *);
void *pm_recvHandler(void *);
void initAll(void);
int isInHist(char *usr);
int delFromHist(int id, char *user);
int addToHist(int id, char *ip, int port, char* user);

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
}clientInfo;

clientInfo thisClient[MAX_CONNECTS];
int clientIdx = 0;

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

	if (argc < 6) {		//   0       1		   2            3                4                 5
		printf("USAGE:  ./client <user id> <server ip> <server port #> <status_msg> <private listen port#>\n");
		exit(1);
	}
	
	cPort = (char*) malloc ((strlen(argv[5]) + 1) * sizeof(char));
	strcpy(cPort, argv[5]);
	
	userId = (char*) malloc ((strlen(argv[1]) + 1) * sizeof(char));
	strcpy(userId, argv[1]);
	
	//TODO: get all of status msg - this gets 1st word only
	statusMsg = (char*) malloc ((strlen(argv[4]) + 1) * sizeof(char));
	strcpy(statusMsg, argv[4]);
	
	listenPort = atoi(argv[5]);
	
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
	pm_server_addr.sin_port = htons(atoi(argv[5]));     
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
	}while (retval == -1);
	
	sprintf(sendBuf, "%s %s %s", cPort, userId, statusMsg);
	send(sock,sendBuf,strlen(sendBuf), 0);
	
	//====================create user terminal======================================================
	
	retval = pthread_create(&th, 0, recvHandler, (void *)sock);
	if (retval != 0) { 
		fprintf(stdout, "thread create failed\n"); 
	}

	do {
		printf ("%s>", userId);
		bzero(cmd,MAXBUFSIZE);
		//TODO: make input buffered
		fgets(cmd, MAXBUFSIZE, stdin);
		//scanf("%s", cmd);
		
		for (i=0; i<MAXBUFSIZE; i++) {
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
						send(sock,sendBuf,strlen(sendBuf), 0);
					}
					else { 								//connection already exists, use directly.
						int loc_pm_sock = 0;
						
						printf("Client info for %s retrieved from database\n", locUsr);
						loc_pm_sock = retval;
						send(loc_pm_sock, pm_sendBuf, strlen(pm_sendBuf), 0);
					}
				}
			}
		}
		
		else if (strncmp(cmd, "/exit", 5) == 0) {
			printf ("\nExiting...\n");
			fflush(stdout);
			bzero(sendBuf,MAXBUFSIZE);
			strcpy(sendBuf, cmd);
			send(sock,sendBuf,strlen(sendBuf), 0);
			killFlag = 1;
			break;
		}
		
		else if(!killFlag) {
			bzero(sendBuf,MAXBUFSIZE);
			strcpy(sendBuf, cmd);
			send(sock,sendBuf,strlen(sendBuf), 0);
		}

	}while(killFlag == 0);

    return 0;
}



//====================Various threads=============================================================


void *recvHandler(void *sockid) {
	int s = (int)sockid;
	char recvBuf[MAXBUFSIZE];
	int sz_recv = 0;
	char *tmp = NULL;
	int i = 0;
	int retval = 0;
	
	
	while(!killFlag) {
		bzero(recvBuf, MAXBUFSIZE);
		sz_recv = recv(s, recvBuf, MAXBUFSIZE, 0);
		
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
			}
			else {
				//send the data
				send(pm_connectSock, pm_sendBuf, strlen(pm_sendBuf), 0);
				
				//save client info for future use
				retval = addToHist(pm_connectSock, locIp, connectPort, locUsr);
				if(retval) {
					//printf("Client %s saved\n", locUsr);
				}
				else {
					//printf("Unable to add %s to database, possibly out of space\n", locUsr);
				}
			}
		}
		
		else if (strstr(recvBuf, "ADMIN>") != NULL) {
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
	int newsockfd;
	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	int retval = 0;
	pthread_t th;
	
	printf("Ready for PM connection\n");
	
	while(!killFlag) {
	
		bzero( &client_addr, client_len );
		newsockfd = accept(s, (struct sockaddr *)&client_addr,&client_len);
		//printf("New Connection %d from %d\n", newsockfd, client_addr.sin_addr.s_addr);
		fflush(stdout);
		
		retval = pthread_create(&th, 0, pm_recvHandler, (void *)newsockfd);
		if (retval != 0) { 
			fprintf(stdout, "pm_acceptHandler thread create failed\n"); 
		}
	}
	return 0;
}

void *pm_recvHandler(void *sockid) {
	int s = (int)sockid;
	char recvBuf[MAXBUFSIZE];
	int sz_recv = 0;

	while(!killFlag) {
		bzero(recvBuf, MAXBUFSIZE);
		sz_recv = recv(s, recvBuf, MAXBUFSIZE, 0);
		
		if(sz_recv == 0) {
			//connection lost; pm_client died
			//printf("Connection to pm_client lost.\n");
			pthread_exit(NULL);	
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

int addToHist(int id, char *ip, int port, char* user) {
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
			printf("Adding User to database %s\n", thisClient[clientIdx].username);
			added = 1;
			break;
		}
	}while (tries > 0);
	
	pthread_mutex_unlock(&(myMutex));
	
	return added;
}











