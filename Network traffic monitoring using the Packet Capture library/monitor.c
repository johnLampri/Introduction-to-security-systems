	#include <stdio.h>
	#include <pcap.h>
	#include <netinet/udp.h>
	#include <netinet/tcp.h>
	#include <netinet/ip.h>
	#include <stdlib.h>
	#include <string.h>
	#include <net/ethernet.h>
	#include <unistd.h>
struct networkflow{
	char sourceAddress[INET_ADDRSTRLEN];
	char destinationAddress[INET_ADDRSTRLEN];
	unsigned int sourcePort;
	unsigned int destinationPort;
	unsigned int protocol;
	struct networkflow *next;
};


int totalPackets=0;
int totalUDPpackets=0;
int totalTCPpackets=0;
int totalTCPBytes=0;
int totalUDPBytes=0;
int totalTCPNetworkFlows=0;
int totalUDPNetworkFlows=0;
int totalnetworkFlows=0;
int maximumTCPsequenceNumber=0;
struct networkflow *networkflowhead=NULL; 


int existsInList(char* sourceAddress,char* destinationAddress, unsigned int sourcePort, unsigned int destinationPort, unsigned int protocol){
	struct networkflow* temp=networkflowhead;
	while(temp!= NULL){
		if((strcmp(temp->sourceAddress,sourceAddress)==0) && (strcmp(temp->destinationAddress,destinationAddress)==0) && (temp->sourcePort==sourcePort) && (temp->destinationPort=destinationPort) && (temp->protocol==protocol)){
			return 1;
		}
		temp=temp->next;
	}



	return 0;
}

void addToList(char* sourceAddress,char* destinationAddress, unsigned int sourcePort, unsigned int destinationPort, unsigned int protocol){
	struct networkflow *temp=(struct networkflow*)malloc(sizeof(struct networkflow));
	struct networkflow *findEnd=networkflowhead;

	while(findEnd->next!=NULL){
		findEnd=findEnd->next;
	}
	findEnd->next=temp;

	memcpy(temp->sourceAddress,sourceAddress,INET_ADDRSTRLEN);
	memcpy(temp->destinationAddress,destinationAddress,INET_ADDRSTRLEN);
	temp->sourcePort=sourcePort;
	temp->destinationPort=destinationPort;
	temp->protocol=protocol;
	temp->next=NULL;
	totalnetworkFlows++;
	if(protocol==6){
		totalTCPNetworkFlows++;
	}else if(protocol==17){
		totalUDPNetworkFlows++;
	}else{

	}
}

void PrintUDP(const u_char* packet,int size){
	char sourceAddress[INET_ADDRSTRLEN];
	char destinationAddress[INET_ADDRSTRLEN];

	struct ethhdr *eth = (struct ethhdr*)packet;

	if(ntohs(eth->h_proto)!=ETH_P_IPV6 && ntohs(eth->h_proto)!=ETH_P_IP){
		printf("Not an IPV4 or IPV6 protocol. Strange\n");
		return;
	}
	struct iphdr *ipheader=(struct iphdr*)(packet+ sizeof(struct ethhdr));
	int iphdrlength=ipheader->ihl*4;

	struct udphdr *udph=(struct udphdr*)(packet+iphdrlength+sizeof(struct ethhdr));
	totalUDPBytes=totalUDPBytes+size;
	int header=sizeof(struct ethhdr)+iphdrlength+sizeof(udph);

	inet_ntop(AF_INET, &(ipheader->saddr),sourceAddress,INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ipheader->daddr),destinationAddress,INET_ADDRSTRLEN);

	printf("SOURCE IP ADDRESS: %s ",sourceAddress);
	printf("DESTINATION IP ADDRESS: %s ",destinationAddress);
	printf("SOURCE PORT NUMBER: %u ", ntohs(udph->source));
	printf("DESTINATION PORT NUMBER: %u ", ntohs(udph->dest));
	printf("PROTOCOL: UDP ");
	printf("HEADER LENGTH: %d ",(unsigned int)udph->len);
	printf("PAYLOAD LENGTH: %d \n", (size-header));


	if(networkflowhead==NULL){
		struct networkflow* tempNetworkFlow=(struct networkflow*)malloc(sizeof(struct networkflow));
		memcpy(tempNetworkFlow->sourceAddress,sourceAddress,INET_ADDRSTRLEN);
		memcpy(tempNetworkFlow->destinationAddress,destinationAddress,INET_ADDRSTRLEN);
		tempNetworkFlow->sourcePort=ntohs(udph->source);
		tempNetworkFlow->destinationPort=ntohs(udph->dest);
		tempNetworkFlow->protocol=(unsigned int)ipheader->protocol;
		tempNetworkFlow->next=NULL;
		networkflowhead=tempNetworkFlow;
		totalnetworkFlows++;
		totalUDPNetworkFlows++;

	}else{
		if(existsInList(sourceAddress,destinationAddress,ntohs(udph->source),ntohs(udph->dest),(unsigned int)ipheader->protocol)==0){
			addToList(sourceAddress,destinationAddress,ntohs(udph->source),ntohs(udph->dest),(unsigned int)ipheader->protocol);
		}
	}






}

void PrintTCP(const u_char *packet,int size){
	char sourceAddress[INET_ADDRSTRLEN];
	char destinationAddress[INET_ADDRSTRLEN];

	struct ethhdr *eth = (struct ethhdr*)packet;

	if(ntohs(eth->h_proto)!=ETH_P_IPV6 && ntohs(eth->h_proto)!=ETH_P_IP){
		printf("Not an IPV4 or IPV6 protocol. Yeeted \n");
		return;
	}
		struct iphdr *ipheader=(struct iphdr*)(packet+ sizeof(struct ethhdr));

	int iphdrlength=ipheader->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(packet +iphdrlength +sizeof(struct ethhdr));
	
	totalTCPBytes=totalTCPBytes+size;
	int header=sizeof(struct ethhdr)+iphdrlength+tcph->doff*4;
	inet_ntop(AF_INET, &(ipheader->saddr),sourceAddress,INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ipheader->daddr),destinationAddress,INET_ADDRSTRLEN);

	printf("SOURCE IP ADDRESS: %s ",sourceAddress);
	printf("DESTINATION IP ADDRESS: %s ",destinationAddress);
	printf("SOURCE PORT NUMBER: %u ", ntohs(tcph->source));
	printf("DESTINATION PORT NUMBER: %u ", ntohs(tcph->dest));
	printf("PROTOCOL: TCP ");
	printf("HEADER LENGTH: %d ",(unsigned int)tcph->doff*4);
	printf("PAYLOAD LENGTH: %d ", (size-header));

	if(networkflowhead==NULL){
		struct networkflow* tempNetworkFlow=(struct networkflow*)malloc(sizeof(struct networkflow));
		memcpy(tempNetworkFlow->sourceAddress,sourceAddress,INET_ADDRSTRLEN);
		memcpy(tempNetworkFlow->destinationAddress,destinationAddress,INET_ADDRSTRLEN);
		tempNetworkFlow->sourcePort=ntohs(tcph->source);
		tempNetworkFlow->destinationPort=ntohs(tcph->dest);
		tempNetworkFlow->protocol=(unsigned int)ipheader->protocol;
		tempNetworkFlow->next=NULL;
		networkflowhead=tempNetworkFlow;
		totalnetworkFlows++;
		totalTCPNetworkFlows++;

		maximumTCPsequenceNumber=(unsigned int)ntohl(tcph->seq);

	}else{
		if(existsInList(sourceAddress,destinationAddress,ntohs(tcph->source),ntohs(tcph->dest),(unsigned int)ipheader->protocol)==0){
			addToList(sourceAddress,destinationAddress,ntohs(tcph->source),ntohs(tcph->dest),(unsigned int)ipheader->protocol);
		}
		if(maximumTCPsequenceNumber>(unsigned int)ntohl(tcph->seq)){
			printf("RETRANSMITTED. \n");
		}
			maximumTCPsequenceNumber=(unsigned int)ntohl(tcph->seq);
		
		
	}
	printf("\n");
}



void handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){
	totalPackets++;
	struct iphdr *ipheader=(struct iphdr*)(packet+ sizeof(struct ethhdr));
	switch(ipheader->protocol){
		case 6:
		totalTCPpackets++;
		PrintTCP(packet,(header->caplen));
		break;
		case 17:
		totalUDPpackets++;
		PrintUDP(packet,(header->caplen));
		break;
		default:
		break;
	}


}




void capture(char* filename){
	char errbuf[PCAP_ERRBUF_SIZE];


	pcap_t* p=pcap_open_offline(filename,errbuf);
	if(p==NULL){
		printf("Error: %s \n",errbuf);
	}else{
		pcap_loop(p,-1, handler,NULL);

	}
	printf("\n \n \n");
	printf("Total number of network flows captured: %d \n",totalnetworkFlows);
	printf("Total number of TCP network flows captured: %d \n",totalTCPNetworkFlows);
	printf("Total number of UDP network flows captured: %d \n",totalUDPNetworkFlows);
	printf("Total number of packets received: %d \n",totalPackets);
	printf("Total number of TCP packets received: %d \n",totalTCPpackets);
	printf("Total number of UDP packets received: %d \n",totalUDPpackets);
	printf("Total bytes of TCP packets received: %d \n",totalTCPBytes);
	printf("Total bytes of UDP packets received: %d \n",totalUDPBytes);

	return;
}

void usage(){
	printf("\n Usage: \n Options: \n \n -r Packet capture file name(e.g. test.pcap \n -h Help message \n");
}

int main(int argc, char *argv[]){
	int c;
	char filename[1024];
	if(argc!=2)
		usage();
	while( (c= getopt(argc , argv ,"hr"))!= -1){
		switch(c){
			case 'r':
			printf("enter the name of the file that you want to capture: ");
			scanf("%s",filename);
			capture(filename);
			break;
			case 'h':
			usage();
			break;
			default: 
			printf("Incorrect command use '-h' for more info.");
		}

	}
	return 0;	
}