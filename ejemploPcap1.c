/***************************************************************************
EjemploPcapP1.c
Muestra el tiempo de llegada de los primeros 50 paquetes a la interface eth0
y los vuelca a traza nueva (�correctamente?) con tiempo actual

 Compila: gcc -Wall -o EjemploPcapP1 EjemploPcapP1.c -lpcap
 Autor: Jose Luis Garcia Dorado (primera Versión)
 Autores: Inés Fernández Campos y Javier Encinas Cortés
 2018 EPS-UAM
***************************************************************************/
#include "ejemploPcap1.h"

#define ETH_FRAME_MAX 1514	/* Tamanyo maximo trama ethernet */

/* VARIABLES GLOBALES */
pcap_t *descr=NULL,*descr2=NULL;
pcap_dumper_t *pdumper=NULL;
int count_paquetes = 0;


/*
	funcion para la gestion del Ctrl-C
*/
void handle(int nsignal){
	printf("Control C pulsado\n");
	if(descr)
		pcap_close(descr);
	if(descr2)
		pcap_close(descr2);
	if(pdumper)
		pcap_dump_close(pdumper);
	exit(OK);
}

/*
	funcion de atencion de los paquetes
	argumento callback de pcap_loop
*/  
void fa_nuevo_paquete(uint8_t *usuario, const struct pcap_pkthdr* cabecera, const uint8_t* paquete){
	int* num_paquete=(int *)usuario;
	(*num_paquete)++;
	count_paquetes ++;
	cabecera->ts.tv_sec + 1800;
	printf("Nuevo paquete capturado a las %s\n",ctime((const time_t*)&(cabecera->ts.tv_sec)));
	if(pdumper){
		pcap_dump((uint8_t *)pdumper,cabecera,paquete);
	}
}

int main(int argc, char **argv)
{
	int retorno=0, contador=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	char file_name[256];
	struct timeval time;

	/* Caso 1: ningun argumento */
	if (argc == 1) {
		fprintf (stdout, "ERROR POCOS ARGUMENTOS\n"); 
		fprintf (stdout, "La entrada debe ser:\n"); 
		fprintf (stdout, "\t\t\t./ejemploPcap1 \tnumero_bytes_a_mostrar\n"); 
		fprintf (stdout, "\t\t\t./ejemploPcap1 \tnumero_bytes_a_mostrar \tnombre_traza.pcap\n"); 
		return -1;
	} 

	if(signal(SIGINT,handle)==SIG_ERR){ 													/* ¡WARNING!  esto va aqui?? */
		printf("Error: Fallo al capturar la senal SIGINT.\n");
		exit(ERROR);
	}

	/* Caso 2: un argumento, el numero de Bytes a mostrar de los paquetes*/
	if(argc == 2) {

		gettimeofday(&time,NULL);	
		sprintf(file_name,"eth0.%lld.pcap",(long long)time.tv_sec);		/*	file_name: nombre de la traza donde vamos a volcar los pqts */

		/* para poder almacenar en file_name */
		descr2 = pcap_open_dead(DLT_EN10MB,1514);
		if( descr2 == NULL ){
			printf("Algo fue mal en pcap_open_dead \n");
			exit(ERROR);
		}
		pdumper = pcap_dump_open(descr2,file_name);
		if( pdumper == NULL ){
			printf("Algo fue mal en pcap_dump_open \n");
			pcap_close(descr2);
			exit(ERROR);
		}

		/* Apertura de interface */
	   	if ((descr = pcap_open_live("eth0",*argv[1],1,100, errbuf)) == NULL){				/* ¡WARNING! 100ms de tiempo de respuesta?? */
			printf("Error: pcap_open_live(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
			pcap_close(descr2);
			pcap_dump_close(pdumper);
			exit(ERROR);
		}

		/* Se pasa el contador como argumento, pero sera mas comodo y mucho mas habitual usar variables globales */
		retorno = pcap_loop(descr,-1,fa_nuevo_paquete, (uint8_t*)&contador);				/*  ¡WARNING! como funciona fa_nuevo_paquete*/
		if(retorno == -1){
			printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
			pcap_close(descr);
			pcap_close(descr2);
			pcap_dump_close(pdumper);
			exit(ERROR);
		}
		else if(retorno==-2){ /* pcap_breakloop() no asegura la no llamada a la funcion de atencion para paquetes ya en el buffer */
			printf("Llamada a %s %s %d.\n","pcap_breakloop()",__FILE__,__LINE__); 
		}
		else if(retorno == 0){
			printf("No mas paquetes o limite superado %s %d.\n",__FILE__,__LINE__);
		}
	
		printf("Numero de paquetes recibidos por eth0: %d\n", count_paquetes);

	}
	
	pcap_dump_close(pdumper);
	pcap_close(descr);
	pcap_close(descr2);

	return OK;
}