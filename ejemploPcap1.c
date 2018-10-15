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
int num_bytes;
char file_name[256];

/*
 * funcion para la impresion de los paquetes por pantalla
*/

/*
void n_bytes(int n, char *f) {

	FILE *fichero = NULL;
	int i=0;
	int c;
	char *resultado = " ";
	char * errbuf;

	fichero = fopen(f,"r");
	if(fichero==NULL) {
		printf("Error al leer el fichero para los n Bytes\n");
	}

	if(n == 0) {
		printf("No hay nada que imprimir si se quieren mostrar %d Bytes\n", n);
	} else {

		while( i < (2*n)) {
			c = fgetc(fichero);
			if(c != 32){
				printf("%x ", c);
				i++;
			}
		}
	}

	printf("%s\n", resultado);
	fclose(fichero);
}
*/

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

	printf("\nNumero de paquetes recibidos por eth0: %d\n", count_paquetes);
	/*n_bytes(num_bytes, file_name);*/

	exit(OK);
}

/*
	funcion de atencion de los paquetes
	argumento callback de pcap_loop
*/  
void fa_nuevo_paquete(uint8_t *usuario, const struct pcap_pkthdr* cabecera, const uint8_t* paquete){
	int* num_paquete=(int *)usuario;
	struct pcap_pkthdr cabeceraAux;
	const uint8_t *paqueteAux = paquete;
	int maxBytes = 0, i;


	/*Aumentamos en uno el paquete leido*/
	(*num_paquete)++;
	count_paquetes ++;

	/*Imprimimos los N_Bytes del paquete*/
	if(cabecera->len < num_bytes) {
		maxBytes = cabecera->len;
	} else {
		maxBytes = num_bytes;
	}

	for(i=0; i < maxBytes; i++) {
		printf("%02X", *paqueteAux);
		paqueteAux = paqueteAux + sizeof(uint8_t);
	}
	printf("\n");

	/*Creamos una nueva cabecera igual que la anterior pero con el tiempo modificado en 30 minutos adelantados*/
	cabeceraAux.ts.tv_sec = cabecera->ts.tv_sec + 1800;
	cabeceraAux.ts.tv_usec = cabecera->ts.tv_usec;
	cabeceraAux.len = cabecera->len;
	cabeceraAux.caplen = cabecera->caplen;

	/*Capturamos el paquete*/
	printf("Nuevo paquete capturado a las %s\n",ctime((const time_t*)&(cabecera->ts.tv_sec)));
	if(pdumper){
		pcap_dump((uint8_t *)pdumper,&cabeceraAux,paquete);
	}
}


int main(int argc, char **argv){
	int retorno=0, contador=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct timeval time;

	/* Caso 1: ningun argumento */
	if (argc == 1) {
		fprintf (stdout, "ERROR POCOS ARGUMENTOS\n"); 
		fprintf (stdout, "La entrada debe ser:\n"); 
		fprintf (stdout, "\t\t\t./ejemploPcap1 \tnumero_bytes_a_mostrar\n"); 
		fprintf (stdout, "\t\t\t./ejemploPcap1 \tnumero_bytes_a_mostrar \tnombre_traza.pcap\n"); 
		return -1;
	}

	if(argc == 2) {		/* Caso 2: un argumento, el numero de Bytes a mostrar de los paquetes*/

		if( signal(SIGINT,handle)==SIG_ERR ){
			printf("Error: Fallo al capturar la senal SIGINT.\n");
			exit(ERROR);
		}

		gettimeofday(&time,NULL);	
		sprintf(file_name,"eth0.%lld.pcap",(long long)time.tv_sec);		/*	file_name: nombre de la traza donde vamos a volcar los pqts */

		/* recuperamos el numero de bytes a imprimir por pantalla */
		sscanf (argv[1],"%d",&num_bytes);

		/* para poder almacenar en file_name */
		descr2 = pcap_open_dead(DLT_EN10MB,1514);
		if( descr2 == NULL ){
			printf("Error: pcap_open_dead() \n");
			exit(ERROR);
		}
		pdumper = pcap_dump_open(descr2,file_name);
		if( pdumper == NULL ){
			printf("Error: pcap_dump_open() \n");
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

	} else if(argc == 3){
		/* recuperamos el numero de bytes a imprimir por pantalla */
		sscanf (argv[1],"%d",&num_bytes);
		pcap_open_offline(argv[2], errbuf);

	} else {
		fprintf(stdout, "El numero de argumentos no es valido, por favor, trate de introducir uno, dos o ninguno\n");
		return -1;
	}

	return OK;
}