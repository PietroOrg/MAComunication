#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
 
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
 
int main(int argc, char **argv)
{
    int choice,returnToMenu = 0; // Aggiunto il flag per tornare al menu
    do
    {
        if (!returnToMenu) {
            printf("1. Invia un pacchetto\n2. Ricevi un pacchetto\n3. Esci\n\nScegli opzione: ");
            scanf("%d", &choice);
        } else {
            returnToMenu = 0; // Resetta il flag per evitare di entrare automaticamente nel menu successivo
        }
 
        switch (choice)
        {
 
        case 1:
        {
            pcap_t *fp;
            char errbuf[PCAP_ERRBUF_SIZE];
            u_char packet[100];
            int i;
 
            char destMac[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}; // Destination MAC address
 
            /* aprire l'adattatore */
            if ((fp = pcap_open_live(argv[1], // Nome dispositivo
                                     65536,   // Porzione del pacchetto da catturare
                                     0,       // Disabilita modalità promiscua
                                     1000,    // timeout di lettura
                                     errbuf   // buffer di errore
                                     )) == NULL)
            {
                fprintf(stderr, "\nImpossibile aprire la scheda di rete. %s non è supportato da WinPcap\n", argv[1]);
                return 2;
            }
 
            /* MAC di destinazione */
            for (i = 0; i < 6; i++)
            {
                packet[i] = destMac[i];
            }
 
            char sourceMac[] = {0xAB, 0xCD, 0xEF, 0x99, 0x99, 0x99}; // MAC di sorgente
 
            /* MAC di sorgente */
            for (i = 0; i < 6; i++)
            {
                packet[i + 6] = sourceMac[i];
            }
 
            /* Byte di controllo per la ricezione */
            packet[12] = 0xBA;
            packet[13] = 0xD0;
 
            /* resto del pacchetto */
            for (i = 14; i < 100; i++)
            {
                packet[i] = 0xBA;
            }
 
            /* Invia il pacchetto */
            if (pcap_sendpacket(fp,     // Adattatore
                                packet, // buffer pacchetto
                                100     // dimensione
                                ) != 0)
            {
                fprintf(stderr, "\nErrore nell'invio del pacchetto: %s\n", pcap_geterr(fp));
                return 3;
            }
 
            printf("\nPacchetto inviato.\n");
 
            pcap_close(fp);
        } break;
 
        case 2:
        {
            while (1) { // Ciclo infinito per tornare al menu dopo la ricezione
                pcap_if_t *alldevs;
                pcap_if_t *d;
                int inum;
                int i = 0;
                pcap_t *adhandle;
                int res;
                char errbuf[PCAP_ERRBUF_SIZE];
                struct tm *ltime;
                char timestr[16];
                struct pcap_pkthdr *header;
                const u_char *pkt_data;
                time_t local_tv_sec;
 
                /* Lista dispositivi */
                if (pcap_findalldevs(&alldevs, errbuf) == -1)
                {
                    fprintf(stderr, "Errore nella rilevazione delle schede di rete: %s\n", errbuf);
                    return -1;
                }
 
                /* Imposto la scheda di rete da utilizzare */
                /* NECESSARIO INDIVIDUARE LA SCHEDA DI RETE CORRETTA UTILIZZANDO I FILE DI ESEMPIO PCAP, PER LA PRECISIONE IFLIST */
                inum = 4;
 
                /* Vai alla scheda di rete selezionata */
                for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
 
                /* Apro scheda di rete */
                if ((adhandle = pcap_open_live(d->name, // nome
                                               65536,   // porzione del pacchetto da catturare (tutto)
                                               1,       // modalità promiscua attiva
                                               1000,    // timeout di lettura
                                               errbuf   // buffer di errore
                                               )) == NULL)
                {
                    fprintf(stderr, "\nImpossibile aprire la scheda di rete. %s non è supportato da WinPcap\n", d->name);
                    /* svuota la lista dei dispositivi */
                    pcap_freealldevs(alldevs);
                    return -1;
                }
 
                printf("\nIn attesa di pacchetti su %s...\n", d->description);
 
                pcap_freealldevs(alldevs);
 
                /* Retrieve the packets */
                while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
                {
                    if (res == 0)
                    {
                        /* Tempo scaduto */
                        continue;
                    }
 
                    // Verifica se il pacchetto è lungo almeno 14 byte (dimensione dell'header Ethernet)
                    if (header->len < 14)
                    {
                        continue;
                    }
 
                    // Estrai il MAC address di origine dal pacchetto
                    unsigned char sourceMac[6];
 
                    // Confronta il MAC address di origine con il valore desiderato
                    if (pkt_data[12] == 0xBA && pkt_data[13] == 0xD0)
                    {
                        int count = 0;
                        for (int i = 0; i < header->len; i++)
                        {
                            if (5 < i < 11)
                            {
                                printf("%02X ", pkt_data[i]);
                            }
                            if (i == 12)
                            {
                                printf(" (%02X %02X) ", pkt_data[12], pkt_data[13]);
                                i = 14;
                            }
                            else if (i > 14)
                            {
                                printf("%02X ", pkt_data[i]);
                            }
                        }
 
                        printf("\n\n\n");
                        break; // Esci dal ciclo interno dopo la ricezione
                    }
                }
                pcap_close(adhandle);
 
                printf("Premi invio per tornare al menu...");
                getchar(); // Attendere un tasto Enter prima di tornare al menu
                getchar(); // Attendere il tasto Enter
 
                // Torna al menu principale
                break;
            } // Fine del ciclo while interno
        } break;
        }
    } while (choice != 3);
}
