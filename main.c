#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <MQTTClient.h>
#include "main.h"

void address_to_string(char* str, uint8_t *addr) {
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    str[17] = 0;
}

char* readparam(char* str) {
    int s = 0;
    int e = 0;
    while(str[s] == ' ') s++;
    e = s;
    while(str[e] != 0) e++;
    e--;
    while(e >= s && (str[e] == ' ' || str[e] == '\n' || str[e] == '\r')) e--;
    char *ret = malloc(e - s + 1);
    for(int i = s; i <= e; i++) ret[i - s] = str[i];
    ret[e + 1] = 0;
    return ret;
}

int initconfig() {
    FILE *fp;
    fp = fopen("./espnowgw.conf", "r");
    if(fp == NULL) {
        fp = fopen("/etc/espnowgw.conf", "r");
    }
    if(fp == NULL) {
        printf("Could not find conf file\n");
        return -1;
    }
    size_t len = 100;
    ssize_t res;
    char* line = malloc(len);
    while((res = getline(&line, &len, fp)) != -1) {
        char* first = strtok(line, " ");
        if(strcmp(first, "wifi") == 0) {
            wifiname = readparam(strtok(NULL, " "));
        } else if(strcmp(first, "mqtturl") == 0) {
            mqtturl = readparam(strtok(NULL, " "));
        } else if(strcmp(first, "dev") == 0) {
            struct map_item* mi = malloc(sizeof(mi));
            mi->addr = readparam(strtok(NULL, " "));
            mi->topic = readparam(strtok(NULL, " "));
            if(firstdev == NULL) {
                firstdev = mi;
                lastdev = mi;
            } else {
                lastdev->next = mi;
                lastdev = mi;
            }
        } 
    }
    free(line);
    printf("Succesfully configured\n");
    return 0;
}

int initwifi() {
    int ret = 0;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, wifiname, IFNAMSIZ);

    struct iwreq pwrq;
    memset(&pwrq, 0, sizeof(pwrq));
    strncpy(pwrq.ifr_name, wifiname, IFNAMSIZ);

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock == -1){
        printf("Socket opening error\n");
        return -1;
    }

    int res = ioctl(sock, SIOCGIFINDEX, &ifr);
    if(res != 0) {
        printf("Cannot find network adapter: %s\n", strerror(res));
        return res;
    }
    ifid = ifr.ifr_ifindex;
    printf("Adapter %s has index %i\n", wifiname, ifid);


    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifid;
    res = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if(res != 0) {
        printf("Cannot bind to adapter: %s\n", strerror(res));
        return res;
    }

    res = ioctl(sock, SIOCGIWMODE, &pwrq);
    if(res != 0) {
        printf("Cannot read current mode: %s\n", strerror(res));
        return res;
    }

    if(pwrq.u.mode == 6) {
        printf("Wifi already in monitor mode\n");
        return res;
    }

    res = ioctl(sock, SIOCGIFFLAGS, &ifr);
    if(res != 0) {
        printf("Cannot get adapter status: %s\n", strerror(res));
        return res;
    }

    if(ifr.ifr_flags & IFF_UP != 0) {
        ifr.ifr_flags ^= IFF_UP;
        res = ioctl(sock, SIOCSIFFLAGS, &ifr);
        if(res != 0) {
            printf("Error stopping adapter: %s\n", strerror(res));
            return res;
        }
    }

    pwrq.u.mode = 6;
    res = ioctl(sock, SIOCSIWMODE, &pwrq);
    if(res != 0) {
        printf("Wifi could not be set to monitor mode: %s\n", strerror(res));
        return res;
    }

    ifr.ifr_flags ^= IFF_UP;
    res = ioctl(sock, SIOCSIFFLAGS, &ifr);
    if(res != 0) {
        printf("Error starting adapter: %s\n", strerror(res));
        return res;
    }

    printf("Wifi set to monitor mode\n");
    return ret;
}

int initmqtt() {
    int res = MQTTClient_create(&mqttclient, mqtturl, "espgw", MQTTCLIENT_PERSISTENCE_NONE, NULL);
    if(res != 0) {
        printf("Error creating MQTT client: %i\n", res);
        return -1;
    }

    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;
    res = MQTTClient_connect(mqttclient, &conn_opts); 
    if(res != 0) {
        printf("Error connecting MQTT client %i\n", res);
        return -1;
    }
    printf("Connected to MQTT\n");
    return 0;
}

void terminate() {
    close(sock);
    MQTTClient_destroy(&mqttclient);
}

int sendmqtt(char *topic, char *msg, int len) {
    int res = 0;
    if(!MQTTClient_isConnected(mqttclient)) 
        res = initmqtt();
    if(res != 0) {
        return res;
    }
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token;
    pubmsg.payload = msg;
    pubmsg.payloadlen = len;
    pubmsg.qos = 1;
    pubmsg.retained = 0;
    res = MQTTClient_publishMessage(mqttclient, topic, &pubmsg, &token);
    if(res != 0) {
        printf("Error publishing a message: %i\n", res);
        return res;
    }
    res = MQTTClient_waitForCompletion(mqttclient, token, 2000);
    if(res != 0) {
        printf("Message never completed: %i\n", res);
        return res;
    }
}

int parseradiotapheader(struct radiotap_header *rth, uint8_t *rawdata, int len) {
    if(len >= 8) {
        rth->version = rawdata[0];
        rth->pad = rawdata[1];
        rth->len = rawdata[2] + (rawdata[3] << 8);
        rth->present = rawdata[4] + (rawdata[5] << 8) + (rawdata[6] << 16) + (rawdata[7] << 24);
        int i = 8;
        if(rth->present & 0x01) {
            i+=8;
        }
        if(rth->present & 0x02) {
            rth->flags = rawdata[i++];
        }
        if(rth->present & 0x04) {
            rth->rate = rawdata[i++];
        }
        if(rth->present & 0x08) {
            rth->channel = rawdata[i] + (rawdata[i + 1] << 8);
            i+=4;
        }
        if(rth->present & 0x10) {
            i++;
        }    
        if(rth->present & 0x20) {
            rth->antenna_signal = rawdata[i++];
        }
        return 0;
    } else {
        return -1;
    }
}

int processreceiveddata(uint8_t *raw_bytes, int len) {
    if(len >= 8) {
        struct radiotap_header rth = {};
        int res = parseradiotapheader(&rth, raw_bytes, len);
        if(res != 0) {
            printf("Error pasing radiotap header\n");
            return res;
        }
        if(rth.len < len) {
            uint8_t *frame = &raw_bytes[rth.len];
            uint8_t type = (frame[0] & 0x0C) >> 2;
            uint8_t subtype = (frame[0] & 0xF0) >> 4;
            //printf("version %i  pad %i  type %i subtype %i\n", rth.version, rth.pad, type, subtype);
            if(type == 0) { // Management frame
                if(subtype == 13) { // Action Frame
                    uint16_t actionheaderlen = 24;
                    uint8_t *srcaddr = &frame[10];
                    char srcaddrstr[18];
                    address_to_string(srcaddrstr, srcaddr);
                    uint8_t *framebody = &frame[actionheaderlen];
                    if(framebody[0] == 127 && framebody[1] == 24 && framebody[2] == 254 && framebody[3] == 52) {
                        if(framebody[8] == 221 && framebody[13] == 4) {
                            int espdatalen = framebody[9] - 5;
                            int espversion = framebody[14];
                            uint8_t *espdata = &framebody[15];
                            while(espdatalen > 0 && espdata[espdatalen - 1] == 0) espdatalen--;
                            printf("ESP data from %s (%i) : %s\n", srcaddrstr, rth.antenna_signal, espdata);
                            struct map_item *dev = firstdev;
                            while(dev != NULL) {
                                if(strcmp(dev->addr, srcaddrstr) == 0) {
                                    sendmqtt(dev->topic, espdata, espdatalen);
                                }
                                dev = dev->next;
                            }
                        }
                    }
                }
            }
        } 
    }
}

int main(int argc, char *argv[]) {
    int res = initconfig();
    if(res != 0) {
        printf("Error reading config file\n");
        return res;
    }
    res = initwifi();
    if(res != 0) {
        printf("Error initiating wifi: %s\n", strerror(res));
        return res;
    }

    res = initmqtt();
    if(res != 0) {
        printf("Error initiating mqtt connection: %s\n", strerror(res));
        return res;
    }  

    printf("Starting monitoring loop\n");
    uint8_t *raw_bytes = malloc(512);
    while(sock > -1) {
        int len = recvfrom(sock, raw_bytes, 512, MSG_TRUNC, NULL, 0);
        if(len < 0) {
            printf("Socket receive error: %i\n", len);
        } else {
            //printf("Recevied %i bytes\n", len);
            processreceiveddata(raw_bytes, len);
        }
    }
    printf("Exiting\n");
}