int sock = -1;
int ifid = -1;
MQTTClient mqttclient;

struct map_item {
    char* addr;
    char* topic;
    void* next;
};

struct radiotap_header {
    u_int8_t        version;
    u_int8_t        pad;
    u_int16_t       len;
    u_int32_t       present;
    u_int64_t       timestamp;
    u_int8_t        flags;
    u_int8_t        rate;    
    u_int8_t        channel;   
    int8_t          antenna_signal;  
};

struct map_item* firstdev;
struct map_item* lastdev;
int maplen = 0;
    
char* mqtturl;
char* wifiname;