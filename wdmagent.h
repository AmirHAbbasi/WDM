 #ifndef WDMAGENT_H
 #define WDMAGENT_H
 
 #ifdef __cplusplus
 extern "C" {
 #endif
 
#define MAX_SYS_SCALARS     20

#ifdef  MAIN
static long Test = 421;
static char    sysName[100] = "dwdm.danialMoj";
static char    wdmsnmpversion[20];
static char    wdmrocommunity[20];
static char    wdmrwcommunity[20];
static char    wdmTrapDestination1[50];
static char    wdmTrapDestination2[50];
static char    wdmTrapDestination3[50];
static char    wdmTrapDestination4[50];
stControlScalars    sysScalars[MAX_SYS_SCALARS];
byte    nSysCalars = 0;
#endif

void    init_wdmagent(void);
void    update_sysdatetime();
void*    log_message_thread(void* param);

 #ifdef __cplusplus
 }
 #endif
 
 #endif                          /* SCALAR_INT_H */
