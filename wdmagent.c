/*
 * start be including the appropriate header files 
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-features.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/agent_callbacks.h>

#include <stdlib.h>

#include <sys/types.h>
#include <netdb.h> 
#include <stdarg.h>  
#include <mqueue.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <sys/stat.h>
#include <sys/statvfs.h>

#define MAIN
#include "globaltypes.h"
#include "wdmagent.h"
#include "utills.h"
#include "wdmsocket_fd.h"
#include "wdmCardTable_fd.h"
#include "wdmSfpTable_fd.h"
#include "wdmXfpTable_fd.h"
#include "wdmShelfTable_fd.h"
#include "wdmOpticalSwitch_fd.h"
#include "wdmControlCard_fd.h"
#include "wdmQSfpTable_fd.h"

#include "wdmCardTable_vd.h"
#include "wdmSfpTable_vd.h"
#include "wdmXfpTable_vd.h"
#include "wdmShelfTable_vd.h"
#include "wdmOpticalSwitch_vd.h"
#include "wdmEDFAModule_fd.h"
#include "wdmEDFAModule_vd.h"
#include "wdmQSfpTable_vd.h"


#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)


void    notify_new_row(oid*  rootOid, size_t oidLen, netsnmp_table_row *row, byte* cols, byte nCols)
{
//    netsnmp_table_data_set_storage* ds = (netsnmp_table_data_set_storage*) row->data;
    if(!sendChangedData)
        return;
    
    byte i;
    for(i = 0; i < nCols; i++)
    {
        netsnmp_table_data_set_storage* ds = 
                netsnmp_table_data_set_find_column((netsnmp_table_data_set_storage*) row->data, cols[i]);   
        if(!ds)
            continue;
        oid*    temp_oid = NULL;
        size_t  temp_oid_len = 0;
        temp_oid = (oid*) malloc((oidLen + 2 + row->index_oid_len) * sizeof (oid));
        memcpy(temp_oid, rootOid, oidLen * sizeof (oid));
        temp_oid[oidLen] = 1; //entry
        temp_oid[oidLen + 1] = ds->column;
        memcpy(&temp_oid[oidLen + 2], row->index_oid, row->index_oid_len * sizeof (oid));
        temp_oid_len = oidLen + 2 + row->index_oid_len;
        
        byte len = ds->data_len;
        if(ds->type == ASN_INTEGER)
            len = sizeof(int);
        
        byte* msg = (byte*)malloc((temp_oid_len) * sizeof (oid) + 4 + len);
        if(msg)
        {
            int ptr = 0;
            msg[ptr++] = IND_DATA_CHANGED;
            msg[ptr++] = temp_oid_len;
            memcpy(&msg[ptr], temp_oid, temp_oid_len * sizeof (oid));
            ptr += (temp_oid_len * sizeof(oid));
            msg[ptr++] = ds->type;
            msg[ptr++] = len;
            if(ds->type == ASN_OCTET_STR)
                memcpy(&msg[ptr], ds->data.string, ds->data_len);
            else if(ds->type == ASN_INTEGER)
                *(int*)&msg[ptr] = *ds->data.integer;
            ptr += len;
            
            char    oidstr[200];
            int len2 = snprint_objid(oidstr, 200, temp_oid , temp_oid_len);
            oidstr[len2] = 0;
            log_message("newrow_token", "notify_new_row %s, %d, %d", oidstr, ds->type, ds->data.string[0]);
            put_message_to_trap_sending_queue(msg, ptr, TRUE);
           
            free(msg);
        }
        free(temp_oid);
    }

}


void    ind_data_changed(byte* buff, int buflen)
{
//send trap to notify col value changed
   oid objid_snmptrap[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
   size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);
   netsnmp_variable_list *notification_vars = NULL;
   netsnmp_variable_list *returnVar = NULL;

   oid objid_sysuptime[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
   size_t objid_sysuptime_len = OID_LENGTH(objid_sysuptime);
   u_long sysuptime = netsnmp_get_agent_uptime();

    oid*    temp_oid = NULL;
    size_t  temp_oid_len = buff[0];
    temp_oid = (oid*) malloc(temp_oid_len * sizeof (oid));
    memcpy(temp_oid, &buff[1], temp_oid_len * sizeof (oid));

    int ptr = temp_oid_len * sizeof (oid) + 1;
    int type = buff[ptr++];
    int len =  buff[ptr++];
   
   returnVar = snmp_varlist_add_variable(&notification_vars,
           objid_sysuptime, objid_sysuptime_len,
           ASN_TIMETICKS,
           (u_char*) &sysuptime,
           sizeof (sysuptime));
   if(!returnVar)
   {
       free(temp_oid);
       return;
   }
   returnVar = snmp_varlist_add_variable(&notification_vars,
           objid_snmptrap, objid_snmptrap_len,
           ASN_OBJECT_ID,
           (u_char *) dataChangedNotifRaise_oid,
           OID_LENGTH(dataChangedNotifRaise_oid) * sizeof (oid));
   if(!returnVar)
   {
       free(temp_oid);
       return;
   }
   returnVar = snmp_varlist_add_variable(&notification_vars,
//                tempvar->name, tempvar->name_length,
           temp_oid, temp_oid_len,
           type,
           (u_char*) &buff[ptr],
           len);
   if(!returnVar)
   {
       free(temp_oid);
       return;
   }
   if (notification_vars)
   {
       log_message("wdmagent_token", "in trap 888 %d", objid_snmptrap_len);
       wdm_send_and_save_v2Trap(notification_vars);
   }
   free(temp_oid);
}

void    send_scalar_ind_changed(oid*  rootOid, size_t oidLen, int type, const void *data, size_t len)
{
    oid*    temp_oid = NULL;
    size_t  temp_oid_len = 0;
    temp_oid = (oid*) malloc((oidLen + 1) * sizeof (oid));
    memcpy(temp_oid, rootOid, oidLen * sizeof (oid));
    temp_oid_len = oidLen;
    temp_oid[temp_oid_len] = 0;
    
    byte sendTrap = FALSE;
    
    char    oidstr[200];
    int len2 = snprint_objid(oidstr, 200, temp_oid , temp_oid_len);
    oidstr[len2] = 0;
    
    byte* msg = (byte*)malloc((temp_oid_len) * sizeof (oid) + 4 + len);
    if(msg)
    {

        int ptr = 0;
        msg[ptr++] = IND_DATA_CHANGED;
        msg[ptr++] = temp_oid_len;
        memcpy(&msg[ptr], temp_oid, temp_oid_len * sizeof (oid));
        ptr += (temp_oid_len * sizeof(oid));
        msg[ptr++] = type;
        msg[ptr++] = len;
        memcpy(&msg[ptr], data, len);
        ptr += len;
        put_message_to_trap_sending_queue(msg, ptr, TRUE);

        char    oidstr[200];
        int len2 = snprint_objid(oidstr, 200, temp_oid , temp_oid_len);
        oidstr[len2] = 0;
        log_message("wdmagent_token", "send_scalar_ind_changed %s ", oidstr); 
        free(msg);
    }
    free(temp_oid);
}

void    my_netsnmp_set_row_column(oid*  rootOid, size_t oidLen, netsnmp_table_row *row, unsigned int col, int type, const void *data, size_t len)
{
 //   netsnmp_set_row_column(row, col, type, data, len);
 //   return;
    
    if(!sendChangedData)
    {
        netsnmp_set_row_column(row, col, type, data, len);
        return;
    }
        
  
    oid*    temp_oid = NULL;
    size_t  temp_oid_len = 0;
    temp_oid = (oid*) malloc((oidLen + 2 + row->index_oid_len) * sizeof (oid));
    memcpy(temp_oid, rootOid, oidLen * sizeof (oid));
    temp_oid[oidLen] = 1; //entry
    temp_oid[oidLen + 1] = col;
    memcpy(&temp_oid[oidLen + 2], row->index_oid, row->index_oid_len * sizeof (oid));
    temp_oid_len = oidLen + 2 + row->index_oid_len;
//    *(oid*)&temp_oid[temp_oid_len * sizeof (oid)] = 0;
    
//    temp_oid_len++;
    
    byte sendTrap = FALSE;
    netsnmp_table_data_set_storage* ds = 
        netsnmp_table_data_set_find_column((netsnmp_table_data_set_storage*) row->data, col);
    
    
    char    oidstr[200];
    int len2 = snprint_objid(oidstr, 200, temp_oid , temp_oid_len);
    oidstr[len2] = 0;
    if(!ds)
    {
        sendTrap = FALSE;
        log_message("wdmagent_token", "my_netsnmp_set_row_column1 %s", oidstr);        
    }
    else
    {
        if(ds->type == type)
        {
            if(ds->type == ASN_OCTET_STR)
            {
                if(ds->data_len != len)
                    sendTrap = TRUE;
                else
                {
                    if(memcmp(ds->data.string, data, len))
                        sendTrap = TRUE;
                }

            }
            else if (ds->type == ASN_INTEGER)
            {
                if(*ds->data.integer != *(int*)data)
                    sendTrap = TRUE;
            }
        }
    }

    if(sendTrap)
    {
        byte* msg = (byte*)malloc((temp_oid_len) * sizeof (oid) + 4 + len);
        if(msg)
        {
            
            int ptr = 0;
            msg[ptr++] = IND_DATA_CHANGED;
            msg[ptr++] = temp_oid_len;
            memcpy(&msg[ptr], temp_oid, temp_oid_len * sizeof (oid));
            ptr += (temp_oid_len * sizeof(oid));
            msg[ptr++] = type;
            msg[ptr++] = len;
            memcpy(&msg[ptr], data, len);
            ptr += len;
            put_message_to_trap_sending_queue(msg, ptr, TRUE);

//            char    oidstr[200];
//            int len2 = snprint_objid(oidstr, 200, temp_oid , temp_oid_len);
//            oidstr[len2] = 0;
      //      log_message("wdmagent_token", "my_netsnmp_set_row_column3 %s ", oidstr); 
            free(msg);
            
            if(ds)
            {
                if(type == ASN_OCTET_STR)
                {
                    char    *str1 = (char*)malloc(ds->data_len + 1);
                    memcpy(str1, ds->data.string, ds->data_len);
                    str1[ds->data_len] = 0;

                    char    *str2 = (char*)malloc(len + 1);
                    memcpy(str2, data, len);
                    str2[len] = 0;

                    log_message("wdmagent_token", "my_netsnmp_set_row_column3 %s, (%d, %d),(%d, %d),(%s,%s) ", 
                                oidstr, type, ds->type, len, ds->data_len, str2, str1);  
                    
                    free(str1);
                    free(str2);
                }
                else if (ds->type == ASN_INTEGER)
                {
                    log_message("wdmagent_token", "my_netsnmp_set_row_column3 %s, (%d, %d), (%d, %d)", 
                                oidstr, len, ds->data_len, *(int*)data, *ds->data.integer);        
                }
            }                
                            
        }
    }
    
    free(temp_oid);
    
    netsnmp_set_row_column(row, col, type, data, len);
}

void    add_sysScalar_params(char*    name, oid oid1[], int oid1len, byte  type, byte  access)
{
    if(nSysCalars >= MAX_SYS_SCALARS)
        return;
    sysScalars[nSysCalars].access = access;
    strcpy(sysScalars[nSysCalars].name , name);
    memcpy(sysScalars[nSysCalars].scalar_oid, oid1, oid1len * sizeof(oid));
    sysScalars[nSysCalars].oid_len = oid1len;
    sysScalars[nSysCalars].value.value.string.len = 0;
    sysScalars[nSysCalars].value.value.string.ptr = NULL;
    sysScalars[nSysCalars++].value.Type = type;
}

stControlScalars*   find_sysScalar_parameter_struct(char* param)
{
    for(byte i = 0; i < nSysCalars; i++)
    {
        if(!strcmp(sysScalars[i].name, param))
            return &sysScalars[i];
    }
    return NULL;
}


void    init_sysScalar_params()
{
    add_sysScalar_params("sysSnmpVersion", sysSnmpVersion_oid, OID_LENGTH(sysSnmpVersion_oid), ASN_OCTET_STR, HANDLER_CAN_RWRITE);
    add_sysScalar_params("sysSnmproCommunity", sysSnmprocommunity_oid, OID_LENGTH(sysSnmprocommunity_oid), ASN_OCTET_STR, HANDLER_CAN_RWRITE);
    add_sysScalar_params("sysSnmprwCommunity", sysSnmprwcommunity_oid, OID_LENGTH(sysSnmprwcommunity_oid), ASN_OCTET_STR, HANDLER_CAN_RWRITE);
    add_sysScalar_params("sysTrapDestination1", sysTrapDestination1_oid, OID_LENGTH(sysTrapDestination1_oid), ASN_OCTET_STR, HANDLER_CAN_RWRITE);
    add_sysScalar_params("sysTrapDestination2", sysTrapDestination2_oid, OID_LENGTH(sysTrapDestination2_oid), ASN_OCTET_STR, HANDLER_CAN_RWRITE);
    add_sysScalar_params("sysTrapDestination3", sysTrapDestination3_oid, OID_LENGTH(sysTrapDestination3_oid), ASN_OCTET_STR, HANDLER_CAN_RWRITE);
    add_sysScalar_params("sysTrapDestination4", sysTrapDestination4_oid, OID_LENGTH(sysTrapDestination4_oid), ASN_OCTET_STR, HANDLER_CAN_RWRITE);
    
    add_sysScalar_params("sysIPAddress", sysIPAddress_oid, OID_LENGTH(sysIPAddress_oid), ASN_OCTET_STR, HANDLER_CAN_RWRITE);
    add_sysScalar_params("sysRoute1", sysRoute1_oid, OID_LENGTH(sysRoute1_oid), ASN_OCTET_STR, HANDLER_CAN_RWRITE);
    add_sysScalar_params("sysRoute2", sysRoute2_oid, OID_LENGTH(sysRoute2_oid), ASN_OCTET_STR, HANDLER_CAN_RWRITE);
    add_sysScalar_params("sysRoute3", sysRoute3_oid, OID_LENGTH(sysRoute3_oid), ASN_OCTET_STR, HANDLER_CAN_RWRITE);
    add_sysScalar_params("sysRoute4", sysRoute4_oid, OID_LENGTH(sysRoute4_oid), ASN_OCTET_STR, HANDLER_CAN_RWRITE);
    add_sysScalar_params("eventLocation", eventLocation_oid, OID_LENGTH(eventLocation_oid), ASN_OCTET_STR, HANDLER_CAN_RONLY);
    add_sysScalar_params("sysFactoryDefaults", sysFactoryDefaults_oid, OID_LENGTH(sysFactoryDefaults_oid), ASN_OCTET_STR, HANDLER_CAN_RWRITE);

    stControlScalars* pParam = find_sysScalar_parameter_struct("sysSnmpVersion");
    if(!pParam)
        return;    
    pParam->value.value.string.ptr = (byte*)realloc(pParam->value.value.string.ptr, strlen("v2c"));
    memcpy(pParam->value.value.string.ptr, "v2c", strlen("v2c"));
    pParam->value.value.string.len = strlen("v2c");

    pParam = find_sysScalar_parameter_struct("eventLocation");
    if(!pParam)
        return;    
    pParam->value.value.string.ptr = (byte*)realloc(pParam->value.value.string.ptr, 4);
    memset(pParam->value.value.string.ptr, 0, 4);

    pParam = find_sysScalar_parameter_struct("sysFactoryDefaults");
    if(!pParam)
        return;    
    pParam->value.value.string.ptr = (byte*)realloc(pParam->value.value.string.ptr, 1);
    memset(pParam->value.value.string.ptr, 0, 1);

}


long    wdm_send_v2Trap(netsnmp_variable_list * vars);

        
int handle_sysName(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests)
{
    char buffer[200];
    int val;

    //check for req info
    switch (reqinfo->mode)
    {
        case MODE_GET:
            log_message("wdmagent_token", "handle_sysName scalar handler MODE_GET");
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (u_char*)sysName, strlen(sysName));
            break;
            
        case MODE_GETNEXT:
            break;

        case MODE_SET_RESERVE1:
            log_message("wdmagent_token", "scalar handler MODE_SET_RESERVE1");
            break;

        case MODE_SET_RESERVE2:
            log_message("wdmagent_token", "scalar handler MODE_SET_RESERVE2");
            break;

        case MODE_SET_ACTION:
            log_message("wdmagent_token", "scalar handler MODE_SET_ACTION");
            memcpy(sysName, requests->requestvb->val.string, requests->requestvb->val_len);
            sysName[requests->requestvb->val_len] = 0;
            break;

        case MODE_SET_UNDO:
            log_message("wdmagent_token", "scalar handler MODE_SET_UNDO");
            break;

        case MODE_SET_COMMIT:
            log_message("wdmagent_token", "scalar handler MODE_SET_COMMIT");
            break;

        case MODE_SET_FREE:
            log_message("wdmagent_token", "scalar handler MODE_SET_FREE");
            break;

        default:
            log_message("wdmagent_token", "scalar handler unknown(%d) ", reqinfo->mode);
            break;

    }
    return SNMP_ERR_NOERROR;
}



int my_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests)
{
    char buffer[200];
    int val;

    //check for req info
    switch (reqinfo->mode)
    {
        case MODE_GET:
            log_message("wdmagent_token", "scalar handler MODE_GET");
        case MODE_GETNEXT:
            if (reqinfo->mode == MODE_GETNEXT)
                log_message("wdmagent_token", "scalar handler MODE_GETNEXT");
            sprintf(buffer, "get value ");
            log_message("wdmagent_token", "msdg->%s", buffer);
            //  put_message_to_snd_queue(buffer, strlen(buffer));
            //	*(requests->requestvb->val.integer) = 5;
            /*
                    snmp_set_var_typed_value(cache->requests->requestvb,
                                             ASN_INTEGER,
                                             (u_char *) & delay_time,
                                             sizeof(delay_time));*/
            break;

        case MODE_SET_RESERVE1:
            log_message("wdmagent_token", "scalar handler MODE_SET_RESERVE1");
            if (requests->requestvb->type != ASN_INTEGER)
            {
                /*
                 * not an integer.  Bad dog, no bone. 
                 */
                netsnmp_set_request_error(reqinfo, requests,
                        SNMP_ERR_WRONGTYPE);
                /*
                 * we don't need the cache any longer 
                 */
                return 0;
            }
            break;

        case MODE_SET_RESERVE2:
            log_message("wdmagent_token", "scalar handler MODE_SET_RESERVE2");
            break;

        case MODE_SET_ACTION:
            log_message("wdmagent_token", "scalar handler MODE_SET_ACTION");
            val = *(requests->requestvb->val.integer);
            sprintf(buffer, "set value %d", val);
            log_message("wdmagent_token", "msdg->%s", buffer);
            //   put_message_to_snd_queue(buffer, strlen(buffer));
            break;

        case MODE_SET_UNDO:
            log_message("wdmagent_token", "scalar handler MODE_SET_UNDO");
            break;

        case MODE_SET_COMMIT:
            log_message("wdmagent_token", "scalar handler MODE_SET_COMMIT");
            break;

        case MODE_SET_FREE:
            log_message("wdmagent_token", "scalar handler MODE_SET_FREE");
            break;

        default:
            log_message("wdmagent_token", "scalar handler unknown(%d) ", reqinfo->mode);
            break;

    }
    return 0;
}

int handle_sysDateTime(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests)
{
    switch (reqinfo->mode)
    {
        case MODE_GET:
            log_message("wdmagent_token", "handle_controlCard MODE_GET %s", reginfo->handlerName);
            snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (u_char*)sysDateTime, 11);
            break;
            
        case MODE_GETNEXT:
            break;

        case MODE_SET_ACTION:
            log_message("wdmagent_token", "sysDateTime handler MODE_SET_ACTION %d", requests->requestvb->val_len);
            if(requests->requestvb->val_len != 11)
                return SNMP_ERR_NOERROR;
            memcpy(sysDateTime, requests->requestvb->val.string, requests->requestvb->val_len);
            set_datetime_in_control_card(sysDateTime, 11);
            break;

        default:
            log_message("wdmagent_token", "scalar handler unknown(%d) ", reqinfo->mode);
            break;

    }
    return SNMP_ERR_NOERROR;
}

void    set_trap_destinations()
{
    //delete all trap destinations
    int val = system("sed -i \"/informsink/d\" /usr/local/share/snmp/snmpd.conf "); 
    if(val == -1)
        return;

    //set trap destinations
    byte i;
    char    buffer[100];
    char    val1[50];
    for(i = 0; i < nSysCalars; i++)
    {
        if(strstr(sysScalars[i].name, "sysTrapDestination"))
        {
            if(sysScalars[i].value.value.string.len)
            {
                if(memcmp(sysScalars[i].value.value.string.ptr, "null", 4))
                {
                    memcpy(val1, sysScalars[i].value.value.string.ptr, sysScalars[i].value.value.string.len);
                    val1[sysScalars[i].value.value.string.len] = 0;
                    if(val1[0] != 0)
                    {
                        sprintf(buffer ,"sed -i \"/rwcommunity / a informsink %s\" /usr/local/share/snmp/snmpd.conf ", val1);
                        int val = system(buffer);
                        if(val == -1)
                            break;
                    }
                }
            }
        }
    }
}

void    init_ip_address_and_routes()
{
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    byte i = 0;

    stream = fopen("/etc/network/interfaces", "r");
    if (stream == NULL)
        return;
    char*   pch;
    byte state = 0;
    char    address[30] = "";
    char    cidrStr[10] = "";
    byte    rtcntr = 0;

    while((nread = getline(&line, &len, stream)) != -1)
    {
        if(state == 0)
        {
            if(strstr(line, "eth0:0") && strstr(line, "iface"))
                state = 1;
        }        
        else if(state == 1)
        {
            if(strstr(line, "address"))
            {
                pch = strtok(line, " \t\n");
                if(!pch)
                    break;
                pch = strtok(NULL, " \t\n");
                if(!pch)
                    break;
                strcpy(address, pch);
                state = 2;
            }
        }
        else if(state == 2)
        {
            if(strstr(line, "netmask"))
            {
                pch = strtok(line, " \t\n");
                if(!pch)
                    break;
                pch = strtok(NULL, " \t\n");
                if(!pch)
                    break;
                char    netmask[20];
                strcpy(netmask, pch);
                pch = strtok(netmask, ".");
                if(!pch)
                    break;
                int netmaskint = (atoi(pch) << 24);
                pch = strtok(NULL, ".");
                if(!pch)
                    break;
                netmaskint |= (atoi(pch) << 16);
                pch = strtok(NULL, ".");
                if(!pch)
                    break;
                netmaskint |= (atoi(pch) << 8);
                pch = strtok(NULL, ".");
                if(!pch)
                    break;
                netmaskint |= atoi(pch);
                byte    cidr = 0;
                for (byte i = 0; i < 32; i++)
                    if (netmaskint & (1 << i))
                        cidr++;
                sprintf(cidrStr, "%d", cidr);
                state = 3;
            }
        }
        else
        {
            if(strstr(line, "up route add"))
            {
                char*   str1 = strstr(line, "-net ");
                if(!str1)
                    continue;
                str1 = str1 + strlen("-net ");
                pch = strtok(str1, " ");//address
                if(!pch)
                    continue;
                char    addr1[20];
                strcpy(addr1, pch);
                pch = strtok(NULL, " ");//gw
                if(!pch)
                    continue;
                pch = strtok(NULL, " ");//gw
                if(!pch)
                    continue;
                char    gw[20];
                strcpy(gw, pch);
                
                char    str2[100];
                sprintf(str2, "sysRoute%d", rtcntr+1);
                stControlScalars* pParam = find_sysScalar_parameter_struct(str2);
                if(!pParam)
                    continue; 
                sprintf(str2, "%s,%s", addr1, gw);
                pParam->value.value.string.ptr = (byte*)realloc(pParam->value.value.string.ptr, strlen(str2));
                memcpy(pParam->value.value.string.ptr, str2, strlen(str2));
                pParam->value.value.string.len = strlen(str2);
                rtcntr++;
                 if(rtcntr >= 4)
                     break;
            }
        }
    }
    if(line)
        free(line);
    fclose(stream);
    
    if (address[0] != 0 && cidrStr[0] != 0)
    {
        char    address_cidr[50];
        sprintf(address_cidr, "%s/%s", address, cidrStr);
        stControlScalars* pParam = find_sysScalar_parameter_struct("sysIPAddress");
        if(!pParam)
            return; 
        pParam->value.value.string.ptr = (byte*)realloc(pParam->value.value.string.ptr, strlen(address_cidr));
        memcpy(pParam->value.value.string.ptr, address_cidr, strlen(address_cidr));
        pParam->value.value.string.len = strlen(address_cidr);
    }
}

void    set_sys_ipaddress(byte* value, word len)
{
    char    ipaddr[50];
    memcpy(ipaddr, value, len);
    ipaddr[len] = 0;

    char*   pch;
    pch = strtok(ipaddr, "/"); //address
    if(!pch)
        return;
    char*   pch1 = strtok(NULL, "/"); //netmask
    if(!pch1)
        return;
    int netVal = atoi(pch1);
    dword netmaskInt = 0;
//    for(byte i = 0; i < netVal; i++)
//        netmaskInt |= (1 << i);
    if(netVal >= 31)
        return;
    
    for(byte i = 31; i > 31 - netVal; i--)
    {
        
        netmaskInt |= (1 << i);
    }
//    netmaskInt = ~netmaskInt;
    char    netmaskStr[20];
    sprintf(netmaskStr, "%d.%d.%d.%d",  ((netmaskInt >> 24) & 0xFF), ((netmaskInt >> 16) & 0xFF),
                        ((netmaskInt >> 8) & 0xFF), (netmaskInt & 0xFF));
    
    char    buffer[200];
    //delete current address  and netmask
    int val = system("sed -i '/iface eth0:0/{\nN\nN\ns/\\n.*\\n.*//}' /etc/network/interfaces "); 
    if(val == -1)
        return;

    sprintf(buffer ,"sed -i '/iface eth0:0 / a netmask %s' /etc/network/interfaces ", netmaskStr);
    val = system(buffer);
    if(val == -1)
        return;

    sprintf(buffer ,"sed -i '/iface eth0:0 / a address %s' /etc/network/interfaces ", pch);
    val = system(buffer);
    if(val == -1)
        return;
    
}

void    set_sys_routes()
{
    //delete all routes
    int val = system("sed -i \"/up route add/d\" /etc/network/interfaces "); 
    if(val == -1)
        return;
    //set trap destinations
    byte i;
    char    buffer[100];
    char    val1[50];
    for(i = 0; i < nSysCalars; i++)
    {
        if(strstr(sysScalars[i].name, "sysRoute"))
        {
            if(sysScalars[i].value.value.string.len)
            {
                if(memcmp(sysScalars[i].value.value.string.ptr, "null", 4))
                {
                    memcpy(val1, sysScalars[i].value.value.string.ptr, sysScalars[i].value.value.string.len);
                    val1[sysScalars[i].value.value.string.len] = 0;
                    if(val1[0] != 0)
                    {
                        char*   pch;
                        pch = strtok(val1, ","); //address
                        if(!pch)
                            return;
                        char*   pch1 = strtok(NULL, ","); //gw
                        if(!pch1)
                            return;
                        sprintf(buffer ,"sed -i \"\\$a up route add -net %s gw %s dev eth0:0\" /etc/network/interfaces ", pch, pch1);
                        int val = system(buffer);
                        if(val == -1)
                            break;
                    }
                }
            }
        }
    }
 }

void    reset_to_factory_defaults()
{
    char tmp[100];
    char    buffer[200];
    int val;
    //remove txdisable and delete passives (all persistent data)
//     sed "/^\[persistentData\]/,/^\[/{//! d;};" wdmDB.cfg
    sprintf(buffer, "sed -i \"/^\\[persistentData\\]/,/^\\[/{//! d;};\" /usr/local/share/snmp/wdmDB.cfg");
    val = system(buffer);
    if(val == -1)
        return;    
    
    //reset default card plug severities
    sprintf(buffer, "sed -i \"/^\\[cardPlugSeverity\\]/,/^\\[/{//! d;};\" /usr/local/share/snmp/wdmDB.cfg");
    val = system(buffer);
    if(val == -1)
        return;    
    
    byte shelf = give_ownShelfNumber();
    for(byte slot = 0; slot < 32; slot++)
    {
        if(slot < 16)
        {
            if(slot == 0)
                sprintf(buffer, "sed -i '/cardPlugSeverity/ a %d,%d=%d,%d,%d,%d,%d'  /usr/local/share/snmp/wdmDB.cfg", shelf, slot+1, 0, 4, 4, 4, 4);
            else
                sprintf(buffer, "sed -i '/cardPlugSeverity/ a %d,%d=%d,%d,%d,%d,%d'  /usr/local/share/snmp/wdmDB.cfg", shelf, slot+1, 4, 4, 4, 4, 4);
        }
        else
            sprintf(buffer, "sed -i '/cardPlugSeverity/ a %d,%d=%d,%d,%d,%d,%d'  /usr/local/share/snmp/wdmDB.cfg", shelf, slot+1, 0, 0, 0, 0, 0);
        val = system(buffer);
        if(val == -1)
            return;    
    }
    
    byte    defDef[50];
    //{LA, LW, HA, HW}
    byte modTempDef[]={1, 1, 4, 3};
    byte modRXPwrDef[]={4, 3, 4, 3};
    byte modTXBiasDef[]={4, 2, 4, 2};
    byte modTXPwrDef[]={4, 3, 4, 3};
    byte modLOSDef=4;
    byte modLSDef=3;
    byte modTXFltDef=2;
    
    memcpy(&defDef[0], modTempDef, 4);
    memcpy(&defDef[4], modRXPwrDef, 4);
    memcpy(&defDef[8], modTXBiasDef, 4);
    memcpy(&defDef[12], modTXPwrDef, 4);
    defDef[16] = modLOSDef;
    defDef[17] = modLSDef;
    defDef[18] = modTXFltDef;
    write_default_severity(shelf, (byte*)defDef, "shelfDefSfpSeverity");
    write_default_severity(shelf, (byte*)defDef, "shelfDefXfpSeverity");
    
    //remove log file enables
    sprintf(buffer, "sed -i 's/\\(logEnable:\\).*/\\10/' /usr/local/share/snmp/wdmconfig.cfg");
    val = system(buffer);
    

    //remove all log files
    sprintf(buffer, "sudo rm -r /var/log/wdmsnmp/*");
    val = system(buffer);
    
    //remove all log files
    sprintf(buffer, "sudo rm /var/log/snmpd*");
    val = system(buffer);
    
    //delete all notifications from mysql
}

void    process_special_jobs_for_scalars(byte* value, word  len, byte* param)
{
    char*   tmp = (char*)malloc(len + 1);
    memcpy(tmp, value, len);
    tmp[len] = 0;
    if(!strcmp(param, "sysSnmproCommunity"))
    {
        char    buffer[100];
        sprintf(buffer ,"sed -i -e  \"s/\\(rocommunity \\).*/\\1%s/\" /usr/local/share/snmp/snmpd.conf ", tmp);
        int val = system(buffer);
        if(val == -1)
        {
            free(tmp);
            return;
        }
    }    
    else if(!strcmp(param, "sysSnmprwCommunity"))
    {
        char    buffer[100];
        sprintf(buffer ,"sed -i -e  \"s/\\(rwcommunity \\).*/\\1%s/\" /usr/local/share/snmp/snmpd.conf ", tmp);
        int val = system(buffer);
        if(val == -1)
        {
            free(tmp);
            return;
        }
    }    
    else if(!strcmp(param, "sysFactoryDefaults"))
    {
        if(len == 1 && tmp[0] == 1)
            reset_to_factory_defaults();
    }    
    else if(strstr(param, "sysTrapDestination"))
    {
        set_trap_destinations();
    }
    else if(!strcmp(param, "sysIPAddress"))
    {
        set_sys_ipaddress(value, len);
    }
    else if(strstr(param, "sysRoute"))
    {
        set_sys_routes();
    }    
    free(tmp);
}

void    process_snmpset_sysScalars_request(netsnmp_request_info *requests, char*  paramName)
{
    stControlScalars* pParam = find_sysScalar_parameter_struct(paramName);
    if(!pParam)
        return;
    if(requests->requestvb->type == ASN_OCTET_STR)
       if(requests->requestvb->val_len)
           if(pParam->value.Type == ASN_OCTET_STR)
           {
               pParam->value.value.string.ptr = (byte*)realloc(pParam->value.value.string.ptr, requests->requestvb->val_len);
               memcpy(pParam->value.value.string.ptr, requests->requestvb->val.string, requests->requestvb->val_len);
               pParam->value.value.string.len = requests->requestvb->val_len;
               
               process_special_jobs_for_scalars(pParam->value.value.string.ptr, requests->requestvb->val_len, paramName);
           }
}

void    process_snmpget_sysScalars_request(netsnmp_request_info *requests, char*  paramName)
{
    stControlScalars* pParam = find_sysScalar_parameter_struct(paramName);
    if(!pParam)
        return;
    if(pParam->value.Type == ASN_OCTET_STR)
       if(pParam->value.value.string.len)
            snmp_set_var_typed_value(requests->requestvb, pParam->value.Type, (u_char*)pParam->value.value.string.ptr, pParam->value.value.string.len);
}

int handle_sysScalars(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests)
{
    switch (reqinfo->mode)
    {
        case MODE_GET:
            log_message("wdmagent_token", "handle_controlCard MODE_GET %s", reginfo->handlerName);
            process_snmpget_sysScalars_request(requests, reginfo->handlerName);
            break;
            
        case MODE_GETNEXT:
            break;

        case MODE_SET_ACTION:
            log_message("wdmagent_token", "scalar handler MODE_SET_ACTION");
            process_snmpset_sysScalars_request(requests, reginfo->handlerName);
            break;

        default:
            log_message("wdmagent_token", "scalar handler unknown(%d) ", reqinfo->mode);
            break;

    }
    return SNMP_ERR_NOERROR;
}

void    init_trapDestinations()
{
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    byte i = 0;

    stream = fopen("/usr/local/share/snmp/snmpd.conf", "r");
    if (stream == NULL)
        return;
    char*   pch;
    while((nread = getline(&line, &len, stream)) != -1)
    {
        pch = strtok(line, " ");
        if(!pch)
            continue;
        char name[200], value[200], ii[10], trap1str[100];
        strcpy(name, pch);
        if(!strcmp(name, "informsink"))
        {
            pch = strtok(NULL, " \n");
            if(!pch)
                continue;
            sprintf(trap1str, "sysTrapDestination%d", i+1);
            stControlScalars* pParam = find_sysScalar_parameter_struct(trap1str);
            if(!pParam)
                break;    
            pParam->value.value.string.ptr = (byte*)realloc(pParam->value.value.string.ptr, strlen(pch));
            memcpy(pParam->value.value.string.ptr, pch, strlen(pch));
            pParam->value.value.string.len = strlen(pch);
            i++;
             if(i >= 4)
                 break;
        }
    }
    if(line)
        free(line);
    fclose(stream);
}

void    init_communities()
{
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    byte i = 0;

    stream = fopen("/usr/local/share/snmp/snmpd.conf", "r");
    if (stream == NULL)
        return;
    char*   pch;
    while((nread = getline(&line, &len, stream)) != -1)
    {
        pch = strtok(line, " ");
        if(!pch)
            continue;
        char name[200], value[200];
        strcpy(name, pch);
        if(!strcmp(name, "rocommunity"))
        {
            pch = strtok(NULL, " \n");
            if(!pch)
                continue;
//            strcpy(wdmrocommunity, pch);   
            stControlScalars* pParam = find_sysScalar_parameter_struct("sysSnmproCommunity");
            if(!pParam)
                break;    
            pParam->value.value.string.ptr = (byte*)realloc(pParam->value.value.string.ptr, strlen(pch));
            memcpy(pParam->value.value.string.ptr, pch, strlen(pch));
            pParam->value.value.string.len = strlen(pch);
            i++;
            if(i >= 2)
                break;
        }
        else if(!strcmp(name, "rwcommunity"))
        {
            pch = strtok(NULL, " \n");
            if(!pch)
                continue;
//            strcpy(wdmrwcommunity, pch);   
            stControlScalars* pParam = find_sysScalar_parameter_struct("sysSnmprwCommunity");
            if(!pParam)
                break;    
            pParam->value.value.string.ptr = (byte*)realloc(pParam->value.value.string.ptr, strlen(pch));
            memcpy(pParam->value.value.string.ptr, pch, strlen(pch));
            pParam->value.value.string.len = strlen(pch);
            i++;
            if(i >= 2)
                break;
        }
    }
    if(line)
        free(line);
    fclose(stream);
}

    
void init_wdmagent(void)
{
    log_message("wdmagent_token", "Initializing wdmagent scalars ");
//    netsnmp_register_long_instance("my example int variable", scalar_oid, OID_LENGTH(scalar_oid), &Test, &my_handler);
//    netsnmp_register_instance(netsnmp_create_handler_registration("sysNameScalar", handle_sysName,
//                             sysName_oid,OID_LENGTH(sysName_oid),HANDLER_CAN_RWRITE));
    netsnmp_register_instance(netsnmp_create_handler_registration("sysDateTime", handle_sysDateTime,
                           sysDateTime_oid, OID_LENGTH(sysDateTime_oid), HANDLER_CAN_RWRITE));
    
    log_message("wdmagent_token", "Initialized wdmagent scalars");
/*
    int version = netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_SNMPVERSION);
    version = NETSNMP_DS_SNMP_VERSION_2c;
    strcpy(wdmsnmpversion, "invalid");
    if(version == NETSNMP_DS_SNMP_VERSION_1)
        strcpy(wdmsnmpversion, "v1");
    else if(version == NETSNMP_DS_SNMP_VERSION_2c)
        strcpy(wdmsnmpversion, "v2c");
    else if(version == NETSNMP_DS_SNMP_VERSION_3)
        strcpy(wdmsnmpversion, "v3");
*/
    
    init_sysScalar_params();
    init_communities();
    init_trapDestinations();
    init_ip_address_and_routes();
    

    for(byte i = 0; i < nSysCalars; i++)
    {
        netsnmp_register_instance(netsnmp_create_handler_registration(sysScalars[i].name, handle_sysScalars,
                               sysScalars[i].scalar_oid, sysScalars[i].oid_len, sysScalars[i].access));
        
    }
    
    netsnmp_table_data_set *table_set;

    //////////////////////////////////////////////////	trapTable//////////////////
    table_set = netsnmp_create_table_data_set("wdmTrapTable");
    table_set->allow_creation = 1;
    netsnmp_table_dataset_add_index(table_set, ASN_INTEGER); //shelfIndex
    netsnmp_table_dataset_add_index(table_set, ASN_INTEGER); //rowNumber
    netsnmp_table_set_multi_add_default_row(table_set,
            3, ASN_INTEGER, 0, NULL, 0, //trap id
            4, ASN_OCTET_STR, 0, NULL, 0, //varbind
            5, ASN_INTEGER, 1, NULL, 0, //trapRowStatus
            0);
    netsnmp_register_table_data_set(netsnmp_create_handler_registration("wdmTrapTable", NULL, trapTable_oid, OID_LENGTH(trapTable_oid), HANDLER_CAN_RWRITE), table_set, NULL);
    netsnmp_register_auto_data_table(table_set, NULL);
    wdmTrapTable = table_set;
    ///////////////////////////////////////////
/*
    struct timeval t1;
    t1.tv_sec = 1;
    t1.tv_usec = 0;
    snmp_alarm_register_hr(t1, SA_REPEAT, one_sec_timer, NULL);
//    snmp_alarm_register_hr(t1, SA_REPEAT, one_sec_timer2, NULL);
*/
 /*   
    struct timeval t1;
    t1.tv_sec = 0;
    t1.tv_usec = 100000;
    snmp_alarm_register_hr(t1, SA_REPEAT, hundred_msec_timer, NULL);

    
*/
    snmp_alarm_register(1, SA_REPEAT, one_sec_timer, NULL);
    
    gettimeofday(&startTime, NULL);

    
    struct mq_attr attr;

    /* initialize the queue attributes */
    attr.mq_flags = 0;
    attr.mq_maxmsg = 50;
    attr.mq_msgsize = MAX_SIZE;
    attr.mq_curmsgs = 0;
/*
    trapSendingQueue = mq_open(TRAP_SENDING_QUEUE_NAME, O_RDWR | O_CREAT, 0644, &attr);
    CHECK((mqd_t) - 1 != trapSendingQueue);*/
    
    pthread_mutex_init(&trapSendingQmutex, NULL);
    pthread_mutex_init(&unackedTrapQmutex, NULL);
    pthread_mutex_init(&sendingTrapQmutex, NULL);

    pthread_t   thread_id1;
    pthread_create (&thread_id1, NULL, &log_message_thread, NULL);
    log_thread_id("init_wdmagent", 0);
}


void    log_thread_id(char*  str, byte p1)
{
    FILE* fp = fopen("/var/log/wdmsnmp/threads.txt", "a+");
    if(fp)
    {
        fprintf(fp, "log_thread_id %s, %d, (%ld) \n", str, p1, gettid());
        fclose(fp);
    }
}

void*    log_message_thread(void* param)
{
    log_thread_id("log_message_thread", 0);
    while (1) 
    {
        log_message_from_queue();
        nsleep(100);
    }
}

byte check_for_agent_status()
{
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    stream = fopen("/var/log/snmpd.log", "r");
    if (stream == NULL)
        return FALSE;
    while ((nread = getline(&line, &len, stream)) != -1)
    {
        if (strstr(line, "NET-SNMP version"))
        {
            if (line)
                free(line);
            fclose(stream);
            return TRUE;
        }
    }
    if (line)
        free(line);
    fclose(stream);
    return FALSE;
}

static int notification_sent(int majorID, int minorID, void *serverarg, void *clientarg)
{
    netsnmp_pdu    *template_pdu = (netsnmp_pdu *) serverarg;
    
    //check if template_pdu->variables found in unacked list 
    //then insert req id to unacked list
    
    return 0;
}

void agent_started()
{
//    snmp_register_callback(SNMP_CALLBACK_APPLICATION, SNMPD_CALLBACK_SEND_TRAP2, notification_sent, NULL);
    
    check_log_flag();
    
    if(!wdmcard_started())
        return;
    
    wdmsocket_agent_started();
    
    pthread_t thread_id1;
    pthread_create (&thread_id1, NULL, &process_trap_sending_messages, NULL);
    pthread_create (&thread_id1, NULL, &process_unacked_trap_messages, NULL);
}

void agentAddress_changed(byte newAddress)
{
    send_new_agentAddress_to_cards(newAddress);
}

void check_agent_address()
{
    static word counter = 0;
    if(counter++ < 5 * 60)
        return;
    counter = 0;
    
    static byte agentAddress = 0;
    struct in_addr **addr_list;
    struct hostent* hp = gethostbyname("localhost");
    if (!hp)
        return;
    byte addr[4];

    addr_list = (struct in_addr **) hp->h_addr_list;
    byte i;
    for (i = 0; addr_list[i] != NULL; i++)
    {
        char * pch;
        pch = strtok(inet_ntoa(*(struct in_addr*) addr_list[i]), ".");
        byte I = 0;
        while (pch != NULL)
        {
            addr[I] = atoi(pch);
            pch = strtok(NULL, ".");
            I++;
        }
        if (addr[0] != 10 || addr[1] != 1 || addr[2] != 60)
            continue;
        if (agentAddress != addr[3])
        {
            agentAddress_changed(addr[3]);
            agentAddress = addr[3];
        }
    }
}

void one_sec_timer2(unsigned int clientreg, void *clientarg)
{
/*    char buffer[MAX_SIZE + 1];
    if (get_message_from_trap_sending_queue(buffer, 0)) 
    {
        netsnmp_variable_list *vars;
        int   ptr;

        memcpy(&ptr, buffer, sizeof(int));

        vars = (netsnmp_variable_list *)ptr;

       // memcpy(&vars, buffer, sizeof(void*));
       // ptr = *(void*)&buffer[0];

        log_message("wdmagent_token", "in get message trap sending  %x ", vars);
//            = *(netsnmp_variable_list *)buffer;
        if(vars)
        {
            nsleep(1000);
            send_v2trap(vars);
            snmp_free_varbind(vars);
        }
    }*/
}

void    check_log_flag()
{
    FILE *stream;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    byte i;

    stream = fopen("/usr/local/share/snmp/wdmconfig.cfg", "r");
    if (stream == NULL)
        return;
    char*   pch;
//    line = (char*) malloc(500);
    char name[50], value[500];
    
    while((nread = getline(&line, &len, stream)) != -1)
    {
        pch = strtok(line, ":,\n");
        if(!pch)
            break;
        strcpy(name, pch);
        pch = strtok(NULL, ":,\n");
        if(!pch)
            break;
        strcpy(value, pch);
        char* ptmp = strstr(name, "logEnable");
        if(ptmp == (char*)name)
        {
            logEnable = atoi(value);
            if(logEnable == 0)
                break;
            nLogTokens = 0;
            pch = strtok(NULL, ":,\n");
            while(pch)
            {
                strcpy(logTokens[nLogTokens++], pch);
                pch = strtok(NULL, ":,\n");
            }
            break;
        }
    }
//    if(line)
//        free(line);
    fclose(stream);
}

void    update_log_file(char* curFile, char    *oldFile)
{
    char    buffer[100];
    sprintf(buffer ,"sudo tar -cvzf %s.tar.gz  %s", oldFile, curFile);
    int val = system(buffer);
    if(val == -1)
        return;
/*
    sprintf(buffer ,"sudo rm %s", curFile);
    val = system(buffer);
    if(val == -1)
        return;*/
    
    
}

void    update_log_file1(char* curFile, char    *oldFile)
{
    char    buffer[100];
    

    sprintf(buffer ,"sudo mv %s %s.tmp", curFile, curFile);
    int val = system(buffer);
    if(val == -1)
        return;
    
    sprintf(buffer ,"sudo tar -cvzf %s.tar.gz  %s.tmp", oldFile, curFile);
    val = system(buffer);
    if(val == -1)
        return;
  
    sprintf(buffer ,"sudo rm %s.tmp", curFile);
    val = system(buffer);
    if(val == -1)
        return;    
}

void    check_to_clear_snmpdlog()
{
    static int secCounter = 0;
    static int minCounter = 0;
    
    if(secCounter++ > 60 )
    {
        time_t t;
        struct tm* t1;
        t = time(NULL);
        t1 = localtime(&t);
/*
        if(minCounter++ > 10 )
        {
            struct statvfs buffer;
            int ret = statvfs("/", &buffer);
            if (!ret) 
            {
                byte usedPercentage = ((buffer.f_blocks - buffer.f_bavail) * 100 / buffer.f_blocks);
                log_message("wdmagent_token", "disk usage : %i", usedPercentage);       
                if(usedPercentage > 85)
                {
                    //release file descriptors
                    if(logEnable)
                    {
                        deleteLogFile1 = TRUE;
                        deleteLogFile2 = TRUE;
                        deleteLogFile3 = TRUE;                
                    }
                }
            }
        }       
*/                
            char    fName[100];
            struct stat st;
            int expectedfilesize = 500;//1.5G
            
            if (stat("/var/log/snmpd.log", &st) == -1)
            {
                printf("failed to stat %s\n", "/var/log/snmpd.log");
            }
            if(st.st_size > (expectedfilesize * 1000 * 1000)) 
            {
                sprintf(fName, "/var/log/snmpd_%02d_%02d_%02d_%02d_%02d.log", t1->tm_mon + 1, 
                        t1->tm_mday, t1->tm_hour, t1->tm_min, t1->tm_sec);
                update_log_file1("/var/log/snmpd.log", fName);
            }

            if (stat("/var/log/wdmsnmp/snmpdlog.txt", &st) == -1)
            {
                printf("failed to stat %s\n", "/var/log/wdmsnmp/snmpdlog.txt");
            }
            if(st.st_size > (expectedfilesize * 1000 * 1000))
            {
                sprintf(fName, "/var/log/wdmsnmp/snmpdlog_%02d_%02d_%02d_%02d_%02d.txt", t1->tm_mon + 1, 
                        t1->tm_mday, t1->tm_hour, t1->tm_min, t1->tm_sec);
                
                update_log_file1("/var/log/wdmsnmp/snmpdlog.txt", fName);
                
//                update_log_file("/var/log/wdmsnmp/snmpdlog.txt", fName);
//                if(logEnable)
//                    deleteLogFile1 = TRUE;
            }

            if (stat("/var/log/wdmsnmp/card.txt", &st) == -1)
            {
                printf("failed to stat %s\n", "/var/log/wdmsnmp/card.txt");
            }
            if(st.st_size > (expectedfilesize * 1000 * 1000))
            {
                sprintf(fName, "/var/log/wdmsnmp/card_%02d_%02d_%02d_%02d_%02d.txt", t1->tm_mon + 1, 
                        t1->tm_mday, t1->tm_hour, t1->tm_min, t1->tm_sec);
                update_log_file1("/var/log/wdmsnmp/card.txt", fName);
//                if(logEnable)
//                    deleteLogFile2 = TRUE;
            }
            
            if (stat("/var/log/wdmsnmp/kp.txt", &st) == -1)
            {
                printf("failed to stat %s\n", "/var/log/wdmsnmp/kp.txt");
            }
            if(st.st_size > (expectedfilesize * 1000 * 1000))
            {
                sprintf(fName, "/var/log/wdmsnmp/kp_%02d_%02d_%02d_%02d_%02d.txt", t1->tm_mon + 1, 
                        t1->tm_mday, t1->tm_hour, t1->tm_min, t1->tm_sec);
                update_log_file1("/var/log/wdmsnmp/kp.txt", fName);
//                if(logEnable)
//                    deleteLogFile3 = TRUE;
            }
        secCounter = 0;
    }
}


void one_sec_timer(unsigned int clientreg, void *clientarg)
{
    static char counter1 = 1;
    static char counter2 = 1;
    
    checksnmpdCounter = 0;
    

//    log_message("wdmagent_token", "one_sec_timer %d", agentStarted);
    if (!agentStarted)
    {
        agentStarted = check_for_agent_status();
        if (agentStarted)
            agent_started();
    }

    //    log_message("wdmagent_token", "one sec %d", agentStarted);

    if (!agentStarted)
        return;
/*    
    if(counter1++ > 10)
    {
        check_log_flag();
        counter1 = 0;
    }*/
    update_sysdatetime();
    

//    check_agent_address();
    
    if(sendChangedDataTimeout)
    {
        sendChangedDataTimeout--;
        if(!sendChangedDataTimeout)
            sendChangedData = TRUE;
    }
    
//    check_to_clear_snmpdlog();
    
}

void    hundred_msec_timer(unsigned int clientreg, void *clientarg)
{
    static char counter3 = 0;
    if(++counter3 >= 10)
    {
        one_sec_timer(clientreg, clientarg);
        counter3 = 0;
    }
    
//    log_message_from_queue();
}


void trapTable_make_row(netsnmp_table_row *row, int shelf, int trapIndex, int Id, char*  varbind, int varlen, int RowStat)
{
    /*
    netsnmp_table_row_add_index(row, ASN_INTEGER, &shelf, sizeof (int));
    netsnmp_table_row_add_index(row, ASN_INTEGER, &trapIndex, sizeof (int));
    my_netsnmp_set_row_column(row, 3, ASN_INTEGER, &Id, sizeof(long));
    my_netsnmp_set_row_column(row, 4, ASN_OCTET_STR, varbind, varlen);
    my_netsnmp_set_row_column(row, 5, ASN_INTEGER, &RowStat, sizeof (RowStat));
    netsnmp_mark_row_column_writable(row, 5, 1);*/
}

void    make_and_send_card_notification(byte shelf, byte slot, byte ctype, byte notif, byte param, oid* notifOid, size_t notifOidLen, byte* notifCol, byte nNotifCols)
{
    int     valueInt;
    unsigned int    valueUint;
    char    valueChar[50];

    
    oid objid_snmptrap[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
    size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);
    netsnmp_variable_list *notification_vars = NULL;
    netsnmp_variable_list *returnVar = NULL;
    
    oid objid_sysuptime[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
    size_t objid_sysuptime_len = OID_LENGTH(objid_sysuptime);
    u_long sysuptime = netsnmp_get_agent_uptime();
//    sysuptime = get_uptime ();
    returnVar = snmp_varlist_add_variable(&notification_vars,
            objid_sysuptime, objid_sysuptime_len,
            ASN_TIMETICKS,
            (u_char*) &sysuptime,
            sizeof (sysuptime));
    if(!returnVar)
        return;

    returnVar = snmp_varlist_add_variable(&notification_vars,
            objid_snmptrap, objid_snmptrap_len,
            ASN_OBJECT_ID,
            (u_char *) notifOid,
            notifOidLen * sizeof (oid));
    if(!returnVar)
        return;
    
    netsnmp_table_row* row;
    size_t dataset_oid_len;
    size_t temp_oid_len;
    oid* temp_oid = NULL;
    oid* datasetOid;
    netsnmp_table_data_set_storage* ds= NULL;
    
    
    byte colIndex = 0;

    stIndexStructure s[2];
    s[0].type = ASN_INTEGER;
    s[0].value.Id = shelf;
    s[1].type = ASN_INTEGER;
    s[1].value.Id = slot;
    if(notif == NOTIF_CARD_MISMATCH_RAISE || notif == NOTIF_CARD_MISMATCH_RECOV)
    {
        give_shelftable_oid_len(&datasetOid, &dataset_oid_len);
        row = find_row_in_dataset(wdmShelfTable, s, 1);
    }
    else
    {
        give_cardtable_oid_len(&datasetOid, &dataset_oid_len);
        row = find_row_in_dataset(wdmCardTable, s, 2);
    }

    if (!row)
    {
        log_message("wdmagent_token", "in trap 91 row failed, %d, %d", shelf, slot);
        if(notification_vars)
            snmp_free_varbind(notification_vars);
        return;    
    }
    
    
    for (colIndex = 0; colIndex < nNotifCols; colIndex++)
    {
        char    *temp_value = NULL;
        byte    temp_value_len;
        temp_oid = NULL;

        temp_oid = (oid*) malloc((dataset_oid_len + 3 + row->index_oid_len) * sizeof (oid));
        memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));

        ds = (netsnmp_table_data_set_storage*) row->data;
        ds = netsnmp_table_data_set_find_column(ds, notifCol[colIndex]);
        if(!ds)
        {
            
            log_message("wdmagent_token", "in trap 90 ds failed, %d, %d", colIndex, notifCol[colIndex]);
            if(notification_vars)
                snmp_free_varbind(notification_vars);
            free(temp_oid);
            return;
        }
        temp_oid[dataset_oid_len] = 1; //entry
        temp_oid[dataset_oid_len + 1] = notifCol[colIndex];
        memcpy(&temp_oid[dataset_oid_len + 2], row->index_oid, row->index_oid_len * sizeof (oid));
        temp_oid_len = dataset_oid_len + 2 + row->index_oid_len;
        temp_oid[temp_oid_len] = 0;

        {
            char    oidstr[200];
            int len2 = snprint_objid(oidstr, 200, temp_oid , temp_oid_len);
            oidstr[len2] = 0;
            log_message("wdmagent_token", "make_and_send_card_notification 1 %s ", oidstr);
        }
       
        if(ds)
        {
            temp_value = (char*)malloc(50);
            if (ds->type == ASN_INTEGER)
            {
                valueInt = *ds->data.integer;
                returnVar = snmp_varlist_add_variable(&notification_vars,
                        temp_oid, temp_oid_len,
                        ASN_INTEGER,
                        (u_char*) &valueInt,
                        sizeof (valueInt));
                if(!returnVar)
                {
                    free(temp_oid);
                    free(temp_value);
                    return;
                }
                sprintf(temp_value, "%d", valueInt);
                temp_value_len = strlen(temp_value);
            }
            else if(ds->type == ASN_UNSIGNED)
            {
                valueUint = *ds->data.integer;
                returnVar = snmp_varlist_add_variable(&notification_vars,
                        temp_oid, temp_oid_len,
                        ASN_UNSIGNED,
                        (u_char*) &valueUint,
                        sizeof (valueUint));
                if(!returnVar)
                {
                    free(temp_oid);
                    free(temp_value);
                    return;
                }
                sprintf(temp_value, "%d", valueInt);
                temp_value_len = strlen(temp_value);
            }
            else if(ds->type == ASN_OCTET_STR)
            {
                memcpy(valueChar, ds->data.string, ds->data_len);
                returnVar = snmp_varlist_add_variable(&notification_vars,
                        temp_oid, temp_oid_len,
                        ASN_OCTET_STR,
                        (u_char*) valueChar,
                        ds->data_len);
                if(!returnVar)
                {
                    free(temp_oid);
                    free(temp_value);
                    return;
                }
                memcpy(temp_value, valueChar, ds->data_len);
                temp_value_len = ds->data_len;
            }
        }
        if(temp_value)
            free(temp_value);
        if(temp_oid)
            free(temp_oid);
    }
    
    if(notif == NOTIF_CARD_MISMATCH_RAISE || notif == NOTIF_CARD_MISMATCH_RECOV)
    {
        byte val[10];
        val[0] = shelf;
        val[1] = slot;
        size_t objid_len = OID_LENGTH(cardNumberMismatch_oid);
        returnVar = snmp_varlist_add_variable(&notification_vars,
                    cardNumberMismatch_oid, objid_len,
                    ASN_OCTET_STR,
                    val,
                    2);    
        if(!returnVar)
        {
            free(temp_oid);
            return;
        }
    }
    else
    {
        byte plugSev = 0;
        netsnmp_table_row*  row1 = find_row_in_dataset(wdmShelfTable, s, 1);
        if(row1)
        {
            ds = (netsnmp_table_data_set_storage*) row1->data;
            ds = netsnmp_table_data_set_find_column(ds, 40); //cardPlugseverity
            if(ds)
                plugSev = ds->data.string[slot - 1];
        }
        temp_oid = (oid*) malloc((dataset_oid_len + 3 + row->index_oid_len) * sizeof (oid));
        memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));
        temp_oid[dataset_oid_len] = 1; //entry
        temp_oid[dataset_oid_len + 1] = 18;//modplugseverity
        memcpy(&temp_oid[dataset_oid_len + 2], row->index_oid, row->index_oid_len * sizeof (oid));
        temp_oid_len = dataset_oid_len + 2 + row->index_oid_len;
        temp_oid[temp_oid_len] = 0;
        
        valueChar[0] = plugSev;
        
        returnVar = snmp_varlist_add_variable(&notification_vars,
                temp_oid, temp_oid_len,
                ASN_OCTET_STR,
                (u_char*) valueChar,
                1);
        free(temp_oid);
        if(!returnVar)
            return;
    }

    add_cardType_to_variable_bindings(shelf, slot, &notification_vars);
    add_eventLocatoin_to_variable_bindings(shelf, slot, 0, 0, &notification_vars);
    add_systemTime_to_variable_bindings(&notification_vars);

    if (notification_vars)
    {
        log_message("wdmagent_token", "in trap 8 %d", objid_snmptrap_len);
//        send_v2trap(notification_vars);
        wdm_send_and_save_v2Trap(notification_vars);
//        snmp_free_varbind(notification_vars);
    }
    
    return;
}

void ind_card_notification(byte shelf, byte slot, byte ctype, byte notif, byte param, byte enQueue)
{
    byte msg[10];
    int ptr = 0;
    msg[ptr++] = IND_CARD_NOTIF;
    msg[ptr++] = shelf;
    msg[ptr++] = slot;
    msg[ptr++] = ctype;
    msg[ptr++] = notif;
    msg[ptr++] = param;
    put_message_to_trap_sending_queue(msg, ptr, enQueue);
}

void process_card_notification(byte shelf, byte slot, byte ctype, byte notif, byte param)
{
/*    if(enQueue)
    {
        byte msg[10];
        int ptr = 0;
        msg[ptr++] = IND_CARD_NOTIF;
        msg[ptr++] = shelf;
        msg[ptr++] = slot;
        msg[ptr++] = ctype;
        msg[ptr++] = notif;
        msg[ptr++] = param;
        put_message_to_trap_sending_queue(msg, ptr);
        return;
    } */

    if (notif == NOTIF_CARD_ADDED)
    {
        byte notifCols[10];
        notifCols[0] = 3;
        notifCols[1] = 19;
        byte idx = 0;
        if(!give_card_mutex_index(shelf, slot, &idx))
            return;
#ifdef  THREAD_SAFE_ACCESS    
        pthread_mutex_lock(&cardmutex[idx]);
#endif  
        make_and_send_card_notification(shelf, slot, ctype, notif, param, cardUnPlugNotifRecov_oid, OID_LENGTH(cardUnPlugNotifRecov_oid), notifCols, 2);
#ifdef  THREAD_SAFE_ACCESS    
        pthread_mutex_unlock(&cardmutex[idx]);
#endif  
    }
    else if(notif == NOTIF_CARD_REMOVED)
    {
        byte notifCols[10];
        notifCols[0] = 3;
        notifCols[1] = 19;
        byte idx = 0;
        if(!give_card_mutex_index(shelf, slot, &idx))
            return;
#ifdef  THREAD_SAFE_ACCESS    
        pthread_mutex_lock(&cardmutex[idx]);
#endif  
        make_and_send_card_notification(shelf, slot, ctype, notif, param, cardUnPlugNotifRaise_oid, OID_LENGTH(cardUnPlugNotifRaise_oid), notifCols, 2);
#ifdef  THREAD_SAFE_ACCESS    
        pthread_mutex_unlock(&cardmutex[idx]);
#endif  
        delete_related_card_traps_from_queue(shelf, slot);
    }
    else if(notif == NOTIF_CARD_MISMATCH_RAISE)
    {
        byte notifCols[10];
        notifCols[0] = 40;
        make_and_send_card_notification(shelf, slot, ctype, notif, param, cardMismatchNotifRaise_oid, OID_LENGTH(cardMismatchNotifRaise_oid), notifCols, 1);
        delete_related_card_traps_from_queue(shelf, slot);
    }
    else if(notif == NOTIF_CARD_MISMATCH_RECOV)
    {
        byte notifCols[10];
        notifCols[0] = 40;
        make_and_send_card_notification(shelf, slot, ctype, notif, param, cardMismatchNotifRecov_oid, OID_LENGTH(cardMismatchNotifRecov_oid), notifCols, 1);
    }
}


void    make_and_send_switch_notification(byte shelf, byte slot, byte ctype, byte mtype, byte modno, byte param, oid* notifOid, size_t notifOidLen, byte* notifCol, byte nNotifCols)
{
    int     valueInt;
    unsigned int    valueUint;
    char    valueChar[50];
    char    *temp_value;
    byte    temp_value_len;
    
    stIndexStructure s[3];
    s[0].type = ASN_INTEGER;
    s[0].value.Id = shelf;
    s[1].type = ASN_INTEGER;
    s[1].value.Id = slot;
    s[2].type = ASN_INTEGER;
    s[2].value.Id = modno;

    netsnmp_table_row* row;
    size_t dataset_oid_len;
    oid* temp_oid = NULL;
    oid* datasetOid;
    if (ctype == SW2_CARD_TYPE || ctype == SW4_CARD_TYPE || ctype == SW2_4_CARD_TYPE)
    {
        give_switchtable_oid_len(&datasetOid, &dataset_oid_len);
        row = find_row_in_dataset(wdmOPSwitchTable, s, 3);
        if (!row)
            return;
        temp_oid = (oid*) malloc((dataset_oid_len + 3 + row->index_oid_len) * sizeof (oid));
        memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));
    } 
    else
        return;
    
    oid objid_snmptrap[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
    size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);
    
    netsnmp_table_data_set_storage* ds;
    byte alarmtype, alarmSeverity;
    alarmtype = ((param >> 7) & 0x01);
    alarmSeverity = param & 0x0F;
    
    netsnmp_variable_list *notification_vars = NULL;
    netsnmp_variable_list *returnVar = NULL;
    
    oid objid_sysuptime[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
    size_t objid_sysuptime_len = OID_LENGTH(objid_sysuptime);
    u_long sysuptime = netsnmp_get_agent_uptime();
//    sysuptime = get_uptime ();
    returnVar = snmp_varlist_add_variable(&notification_vars,
            objid_sysuptime, objid_sysuptime_len,
            ASN_TIMETICKS,
            (u_char*) &sysuptime,
            sizeof (sysuptime));
    if(!returnVar)
    {
        if(temp_oid)
            free(temp_oid);
        return;
    }
    
    returnVar = snmp_varlist_add_variable(&notification_vars,
            objid_snmptrap, objid_snmptrap_len,
            ASN_OBJECT_ID,
            (u_char *) notifOid,
            notifOidLen * sizeof (oid));
    if(!returnVar)
    {
        if(temp_oid)
            free(temp_oid);
        return;
    }

    ds = (netsnmp_table_data_set_storage*) row->data;
    byte colIndex = 0;
    for (colIndex = 0; colIndex < nNotifCols; colIndex++)
    {
        ds = (netsnmp_table_data_set_storage*) row->data;
        ds = netsnmp_table_data_set_find_column(ds, notifCol[colIndex]);
        if(!ds)
        {
            if(notification_vars)
                snmp_free_varbind(notification_vars);
            free(temp_oid);
            return;
        }
        temp_oid[dataset_oid_len] = 1; //entry
        temp_oid[dataset_oid_len + 1] = notifCol[colIndex];
        memcpy(&temp_oid[dataset_oid_len + 2], row->index_oid, row->index_oid_len * sizeof (oid));
        size_t temp_oid_len = dataset_oid_len + 2 + row->index_oid_len;
        temp_oid[temp_oid_len] = 0;

        {
            char    oidstr[200];
            int len2 = snprint_objid(oidstr, 200, temp_oid , temp_oid_len);
            oidstr[len2] = 0;
            log_message("wdmagent_token", "make_and_send_switch_notification 1 %s ", oidstr);
        }

        temp_value = (char*)malloc(50);
        if (ds->type == ASN_INTEGER)
        {
            valueInt = *ds->data.integer;
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_INTEGER,
                    (u_char*) &valueInt,
                    sizeof (valueInt));
            if(!returnVar)
            {
                free(temp_oid);
                free(temp_value);
                return;
            }
            sprintf(temp_value, "%d", valueInt);
            temp_value_len = strlen(temp_value);
        }
        else if(ds->type == ASN_UNSIGNED)
        {
            valueUint = *ds->data.integer;
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_UNSIGNED,
                    (u_char*) &valueUint,
                    sizeof (valueUint));
            if(!returnVar)
            {
                free(temp_oid);
                free(temp_value);
                return;
            }
            sprintf(temp_value, "%d", valueInt);
            temp_value_len = strlen(temp_value);
        }
        else if(ds->type == ASN_OCTET_STR)
        {
            memcpy(valueChar, ds->data.string, ds->data_len);
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_OCTET_STR,
                    (u_char*) valueChar,
                    ds->data_len);
            if(!returnVar)
            {
                free(temp_oid);
                free(temp_value);
                return;
            }
            memcpy(temp_value, valueChar, ds->data_len);
            temp_value_len = ds->data_len;
        }
        else
            snmp_free_varbind(notification_vars);
        free(temp_value);
    }

    add_cardType_to_variable_bindings(shelf, slot, &notification_vars);
    add_eventLocatoin_to_variable_bindings(shelf, slot, modno, 0, &notification_vars);
    add_systemTime_to_variable_bindings(&notification_vars);

    if (notification_vars)
    {
        log_message("wdmagent_token", "in trap 8 %d, %d", objid_snmptrap_len, OID_LENGTH(temp_oid));
        wdm_send_and_save_v2Trap(notification_vars);
    }
    free(temp_oid);
    
    return;
}


void    make_and_send_edfa_notification(byte shelf, byte slot, byte ctype, byte mtype, byte modno, byte param, oid* notifOid, size_t notifOidLen, byte* notifCol, byte nNotifCols)
{
    int     valueInt;
    unsigned int    valueUint;
    char    valueChar[50];
    char    *temp_value;
    byte    temp_value_len;
    
    stIndexStructure s[3];
    s[0].type = ASN_INTEGER;
    s[0].value.Id = shelf;
    s[1].type = ASN_INTEGER;
    s[1].value.Id = slot;
    s[2].type = ASN_INTEGER;
    s[2].value.Id = modno;

    netsnmp_table_row* row;
    size_t dataset_oid_len;
    oid* temp_oid = NULL;
    oid* datasetOid;
    if (ctype == EDFA_CARD_TYPE || ctype == EDFA2_CARD_TYPE)
    {
        give_edfatable_oid_len(&datasetOid, &dataset_oid_len);
        row = find_row_in_dataset(wdmEdfaModuleTable, s, 3);
        if (!row)
            return;
        temp_oid = (oid*) malloc((dataset_oid_len + 3 + row->index_oid_len) * sizeof (oid));
        memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));
    } 
    else
        return;
    
    oid objid_snmptrap[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
    size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);
    
    netsnmp_table_data_set_storage* ds;
    byte alarmtype, alarmSeverity;
    alarmtype = ((param >> 7) & 0x01);
    alarmSeverity = param & 0x0F;
    
    netsnmp_variable_list *notification_vars = NULL;
    netsnmp_variable_list *returnVar = NULL;
    
    oid objid_sysuptime[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
    size_t objid_sysuptime_len = OID_LENGTH(objid_sysuptime);
    u_long sysuptime = netsnmp_get_agent_uptime();
//    sysuptime = get_uptime ();
    returnVar = snmp_varlist_add_variable(&notification_vars,
            objid_sysuptime, objid_sysuptime_len,
            ASN_TIMETICKS,
            (u_char*) &sysuptime,
            sizeof (sysuptime));
    if(!returnVar)
    {
        if(temp_oid)
            free(temp_oid);
        return;
    }
    returnVar = snmp_varlist_add_variable(&notification_vars,
            objid_snmptrap, objid_snmptrap_len,
            ASN_OBJECT_ID,
            (u_char *) notifOid,
            notifOidLen * sizeof (oid));
    if(!returnVar)
    {
        if(temp_oid)
            free(temp_oid);
        return;
    }
    

    ds = (netsnmp_table_data_set_storage*) row->data;
    byte colIndex = 0;
    for (colIndex = 0; colIndex < nNotifCols; colIndex++)
    {
        ds = (netsnmp_table_data_set_storage*) row->data;
        ds = netsnmp_table_data_set_find_column(ds, notifCol[colIndex]);
        if(!ds)
        {
            if(notification_vars)
                snmp_free_varbind(notification_vars);
            free(temp_oid);
            return;
        }
        temp_oid[dataset_oid_len] = 1; //entry
        temp_oid[dataset_oid_len + 1] = notifCol[colIndex];
        memcpy(&temp_oid[dataset_oid_len + 2], row->index_oid, row->index_oid_len * sizeof (oid));
        size_t temp_oid_len = dataset_oid_len + 2 + row->index_oid_len;
        temp_oid[temp_oid_len] = 0;

        {
            char    oidstr[200];
            int len2 = snprint_objid(oidstr, 200, temp_oid , temp_oid_len);
            oidstr[len2] = 0;
            log_message("wdmagent_token", "make_and_send_edfa_notification 1 %s ", oidstr);
        }

        temp_value = (char*)malloc(50);
        if (ds->type == ASN_INTEGER)
        {
            valueInt = *ds->data.integer;
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_INTEGER,
                    (u_char*) &valueInt,
                    sizeof (valueInt));
            if(!returnVar)
            {
                free(temp_oid);
                free(temp_value);
                return;
            }
            sprintf(temp_value, "%d", valueInt);
            temp_value_len = strlen(temp_value);
        }
        else if(ds->type == ASN_UNSIGNED)
        {
            valueUint = *ds->data.integer;
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_UNSIGNED,
                    (u_char*) &valueUint,
                    sizeof (valueUint));
            if(!returnVar)
            {
                free(temp_oid);
                free(temp_value);
                return;
            }
            sprintf(temp_value, "%d", valueInt);
            temp_value_len = strlen(temp_value);
        }
        else if(ds->type == ASN_OCTET_STR)
        {
            memcpy(valueChar, ds->data.string, ds->data_len);
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_OCTET_STR,
                    (u_char*) valueChar,
                    ds->data_len);
            if(!returnVar)
            {
                free(temp_oid);
                free(temp_value);
                return;
            }
            memcpy(temp_value, valueChar, ds->data_len);
            temp_value_len = ds->data_len;
        }
        else
            snmp_free_varbind(notification_vars);
        free(temp_value);
    }
    
    add_cardType_to_variable_bindings(shelf, slot, &notification_vars);
    add_eventLocatoin_to_variable_bindings(shelf, slot, modno, 0, &notification_vars);
    add_systemTime_to_variable_bindings(&notification_vars);
    
    if (notification_vars)
    {
        log_message("wdmagent_token", "edfa notif in trap 8 %d, %d", objid_snmptrap_len, OID_LENGTH(temp_oid));
//        send_v2trap(notification_vars);
        wdm_send_and_save_v2Trap(notification_vars);
//        snmp_free_varbind(notification_vars);
    }
    free(temp_oid);
}

void    make_and_send_module_notification(byte shelf, byte slot, byte ctype, byte mtype, byte modno, byte param, oid* notifOid, size_t notifOidLen, byte* notifCol, byte nNotifCols)
{
    int     valueInt;
    unsigned int    valueUint;
    char    valueChar[50];
    char    *temp_value;
    byte    temp_value_len;
    
    stIndexStructure s[3];
    s[0].type = ASN_INTEGER;
    s[0].value.Id = shelf;
    s[1].type = ASN_INTEGER;
    s[1].value.Id = slot;
    s[2].type = ASN_INTEGER;
    s[2].value.Id = modno;

    netsnmp_table_row* row;
    size_t dataset_oid_len;
    oid* temp_oid = NULL;
    oid* datasetOid;
//    if (ctype == SFP_CARD_TYPE || ctype == RETIMER_CARD_TYPE || ctype == CTRL_CARD_TYPE)
    if (mtype == SFP_MODULE_TYPE)
    {
        give_sfptable_oid_len(&datasetOid, &dataset_oid_len);
        row = find_row_in_dataset(wdmSfpTable, s, 3);
        if (!row)
            return;
        temp_oid = (oid*) malloc((dataset_oid_len + 3 + row->index_oid_len) * sizeof (oid));
        memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));
    } 
//    else if (ctype == XFP_CARD_TYPE)
    else if (mtype == XFP_MODULE_TYPE)
    {
        give_xfptable_oid_len(&datasetOid, &dataset_oid_len);
        row = find_row_in_dataset(wdmXfpTable, s, 3);
        if (!row)
            return;
        temp_oid = (oid*) malloc((dataset_oid_len + 3 + row->index_oid_len) * sizeof (oid));
        memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));
    } 
    else if (mtype == QSFP_MODULE_TYPE)
    {
        give_qsfptable_oid_len(&datasetOid, &dataset_oid_len);
        row = find_row_in_dataset(wdmQSfpTable, s, 3);
        if (!row)
            return;
        temp_oid = (oid*) malloc((dataset_oid_len + 3 + row->index_oid_len) * sizeof (oid));
        memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));
    } 
    else
        return;
    
    oid objid_snmptrap[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
    size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);
    
    netsnmp_table_data_set_storage* ds;
    byte alarmtype, alarmSeverity;
    alarmtype = ((param >> 4) & 0x07);
    alarmSeverity = param & 0x0F;
    
    netsnmp_variable_list *notification_vars = NULL;
    netsnmp_variable_list *returnVar = NULL;

    oid objid_sysuptime[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
    size_t objid_sysuptime_len = OID_LENGTH(objid_sysuptime);
    u_long sysuptime = netsnmp_get_agent_uptime();
//    sysuptime = get_uptime ();
    returnVar = snmp_varlist_add_variable(&notification_vars,
            objid_sysuptime, objid_sysuptime_len,
            ASN_TIMETICKS,
            (u_char*) &sysuptime,
            sizeof (sysuptime));
    if(!returnVar)
    {
        if(temp_oid)
            free(temp_oid);
        return;
    }

    returnVar = snmp_varlist_add_variable(&notification_vars,
            objid_snmptrap, objid_snmptrap_len,
            ASN_OBJECT_ID,
            (u_char *) notifOid,
            notifOidLen * sizeof (oid));
    if(!returnVar)
    {
        if(temp_oid)
            free(temp_oid);
        return;
    }
    
    ds = (netsnmp_table_data_set_storage*) row->data;
    byte colIndex = 0;
    for (colIndex = 0; colIndex < nNotifCols; colIndex++)
    {
        ds = (netsnmp_table_data_set_storage*) row->data;
        ds = netsnmp_table_data_set_find_column(ds, notifCol[colIndex]);
        if(!ds)
        {
            if(notification_vars)
                snmp_free_varbind(notification_vars);
            free(temp_oid);
            return;
        }
        temp_oid[dataset_oid_len] = 1; //entry
        temp_oid[dataset_oid_len + 1] = notifCol[colIndex];
        memcpy(&temp_oid[dataset_oid_len + 2], row->index_oid, row->index_oid_len * sizeof (oid));
        size_t temp_oid_len = dataset_oid_len + 2 + row->index_oid_len;


        temp_oid[temp_oid_len] = 0;
        {
            char    oidstr[200];
            int len2 = snprint_objid(oidstr, 200, temp_oid , temp_oid_len);
            oidstr[len2] = 0;
            log_message("wdmagent_token", "make_and_send_module_notification 1 %s ", oidstr);
        }
        temp_value = (char*)malloc(50);
        if (ds->type == ASN_INTEGER)
        {
            valueInt = *ds->data.integer;
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_INTEGER,
                    (u_char*) &valueInt,
                    sizeof (valueInt));
            if(!returnVar)
            {
                free(temp_oid);
                free(temp_value);
                return;
            }
            sprintf(temp_value, "%d", valueInt);
            temp_value_len = strlen(temp_value);
        }
        else if(ds->type == ASN_UNSIGNED)
        {
            valueUint = *ds->data.integer;
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_UNSIGNED,
                    (u_char*) &valueUint,
                    sizeof (valueUint));
            if(!returnVar)
            {
                free(temp_oid);
                free(temp_value);
                return;
            }
            sprintf(temp_value, "%d", valueInt);
            temp_value_len = strlen(temp_value);
        }
        else if(ds->type == ASN_OCTET_STR)
        {
            memcpy(valueChar, ds->data.string, ds->data_len);
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_OCTET_STR,
                    (u_char*) valueChar,
                    ds->data_len);
            if(!returnVar)
            {
                free(temp_oid);
                free(temp_value);
                return;
            }
            memcpy(temp_value, valueChar, ds->data_len);
            temp_value_len = ds->data_len;
        }
        else
            snmp_free_varbind(notification_vars);
        free(temp_value);
    }

    add_cardType_to_variable_bindings(shelf, slot, &notification_vars);
    add_eventLocatoin_to_variable_bindings(shelf, slot, modno, 0, &notification_vars);
    add_systemTime_to_variable_bindings(&notification_vars);

    if (notification_vars)
    {
        log_message("wdmagent_token", "in trap 8 module %d, %d", objid_snmptrap_len, OID_LENGTH(temp_oid));
        wdm_send_and_save_v2Trap(notification_vars);
    }
    free(temp_oid);
}

void    make_and_send_module_notification1(byte shelf, byte slot, byte ctype, byte mtype, byte modno, byte notif, byte param, oid* notifOid, size_t notifOidLen, byte* notifCol, byte nNotifCols)
{
    int     valueInt;
    unsigned int    valueUint;
    char    valueChar[50];
    char    *temp_value;
    byte    temp_value_len;

    oid objid_snmptrap[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
    size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);
    
    byte alarmtype, alarmSeverity;
    alarmtype = ((param >> 4) & 0x07);
    alarmSeverity = param & 0x0F;

    netsnmp_variable_list *notification_vars = NULL;
    netsnmp_variable_list *returnVar = NULL;
    
    oid objid_sysuptime[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
    size_t objid_sysuptime_len = OID_LENGTH(objid_sysuptime);
    u_long sysuptime = netsnmp_get_agent_uptime();
//    sysuptime = get_uptime ();
    returnVar = snmp_varlist_add_variable(&notification_vars,
            objid_sysuptime, objid_sysuptime_len,
            ASN_TIMETICKS,
            (u_char*) &sysuptime,
            sizeof (sysuptime));
    if(!returnVar)
        return;

    returnVar = snmp_varlist_add_variable(&notification_vars,
            objid_snmptrap, objid_snmptrap_len,
            ASN_OBJECT_ID,
            (u_char *) notifOid,
            notifOidLen * sizeof (oid));

    if(!returnVar)
        return;
                
    netsnmp_table_row* row;
    size_t dataset_oid_len;
    size_t temp_oid_len;
    oid* temp_oid = NULL;
    oid* datasetOid;

   
    stIndexStructure s[3];
    s[0].type = ASN_INTEGER;
    s[0].value.Id = shelf;
    s[1].type = ASN_INTEGER;
    s[1].value.Id = slot;
    s[2].type = ASN_INTEGER;
    s[2].value.Id = modno;

    netsnmp_table_data_set_storage* ds= NULL;
    if (mtype == SFP_MODULE_TYPE)
    {
        give_sfptable_oid_len(&datasetOid, &dataset_oid_len);
        row = find_row_in_dataset(wdmSfpTable, s, 3);
        if (!row)
            return;
        temp_oid = (oid*) malloc((dataset_oid_len + 3 + row->index_oid_len) * sizeof (oid));
        memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));
    }
    else if (mtype == XFP_MODULE_TYPE)
    {
        give_xfptable_oid_len(&datasetOid, &dataset_oid_len);
        row = find_row_in_dataset(wdmXfpTable, s, 3);
        if (!row)
            return;
        temp_oid = (oid*) malloc((dataset_oid_len + 3 + row->index_oid_len) * sizeof (oid));
        memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));
    } 
    else if (mtype == OPSW_LATCH_TYPE || mtype == OPSW_NOLATCH_TYPE || mtype == OPSW_SFP_TYPE)
    {
        give_opswitchtable_oid_len(&datasetOid, &dataset_oid_len);
        row = find_row_in_dataset(wdmOPSwitchTable, s, 3);
        if (!row)
            return;
        temp_oid = (oid*) malloc((dataset_oid_len + 3 + row->index_oid_len) * sizeof (oid));
        memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));
    }
    else if (mtype == EDFA_MODULE_TYPE)
    {
        give_edfatable_oid_len(&datasetOid, &dataset_oid_len);
        row = find_row_in_dataset(wdmEdfaModuleTable, s, 3);
        if (!row)
            return;
        temp_oid = (oid*) malloc((dataset_oid_len + 3 + row->index_oid_len) * sizeof (oid));
        memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));
    }
    else if (mtype == QSFP_MODULE_TYPE)
    {
        give_qsfptable_oid_len(&datasetOid, &dataset_oid_len);
        row = find_row_in_dataset(wdmQSfpTable, s, 3);
        if (!row)
            return;
        temp_oid = (oid*) malloc((dataset_oid_len + 3 + row->index_oid_len) * sizeof (oid));
        memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));
    } 
    else
    {
        if(notification_vars)
            snmp_free_varbind(notification_vars);
        return;
    }
    
    byte colIndex = 0;
    for (colIndex = 0; colIndex < nNotifCols; colIndex++ )
    {
        ds = (netsnmp_table_data_set_storage*) row->data;
        ds = netsnmp_table_data_set_find_column(ds, notifCol[colIndex]);
        if(!ds)
        {
            if(notification_vars)
                snmp_free_varbind(notification_vars);
            free(temp_oid);
            return;
        }
        temp_oid[dataset_oid_len] = 1; //entry
        temp_oid[dataset_oid_len + 1] = notifCol[colIndex];
        memcpy(&temp_oid[dataset_oid_len + 2], row->index_oid, row->index_oid_len * sizeof (oid));
        temp_oid_len = dataset_oid_len + 2 + row->index_oid_len;
        temp_oid[temp_oid_len] = 0;
        
        {
            char    oidstr[200];
            int len2 = snprint_objid(oidstr, 200, temp_oid , temp_oid_len);
            oidstr[len2] = 0;
            log_message("wdmagent_token", "make_and_send_module_notification1 1 %s ", oidstr);
        }

        temp_value = NULL;
        
        temp_value = (char*)malloc(50);
        if (ds->type == ASN_INTEGER)
        {
            valueInt = *ds->data.integer;
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_INTEGER,
                    (u_char*) &valueInt,
                    sizeof (valueInt));
            if(!returnVar)
            {
                free(temp_oid);
                free(temp_value);
                return;
            }
            sprintf(temp_value, "%d", valueInt);
            temp_value_len = strlen(temp_value);
        }
        else if(ds->type == ASN_UNSIGNED)
        {
            valueUint = *ds->data.integer;
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_UNSIGNED,
                    (u_char*) &valueUint,
                    sizeof (valueUint));
            if(!returnVar)
            {
                free(temp_oid);
                free(temp_value);
                return;
            }
            sprintf(temp_value, "%d", valueInt);
            temp_value_len = strlen(temp_value);
        }
        else if(ds->type == ASN_OCTET_STR)
        {
            memcpy(valueChar, ds->data.string, ds->data_len);
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_OCTET_STR,
                    (u_char*) valueChar,
                    ds->data_len);
            if(!returnVar)
            {
                free(temp_oid);
                free(temp_value);
                return;
            }
            memcpy(temp_value, valueChar, ds->data_len);
            temp_value_len = ds->data_len;
        }
        else
        {
            if(notification_vars)
                snmp_free_varbind(notification_vars);
            free(temp_oid);
            free(temp_value);
            return;
        }
        if(temp_value)
            free(temp_value);
    }

    byte plugSev = 0;
    netsnmp_table_row*  row1 = find_row_in_dataset(wdmCardTable, s, 2);
    if(row1)
    {
        ds = (netsnmp_table_data_set_storage*) row1->data;
        ds = netsnmp_table_data_set_find_column(ds, 18); //modseverity
        if(ds)
            plugSev = ds->data.string[modno - 1];
    }

    temp_oid[dataset_oid_len] = 1; //entry
    temp_oid[dataset_oid_len + 1] = 50;
    memcpy(&temp_oid[dataset_oid_len + 2], row->index_oid, row->index_oid_len * sizeof (oid));
    temp_oid_len = dataset_oid_len + 2 + row->index_oid_len;
    temp_oid[temp_oid_len] = 0;
    valueChar[0] = plugSev;
    returnVar = snmp_varlist_add_variable(&notification_vars,
            temp_oid, temp_oid_len,
            ASN_OCTET_STR,
            (u_char*) valueChar,
            1);
    free(temp_oid);
    if(!returnVar)
        return;

    add_cardType_to_variable_bindings(shelf, slot, &notification_vars);
    add_eventLocatoin_to_variable_bindings(shelf, slot, modno, 0, &notification_vars);
    add_systemTime_to_variable_bindings(&notification_vars);

    if (notification_vars)
    {
        log_message("wdmagent_token", "in trap 8 %d", notification_vars);
//        send_v2trap(notification_vars);
        wdm_send_and_save_v2Trap(notification_vars);
//        snmp_free_varbind(notification_vars);
    }
    
    return;
}

void ind_module_notification1(byte shelf, byte slot, byte ctype, byte mtype, byte modno, byte notif, byte param, byte enQueue)
{
    byte msg[10];
    int ptr = 0;
    msg[ptr++] = IND_MOD_NOTIF1;
    msg[ptr++] = shelf;
    msg[ptr++] = slot;
    msg[ptr++] = ctype;
    msg[ptr++] = mtype;
    msg[ptr++] = modno;
    msg[ptr++] = notif;
    msg[ptr++] = param;
    put_message_to_trap_sending_queue(msg, ptr, enQueue);
}

void process_module_notification1(byte shelf, byte slot, byte ctype, byte mtype, byte modno, byte notif, byte param)
{
  /*  if(enQueue)
    {
        byte msg[10];
        int ptr = 0;
        msg[ptr++] = IND_MOD_NOTIF1;
        msg[ptr++] = shelf;
        msg[ptr++] = slot;
        msg[ptr++] = ctype;
        msg[ptr++] = mtype;
        msg[ptr++] = modno;
        msg[ptr++] = notif;
        msg[ptr++] = param;
        put_message_to_trap_sending_queue(msg, ptr);
        return;
    } */
    
     byte notifCols[10];
    if (notif == NOTIF_MODULE_ADDED)
    {
        notifCols[0] = 6;
        notifCols[1] = 4;
        byte idx = 0;
        if(!give_card_mutex_index(shelf, slot, &idx))
            return;
#ifdef  THREAD_SAFE_ACCESS    
        pthread_mutex_lock(&cardmutex[idx]);
#endif             
        make_and_send_module_notification1(shelf, slot, ctype, mtype, modno, notif, param, modUnPlugNotifRecov_oid, OID_LENGTH(modUnPlugNotifRecov_oid), notifCols, 2);
#ifdef  THREAD_SAFE_ACCESS    
        pthread_mutex_unlock(&cardmutex[idx]);
#endif               
    }
    else if(notif == NOTIF_MODULE_REMOVED)
    {
        notifCols[0] = 6;
        byte idx = 0;
        if(!give_card_mutex_index(shelf, slot, &idx))
            return;
#ifdef  THREAD_SAFE_ACCESS    
        pthread_mutex_lock(&cardmutex[idx]);
#endif             
        make_and_send_module_notification1(shelf, slot, ctype, mtype, modno, notif, param, modUnPlugNotifRaise_oid, OID_LENGTH(modUnPlugNotifRaise_oid), notifCols, 1);
#ifdef  THREAD_SAFE_ACCESS    
        pthread_mutex_unlock(&cardmutex[idx]);
#endif           
        delete_related_module_traps_from_queue(shelf, slot, modno);
    }
}

void    ind_switch_notification(byte shelf, byte slot, byte ctype, byte mtype, byte modno, char* Info, word len)
{
    if (len < 1)
        return;

    byte losAlarm = Info[0];
    int   nCAl = 0, nJAl = 0, nNAl = 0,  nW = 0;
    byte alarmtype, alarmSeverity;

    byte notifCols[10];
    byte nCols = 0;
    
    if (losAlarm & 0x10)
    {
        alarmtype = ((losAlarm >> 7) & 0x01);
        alarmSeverity = losAlarm & 0x0F;
        if(!alarmSeverity)
            alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 9, alarmtype);
        nCols = 0;
        notifCols[nCols++] = 4;
        if(alarmSeverity)
            notifCols[nCols++] = 9; //opswLOSSeverity
        if (losAlarm & 0x80)
        {
            if(ctype == SW2_4_CARD_TYPE)
            {
                byte main = ((modno == 1) || (modno == 3));
                if(modno == 1 || modno == 2)
                    modno = 1;
                else
                    modno = 2;
                if(main)
                    make_and_send_switch_notification(shelf, slot, ctype, mtype, modno, losAlarm, opswlosNotifRaise_oid, OID_LENGTH(opswlosNotifRaise_oid), notifCols, nCols);
                else
                    make_and_send_switch_notification(shelf, slot, ctype, mtype, modno, losAlarm, opswPlosNotifRaise_oid, OID_LENGTH(opswPlosNotifRaise_oid), notifCols, nCols);
            }
            else
//                make_and_send_switch_notification(shelf, slot, ctype, mtype, modno, losAlarm, modlosNotifRaise_oid, OID_LENGTH(modlosNotifRaise_oid), notifCols, nCols);
                make_and_send_switch_notification(shelf, slot, ctype, mtype, modno, losAlarm, opswlosNotifRaise_oid, OID_LENGTH(opswlosNotifRaise_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW++;
            else if(alarmSeverity & 0x02)
                nNAl++;
            else if(alarmSeverity & 0x04)
                nJAl++;
           else if(alarmSeverity & 0x08)
                nCAl++;
        }
        else
        {
            if(ctype == SW2_4_CARD_TYPE)
            {
                byte main = ((modno == 1) || (modno == 3));
                if(modno == 1 || modno == 2)
                    modno = 1;
                else
                    modno = 2;
                if(main)
                    make_and_send_switch_notification(shelf, slot, ctype, mtype, modno, losAlarm, opswlosNotifRecov_oid, OID_LENGTH(opswlosNotifRecov_oid), notifCols, nCols);
                else
                    make_and_send_switch_notification(shelf, slot, ctype, mtype, modno, losAlarm, opswPlosNotifRecov_oid, OID_LENGTH(opswPlosNotifRecov_oid), notifCols, nCols);
            }
            else
//            make_and_send_switch_notification(shelf, slot, ctype, mtype, modno, losAlarm, modlosNotifRecov_oid, OID_LENGTH(modlosNotifRecov_oid), notifCols, nCols);
                make_and_send_switch_notification(shelf, slot, ctype, mtype, modno, losAlarm, opswlosNotifRecov_oid, OID_LENGTH(opswlosNotifRecov_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW--;
            else if(alarmSeverity & 0x02)
                nNAl--;
            else if(alarmSeverity & 0x04)
                nJAl--;
           else if(alarmSeverity & 0x08)
                nCAl--;
        }
        update_switch_nAlarms(shelf, slot, modno, nCAl, nJAl, nNAl, nW);
    }
}
void    ind_edfa_notification(byte shelf, byte slot, byte ctype, byte mtype, byte modno, char* Info, word len)
{
    if (len < 5)
        return;
    int   nCAl = 0, nJAl = 0, nNAl = 0,  nW = 0;
    byte alarmtype, alarmSeverity;

    byte notifCols[10];
    byte nCols = 0;
    byte i;
    byte nParams = 5;
    oid tempOid[MAX_OID_LEN];
    int oidLen = 0;
    int j = 0;
    for (i = 0; i < nParams; i++)
    {
        if (Info[i] & 0x80)
        {
            alarmtype = ((Info[i] >> 4) & 0x07);
            alarmSeverity = Info[i] & 0x0F;
            switch(i)
            {
                case 0://iLos
                    if (Info[i] & 0x70)
                    {
                        memcpy(tempOid, edfaILosNotifRaise_oid, OID_LENGTH(edfaILosNotifRaise_oid) * sizeof(oid));
                        oidLen = OID_LENGTH(edfaILosNotifRaise_oid);    
                    }
                    else
                    {
                        memcpy(tempOid, edfaILosNotifRecov_oid, OID_LENGTH(edfaILosNotifRecov_oid) * sizeof(oid));
                        oidLen = OID_LENGTH(edfaILosNotifRecov_oid);    
                    }
                    nCols = 0;
                    notifCols[nCols++] = 4;
                    if(!alarmSeverity)
                        alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 18, alarmtype);
                    if(alarmSeverity)
                        notifCols[nCols++] = 18;
                    break;
                    
                case 1://oLos
                    if (Info[i] & 0x70)
                    {
                        memcpy(tempOid, edfaOLosNotifRaise_oid, OID_LENGTH(edfaOLosNotifRaise_oid) * sizeof(oid));
                        oidLen = OID_LENGTH(edfaOLosNotifRaise_oid);    
                    }
                    else
                    {
                        memcpy(tempOid, edfaOLosNotifRecov_oid, OID_LENGTH(edfaOLosNotifRecov_oid) * sizeof(oid));
                        oidLen = OID_LENGTH(edfaOLosNotifRecov_oid);    
                    }
                    nCols = 0;
                    notifCols[nCols++] = 5;
                    if(!alarmSeverity)
                        alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 19, alarmtype);
                    if(alarmSeverity)
                        notifCols[nCols++] = 19;
                    break;
                    
                case 2://cTemp
                    if (Info[i] & 0x70)
                    {
                        memcpy(tempOid, edfaCTempNotifRaise_oid, OID_LENGTH(edfaCTempNotifRaise_oid) * sizeof(oid));
                        oidLen = OID_LENGTH(edfaCTempNotifRaise_oid);    
                    }
                    else
                    {
                        memcpy(tempOid, edfaCTempNotifRecov_oid, OID_LENGTH(edfaCTempNotifRecov_oid) * sizeof(oid));
                        oidLen = OID_LENGTH(edfaCTempNotifRecov_oid);    
                    }
                    nCols = 0;
                    notifCols[nCols++] = 16;
                    if(!alarmSeverity)
                        alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 20, alarmtype);
                    if(alarmSeverity)
                        notifCols[nCols++] = 20;
                    break;
                    
                case 3://pTemp
                    if (Info[i] & 0x70)
                    {
                        memcpy(tempOid, edfaPTempNotifRaise_oid, OID_LENGTH(edfaPTempNotifRaise_oid) * sizeof(oid));
                        oidLen = OID_LENGTH(edfaPTempNotifRaise_oid);    
                    }
                    else
                    {
                        memcpy(tempOid, edfaPTempNotifRecov_oid, OID_LENGTH(edfaPTempNotifRecov_oid) * sizeof(oid));
                        oidLen = OID_LENGTH(edfaPTempNotifRecov_oid);    
                    }
                    nCols = 0;
                    notifCols[nCols++] = 10;
                    if(!alarmSeverity)
                        alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 21, alarmtype);
                    if(alarmSeverity)
                        notifCols[nCols++] = 21;
                    break;
                    
                case 4://pCurrentBias
                    if (Info[i] & 0x70)
                    {
                        memcpy(tempOid, edfaPCurrNotifRaise_oid, OID_LENGTH(edfaPCurrNotifRaise_oid) * sizeof(oid));
                        oidLen = OID_LENGTH(edfaPCurrNotifRaise_oid);    
                    }
                    else
                    {
                        memcpy(tempOid, edfaPCurrNotifRecov_oid, OID_LENGTH(edfaPCurrNotifRecov_oid) * sizeof(oid));
                        oidLen = OID_LENGTH(edfaPCurrNotifRecov_oid);    
                    }
                    nCols = 0;
                    notifCols[nCols++] = 9;
                    if(!alarmSeverity)
                        alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 22, alarmtype);
                    if(alarmSeverity)
                        notifCols[nCols++] = 22;
                    break;
                    
                default:
                    continue;
            }
            if (Info[i] & 0x70)
                j = 1;
            else
                j = -1;
            make_and_send_edfa_notification(shelf, slot, ctype, mtype, modno, Info[i], tempOid, oidLen, notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW += j;
            else if(alarmSeverity & 0x02)
                nNAl += j;
            else if(alarmSeverity & 0x04)
                nJAl += j;
            else if(alarmSeverity & 0x08)
                nCAl += j;
        }
    }
    update_edfa_nAlarms(shelf, slot, modno, nCAl, nJAl, nNAl, nW);
}



void ind_module_notification(byte shelf, byte slot, byte ctype, byte mtype, byte modno, char* Info, word len, byte enQueue)
{
    byte *msg = (byte*)malloc(6 + len);
    if(!msg)
        return;
    int ptr = 0;
    msg[ptr++] = IND_MOD_NOTIF;
    msg[ptr++] = shelf;
    msg[ptr++] = slot;
    msg[ptr++] = ctype;
    msg[ptr++] = mtype;
    msg[ptr++] = modno;
    msg[ptr++] = len;
    memcpy(&msg[ptr], Info, len);
    ptr += len;
    put_message_to_trap_sending_queue(msg, ptr, enQueue);
    free(msg);
}

void process_module_notification(byte shelf, byte slot, byte ctype, byte mtype, byte modno, char* Info, word len)
{

/*    if(enQueue)
    {
        byte *msg = (byte*)malloc(6 + len);
        if(!msg)
            return;
        int ptr = 0;
        msg[ptr++] = IND_MOD_NOTIF;
        msg[ptr++] = shelf;
        msg[ptr++] = slot;
        msg[ptr++] = ctype;
        msg[ptr++] = mtype;
        msg[ptr++] = modno;
        msg[ptr++] = len;
        memcpy(&msg[ptr], Info, len);
        ptr += len;
        put_message_to_trap_sending_queue(msg, ptr);
        free(msg);
        return;
    }    */
    
   
    if (ctype == SW2_CARD_TYPE || ctype == SW4_CARD_TYPE || ctype == SW2_4_CARD_TYPE)
    {
        ind_switch_notification(shelf, slot, ctype, mtype, modno, Info, len);
        return;
    }

    if (ctype == EDFA2_CARD_TYPE || ctype == EDFA_CARD_TYPE)
    {
        ind_edfa_notification(shelf, slot, ctype, mtype, modno, Info, len);
        return;
    }

    if (ctype == CTRL_CARD_TYPE && modno == 3)
    {
        ind_control_notification(shelf, slot, ctype, mtype, modno, Info, len);
        return;
    }

    
    if (ctype == QSFP_CARD_TYPE && mtype == QSFP_MODULE_TYPE)
    {
        ind_qsfp_notification(shelf, slot, ctype, mtype, modno, Info, len);
        return;
    }

    if (len < 7)
        return;
    
  
    byte tempAlarm = Info[0];
    byte rxPWRAlarm = Info[1];
    byte txBiasAlarm = Info[2];
    byte txPWRAlarm = Info[3];
    byte losAlarm = Info[4];
    byte lsAlarm = Info[5];
    byte txFaultAlarm = Info[6];
    int   nCAl = 0, nJAl = 0, nNAl = 0,  nW = 0;
    
    log_message("wdmagent_token", "ind_module_notification %x, %x, %x, %x, %x ,%x, %x ", tempAlarm, rxPWRAlarm, txBiasAlarm, txPWRAlarm, losAlarm,
                                                    lsAlarm, txFaultAlarm
            
            );
    
    byte alarmtype, alarmSeverity;

    byte notifCols[10];
    byte nCols = 0;
    if (tempAlarm & 0x80)
    {
        alarmtype = ((tempAlarm >> 4) & 0x07);
        alarmSeverity = tempAlarm & 0x0F;
        if(!alarmSeverity)
        {
            if(alarmtype == 0)
                alarmtype = give_module_current_alarm(shelf, slot, modno, ctype, mtype, 0);
            alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 46, alarmtype);
        }
        nCols = 0;
        notifCols[nCols++] = 34;
        if(alarmSeverity)
        {
            notifCols[nCols++] = 46; //tempSeverity
            switch(alarmtype)
            {
                case 1:
                    notifCols[nCols++] = 19;//sfpTempLAThreshold
                    break;
                case 2:
                    notifCols[nCols++] = 21;//sfpTempLWThreshold
                    break;
                case 3:
                    notifCols[nCols++] = 20;//sfpTempHWThreshold
                    break;
                case 4:
                    notifCols[nCols++] = 18;//sfpTempHAThreshold
                    break;
            }
        }
        if (tempAlarm & 0x70)
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, tempAlarm, modTempNotifRaise_oid, OID_LENGTH(modTempNotifRaise_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW++;
            else if(alarmSeverity & 0x02)
                nNAl++;
            else if(alarmSeverity & 0x04)
                nJAl++;
           else if(alarmSeverity & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, tempAlarm, modTempNotifRecov_oid, OID_LENGTH(modTempNotifRecov_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW--;
            else if(alarmSeverity & 0x02)
                nNAl--;
            else if(alarmSeverity & 0x04)
                nJAl--;
           else if(alarmSeverity & 0x08)
                nCAl--;
        }
    }
    
    if (rxPWRAlarm & 0x80)
    {
        alarmtype = ((rxPWRAlarm >> 4) & 0x07);
        alarmSeverity = rxPWRAlarm & 0x0F;
        if(!alarmSeverity)
        {
            if(alarmtype == 0)
                alarmtype = give_module_current_alarm(shelf, slot, modno, ctype, mtype, 1);
            alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 47, alarmtype);
        }
        nCols = 0;
        notifCols[nCols++] = 35;
        if(alarmSeverity)                                                    
        {
            notifCols[nCols++] = 47; //sfpRXPwrSeverity
            switch(alarmtype)
            {
                case 1:
                    notifCols[nCols++] = 23;//sfpRXPwrLAThreshold
                    break;
                case 2:
                    notifCols[nCols++] = 25;//sfpRXPwrLWThreshold
                    break;
                case 3:
                    notifCols[nCols++] = 24;//sfpRXPwrHWThreshold
                    break;
                case 4:
                    notifCols[nCols++] = 22;//sfpRXPwrHAThreshold
                    break;
            }
        }
        if (rxPWRAlarm & 0x70)
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, rxPWRAlarm, modrxpwrNotifRaise_oid, OID_LENGTH(modrxpwrNotifRaise_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW++;
            else if(alarmSeverity & 0x02)
                nNAl++;
            else if(alarmSeverity & 0x04)
                nJAl++;
           else if(alarmSeverity & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, rxPWRAlarm, modrxpwrNotifRecov_oid, OID_LENGTH(modrxpwrNotifRecov_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW--;
            else if(alarmSeverity & 0x02)
                nNAl--;
            else if(alarmSeverity & 0x04)
                nJAl--;
           else if(alarmSeverity & 0x08)
                nCAl--;
        }
    }
    if (txBiasAlarm & 0x80)
    {
        alarmtype = ((txBiasAlarm >> 4) & 0x07);
        alarmSeverity = txBiasAlarm & 0x0F;
        if(!alarmSeverity)
        {
            if(alarmtype == 0)
                alarmtype = give_module_current_alarm(shelf, slot, modno, ctype, mtype, 2);
            alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 48, alarmtype);
        }
        nCols = 0;
        notifCols[nCols++] = 36;
        if(alarmSeverity)
        {
            notifCols[nCols++] = 48; //sfpTXBiasSeverity
            switch(alarmtype)
            {
                case 1:
                    notifCols[nCols++] = 27;//sfpTXBiasLAThreshold
                    break;
                case 2:
                    notifCols[nCols++] = 29;//sfpTXBiasLWThreshold
                    break;
                case 3:
                    notifCols[nCols++] = 28;//sfpTXBiasHWThreshold
                    break;
                case 4:
                    notifCols[nCols++] = 26;//sfpTXBiasHAThreshold
                    break;
            }
        }
        if (txBiasAlarm & 0x70)
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, txBiasAlarm, modtxbiasNotifRaise_oid, OID_LENGTH(modtxbiasNotifRaise_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW++;
            else if(alarmSeverity & 0x02)
                nNAl++;
            else if(alarmSeverity & 0x04)
                nJAl++;
           else if(alarmSeverity & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, txBiasAlarm, modtxbiasNotifRecov_oid, OID_LENGTH(modtxbiasNotifRecov_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW--;
            else if(alarmSeverity & 0x02)
                nNAl--;
            else if(alarmSeverity & 0x04)
                nJAl--;
           else if(alarmSeverity & 0x08)
                nCAl--;
        }
    }
    if (txPWRAlarm & 0x80)
    {
        alarmtype = ((txPWRAlarm >> 4) & 0x07);
        alarmSeverity = txPWRAlarm & 0x0F;
        if(!alarmSeverity)
        {
            if(alarmtype == 0)
                alarmtype = give_module_current_alarm(shelf, slot, modno, ctype, mtype, 3);
            alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 49, alarmtype);
        }
        nCols = 0;
        notifCols[nCols++] = 37;
        if(alarmSeverity)
        {
            notifCols[nCols++] = 49; //sfpTXPwrSeverity
            switch(alarmtype)
            {
                case 1:
                    notifCols[nCols++] = 31;//sfpTXPwrLAThreshold
                    break;
                case 2:
                    notifCols[nCols++] = 33;//sfpTXPwrLWThreshold
                    break;
                case 3:
                    notifCols[nCols++] = 32;//sfpTXPwrHWThreshold
                    break;
                case 4:
                    notifCols[nCols++] = 30;//sfpTXPwrHAThreshold
                    break;
            }
        }
        if (txPWRAlarm & 0x70)
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, txPWRAlarm, modtxpwrNotifRaise_oid, OID_LENGTH(modtxpwrNotifRaise_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW++;
            else if(alarmSeverity & 0x02)
                nNAl++;
            else if(alarmSeverity & 0x04)
                nJAl++;
           else if(alarmSeverity & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, txPWRAlarm, modtxpwrNotifRecov_oid, OID_LENGTH(modtxpwrNotifRecov_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW--;
            else if(alarmSeverity & 0x02)
                nNAl--;
            else if(alarmSeverity & 0x04)
                nJAl--;
           else if(alarmSeverity & 0x08)
                nCAl--;
        }
    }
    if (losAlarm & 0x80)
    {
        alarmtype = ((losAlarm >> 4) & 0x07);
        alarmSeverity = losAlarm & 0x0F;
        if(!alarmSeverity)
            alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 50, alarmtype);
        nCols = 0;
        notifCols[nCols++] = 4;
        if(alarmSeverity)
            notifCols[nCols++] = 50; //sfpLOSSeverity
        if (losAlarm & 0x70)
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, losAlarm, modlosNotifRaise_oid, OID_LENGTH(modlosNotifRaise_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW++;
            else if(alarmSeverity & 0x02)
                nNAl++;
            else if(alarmSeverity & 0x04)
                nJAl++;
           else if(alarmSeverity & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, losAlarm, modlosNotifRecov_oid, OID_LENGTH(modlosNotifRecov_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW--;
            else if(alarmSeverity & 0x02)
                nNAl--;
            else if(alarmSeverity & 0x04)
                nJAl--;
           else if(alarmSeverity & 0x08)
                nCAl--;
        }
    }
    if (lsAlarm & 0x80)
    {
        alarmtype = ((lsAlarm >> 4) & 0x07);
        alarmSeverity = lsAlarm & 0x0F;
        if(!alarmSeverity)
            alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 51, alarmtype);
        nCols = 0;
        notifCols[nCols++] = 5;
        if(alarmSeverity)
            notifCols[nCols++] = 51; //sfpLSSeverity
        if (lsAlarm & 0x70)
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, lsAlarm, modlsNotifRaise_oid, OID_LENGTH(modlsNotifRaise_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW++;
            else if(alarmSeverity & 0x02)
                nNAl++;
            else if(alarmSeverity & 0x04)
                nJAl++;
           else if(alarmSeverity & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, lsAlarm, modlsNotifRecov_oid, OID_LENGTH(modlsNotifRecov_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW--;
            else if(alarmSeverity & 0x02)
                nNAl--;
            else if(alarmSeverity & 0x04)
                nJAl--;
           else if(alarmSeverity & 0x08)
                nCAl--;
        }
    }
    if (txFaultAlarm & 0x80)
    {
        alarmtype = ((txFaultAlarm >> 4) & 0x07);
        alarmSeverity = txFaultAlarm & 0x0F;
        if(!alarmSeverity)
            alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 52, alarmtype);
        nCols = 0;
        notifCols[nCols++] = 40;
        if(alarmSeverity)
            notifCols[nCols++] = 52; //sfpTXFaultSeverity
        if (txFaultAlarm & 0x70)
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, txFaultAlarm, modtxfltNotifRaise_oid, OID_LENGTH(modtxfltNotifRaise_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW++;
            else if(alarmSeverity & 0x02)
                nNAl++;
            else if(alarmSeverity & 0x04)
                nJAl++;
           else if(alarmSeverity & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, txFaultAlarm, modtxfltNotifRecov_oid, OID_LENGTH(modtxfltNotifRecov_oid), notifCols, nCols);
            if(alarmSeverity & 0x01)
                nW--;
            else if(alarmSeverity & 0x02)
                nNAl--;
            else if(alarmSeverity & 0x04)
                nJAl--;
           else if(alarmSeverity & 0x08)
                nCAl--;
        }
    }
    
    if (len >= 8)
    {
        if (Info[7] & 0x80)
        {
            alarmtype = ((Info[7] >> 4) & 0x07);
            alarmSeverity = find_alarm_severity(shelf, slot, modno, ctype, mtype, 51, alarmtype);
            nCols = 0;
            notifCols[nCols++] = 39;
            notifCols[nCols++] = 51; //sfpLSSeverity
            
            if (Info[7] & 0x70)
            {
                make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[7], modtxDisableNotifRaise_oid, OID_LENGTH(modtxDisableNotifRaise_oid), notifCols, nCols);
                if(alarmSeverity & 0x01)
                    nW++;
                else if(alarmSeverity & 0x02)
                    nNAl++;
                else if(alarmSeverity & 0x04)
                    nJAl++;
               else if(alarmSeverity & 0x08)
                    nCAl++;
            }
            else
            {
                make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[7], modtxDisableNotifRecov_oid, OID_LENGTH(modtxDisableNotifRecov_oid), notifCols, nCols);
                if(alarmSeverity & 0x01)
                    nW--;
                else if(alarmSeverity & 0x02)
                    nNAl--;
                else if(alarmSeverity & 0x04)
                    nJAl--;
               else if(alarmSeverity & 0x08)
                    nCAl--;
            }
        }
    }
    
    
    if(ctype == SFP_CARD_TYPE || ctype == RETIMER_CARD_TYPE || ctype == CTRL_CARD_TYPE)
    {
        update_sfp_nAlarms(shelf, slot, modno, nCAl, nJAl, nNAl, nW);
        update_sfpAlarm_Field(shelf, slot, modno, Info);
    }
    else if(ctype == XFP_CARD_TYPE)
    {
        update_xfp_nAlarms(shelf, slot, modno, nCAl, nJAl, nNAl, nW);
        update_xfpAlarm_Field(shelf, slot, modno, Info);
    }
}

void    put_message_to_trap_sending_queue(byte* buffer, int len, byte enQueue)
{
    if (agentStarted) 
    {
        stMsgNode_t*	msgNode = NULL;
        pthread_mutex_lock(&trapSendingQmutex);
        if(!trapSendingMessageListHead)
        {
            trapSendingMessageListHead = (stMsgNode_t*)malloc(sizeof(stMsgNode_t));
            trapSendingMessageListHead->Next = NULL;
            trapSendingMessageListTail = trapSendingMessageListHead;
            msgNode = trapSendingMessageListHead;
        }
        else
        {
            if(enQueue)//add to tail
            {
                if(trapSendingMessageListTail) 
                {
                    msgNode = (stMsgNode_t*)malloc(sizeof(stMsgNode_t));
                    msgNode->Next = NULL;
                    trapSendingMessageListTail->Next = msgNode;
                    trapSendingMessageListTail = msgNode;
                }
            }
            else // add to head
            {
                msgNode = (stMsgNode_t*)malloc(sizeof(stMsgNode_t));
                msgNode->Next = trapSendingMessageListHead;
                trapSendingMessageListHead = msgNode;
            }
        }
        if(msgNode)
        {
            msgNode->Msg = (byte*)malloc(len);
            memcpy(msgNode->Msg, (byte*)buffer, len);
            msgNode->Size = len;
        }
        pthread_mutex_unlock(&trapSendingQmutex);    
        log_message("wdmagent_token", "in put message trap sending %d  ", len);
    }
}

byte get_message_from_trap_sending_queue(byte** buffer, word* len, int  timeout) 
{
    if (!agentStarted)
        return FALSE;
    byte result = FALSE;
    pthread_mutex_lock(&trapSendingQmutex);
    if(trapSendingMessageListHead)
    {
        stMsgNode_t*	RecvMessageList = trapSendingMessageListHead;
        if(RecvMessageList->Msg)
        {
            byte*   RecvMessage = (byte*)malloc(RecvMessageList->Size);
            if(RecvMessage)
            {
                memcpy(RecvMessage, RecvMessageList->Msg, RecvMessageList->Size);
                word MsgSize = RecvMessageList->Size;

                free(RecvMessageList->Msg);
                trapSendingMessageListHead = RecvMessageList->Next;
                free(RecvMessageList);
                result = TRUE;
                *len = MsgSize;
                *buffer = RecvMessage;
            }
        }
    }
    pthread_mutex_unlock(&trapSendingQmutex);		
    return result;
}

void*  process_trap_sending_messages(void*   parameter) 
{
    word len;
    byte* buffer;

    log_thread_id("process_trap_sending_messages", 0 );

    while(1)
    {
        if (get_message_from_trap_sending_queue(&buffer, &len, 0)) 
        {
            nsleep(100);
            
            switch(buffer[0])
            {
                case IND_MOD_NOTIF1:
                    process_module_notification1(buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7]);
                    break;
                    
                case IND_MOD_NOTIF:
                    process_module_notification(buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], &buffer[7], buffer[6]);
                    break;

                case IND_CARD_NOTIF:
                    process_card_notification(buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
                    break;
                    
                case IND_DATA_CHANGED:
                    ind_data_changed(&buffer[1], len - 1);
                    break;
                    
            }
            free(buffer);
        }
        else
            nsleep(100);
    }
    return NULL;
}

void    put_message_to_sending_trap_queue(byte* buffer, int len)
{
//    if (agentStarted) 
    {
        stMsgNode_t*	msgNode = NULL;
        pthread_mutex_lock(&sendingTrapQmutex);
        if(!sendingTrapMessageListHead)
        {
            sendingTrapMessageListHead = (stMsgNode_t*)malloc(sizeof(stMsgNode_t));
            sendingTrapMessageListHead->Next = NULL;
            sendingTrapMessageListTail = sendingTrapMessageListHead;
            msgNode = sendingTrapMessageListHead;
        }
        else
        {
            if(sendingTrapMessageListTail) 
            {
                msgNode = (stMsgNode_t*)malloc(sizeof(stMsgNode_t));
                if(msgNode)
                {
                    msgNode->Next = NULL;
                    sendingTrapMessageListTail->Next = msgNode;
                    sendingTrapMessageListTail = msgNode;
                }
            }
            else
            {
                pthread_mutex_unlock(&sendingTrapQmutex);
                return;
            }
        }
        if(msgNode)
        {
            msgNode->Msg = (byte*)malloc(len);
            memcpy(msgNode->Msg, (byte*)buffer, len);
            msgNode->Size = len;
        }
        pthread_mutex_unlock(&sendingTrapQmutex);    
        log_message("wdmagent_token", "in put message sending trap %d", len);
    }
}

netsnmp_variable_list*    remove_trap_from_sending_trap_messages(long reqId)
{
    byte result = FALSE;
    pthread_mutex_lock(&sendingTrapQmutex);
    stMsgNode_t*	msgNode = sendingTrapMessageListHead;
    int len = sizeof(int) + sizeof(long);
    stMsgNode_t* prev = NULL;
    netsnmp_variable_list* vars = NULL;
    while(msgNode)
    {
        if(msgNode->Msg && len == msgNode->Size)
        {
            int i = *(int*)msgNode->Msg;
            netsnmp_variable_list* tmpvar = (netsnmp_variable_list*)i;
            long id = *(long*)&msgNode->Msg[sizeof(int)];
            if(reqId == id)
            {
                log_message("sendingtrap_token", "remove_trap_from_sending_trap_messages1 %d, %d", reqId, id);
                
                free(msgNode->Msg);
                if(prev)
                    prev->Next = msgNode->Next;
                else
                    sendingTrapMessageListHead = msgNode->Next;
                free(msgNode);
                vars = tmpvar;
                break;
            }
        }
        prev = msgNode;
        msgNode = msgNode->Next;
    }
    pthread_mutex_unlock(&sendingTrapQmutex);
    return vars;
}

void    put_message_to_unacked_trap_queue(byte* buffer, int len)
{
    if (agentStarted) 
    {
        stMsgNode_t*	msgNode = NULL;
        pthread_mutex_lock(&unackedTrapQmutex);
        if(!unackedTrapMessageListHead)
        {
            unackedTrapMessageListHead = (stMsgNode_t*)malloc(sizeof(stMsgNode_t));
            unackedTrapMessageListHead->Next = NULL;
            unackedTrapMessageListTail = unackedTrapMessageListHead;
            msgNode = unackedTrapMessageListHead;
            nUnackedTraps++;
        }
        else
        {
            if(unackedTrapMessageListTail) 
            {
                msgNode = (stMsgNode_t*)malloc(sizeof(stMsgNode_t));
                msgNode->Next = NULL;
                unackedTrapMessageListTail->Next = msgNode;
                unackedTrapMessageListTail = msgNode;
                if(nUnackedTraps >= MAX_SAVED_TRAPS)
                {
                    if(unackedTrapMessageListHead->Msg)
                        free(unackedTrapMessageListHead->Msg);
                    unackedTrapMessageListHead = unackedTrapMessageListHead->Next;
                    nUnackedTraps--;
                }
                nUnackedTraps++;
            }
            else
            {
                pthread_mutex_unlock(&unackedTrapQmutex);
                return;
            }
        }
        if(msgNode)
        {
            msgNode->Msg = (byte*)malloc(len);
            memcpy(msgNode->Msg, (byte*)buffer, len);
            msgNode->Size = len;
        }
        pthread_mutex_unlock(&unackedTrapQmutex);    
        log_message("wdmagent_token", "in put message unacked trap %d", len);
    }
}

byte get_message_from_unacked_trap_queue(byte** buffer, word* len, int  timeout) 
{
    if (!agentStarted)
        return FALSE;
    byte result = FALSE;
    pthread_mutex_lock(&unackedTrapQmutex);
    if(unackedTrapMessageListHead)
    {
        stMsgNode_t*	RecvMessageList = unackedTrapMessageListHead;
        if(RecvMessageList->Msg)
        {
            byte*   RecvMessage = (byte*)malloc(RecvMessageList->Size);
            if(RecvMessage)
            {
                memcpy(RecvMessage, RecvMessageList->Msg, RecvMessageList->Size);
                word MsgSize = RecvMessageList->Size;
                free(RecvMessageList->Msg);
                unackedTrapMessageListHead = RecvMessageList->Next;
                free(RecvMessageList);
                result = TRUE;
                *len = MsgSize;
                *buffer = RecvMessage;
                if(nUnackedTraps > 0)
                    nUnackedTraps--;
            }
        }
    }
    pthread_mutex_unlock(&unackedTrapQmutex);		
    return result;
}

void*  process_unacked_trap_messages(void*   parameter) 
{
    word len;
    byte* buffer;
    log_thread_id("process_unacked_trap_messages", 0);
    while(1)
    {
        sleep(30);
        continue;
        
        if (get_message_from_unacked_trap_queue(&buffer, &len, 0)) 
        {
            netsnmp_variable_list* tmpvar = (netsnmp_variable_list*)(*(int*)buffer);
            long reqId = *(long*)&buffer[sizeof(int)];
            log_message("unackedtrap_token", "in process_unacked_trap_messages buff=%d, %d, %d", tmpvar, len, reqId);
            wdm_send_and_save_v2Trap(tmpvar);

            free(buffer);
        }
    }
    return NULL;
}

netsnmp_variable_list*    remove_trap_from_unacked_trap_messages(long reqId)
{
    byte result = FALSE;
    pthread_mutex_lock(&unackedTrapQmutex);
    stMsgNode_t*	msgNode = unackedTrapMessageListHead;
    int len = sizeof(int) + sizeof(long);
    stMsgNode_t* prev = NULL;
    netsnmp_variable_list* vars = NULL;
    while(msgNode)
    {
        if(msgNode->Msg && len == msgNode->Size)
        {
            int i = *(int*)msgNode->Msg;
            netsnmp_variable_list* tmpvar = (netsnmp_variable_list*)i;
            long id = *(long*)&msgNode->Msg[sizeof(int)];
/*
                char    oidstr1[200], oidstr2[200];
                int len2 = snprint_objid(oidstr1, 200, tmpvar->name , tmpvar->name_length);
                oidstr1[len2] = 0;
                
                len2 = snprint_objid(oidstr2, 200, vars->name , vars->name_length);
                oidstr2[len2] = 0;
                
                log_message("unackedtrap_token", "remove_trap_from_unacked_trap_messages %d, %s", oidstr1, oidstr2);

            if(compare_two_variables(vars, tmpvar))
*/
            if(reqId == id)
            {
                log_message("unackedtrap_token", "remove_trap_from_unacked_trap_messages1 %d, %d", reqId, id);
                
                free(msgNode->Msg);
                if(prev)
                    prev->Next = msgNode->Next;
                else
                    unackedTrapMessageListHead = msgNode->Next;
                free(msgNode);
//                result = TRUE;
//                snmp_free_varbind(tmpvar);
                vars = tmpvar;
                break;
            }
//            log_message("unackedtrap_token", "remove_trap_from_unacked_trap_messages %d, %d", reqId, id);
        }
        prev = msgNode;
        msgNode = msgNode->Next;
    }
    pthread_mutex_unlock(&unackedTrapQmutex);
    return vars;
}

void    process_an_unacked_trap_message()
{
    word len;
    byte* buffer;
    if (get_message_from_unacked_trap_queue(&buffer, &len, 0)) 
    {
        netsnmp_variable_list* tmpvar = (netsnmp_variable_list*)(*(int*)buffer);
        long reqId = *(long*)&buffer[sizeof(int)];
        log_message("unackedtrap_token", "in process_an_unacked_trap_message buff=%d, %d, %d", tmpvar, len, reqId);
        wdm_send_and_save_v2Trap(tmpvar);
        free(buffer);
    }
}


int check_wdm_inform_response(int op, netsnmp_session * session, int reqid, netsnmp_pdu *pdu, void *magic)
{
    return 1;
    
    /* XXX: possibly stats update */
    netsnmp_variable_list *vars;
    switch (op) 
    {
        case NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE:
//            log_message("wdmagent_token", "in check_wdm_inform_response1 reqid=%d", reqid);
            vars = remove_trap_from_unacked_trap_messages(reqid);
            if(!vars)
                vars = remove_trap_from_sending_trap_messages(reqid);
            if(vars)
            {
                snmp_free_varbind(vars);
                process_an_unacked_trap_message();
            }
            break;

        case NETSNMP_CALLBACK_OP_TIMED_OUT:
//            log_message("wdmagent_token", "received a timeout sending an inform for reqid=%d", reqid);
            vars = remove_trap_from_unacked_trap_messages(reqid);
            if(!vars)
                vars = remove_trap_from_sending_trap_messages(reqid);
            
            if(vars)
                wdm_send_and_save_v2Trap_timeout(vars);
            else
                
            break;

        case NETSNMP_CALLBACK_OP_SEND_FAILED:
            log_message("wdmagent_token", "failed to send an inform for reqid=%d", reqid);
            break;

        default:
            log_message("wdmagent_token", "received op=%d for reqid=%d when trying to send an inform", op, reqid);
    }
    return 1;
}

//            
void    remove_trap_table(int shelf, int reqId)
{
    netsnmp_table_row* row = netsnmp_table_data_set_get_first_row(wdmTrapTable);
    netsnmp_table_data_set_storage* ds;
    while (row) 
    {
        stIndexStructure s[2];
        s[0].type = ASN_INTEGER;
        find_indexes(s, 1, row->index_oid, row->index_oid_len);
        if (s[0].value.Id == shelf)
        {
            ds = netsnmp_table_data_set_find_column((netsnmp_table_data_set_storage*) row->data, 3); 
            if(ds && (*ds->data.integer == reqId))
                netsnmp_table_dataset_remove_and_delete_row(wdmTrapTable, row);
        }
        row = netsnmp_table_data_set_get_next_row(wdmTrapTable, row);
    }
}


void    update_trap_table(int shelf, int id, int reqId, char* data, int datalen)
{
    netsnmp_table_row* row = netsnmp_table_data_set_get_first_row(wdmTrapTable);
    netsnmp_table_data_set_storage* ds;
    while (row) 
    {
        stIndexStructure s[2];
        s[0].type = ASN_INTEGER;
        s[1].type = ASN_INTEGER;
        find_indexes(s, 2, row->index_oid, row->index_oid_len);
        if (s[0].value.Id == id && s[1].value.Id == shelf)
            break;
        row = netsnmp_table_data_set_get_next_row(wdmTrapTable, row);
    }
    if(row)
    {
   //     my_netsnmp_set_row_column(row, 3, ASN_INTEGER, &reqId, sizeof (long));
   //     my_netsnmp_set_row_column(row, 4, ASN_OCTET_STR, data, datalen);
    }
}


void save_trap_in_trapTable(long reqId, netsnmp_variable_list*  notification_vars)
{
//    netsnmp_table_row*  row = netsnmp_create_table_data_row();
//    if (row)
    {
        netsnmp_variable_list*  tmp;
/*        int datalen = 1;
        char*   data = (char*)malloc(datalen);
        data[0] = '{'; 
        for(tmp = notification_vars; tmp; tmp = tmp->next_variable )
        {
            char    oidstr[200], valstr[200];
            int len = snprint_objid(oidstr, 200, tmp->name , tmp->name_length);
            oidstr[len] = 0;
            
            
            switch(tmp->type)
            {
                case ASN_OBJECT_ID:
                    snprint_objid(valstr, 200, tmp->val.objid , tmp->val_len);
                    valstr[tmp->val_len] = 0;
                    break;
                case ASN_INTEGER:
                    sprintf(valstr, "%li", *(tmp->val.integer));
                    break;
                case ASN_OCTET_STR:
                    strcpy(valstr, tmp->val.string);
                    break;
            }
            //{{'oid':' ', 'type': , 'len': , 'value': ,},}
            char    temp1[300];
            sprintf(temp1, "{'oid':'%s','type':%d,'len':%d,'value':'%s',},", 
                             oidstr, tmp->type, tmp->val_len, valstr);
            
            data = (char*)realloc(data, datalen + strlen(temp1));
            memcpy(&data[datalen], temp1, strlen(temp1));
            datalen += strlen(temp1);
            
        }
        data = (char*)realloc(data, datalen + 1);
        data[datalen] = '}';

        trapTable_make_row(row, ownShelfNumber, trapIndex, reqId, data, datalen + 1, 1);
        netsnmp_table_dataset_add_row(wdmTrapTable, row);
        trapIndex++;
        if(trapIndex > 100)
        {
            trapIndex = 1;
            update_trap_table(ownShelfNumber, trapIndex, reqId, data, datalen);
            trapIndex++;
        }
        free(data);*/
        
        int datalen = 0;
        char    temp1[250];
        for(tmp = notification_vars; tmp; tmp = tmp->next_variable )
        {
            char    oidstr[200], valstr[200];
            int len = snprint_objid(oidstr, 200, tmp->name , tmp->name_length);
            oidstr[len] = 0;
            
            
            switch(tmp->type)
            {
                case ASN_OBJECT_ID:
                    snprint_objid(valstr, 200, tmp->val.objid , tmp->val_len);
                    valstr[tmp->val_len] = 0;
                    break;
                case ASN_INTEGER:
                    sprintf(valstr, "%li", *(tmp->val.integer));
                    break;
                case ASN_OCTET_STR:
                    strcpy(valstr, tmp->val.string);
                    break;
            }
            //{{'oid':' ', 'type': , 'len': , 'value': ,},}
  
            sprintf(temp1, "{'oid':'%s','type':%d,'len':%d,'value':'%s',}", 
                             oidstr, tmp->type, tmp->val_len, valstr);
            
            if(trapRequestId > 100)
            {
                trapIndex = 1;
                trapRequestId = 1;
                remove_trap_table(ownShelfNumber, trapRequestId);
            }
            
            netsnmp_table_row*  row = netsnmp_create_table_data_row();
            if (row)
            {
                trapTable_make_row(row, ownShelfNumber, trapIndex, trapRequestId, temp1, strlen(temp1) , 1);
                netsnmp_table_dataset_add_row(wdmTrapTable, row);
                trapIndex++;
            }
        }
        trapRequestId++;
    }    
}

void    wdm_send_and_save_v2Trap(netsnmp_variable_list*  notification_vars)
{
    if(notification_vars)
    {
        send_v2trap(notification_vars);
        snmp_free_varbind(notification_vars);
    }
    
    return;
        
    long reqid = wdm_send_v2Trap(notification_vars);
    log_message("wdmagent_token", "wdm_send_and_save_v2Trap  reqid=%d, var = %d", reqid, notification_vars);
    if(reqid > 0)
    {
//        netsnmp_variable_list *tmpvar = snmp_clone_varbind(notification_vars);
        netsnmp_variable_list *tmpvar = notification_vars;
        byte    buffer[100];
        *(int*)buffer = (int)tmpvar;
        *(long*)&buffer[sizeof(int)] = reqid;
//        put_message_to_unacked_trap_queue(buffer, sizeof(int) + sizeof(long));
//        put_message_to_sending_trap_queue(buffer, sizeof(int) + sizeof(long));
        
//        save_trap_in_trapTable(reqid, notification_vars);
    }
}

void    wdm_send_and_save_v2Trap_timeout(netsnmp_variable_list*  notification_vars)
{
    long reqid = wdm_send_v2Trap(notification_vars);
    log_message("wdmagent_token", "wdm_send_and_save_v2Trap  reqid=%d, var = %d", reqid, notification_vars);
    if(reqid > 0)
    {
//        netsnmp_variable_list *tmpvar = snmp_clone_varbind(notification_vars);
        netsnmp_variable_list *tmpvar = notification_vars;
        byte    buffer[100];
        *(int*)buffer = (int)tmpvar;
        *(long*)&buffer[sizeof(int)] = reqid;
        put_message_to_unacked_trap_queue(buffer, sizeof(int) + sizeof(long));
    }
}

void    make_and_send_control_notification(byte shelf, byte slot, byte ctype, oid* notifOid, size_t notifOidLen, byte* notifCol, byte nNotifCols)
{
    netsnmp_variable_list *notification_vars = NULL;
    netsnmp_variable_list *returnVar = NULL;
    
    oid objid_sysuptime[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
    size_t objid_sysuptime_len = OID_LENGTH(objid_sysuptime);
    u_long sysuptime = netsnmp_get_agent_uptime();
    returnVar = snmp_varlist_add_variable(&notification_vars,
            objid_sysuptime, objid_sysuptime_len,
            ASN_TIMETICKS,
            (u_char*) &sysuptime,
            sizeof (sysuptime));
    if(!returnVar)
        return;

    oid objid_snmptrap[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
    size_t objid_snmptrap_len = OID_LENGTH(objid_snmptrap);
    returnVar = snmp_varlist_add_variable(&notification_vars,
            objid_snmptrap, objid_snmptrap_len,
            ASN_OBJECT_ID,
            (u_char *) notifOid,
            notifOidLen * sizeof (oid));
    if(!returnVar)
        return;

    netsnmp_table_row* row;
    size_t temp_oid_len;
    oid temp_oid[MAX_OID_LEN];
    byte colIndex;
    
    size_t dataset_oid_len;
    oid* datasetOid = NULL;
    stIndexStructure s[2];
    s[0].type = ASN_INTEGER;
    s[0].value.Id = shelf;
    row = find_row_in_dataset(wdmShelfTable, s, 1);
    give_shelftable_oid_len(&datasetOid, &dataset_oid_len);
    if (!row)
    {
        log_message("wdmagent_token", "in trap 911 row failed, %d, %d", shelf, slot);
        if(notification_vars)
            snmp_free_varbind(notification_vars);
        return;    
    }
    for (colIndex = 0; colIndex < nNotifCols; colIndex++)
    {
        memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));
        temp_oid[dataset_oid_len] = 1; //entry
        temp_oid[dataset_oid_len + 1] = notifCol[colIndex];
        memcpy(&temp_oid[dataset_oid_len + 2], row->index_oid, row->index_oid_len * sizeof (oid));
        temp_oid_len = dataset_oid_len + 2 + row->index_oid_len;
        temp_oid[temp_oid_len] = 0;
        {
            char    oidstr[200];
            int len2 = snprint_objid(oidstr, 200, temp_oid , temp_oid_len);
            oidstr[len2] = 0;
            log_message("wdmagent_token", "make_and_send_control_notification 1 %s ", oidstr);
        }

        netsnmp_table_data_set_storage* ds = netsnmp_table_data_set_find_column(row->data, notifCol[colIndex]);
        if(!ds)
        {
            if(notification_vars)
                snmp_free_varbind(notification_vars);
            log_message("wdmagent_token", "in trap 901 ds failed, %d, %d", colIndex, notifCol[colIndex]);
            return;
        }
        if (ds->type == ASN_INTEGER)
        {
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_INTEGER,
                    (long*) ds->data.integer,
                    sizeof (long));
            if(!returnVar)
                return;
        }
        else if(ds->type == ASN_OCTET_STR)
        {
            returnVar = snmp_varlist_add_variable(&notification_vars,
                    temp_oid, temp_oid_len,
                    ASN_OCTET_STR,
                    (u_char*) ds->data.string,
                    ds->data_len);
            if(!returnVar)
                return;
        }
    }
    
    add_cardType_to_variable_bindings(shelf, slot, &notification_vars);
    add_eventLocatoin_to_variable_bindings(shelf, slot, 0, 0, &notification_vars);
    add_systemTime_to_variable_bindings(&notification_vars);

    if (notification_vars)
    {
//        log_message("wdmagent_token", "in control trap 8 %d", objid_snmptrap_len);
        wdm_send_and_save_v2Trap(notification_vars);
    }
}

void    update_system_datetime(byte*    dt)
{
    memcpy(sysDateTime, dt, 11);
}

void    update_sysdatetime()
{
    static byte timecounter = 0;
    if(timecounter++ > 10)
    {
        time_t t;
        struct tm* t1;
        t = time(NULL);
        t1 = localtime(&t);
        byte    dt[11];
        *(word*)&dt[0] =  t1->tm_year + 1900;
        byte tmp = dt[0];
        dt[0] = dt[1];
        dt[1] = tmp;    
        dt[2] =  t1->tm_mon + 1;
        dt[3] =  t1->tm_mday;
        dt[4] =  t1->tm_hour;
        dt[5] =  t1->tm_min;
        dt[6] =  t1->tm_sec;
        dt[7] = 0;
        dt[8] = '+';
        dt[9] = 0;
        dt[10] = 0;
        update_system_datetime(dt);
        
        send_scalar_ind_changed(sysDateTime_oid, OID_LENGTH(sysDateTime_oid), ASN_OCTET_STR, sysDateTime, 11);
    }
}

void add_eventLocatoin_to_variable_bindings(byte shelf, byte slot, byte modNo, byte laneNo, netsnmp_variable_list **notification_vars)
{
    byte location[20];
    location[0] = shelf;
    location[1] = slot;
    location[2] = modNo;
    location[3] = laneNo;

    log_message("wdmCfpTable_token", "add_eventLocatoin_to_variable_bindings %d, %d, %d", slot, modNo, OID_LENGTH(eventLocation_oid));
    
    netsnmp_variable_list *returnVar = NULL;
    returnVar = snmp_varlist_add_variable(notification_vars,
            eventLocation_oid, OID_LENGTH(eventLocation_oid),
            ASN_OCTET_STR,
            (u_char*) location,
            4);
}

void add_cardType_to_variable_bindings(byte shelf, byte slot, netsnmp_variable_list **notification_vars)
{
//    return;
    
    netsnmp_table_row* row;
    size_t dataset_oid_len;
    size_t temp_oid_len;
    oid* temp_oid = NULL;
    oid* datasetOid;
    netsnmp_table_data_set_storage* ds= NULL;
    stIndexStructure s[2];
    s[0].type = ASN_INTEGER;
    s[0].value.Id = shelf;
    s[1].type = ASN_INTEGER;
    s[1].value.Id = slot;
    give_cardtable_oid_len(&datasetOid, &dataset_oid_len);
    row = find_row_in_dataset(wdmCardTable, s, 2);
    if(!row)
        return;
    
    temp_oid = (oid*) malloc((dataset_oid_len + 3 + row->index_oid_len) * sizeof (oid));
    memcpy(temp_oid, datasetOid, dataset_oid_len * sizeof (oid));
    ds = (netsnmp_table_data_set_storage*) row->data;
    ds = netsnmp_table_data_set_find_column(ds, 3);
    if(!ds)
    {
        free(temp_oid);
        return;
    }
    byte ctype = ds->data.string[0];
    temp_oid[dataset_oid_len] = 1; //entry
    temp_oid[dataset_oid_len + 1] = 3;
    memcpy(&temp_oid[dataset_oid_len + 2], row->index_oid, row->index_oid_len * sizeof (oid));
    temp_oid_len = dataset_oid_len + 2 + row->index_oid_len;
    temp_oid[temp_oid_len] = 0;
    netsnmp_variable_list *returnVar = NULL;

    log_message("wdmCfpTable_token", "add_cardType_to_variable_bindings %d, %d, %d", slot, ctype, temp_oid_len);

    returnVar = snmp_varlist_add_variable(notification_vars,
            temp_oid, temp_oid_len,
            ASN_OCTET_STR,
            (u_char*) &ctype,
            1);
    free(temp_oid);
}

void add_systemTime_to_variable_bindings(netsnmp_variable_list **notification_vars)
{
    byte systime[11];
    time_t t;
    struct tm* t1;
    t = time(NULL);
    t1 = localtime(&t);
    *(word*)&systime[0] =  t1->tm_year + 1900;
    byte tmp = systime[0];
    systime[0] = systime[1];
    systime[1] = tmp;    
    systime[2] = t1->tm_mon + 1;
    systime[3] = t1->tm_mday;
    systime[4] = t1->tm_hour;
    systime[5] = t1->tm_min;
    systime[6] = t1->tm_sec;
    systime[7] = 0;
    systime[8] = '+';
    systime[9] = 0;
    systime[10] = 0;    
    netsnmp_variable_list *returnVar = NULL;
    returnVar = snmp_varlist_add_variable(notification_vars,
            sysDateTime_oid, OID_LENGTH(sysDateTime_oid),
            ASN_OCTET_STR,
            (u_char*) &systime,
            11);
}

void    delete_related_card_traps_from_queue(byte shelf, byte slot)
{
    pthread_mutex_lock(&trapSendingQmutex);
    stMsgNode_t* msgNode = trapSendingMessageListHead;
    stMsgNode_t* prevNode = NULL;
    while(msgNode)
    {
        byte*   buf = msgNode->Msg;
        if(buf && msgNode->Size >= 7)
        {
            if(buf[1] == shelf && buf[2] == slot)
            {
                if(buf[6] != NOTIF_CARD_ADDED && buf[6] != NOTIF_CARD_REMOVED &&
                   buf[6] != NOTIF_CARD_MISMATCH_RAISE && buf[6] != NOTIF_CARD_MISMATCH_RECOV)
                {
                    free(msgNode->Msg);
                    if(prevNode)
                        prevNode->Next = msgNode->Next;
                    else
                        trapSendingMessageListHead = msgNode->Next;
                    free(msgNode);
                    if(prevNode)
                        msgNode = prevNode->Next;
                    else
                        msgNode = trapSendingMessageListHead;
                    continue;
                }
            }
        }
        prevNode = msgNode;
        msgNode = msgNode->Next;
    }
    pthread_mutex_unlock(&trapSendingQmutex);		
}

void    delete_related_module_traps_from_queue(byte shelf, byte slot, byte modno)
{
    pthread_mutex_lock(&trapSendingQmutex);
    stMsgNode_t* msgNode = trapSendingMessageListHead;
    stMsgNode_t* prevNode = NULL;
    while(msgNode)
    {
        byte*   buf = msgNode->Msg;
        if(buf && msgNode->Size >= 7)
        {
            if(buf[1] == shelf && buf[2] == slot && buf[3] == modno)
            {
                if(buf[6] != NOTIF_MODULE_ADDED && buf[6] != NOTIF_MODULE_REMOVED)
                {
                    free(msgNode->Msg);
                    if(prevNode)
                        prevNode->Next = msgNode->Next;
                    else
                        trapSendingMessageListHead = msgNode->Next;
                    free(msgNode);
                    if(prevNode)
                        msgNode = prevNode->Next;
                    else
                        msgNode = trapSendingMessageListHead;
                    continue;
                }
            }
        }
        prevNode = msgNode;
        msgNode = msgNode->Next;
    }
    pthread_mutex_unlock(&trapSendingQmutex);		
}

byte give_module_current_alarm(byte shelf, byte slot, byte modno, byte ctype, byte mtype, byte index)
{
    netsnmp_table_row* row = NULL;
    netsnmp_table_data_set_storage* ds;
    stIndexStructure s[3];
    s[0].type = ASN_INTEGER;
    s[0].value.Id = shelf;
    s[1].type = ASN_INTEGER;
    s[1].value.Id = slot;
    s[2].type = ASN_INTEGER;
    s[2].value.Id = modno;

    if(mtype == SFP_MODULE_TYPE)
        row = find_row_in_dataset(wdmSfpTable, s, 3);
    else if(mtype == XFP_MODULE_TYPE)
        row = find_row_in_dataset(wdmXfpTable, s, 3);
    else
        return 0;
    
    if(!row)
        return 0;
    ds = netsnmp_table_data_set_find_column((netsnmp_table_data_set_storage*) row->data, 7);
    if(!ds)
        return 0;
    if(ds->data_len == 8 && index <= 6)
        return  ds->data.string[index + 1];
    return 0;
}

byte find_alarm_severity(byte shelf, byte slot, byte modno, byte ctype, byte mtype, byte col, byte alType)
{
    stIndexStructure s[3];
    netsnmp_table_row* row = NULL;
    netsnmp_table_data_set_storage* ds;
    s[0].type = ASN_INTEGER;
    s[0].value.Id = shelf;
    s[1].type = ASN_INTEGER;
    s[1].value.Id = slot;
    s[2].type = ASN_INTEGER;
    s[2].value.Id = modno;

    if(mtype == SFP_MODULE_TYPE)
    {
        row = find_row_in_dataset(wdmSfpTable, s, 3);
        if(!row)
            return 0;
        ds = netsnmp_table_data_set_find_column((netsnmp_table_data_set_storage*) row->data, col);
        if(!ds)
            return 0;
        byte sev[4];
        memcpy(sev, ds->data.string, 4);
        if(alType == 1)
            return  2 ^ (sev[0] - 1);
        else if(alType == 2)
            return  2 ^ (sev[2] - 1);
        else if(alType == 3)
            return  2 ^ (sev[3] - 1);
        else if(alType == 4)
            return  2 ^ (sev[1] - 1);
        else if(alType == 0)
        {
            if(col == 50 || col == 51 || col == 52) //los, ls, txfault
                return 2 ^ (sev[0] - 1);
        }
            
    }
    else if(mtype == XFP_MODULE_TYPE)
    {
        row = find_row_in_dataset(wdmXfpTable, s, 3);
        if(!row)
            return 0;
        ds = netsnmp_table_data_set_find_column((netsnmp_table_data_set_storage*) row->data, col);
        if(!ds)
            return 0;
        byte sev[4];
        memcpy(sev, ds->data.string, 4);
        if(alType == 1)
            return  2 ^ (sev[0] - 1);
        else if(alType == 2)
            return  2 ^ (sev[2] - 1);
        else if(alType == 3)
            return  2 ^ (sev[3] - 1);
        else if(alType == 4)
            return  2 ^ (sev[1] - 1);
        else if(alType == 0)
        {
            if(col == 50 || col == 51 || col == 52) //los, ls, txfault severity
                return 2 ^ (sev[0] - 1);
        }
    }
    else if(mtype == OPSW_SFP_TYPE || mtype == OPSW_LATCH_TYPE || mtype == OPSW_NOLATCH_TYPE)
    {
        row = find_row_in_dataset(wdmOPSwitchTable, s, 3);
        if(!row)
            return 0;
        ds = netsnmp_table_data_set_find_column((netsnmp_table_data_set_storage*) row->data, col);
        if(!ds)
            return 0;
        byte sev = ds->data.string[0];
        if(alType == 1)
            return  2 ^ (sev - 1);
    }
    else if(mtype == EDFA_MODULE_TYPE)
    {
        row = find_row_in_dataset(wdmEdfaModuleTable, s, 3);
        if(!row)
            return 0;
        ds = netsnmp_table_data_set_find_column((netsnmp_table_data_set_storage*) row->data, col);
        if(!ds)
            return 0;
        byte sev = ds->data.string[0];
        if(alType == 1)
            return  2 ^ (sev - 1);
    }
    return 0;
}

void    ind_qsfp_notification(byte shelf, byte slot, byte ctype, byte mtype, byte modno, char* Info, word len)
{
    int   nCAl = 0, nJAl = 0, nNAl = 0,  nW = 0;
    byte alarmtype, alarmSeverity;
    byte notifCols[10];
    byte nCols = 0;
    byte laneCols[10];
    byte nlaneCols = 0;
    
    byte tempAlarm = 0;
    byte rxPWRAlarm = 0;
    byte txBiasAlarm = 0;
    byte txPWRAlarm = 0;
    byte losAlarm = 0;
    byte lsAlarm = 0;
    byte txFaultAlarm = 0;

    
    byte sevVal[10], sevLen, sevtyp;
    
    byte ptr = 0;
    tempAlarm = Info[ptr];

    rxPWRAlarm = Info[1];
    txBiasAlarm = Info[2];
    txPWRAlarm = Info[3];
    losAlarm = Info[4];
    lsAlarm = Info[5];
    txFaultAlarm = Info[6];
    
    byte i = 0;
    
    
    if (len < 16)
        return; 

    if (Info[ptr] & 0x80)//tempAlarm
    {
        alarmtype = ((Info[ptr] >> 4) & 0x07);
        alarmSeverity = Info[ptr] & 0x0F;
        nCols = 0;
        notifCols[nCols++] = 34;
        if(alarmSeverity)
        {
            notifCols[nCols++] = 57; //tempSeverity
            switch(alarmtype)
            {
                case 1: notifCols[nCols++] = 19; break;//qsfpTempLAThreshold
                case 2: notifCols[nCols++] = 21; break;//qsfpTempLWThreshold
                case 3: notifCols[nCols++] = 20; break;//qsfpTempHWThreshold
                case 4: notifCols[nCols++] = 18; break;//qsfpTempHAThreshold
            }
        }
        if (Info[ptr] & 0x70)
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modTempNotifRaise_oid, OID_LENGTH(modTempNotifRaise_oid), notifCols, nCols);
            if(Info[ptr] & 0x01)                nW++;
            else if(Info[ptr] & 0x02)           nNAl++;
            else if(Info[ptr] & 0x04)           nJAl++;
            else if(Info[ptr] & 0x08)           nCAl++;
        }
        else
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modTempNotifRecov_oid, OID_LENGTH(modTempNotifRecov_oid), notifCols, nCols);
            if(Info[ptr] & 0x01)                nW--;
            else if(Info[ptr] & 0x02)                nNAl--;
            else if(Info[ptr] & 0x04)                nJAl--;
            else if(Info[ptr] & 0x08)                nCAl--;
        }
    }
    ptr++;
    
    for(i = 0; i < 4; i++)
    {
        if (Info[ptr] & 0x80)//rxPowerAlarm1
        {
            alarmtype = ((Info[ptr] >> 4) & 0x07);
            alarmSeverity = Info[ptr] & 0x0F;
            nCols = 0;
            notifCols[nCols++] = 35 + i;//qsfpRXPower1..qsfpRXPower4
            if(alarmSeverity)                                                    
            {
                notifCols[nCols++] = 58; //qsfpRXPwrSeverity
                switch(alarmtype)
                {
                    case 1: notifCols[nCols++] = 23; break;//qsfpRXPwrLAThreshold
                    case 2: notifCols[nCols++] = 25; break;//qsfpRXPwrLWThreshold
                    case 3: notifCols[nCols++] = 24; break;//qsfpRXPwrHWThreshold
                    case 4: notifCols[nCols++] = 22; break;//qsfpRXPwrHAThreshold
                }
            }
            if (Info[ptr] & 0x70)
            {
                make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modrxpwrNotifRaise_oid, OID_LENGTH(modrxpwrNotifRaise_oid), notifCols, nCols);
                if(Info[ptr] & 0x01)                nW++;
                else if(Info[ptr] & 0x02)                nNAl++;
                else if(Info[ptr] & 0x04)                nJAl++;
                else if(Info[ptr] & 0x08)                nCAl++;
            }
            else
            {
                make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modrxpwrNotifRecov_oid, OID_LENGTH(modrxpwrNotifRecov_oid), notifCols, nCols);
                if(Info[ptr] & 0x01)                nW--;
                else if(Info[ptr] & 0x02)                nNAl--;
                else if(Info[ptr] & 0x04)                nJAl--;
                else if(Info[ptr] & 0x08)                nCAl--;
            }
        }
        ptr++;
    }    
    
    for(i = 0; i < 4; i++)//txBiasAlarm
    {
        if (Info[ptr] & 0x80)
        {
            alarmtype = ((Info[ptr] >> 4) & 0x07);
            alarmSeverity = Info[ptr] & 0x0F;
            nCols = 0;
            notifCols[nCols++] = 39 + i;//qsfpTXBias1..qsfpTXBias4
            if(alarmSeverity)                                                    
            {
                notifCols[nCols++] = 59; //qsfpTXBiasSeverity
                switch(alarmtype)
                {
                    case 1: notifCols[nCols++] = 27; break;//qsfpTXBiasLAThreshold
                    case 2: notifCols[nCols++] = 29; break;//qsfpTXBiasLWThreshold
                    case 3: notifCols[nCols++] = 28; break;//qsfpTXBiasHWThreshold
                    case 4: notifCols[nCols++] = 26; break;//qsfpTXBiasHAThreshold
                }
            }
            if (Info[ptr] & 0x70)
            {
                make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modtxbiasNotifRaise_oid, OID_LENGTH(modtxbiasNotifRaise_oid), notifCols, nCols);
                if(Info[ptr] & 0x01)                nW++;
                else if(Info[ptr] & 0x02)                nNAl++;
                else if(Info[ptr] & 0x04)                nJAl++;
                else if(Info[ptr] & 0x08)                nCAl++;
            }
            else
            {
                make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modtxbiasNotifRecov_oid, OID_LENGTH(modtxbiasNotifRecov_oid), notifCols, nCols);
                if(Info[ptr] & 0x01)                nW--;
                else if(Info[ptr] & 0x02)                nNAl--;
                else if(Info[ptr] & 0x04)                nJAl--;
                else if(Info[ptr] & 0x08)                nCAl--;
            }
        }
        ptr++;
    }    
    
    for(i = 0; i < 4; i++)//txPWRAlarm
    {
        if (Info[ptr] & 0x80)
        {
            alarmtype = ((Info[ptr] >> 4) & 0x07);
            alarmSeverity = Info[ptr] & 0x0F;
            nCols = 0;
            notifCols[nCols++] = 43 + i;//qsfpTXPower1..qsfpTXPower4
            if(alarmSeverity)                                                    
            {
                notifCols[nCols++] = 60; //qsfpTXPowerSeverity
                switch(alarmtype)
                {
                    case 1: notifCols[nCols++] = 31; break;//qsfpTXPowerLAThreshold
                    case 2: notifCols[nCols++] = 33; break;//qsfpTXPowerLWThreshold
                    case 3: notifCols[nCols++] = 32; break;//qsfpTXPowerHWThreshold
                    case 4: notifCols[nCols++] = 30; break;//qsfpTXPowerHAThreshold
                }
            }
            if (Info[ptr] & 0x70)
            {
                make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modtxpwrNotifRaise_oid, OID_LENGTH(modtxpwrNotifRaise_oid), notifCols, nCols);
                if(Info[ptr] & 0x01)                nW++;
                else if(Info[ptr] & 0x02)                nNAl++;
                else if(Info[ptr] & 0x04)                nJAl++;
                else if(Info[ptr] & 0x08)                nCAl++;
            }
            else
            {
                make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modtxpwrNotifRecov_oid, OID_LENGTH(modtxpwrNotifRecov_oid), notifCols, nCols);
                if(Info[ptr] & 0x01)                nW--;
                else if(Info[ptr] & 0x02)                nNAl--;
                else if(Info[ptr] & 0x04)                nJAl--;
                else if(Info[ptr] & 0x08)                nCAl--;
            }
        }
        ptr++;
    }    
    
    if (Info[ptr] & 0x80) //losAlarm
    {
        alarmtype = ((Info[ptr] >> 4) & 0x07);
        alarmSeverity = Info[ptr] & 0x0F;
        nCols = 0;
        notifCols[nCols++] = 4;//qsfpLos
        if(alarmSeverity)                                                    
            notifCols[nCols++] = 61; //qsfpLOSSeverity
        if (Info[ptr] & 0x70)
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modlosNotifRaise_oid, OID_LENGTH(modlosNotifRaise_oid), notifCols, nCols);
            if(Info[ptr] & 0x01)                nW++;
            else if(Info[ptr] & 0x02)                nNAl++;
            else if(Info[ptr] & 0x04)                nJAl++;
            else if(Info[ptr] & 0x08)                nCAl++;
        }
        else
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modlosNotifRecov_oid, OID_LENGTH(modlosNotifRecov_oid), notifCols, nCols);
            if(Info[ptr] & 0x01)                nW--;
            else if(Info[ptr] & 0x02)                nNAl--;
            else if(Info[ptr] & 0x04)                nJAl--;
            else if(Info[ptr] & 0x08)                nCAl--;
        }
    }
    ptr++;

    if (Info[ptr] & 0x80) //lsAlarm
    {
        alarmtype = ((Info[ptr] >> 4) & 0x07);
        alarmSeverity = Info[ptr] & 0x0F;
        nCols = 0;
        notifCols[nCols++] = 5;//qsfpLs
        if(alarmSeverity)                                                    
            notifCols[nCols++] = 62; //qsfpLSSeverity
        if (Info[ptr] & 0x70)
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modlsNotifRaise_oid, OID_LENGTH(modlsNotifRaise_oid), notifCols, nCols);
            if(Info[ptr] & 0x01)                nW++;
            else if(Info[ptr] & 0x02)                nNAl++;
            else if(Info[ptr] & 0x04)                nJAl++;
            else if(Info[ptr] & 0x08)                nCAl++;
        }
        else
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modlsNotifRecov_oid, OID_LENGTH(modlsNotifRecov_oid), notifCols, nCols);
            if(Info[ptr] & 0x01)                nW--;
            else if(Info[ptr] & 0x02)                nNAl--;
            else if(Info[ptr] & 0x04)                nJAl--;
            else if(Info[ptr] & 0x08)                nCAl--;
        }
    }
    ptr++;
   
    if (Info[ptr] & 0x80) //txFaultAlarm
    {
        alarmtype = ((Info[ptr] >> 4) & 0x07);
        alarmSeverity = Info[ptr] & 0x0F;
        nCols = 0;
        notifCols[nCols++] = 49;//qsfpTXFault
        if(alarmSeverity)                                                    
            notifCols[nCols++] = 63; //qsfpTXFaultSeverity
        if (Info[ptr] & 0x70)
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modtxfltNotifRaise_oid, OID_LENGTH(modtxfltNotifRaise_oid), notifCols, nCols);
            if(Info[ptr] & 0x01)                nW++;
            else if(Info[ptr] & 0x02)                nNAl++;
            else if(Info[ptr] & 0x04)                nJAl++;
            else if(Info[ptr] & 0x08)                nCAl++;
        }
        else
        {
            make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modtxfltNotifRecov_oid, OID_LENGTH(modtxfltNotifRecov_oid), notifCols, nCols);
            if(Info[ptr] & 0x01)                nW--;
            else if(Info[ptr] & 0x02)                nNAl--;
            else if(Info[ptr] & 0x04)                nJAl--;
            else if(Info[ptr] & 0x08)                nCAl--;
        }
    }
    
    ptr++;

    if (len > ptr)
    {
        if (Info[ptr] & 0x80)
        {
            alarmtype = ((Info[ptr] >> 4) & 0x07);
            nCols = 0;
            notifCols[nCols++] = 51;//qsfpSoftTXDisable
            notifCols[nCols++] = 62; //qsfpLSSeverity
            if (Info[ptr] & 0x70)
            {
                make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modtxDisableNotifRaise_oid, OID_LENGTH(modtxDisableNotifRaise_oid), notifCols, nCols);
                if(Info[ptr] & 0x01)                nW++;
                else if(Info[ptr] & 0x02)                nNAl++;
                else if(Info[ptr] & 0x04)                nJAl++;
                else if(Info[ptr] & 0x08)                nCAl++;
            }
            else
            {
                make_and_send_module_notification(shelf, slot, ctype, mtype, modno, Info[ptr], modtxDisableNotifRecov_oid, OID_LENGTH(modtxDisableNotifRecov_oid), notifCols, nCols);
                if(Info[ptr] & 0x01)                nW--;
                else if(Info[ptr] & 0x02)                nNAl--;
                else if(Info[ptr] & 0x04)                nJAl--;
                else if(Info[ptr] & 0x08)                nCAl--;
            }
        }
    }
    update_qsfp_nAlarms(shelf, slot, modno, nCAl, nJAl, nNAl, nW);
}

void    ind_control_notification(byte shelf, byte slot, byte ctype, byte mtype, byte modno, char* Info, word len)
{
    byte ctrl5vAlarm = Info[0];
    byte ctrlwallAlarm = Info[1];
    byte ctrl33vAlarm = Info[2];
    byte ctrl12vAlarm = Info[3];
    byte ctrlPwr1Alarm = Info[4];
    byte ctrlPwr2Alarm = Info[5];
    byte ctrlTempAlarm = Info[6];
    byte ctrlFanAlarm = Info[7];
    int   nCAl = 0, nJAl = 0, nNAl = 0,  nW = 0;
    byte alarmtype, alarmSeverity;

    byte notifCols[10];
    byte nCols = 0;
    if (ctrlTempAlarm & 0x80)
    {
        alarmtype = ((ctrlTempAlarm >> 4) & 0x07);
        alarmSeverity = ctrlTempAlarm & 0x0F;
        nCols = 0;
        notifCols[nCols++] = 10;//temperature
        if(alarmSeverity)
        {
            notifCols[nCols++] = 34; //TemperatureSeverity
            switch(alarmtype)
            {
                case 1:
                    notifCols[nCols++] = 18;//TemperatureLAThrsh
                    break;
                case 4:
                    notifCols[nCols++] = 26;//TemperatureHAThrsh
                    break;
            }
        }
        if (ctrlTempAlarm & 0x70)
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfTemperatureNotifRaise_oid, OID_LENGTH(shelfTemperatureNotifRaise_oid), notifCols, nCols);
            if(ctrlTempAlarm & 0x01)
                nW++;
            else if(ctrlTempAlarm & 0x02)
                nNAl++;
            else if(ctrlTempAlarm & 0x04)
                nJAl++;
           else if(ctrlTempAlarm & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfTemperatureNotifRecov_oid, OID_LENGTH(shelfTemperatureNotifRecov_oid), notifCols, nCols);
            if(ctrlTempAlarm & 0x01)
                nW--;
            else if(ctrlTempAlarm & 0x02)
                nNAl--;
            else if(ctrlTempAlarm & 0x04)
                nJAl--;
           else if(ctrlTempAlarm & 0x08)
                nCAl--;
        }
    }

    if (ctrl5vAlarm & 0x80)
    {
        alarmtype = ((ctrl5vAlarm >> 4) & 0x07);
        alarmSeverity = ctrl5vAlarm & 0x0F;
        nCols = 0;
        notifCols[nCols++] = 4;
        if(alarmSeverity)
        {
            notifCols[nCols++] = 28; 
            switch(alarmtype)
            {
                case 1:
                    notifCols[nCols++] = 12;
                    break;
                case 4:
                    notifCols[nCols++] = 20;
                    break;
            }
        }
        if (ctrl5vAlarm & 0x70)
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfVol5vNotifRaise_oid, OID_LENGTH(shelfVol5vNotifRaise_oid), notifCols, nCols);
            if(ctrl5vAlarm & 0x01)
                nW++;
            else if(ctrl5vAlarm & 0x02)
                nNAl++;
            else if(ctrl5vAlarm & 0x04)
                nJAl++;
           else if(ctrl5vAlarm & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfVol5vNotifRecov_oid, OID_LENGTH(shelfVol5vNotifRecov_oid), notifCols, nCols);
            if(ctrl5vAlarm & 0x01)
                nW--;
            else if(ctrl5vAlarm & 0x02)
                nNAl--;
            else if(ctrl5vAlarm & 0x04)
                nJAl--;
           else if(ctrl5vAlarm & 0x08)
                nCAl--;
        }
    }
    
    if (ctrl33vAlarm & 0x80)
    {
        alarmtype = ((ctrl33vAlarm >> 4) & 0x07);
        alarmSeverity = ctrl33vAlarm & 0x0F;
        nCols = 0;
        notifCols[nCols++] = 5;
        if(alarmSeverity)
        {
            notifCols[nCols++] = 29; 
            switch(alarmtype)
            {
                case 1:
                    notifCols[nCols++] = 13;
                    break;
                case 4:
                    notifCols[nCols++] = 21;
                    break;
            }
        }
        if (ctrl33vAlarm & 0x70)
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfVol33vNotifRaise_oid, OID_LENGTH(shelfVol33vNotifRaise_oid), notifCols, nCols);
            if(ctrl33vAlarm & 0x01)
                nW++;
            else if(ctrl33vAlarm & 0x02)
                nNAl++;
            else if(ctrl33vAlarm & 0x04)
                nJAl++;
           else if(ctrl33vAlarm & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfVol33vNotifRecov_oid, OID_LENGTH(shelfVol33vNotifRecov_oid), notifCols, nCols);
            if(ctrl33vAlarm & 0x01)
                nW--;
            else if(ctrl33vAlarm & 0x02)
                nNAl--;
            else if(ctrl33vAlarm & 0x04)
                nJAl--;
           else if(ctrl33vAlarm & 0x08)
                nCAl--;
        }
    }
    
    if (ctrlwallAlarm & 0x80)
    {
        alarmtype = ((ctrlwallAlarm >> 4) & 0x07);
        alarmSeverity = ctrlwallAlarm & 0x0F;
        nCols = 0;
        notifCols[nCols++] = 6;
        if(alarmSeverity)
        {
            notifCols[nCols++] = 30; 
            switch(alarmtype)
            {
                case 1:
                    notifCols[nCols++] = 14;
                    break;
                case 4:
                    notifCols[nCols++] = 22;
                    break;
            }
        }
        if (ctrlwallAlarm & 0x70)
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfVolWallNotifRaise_oid, OID_LENGTH(shelfVolWallNotifRaise_oid), notifCols, nCols);
            if(ctrlwallAlarm & 0x01)
                nW++;
            else if(ctrlwallAlarm & 0x02)
                nNAl++;
            else if(ctrlwallAlarm & 0x04)
                nJAl++;
           else if(ctrlwallAlarm & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfVolWallNotifRecov_oid, OID_LENGTH(shelfVolWallNotifRecov_oid), notifCols, nCols);
            if(ctrlwallAlarm & 0x01)
                nW--;
            else if(ctrlwallAlarm & 0x02)
                nNAl--;
            else if(ctrlwallAlarm & 0x04)
                nJAl--;
           else if(ctrlwallAlarm & 0x08)
                nCAl--;
        }
    }

    if (ctrl12vAlarm & 0x80)
    {
        alarmtype = ((ctrl12vAlarm >> 4) & 0x07);
        alarmSeverity = ctrl12vAlarm & 0x0F;
        nCols = 0;
        notifCols[nCols++] = 7;
        if(alarmSeverity)
        {
            notifCols[nCols++] = 31; 
            switch(alarmtype)
            {
                case 1:
                    notifCols[nCols++] = 15;
                    break;
                case 4:
                    notifCols[nCols++] = 23;
                    break;
            }
        }
        if (ctrl12vAlarm & 0x70)
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfVol12vNotifRaise_oid, OID_LENGTH(shelfVol12vNotifRaise_oid), notifCols, nCols);
            if(ctrl12vAlarm & 0x01)
                nW++;
            else if(ctrl12vAlarm & 0x02)
                nNAl++;
            else if(ctrl12vAlarm & 0x04)
                nJAl++;
           else if(ctrl12vAlarm & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfVol12vNotifRecov_oid, OID_LENGTH(shelfVol12vNotifRecov_oid), notifCols, nCols);
            if(ctrl12vAlarm & 0x01)
                nW--;
            else if(ctrl12vAlarm & 0x02)
                nNAl--;
            else if(ctrl12vAlarm & 0x04)
                nJAl--;
           else if(ctrl12vAlarm & 0x08)
                nCAl--;
        }
    }
    
    if (ctrlPwr1Alarm & 0x80)
    {
        alarmtype = ((ctrlPwr1Alarm >> 4) & 0x07);
        alarmSeverity = ctrlPwr1Alarm & 0x0F;
        nCols = 0;
        notifCols[nCols++] = 8;
        if(alarmSeverity)
        {
            notifCols[nCols++] = 32; 
            switch(alarmtype)
            {
                case 1:
                    notifCols[nCols++] = 16;
                    break;
                case 4:
                    notifCols[nCols++] = 24;
                    break;
            }
        }
        if (ctrlPwr1Alarm & 0x70)
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfVolPwr1NotifRaise_oid, OID_LENGTH(shelfVolPwr1NotifRaise_oid), notifCols, nCols);
            if(ctrlPwr1Alarm & 0x01)
                nW++;
            else if(ctrlPwr1Alarm & 0x02)
                nNAl++;
            else if(ctrlPwr1Alarm & 0x04)
                nJAl++;
           else if(ctrlPwr1Alarm & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfVolPwr1NotifRecov_oid, OID_LENGTH(shelfVolPwr1NotifRecov_oid), notifCols, nCols);
            if(ctrlPwr1Alarm & 0x01)
                nW--;
            else if(ctrlPwr1Alarm & 0x02)
                nNAl--;
            else if(ctrlPwr1Alarm & 0x04)
                nJAl--;
           else if(ctrlPwr1Alarm & 0x08)
                nCAl--;
        }
    }

    if (ctrlPwr2Alarm & 0x80)
    {
        alarmtype = ((ctrlPwr2Alarm >> 4) & 0x07);
        alarmSeverity = ctrlPwr2Alarm & 0x0F;
        nCols = 0;
        notifCols[nCols++] = 9;
        if(alarmSeverity)
        {
            notifCols[nCols++] = 33; 
            switch(alarmtype)
            {
                case 1:
                    notifCols[nCols++] = 17;
                    break;
                case 4:
                    notifCols[nCols++] = 25;
                    break;
            }
        }
        if (ctrlPwr2Alarm & 0x70)
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfVolPwr2NotifRaise_oid, OID_LENGTH(shelfVolPwr2NotifRaise_oid), notifCols, nCols);
            if(ctrlPwr2Alarm & 0x01)
                nW++;
            else if(ctrlPwr2Alarm & 0x02)
                nNAl++;
            else if(ctrlPwr2Alarm & 0x04)
                nJAl++;
           else if(ctrlPwr2Alarm & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfVolPwr2NotifRecov_oid, OID_LENGTH(shelfVolPwr2NotifRecov_oid), notifCols, nCols);
            if(ctrlPwr2Alarm & 0x01)
                nW--;
            else if(ctrlPwr2Alarm & 0x02)
                nNAl--;
            else if(ctrlPwr2Alarm & 0x04)
                nJAl--;
           else if(ctrlPwr2Alarm & 0x08)
                nCAl--;
        }
    }
    
    if (ctrlFanAlarm & 0x80)
    {
        alarmtype = ((ctrlFanAlarm >> 4) & 0x07);
        alarmSeverity = ctrlFanAlarm & 0x0F;
        nCols = 0;
        notifCols[nCols++] = 11;
        if(alarmSeverity)
        {
            notifCols[nCols++] = 35; 
            switch(alarmtype)
            {
                case 1:
                    notifCols[nCols++] = 19;
                    break;
                case 4:
                    notifCols[nCols++] = 27;
                    break;
            }
        }
        if (ctrlFanAlarm & 0x70)
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfFanSpeedNotifRaise_oid, OID_LENGTH(shelfFanSpeedNotifRaise_oid), notifCols, nCols);
            if(ctrlFanAlarm & 0x01)
                nW++;
            else if(ctrlFanAlarm & 0x02)
                nNAl++;
            else if(ctrlFanAlarm & 0x04)
                nJAl++;
           else if(ctrlFanAlarm & 0x08)
                nCAl++;
        }
        else
        {
            make_and_send_control_notification(shelf, slot, ctype, shelfFanSpeedNotifRecov_oid, OID_LENGTH(shelfFanSpeedNotifRecov_oid), notifCols, nCols);
            if(ctrlFanAlarm & 0x01)
                nW--;
            else if(ctrlFanAlarm & 0x02)
                nNAl--;
            else if(ctrlFanAlarm & 0x04)
                nJAl--;
           else if(ctrlFanAlarm & 0x08)
                nCAl--;
        }
    }
    update_shelf_nAlarms(shelf, nCAl, nJAl, nNAl, nW);
}

