#include <tcl.h>
#include <string.h>
#include <pcap-int.h>
#include <packet32.h>
#include <ntddndis.h>

#include "tclwpcap.h"

__declspec(dllexport)  int Wpcap_Init(Tcl_Interp *interp) {
  if (Tcl_InitStubs(interp, TCL_VERSION, 0) == 0L) {
    return TCL_ERROR;
  }
  Tcl_CreateObjCommand(interp, "::WPCAP::version", VersionCmd, NULL, NULL);
  Tcl_CreateObjCommand(interp, "::WPCAP::devices", DevicesCmd, NULL, NULL);
  Tcl_CreateObjCommand(interp, "::WPCAP::new", NewCmd, NULL, NULL);
  Tcl_PkgProvide(interp, "WPCAP", PKG_VERSION);
  return TCL_OK;
}

static int VersionCmd( ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj * CONST objv[]) {
  if(objc!=1) {
    Tcl_WrongNumArgs(interp,1,objv,NULL);
    return TCL_ERROR;
  }

  Tcl_SetObjResult(interp, Tcl_NewStringObj(pcap_lib_version(), -1));
  return TCL_OK;
}

static int DevicesCmd( ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj * CONST objv[]) {
  Tcl_Obj * device_list = Tcl_NewListObj(0,NULL);
  pcap_if_t *alldevs;
  pcap_if_t *d;
  int i=0;
  char errbuf[PCAP_ERRBUF_SIZE];
  char * src;

  if(objc!=2) {
    Tcl_WrongNumArgs(interp,1,objv,"sources");
    return TCL_ERROR;
  }

  src = Tcl_GetString(objv[1]);

  /* Retrieve the device list from the local machine */
  if (pcap_findalldevs_ex(src,NULL,&alldevs, errbuf) == -1)
  {
    Tcl_AppendResult(interp,"pcap_findalldevs_ex failed: '", errbuf, "'",NULL);
    return TCL_ERROR;
  }

  for(d= alldevs; d != NULL; d= d->next)
  {
    Tcl_Obj * device = Tcl_NewListObj(0,NULL);
    Tcl_ListObjAppendElement(interp,device,Tcl_NewStringObj(d->name,-1));
    Tcl_ListObjAppendElement(interp,device,Tcl_NewStringObj(d->description,-1));
    Tcl_ListObjAppendElement(interp,device_list,device);
  }

  /* We don't need the device list anymore, free it */
  pcap_freealldevs(alldevs);

  Tcl_SetObjResult(interp, device_list);
  return TCL_OK;
}

static int HandleCmd( ClientData adhandle, Tcl_Interp *interp, int objc, Tcl_Obj * CONST objv[]) {
  int inum;
  int i=0;
 
  PPACKET_OID_DATA  OidData;

  int res,index, packet_length;
  char * send_packet ;
  struct bpf_program fp;
  
  Tcl_Obj * lres ;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct tm *ltime;
  char timestr[16];
  struct pcap_pkthdr *header;
  u_char *pkt_data;
  Tcl_Obj * packet;
  static CONST char *options[] = {
    "recv",	"send", "mac", "filter",	(char *) NULL
  };
  enum options {
    RECV,	SEND, MAC, FILTER
  };	  

  if (objc < 2) {
    Tcl_WrongNumArgs(interp, 1, objv, "option ?arg?");
    return TCL_ERROR;
  }

  if (Tcl_GetIndexFromObj(interp, objv[1], options, "option", 0,
        &index) != TCL_OK) {
    return TCL_ERROR;
  }


  switch (index) {
    case FILTER:
      // Apply a new filter to the handle
      if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "filter filterexpression");
        return TCL_ERROR;
      }
      //compile the filter
      if (pcap_compile(adhandle, &fp, Tcl_GetString(objv[2]), 1, 0) < 0)
      {
        Tcl_AppendResult(interp,"unable to compile filter '", Tcl_GetString(objv[2]), "' check syntax",NULL);
        return TCL_ERROR;
      }
      if (pcap_setfilter(adhandle, &fp) < 0)
      {
        Tcl_AppendResult(interp,"unable to set filter",NULL);
        return TCL_ERROR;
      }
      return TCL_OK;
    case RECV:
      if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "recv");
        return TCL_ERROR;
      }
      res = pcap_next_ex( adhandle, &header, &pkt_data);
      lres = Tcl_NewListObj(0,NULL);
      if(res==-2) {
        // EOF in offline file
        Tcl_ListObjAppendElement(interp,lres,Tcl_NewStringObj("eof",-1));  
      } else if (res == 0) {
        Tcl_ListObjAppendElement(interp,lres,Tcl_NewStringObj("timeout",-1));  
      } else if (res == 1) {
        packet = Tcl_NewByteArrayObj(pkt_data, header->len);
        Tcl_ListObjAppendElement(interp,lres,Tcl_NewStringObj("ok",-1));  
        Tcl_ListObjAppendElement(interp,lres,Tcl_NewLongObj(header->ts.tv_sec));
        Tcl_ListObjAppendElement(interp,lres,Tcl_NewLongObj(header->ts.tv_usec));
        Tcl_ListObjAppendElement(interp,lres,packet);
      } else {
        Tcl_AppendResult(interp,"receive failed",NULL);
        return TCL_ERROR;
      }
      Tcl_SetObjResult(interp, lres);
      return TCL_OK;
      
  case SEND:
      if (objc != 3) {
        Tcl_WrongNumArgs(interp, 1, objv, "send packet");
        return TCL_ERROR;
      }
      send_packet = Tcl_GetByteArrayFromObj (objv[2], &packet_length);
      if (packet_length == 0) {
        /* Sending empty packets will put the handle in error state */
        /* after that no more packets can be sent until the handle is closed and a new one is opened */
        Tcl_AppendResult(interp, "cannot send an empty packet", NULL);
        return TCL_ERROR;
      }
      res = pcap_sendpacket(adhandle ,send_packet,packet_length) ;
      if (res!=0) {
        return TCL_ERROR;
      } else {
        return TCL_OK;
      }
  case MAC:
      if (objc != 2) {
        Tcl_WrongNumArgs(interp, 1, objv, "mac");
        return TCL_ERROR;
      }	
      OidData = malloc(6 + sizeof(PACKET_OID_DATA));
      if (OidData == NULL) 
      {
        fprintf(stderr, "error allocating memory for MAC address info!\n");
        exit(-1);
      }
      OidData->Oid = OID_802_3_CURRENT_ADDRESS;

      OidData->Length = 6;
      ZeroMemory(OidData->Data, 6);
	
      if(PacketRequest(((pcap_t *)adhandle)->adapter, FALSE, OidData))
      {

        
        Tcl_AppendResult(interp,
            Tcl_GetString(Tcl_NewIntObj((OidData->Data)[0])), " ", 
            Tcl_GetString(Tcl_NewIntObj((OidData->Data)[1])), " ",
            Tcl_GetString(Tcl_NewIntObj((OidData->Data)[2])), " ",
            Tcl_GetString(Tcl_NewIntObj((OidData->Data)[3])), " ",
            Tcl_GetString(Tcl_NewIntObj((OidData->Data)[4])), " ",
            Tcl_GetString(Tcl_NewIntObj((OidData->Data)[5])),
            NULL);
      }
      else
      {
        Tcl_AppendResult(interp,"unable to retreive MAC address of the adapter",NULL);
        free(OidData);
        return TCL_ERROR;
      }

      free(OidData);

      return TCL_OK;

  default:
      // should never happen
      Tcl_AppendResult(interp, "never has happened",NULL); 
      return TCL_ERROR;
  }

}

static int NewCmd( ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj * CONST objv[]) {
  Tcl_Obj * device;
  Tcl_Obj * cmd;
  pcap_t * addhandle ;
  int inum;
  int i=0;
  pcap_t *adhandle;
  int res;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct tm *ltime;
  char timestr[16];
  struct pcap_pkthdr *header;
  u_char *pkt_data;

  if(objc!=3) {
    Tcl_WrongNumArgs(interp,1,objv,"command device");
    return TCL_ERROR;
  }

  device = objv[2];
  cmd = objv[1];



  if ( (adhandle= pcap_open(Tcl_GetString(device),          // name of the device
          65536,            // portion of the packet to capture. 
          // 65536 guarantees that the whole packet will be captured on all the link layers
          PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
          1000,             // read timeout
          NULL,             // authentication on the remote machine
          errbuf            // error buffer
          ) ) == NULL)
  {
    return TCL_ERROR;
  }
  /* Define the packet commond */
  Tcl_CreateObjCommand(interp, Tcl_GetString(cmd), HandleCmd, adhandle, pcap_close);

  return TCL_OK;
}

