#ifndef _WPCAP_TCL_H
#define _WPCAP_TCL_H

char *iptos(u_long in);
static int VersionCmd ( ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj * CONST objv[]) ;
static int DevicesCmd ( ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj * CONST objv[]) ;
static int AddressesCmd( ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj * CONST objv[]) ;
static int NewCmd ( ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj * CONST objv[]) ;
static int TransferCmd( ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj * CONST objv[]) ;

#endif _WPCAP_TCL_H
