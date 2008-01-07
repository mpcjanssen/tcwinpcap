IFILE = tclwpcap
TCLDIR = c:\tcl84
TCLVERSION = 84
TCLLIB = $(TCLDIR)\lib\tclstub$(TCLVERSION).lib
PKG_VERSION = "0.6"
PKG_VERSION_DOTLESS = "06"
PKG_NAME = WPCAP
WPDPACK = ..\..\WpdPack

INCLUDES = /I$(TCLDIR)\include /I"$(WPDPACK)\include"
LIBS = $(TCLLIB) "$(WPDPACK)\lib\wpcap.lib" "$(WPDPACK)\lib\packet.lib"  Ws2_32.lib

tcl:: 
  cl /c /DPKG_VERSION=\"$(PKG_VERSION)\" /DUSE_TCL_STUBS /DWIN32 /DHAVE_REMOTE $(INCLUDES) $(IFILE).c
  link /out:$(IFILE)$(PKG_VERSION_DOTLESS).dll $(IFILE).obj $(LIBS) /dll

clean:
  del *.obj
  del *.dll
  del *.exp
  del *.lib
