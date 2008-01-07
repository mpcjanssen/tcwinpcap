namespace eval packet {

  # copied from http://wiki.tcl.tk/3242 thanks RS
  proc string2hex {string} {
   set where 0
    set res {}
    while {$where<[string length $string]} {
      set str [string range $string $where [expr $where+15]]
      if {![binary scan $str H* t] || $t==""} break
      regsub -all (....) $t {\1 } t4
      regsub -all (..) $t {\1 } t2
      set asc ""
      foreach i $t2 {
        scan $i %2x c
        append asc [expr {$c>=32 && $c<=127? [format %c $c]: "."}]
      }
      lappend res [format "%7.7x: %-42s %s" $where $t4  $asc]
      incr where 16
    }
    join $res \n
  }

  proc srcip { raw } {
    if { [type $raw] ne "IP"} {
      error "cannot get source IP of non-ip packet"
    }
    set raw_ip [string range $raw 26 29]
    return [raw2dotted $raw_ip]
  }

  proc dstip { raw } {
    if { [type $raw] ne "IP"} {
      error "cannot get destination IP of non-ip packet"
    }
    set raw_ip [string range $raw 30 33]
    return [raw2dotted $raw_ip]
  } 

  proc srcport { raw } {
    if { [type $raw] ne "IP"} {
      error "cannot get source port of non-ip packet"
    }
    set raw_port [string range $raw 34 35]
    scan $raw_port %c%c hi lo
    expr {$hi*256 + $lo}
  }

  proc dstport { raw } {
    if { [type $raw] ne "IP"} {
      error "cannot get destination port of non-ip packet"
    }
    set raw_port [string range $raw 36 37]
    scan $raw_port %c%c hi lo
    expr {$hi*256 + $lo}
  }

  proc type {raw} {
    if {[string range $raw 12 13] eq "\x08\x00"} {
      return IP
    } else {
      return unknown
    }
  }

  proc raw2dotted {raw_ip} {
    set ip {}
    foreach byte [split $raw_ip {}] {
      lappend ip [scan $byte %c]
    }
    join $ip .
  }

  proc dotted2raw {ip} {
      set numbers [split $ip .]
      if {[llength $numbers] != 4 } {
	  error "invalid IP address: $ip"
      }
      foreach {a b c d} $numbers { return [binary format cccc $a $b $c $d] }
  }
}
load [file dirname [info script]]/tclwpcap06.dll WPCAP
