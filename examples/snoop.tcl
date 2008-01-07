package require WPCAP

set devId 0
if {$argc!=0} {
  puts stderr "usage: snoop"
  return -1
}

set i 1
array set devIds ""
foreach {device} [WPCAP::devices "rpcap://" ] {
  puts "$i: [lindex $device 0]\n\t[lindex $device 1]"
  set devIds($i) "[lindex $device 0]"
  incr i
}

while {![info exists devIds($devId)]} {
  puts -nonewline "Select device: "
  flush stdout
  set devId [gets stdin]
}

WPCAP::new pcap1 $devIds($devId)

puts -nonewline "Provide filter (press enter for no filter): "
flush stdout
set filter [gets stdin]

pcap1 filter $filter

set mac {}

catch {
  foreach m [pcap1 mac] {
    lappend mac [format %02X $m] 
  }
}
puts "MAC address of adapter [join $mac :]"



proc snoop {} {
  while {![info exists stopsnoop]} {
    set res  [pcap1 recv]
    set status [lindex $res 0]
    if { $status=="timeout" } { continue }
    if { $status=="eof"} { puts stderr "End of tracefile reached" ; return 0 }
    
    set raw [lindex $res end]

    puts "------------------------------------------------"
    if { [catch {
        puts "Timestamp:\t[clock format [lindex $res 1] -format {%H:%M:%S} ].[lindex $res 2]" 
        puts "Source:\t\t[packet::srcip $raw]:[packet::srcport $raw]"
        puts "Destination:\t[packet::dstip $raw]:[packet::dstport $raw]"
      }] } { puts "Non-IP packet"}
    puts [packet::string2hex $raw]
  }
}
snoop

