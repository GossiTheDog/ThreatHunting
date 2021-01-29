/*
  BazaLoader behaviour, needs VirusTotal Enterprise
*/

import "vt"

rule BazaDomains {
condition:
(
  for any b in vt.behaviour.dns_lookups : (
  b.hostname contains "aaa-customwindows.com" and
  b.hostname contains "century-glassdallas.com" and
  b.hostname contains "door-framesolutions.com" and
  b.hostname contains "energy-onewindows.com" and
  b.hostname contains "expertglass-repair.com" and
  b.hostname contains "exproglassanddesign.com" and
  b.hostname contains "glass-houseofdallas.com" and
  b.hostname contains "glass-najiffy.com" and
  b.hostname contains "hellasconstrution.com" and
  b.hostname contains "mdglassdoorsandwindowsrepair.com" and
  b.hostname contains "millerwoodsworking.com" and
  b.hostname contains "mister-glassinc.com" and
  b.hostname contains "montgomeryglaspro.com" and
  b.hostname contains "topservicebin.com" and
  b.hostname contains "topserviceupd.com" and
  b.hostname contains "vaglassdoorsandwindowsrepair.com" and
  b.hostname contains "insideoutexprescarwash.com.com" and
  b.hostname contains "fastchangeonlline.com"
  )
  and vt.metadata.new_file  
)
}

rule BazaMutex {
  condition:
    for any mutex in vt.behaviour.mutexes_created : (
       mutex == "SIY4IE3YVC8G9E1P508ACR"
    )
    and vt.metadata.new_file
}
