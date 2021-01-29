/*
  BazaLoader behaviour, needs VirusTotal Enterprise
*/
import "vt"

rule BazaDomains {
condition:
(
  for any b in vt.behaviour.dns_lookups : (
  b.hostname contains "aaa-customwindows.com" or
  b.hostname contains "century-glassdallas.com" or
  b.hostname contains "door-framesolutions.com" or
  b.hostname contains "energy-onewindows.com" or
  b.hostname contains "expertglass-repair.com" or
  b.hostname contains "exproglassanddesign.com" or
  b.hostname contains "glass-houseofdallas.com" or
  b.hostname contains "glass-najiffy.com" or
  b.hostname contains "hellasconstrution.com" or
  b.hostname contains "mdglassdoorsandwindowsrepair.com" or
  b.hostname contains "millerwoodsworking.com" or
  b.hostname contains "mister-glassinc.com" or
  b.hostname contains "montgomeryglaspro.com" or
  b.hostname contains "topservicebin.com" or
  b.hostname contains "topserviceupd.com" or
  b.hostname contains "vaglassdoorsandwindowsrepair.com" or
  b.hostname contains "insideoutexprescarwash.com.com" or
  b.hostname contains "fastchangeonlline.com" or
  b.hostname contains "razcar-wash.com" or
  b.hostname contains "forevercleandetaili.com"
)
  and vt.metadata.new_file  
)
}

rule SuspectBazaDomains {
condition:
(
  for any b in vt.behaviour.dns_lookups : (
  b.hostname contains "door-framesolutions.com" or
  b.hostname contains "driveautoupdate.com" or
  b.hostname contains "freightsexpressdelivery.com" or
  b.hostname contains "gazeteaxpres.com" or
  b.hostname contains "montgomeryglaspro.com" or
  b.hostname contains "parcelabcstat.comm" or
  b.hostname contains "resolutionplatform.com" or
  b.hostname contains "scott-exteriors.com" or
  b.hostname contains "secure-device-now.com" or
  b.hostname contains "secure-phone-now.com" or
  b.hostname contains "secure-system-now.com" or
  b.hostname contains "service1elevate.com" or
  b.hostname contains "servicessilverroomhotspot.com" or
  b.hostname contains "thomasincoatings.com"
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
