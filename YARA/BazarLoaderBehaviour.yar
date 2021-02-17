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
  b.hostname contains "finderout.com" or
  b.hostname contains "trywd.com" or
  b.hostname contains "laboratorer.com" or
  b.hostname contains "lionpick.com" or
  b.hostname contains "quickomni.com" or
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

rule BazaLogo
{
condition:
	uint16(0) == 0x5a4d and
	vt.metadata.new_file and
    vt.metadata.main_icon.dhash == "8c129252dac82482"
}

rule BazaLogo2
{
condition:
	uint16(0) == 0x5a4d and
	vt.metadata.new_file and
    vt.metadata.main_icon.dhash == "4a929212dbc824c3"
}

rule BazaLogo3
{
condition:
	uint16(0) == 0x5a4d and
	vt.metadata.new_file and
    vt.metadata.main_icon.dhash == "64e4c8d0f0e8d4d4"
}

rule BazaLogo4
{
condition:
	uint16(0) == 0x5a4d and
	vt.metadata.new_file and
    vt.metadata.main_icon.dhash == "0c129212dbc82493"
}

rule BazaStrikeDroppy {
  condition:
    for any file_dropped in vt.behaviour.files_dropped : (
      file_dropped.path contains "Downloads\\"
    ) and
    for any file_dropped in vt.behaviour.files_dropped : (
      file_dropped.path contains ".exe.Config"
    ) and
    for any file_dropped in vt.behaviour.files_dropped : (
      file_dropped.path contains ".exe.1000.Manifest"
    ) and
    uint16(0) == 0x5a4d and
    vt.metadata.new_file
}
