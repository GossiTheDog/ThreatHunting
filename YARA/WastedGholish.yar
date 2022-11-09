/*
  SocGholish
*/

import "vt"

rule GenericSocGholish
{
  strings:
    $0 = {647C73636F7065642C4B3D5B78323074726E665D2C4C3D283F3A2E7C5B772D5D7C5B5E302D7861305D292B2C4D3D5B2B4B2B282B4C2B29283F3A2B4B2B285B5E247C217E5D3F3D292B4B2B283F3A28283F3A2E7C5B5E5D29297C28283F3A2E7C5B5E5D29297C282B4C2B29297C292B4B2B5D2C4E3D3A282B4C2B29283F}
		$1 = {28297D7D293B7661722079623D253230672C7A623D232E242C41623D285B3F265D295F3D5B5E265D2C42623D5E282E3F293A5B20745D285B5E726E5D2924676D2C43623D5E283F3A61626F75747C6170707C617070}
		$2 = {6E746578742C423D5E3C285B612D7A5D5B5E303E3A78323074726E665D295B78323074726E665D3F3E283F3A3C313E7C2924692C433D5E2E5B5E3A235B2E2C5D243B66756E637469}
		$3 = {6F6E2924692C583D5E686424692C593D5E5B5E7B5D2B7B735B6E617469766520772C5A3D5E283F3A23285B772D5D2B297C28772B297C2E285B772D5D2B2929242C243D5B2B7E}
		$4 = {30323326647C3536333230297D2C62613D285B302D7831667837665D7C5E2D3F64297C5E2D247C5B5E302D7831667837662D7546464646772D5D672C63613D66}
  condition:
    vt.metadata.new_file and any of them
}

rule SocGholishC2Watchlist {
condition:
(
  for any a in vt.behaviour.http_conversations : (a.url contains "wholesalerandy.com") or
  for any b in vt.behaviour.dns_lookups : (b.hostname contains "wholesalerandy.com")
)

}

rule SocGholishC2WatchlistNew {
condition:
(
  for any a in vt.behaviour.http_conversations : (a.url contains "cdn.familyfocus.us") or
  for any b in vt.behaviour.dns_lookups : (b.hostname contains "cdn.familyfocus.us")
)
}

rule SocGholishC2WatchlistOld {
condition:
(
  for any a in vt.behaviour.http_conversations : (a.url contains "auth.codingbit.co.in") or
  for any b in vt.behaviour.dns_lookups : (b.hostname contains "auth.codingbit.co.in")
)

}

rule SocGholishC2WatchlistOlder {
condition:
(
  for any a in vt.behaviour.http_conversations : (a.url contains "user3.altcoinfan.com") or
  for any b in vt.behaviour.dns_lookups : (b.hostname contains "user3.altcoinfan.com")
)
}

rule SocGholishC2WatchlistIP {
condition:
(
  for any a in vt.behaviour.ip_traffic : (a.destination_ip contains "130.0.233.178")
)
}

rule SocGholish2022JSLoader
{
  strings:
    $0 = "\\[object ((I|Ui)nt(8|16|32)|Float(32|64)|Uint8Clamped|Big(I|Ui)nt64)Array\\]/,_0x"
  condition:
    vt.metadata.new_file and
    all of them
}
