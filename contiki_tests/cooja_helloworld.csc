<?xml version="1.0" encoding="UTF-8"?>
<simconf>
  <simulation>
    <title>Hello World</title>
    <delaytime>0</delaytime>
    <ticktime>1</ticktime>
    <randomseed>123456</randomseed>
    <nrticklists>1</nrticklists>
    <motedelay>0</motedelay>
    <radiomedium>
      se.sics.cooja.radiomediums.UDGM
      <transmitting_range>50.0</transmitting_range>
      <interference_range>100.0</interference_range>
      <success_ratio_tx>1.0</success_ratio_tx>
      <success_ratio_rx>1.0</success_ratio_rx>
    </radiomedium>
    <motetype>
      se.sics.cooja.contikimote.ContikiMoteType
      <identifier>mtype3</identifier>
      <description>Contiki Mote #1</description>
      <contikibasedir>../../..</contikibasedir>
      <contikicoredir>../../../platform/cooja</contikicoredir>
      <compilefile>../apps/mrm</compilefile>
      <compilefile>../apps/mspsim</compilefile>
      <compilefile>../../../platform/cooja/testapps</compilefile>
      <compilefile>hello-world.c</compilefile>
      <process>hello_world_process</process>
      <sensor>button_sensor</sensor>
      <sensor>pir_sensor</sensor>
      <sensor>radio_sensor</sensor>
      <sensor>vib_sensor</sensor>
      <moteinterface>se.sics.cooja.interfaces.Position</moteinterface>
      <moteinterface>se.sics.cooja.interfaces.Battery</moteinterface>
      <moteinterface>se.sics.cooja.contikimote.interfaces.ContikiVib</moteinterface>
      <moteinterface>se.sics.cooja.contikimote.interfaces.ContikiMoteID</moteinterface>
      <moteinterface>se.sics.cooja.contikimote.interfaces.ContikiRS232</moteinterface>
      <moteinterface>se.sics.cooja.contikimote.interfaces.ContikiBeeper</moteinterface>
      <moteinterface>se.sics.cooja.contikimote.interfaces.ContikiIPAddress</moteinterface>
      <moteinterface>se.sics.cooja.contikimote.interfaces.ContikiRadio</moteinterface>
      <moteinterface>se.sics.cooja.contikimote.interfaces.ContikiButton</moteinterface>
      <moteinterface>se.sics.cooja.contikimote.interfaces.ContikiPIR</moteinterface>
      <moteinterface>se.sics.cooja.contikimote.interfaces.ContikiClock</moteinterface>
      <moteinterface>se.sics.cooja.contikimote.interfaces.ContikiLED</moteinterface>
      <moteinterface>se.sics.cooja.contikimote.interfaces.ContikiLog</moteinterface>
      <moteinterface>se.sics.cooja.contikimote.interfaces.ContikiCFS</moteinterface>
      <coreinterface>cfs_interface</coreinterface>
      <coreinterface>beep_interface</coreinterface>
      <coreinterface>button_interface</coreinterface>
      <coreinterface>radio_interface</coreinterface>
      <coreinterface>ip_interface</coreinterface>
      <coreinterface>leds_interface</coreinterface>
      <coreinterface>moteid_interface</coreinterface>
      <coreinterface>pir_interface</coreinterface>
      <coreinterface>rs232_interface</coreinterface>
      <coreinterface>vib_interface</coreinterface>
      <coreinterface>clock_interface</coreinterface>
      <coreinterface>simlog_interface</coreinterface>
      <symbols>false</symbols>
      <commstack>Rime</commstack>
    </motetype>
    <mote>
      se.sics.cooja.contikimote.ContikiMote
      <motetype_identifier>mtype3</motetype_identifier>
      <interface_config>
        se.sics.cooja.interfaces.Position
        <x>91.48300003917207</x>
        <y>83.5491879028037</y>
        <z>0.0</z>
      </interface_config>
      <interface_config>
        se.sics.cooja.contikimote.interfaces.ContikiMoteID
        <id>1</id>
      </interface_config>
      <interface_config>
        se.sics.cooja.contikimote.interfaces.ContikiIPAddress
        <ipv4address>10.10.15.14</ipv4address>
      </interface_config>
      <interface_config>
        se.sics.cooja.interfaces.Battery
        <infinite>false</infinite>
      </interface_config>
    </mote>
  </simulation>
</simconf>

