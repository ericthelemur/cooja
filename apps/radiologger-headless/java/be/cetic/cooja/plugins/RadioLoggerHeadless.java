/*
 * Copyright (c) 2013, CETIC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLAR Y, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

package be.cetic.cooja.plugins;

import java.io.IOException;
import java.util.Observable;
import java.util.Observer;
import java.util.Collection;
import java.util.ArrayList;
import java.io.File;
import java.io.RandomAccessFile;

import org.jdom.Element;

import org.contikios.cooja.ClassDescription;
import org.contikios.cooja.Cooja;  //import org.contikios.cooja.GUI;
import org.contikios.cooja.PluginType;
import org.contikios.cooja.RadioConnection;
import org.contikios.cooja.RadioMedium;
import org.contikios.cooja.RadioPacket;
import org.contikios.cooja.Simulation;
import org.contikios.cooja.VisPlugin;
import org.contikios.cooja.interfaces.Radio;
//import org.contikios.cooja.plugins.analyzers.PacketAnalyser;
import org.contikios.cooja.plugins.analyzers.PcapExporter;

/**
 * Radio Logger which exports a pcap file only.
 * It was designed to support radio logging in COOJA's headless mode.
 * Based on Fredrik Osterlind's RadioLogger.java
 *
 * Based on RadioLoggerHeadless.java by primary
 * @author Laurent Deru
 * The work is the stepping stone for keeping separately between destined- and
 * overheard packets in this source code.
 *
 * @author Pasakorn Tiwatthanont
 * @revised 2015/06 - 2016
 */
@ClassDescription("Headless radio logger")
@PluginType(PluginType.SIM_PLUGIN)
public class RadioLoggerHeadless extends VisPlugin {
    private static final long serialVersionUID = -6927091711697081353L;

    private static final String pcapExt = ".pcap";

    private final Simulation simulation;
    private RadioMedium radioMedium;
    private Observer radioMediumObserver;
    private File pcapSendingFile;
    // private File [] pcapReceivingFile;
    private PcapExporter pcapSendingExporter;
    // private PcapExporter [] pcapReceivingExporter;
    private int motesCount;


    /** ***********************************************************************
     * Constructor
     *
     * @param sim
     * @param cooja
     */
    public RadioLoggerHeadless(final Simulation sim, final Cooja cooja) {
        super("Radio messages (RadioLoggerHeadless)", cooja, false);
        // System.err.println("Starting headless radio logger");

        simulation = sim;
        radioMedium = simulation.getRadioMedium();
        motesCount = simulation.getMotesCount();

        try {
            pcapSendingFile = null;
            pcapSendingExporter = new PcapExporter();
            // pcapReceivingFile = new File[motesCount];
            pcapReceivingExporter = new PcapExporter[motesCount];
            // for (int i = 0; i < motesCount; i++) {
            //     pcapReceivingFile[i] = null;
            //     pcapReceivingExporter[i] = new PcapExporter();
            // }
        } catch (IOException e) {
            System.err.println("RadioLogger: open PCAP files error!");
            e.printStackTrace();
        }

        startRadioObservation();
    }

    /** ***********************************************************************
     * Start the observer
     */
    public void startRadioObservation() {

        radioMediumObserver = new Observer() {
            @Override
            public void update(Observable obs, Object obj) {
                RadioConnection conn = radioMedium.getLastConnection();
                if (conn == null)
                    return;

                RadioPacket radioTxPacket = conn.getSource().getLastPacketTransmitted();
                byte [] packetData = radioTxPacket.getPacketData();
                long txTime = simulation.convertSimTimeToActualTime(conn.getStartTime());  //(int)System.currentTimeMillis() * 1000

                /**
                 * [iPAS]: From sender's view  */
                try {
                    pcapSendingExporter.exportPacketData(packetData, txTime);
                } catch (IOException e) {
                    System.err.println("RadioLogger: cannot export PCAP for senders!");
                    e.printStackTrace();
                }

                /**
                 * [iPAS]: From receiver's view  */
                //for (Radio radioRx : conn.getAllDestinations()) {  // All destination radios including interfered ones
                for (Radio radioRx : conn.getDestinations()) {  // All non-interfered radios
                    //RadioPacket radioRxPacket = radioRx.getLastPacketReceived();  // It is always null !?
                    
                    // try {
                    //     int i = radioRx.getMote().getID() - 1;
                    //     pcapReceivingExporter[i].exportPacketData(packetData, txTime);
                    // } catch (IOException e) {
                    //     System.err.println("RadioLogger: cannot export PCAP for receivers!");
                    //     e.printStackTrace();
                    // }
                }
            }
        };

        radioMedium.addRadioTransmissionObserver(radioMediumObserver);  // Add to the medium
    }

    /** ***********************************************************************
     * Stop the observer
     */
    public void stopRadioObservation() {
        if (radioMediumObserver != null)
            radioMedium.deleteRadioTransmissionObserver(radioMediumObserver);
    }

    /** ***********************************************************************
     * Called before close.
     */
    @Override
    public void closePlugin() {
        stopRadioObservation();
    }

    /** ***********************************************************************
     * Create PCAP output files
     */
    private void createPcapFiles(String fpath) {
        try {
            pcapSendingFile = simulation.getCooja().restorePortablePath(new File(fpath + pcapExt));
            pcapSendingExporter.openPcap(pcapSendingFile);
            // for (int i = 0; i < motesCount; i++) {
            //     pcapReceivingFile[i] = simulation.getCooja().restorePortablePath(
            //             new File(fpath + "_" + (i + 1) + pcapExt));
            //     pcapReceivingExporter[i].openPcap(pcapReceivingFile[i]);
            // }
        } catch (IOException e) {
            System.err.println("RadioLogger: cannot create PCAP file!");
            e.printStackTrace();
        }
    }

    /** ***********************************************************************
     *
     */
    private void reOpenPcap(PcapExporter pcap, File fi) {
        try {
            pcap.closePcap();
            pcap.openPcap(fi);
        } catch (IOException e) {
            System.err.println("RadioLogger: re-open PCAP file error!");
            e.printStackTrace();
        }
    }

    /** ***********************************************************************
     * Restart statistical values
     *  Make it clean & recreate the headers
     */
    public void restartStatistics() {
        reOpenPcap(pcapSendingExporter, pcapSendingFile);
        // for (int i = 0; i < motesCount; i++)
        //     reOpenPcap(pcapReceivingExporter[i], pcapReceivingFile[i]);
    }

    /** ***********************************************************************
     * Called on opening the plug-in.
     */
    @Override
    public boolean setConfigXML(Collection<Element> configXML, boolean visAvailable) {
        for (Element element : configXML) {
            String name = element.getName();
            if (name.equals("pcap_file")) {  // Read file-path configuration
                String fpath = element.getText();
                if (fpath.lastIndexOf(pcapExt) >= 0)
                    fpath = fpath.substring(0, fpath.lastIndexOf(pcapExt));
                createPcapFiles(fpath);  // Setup the exporters
                break;
            }
        }

        return true;
    }

    /** ***********************************************************************
     * Called before closing the plug-in.
     */
    @Override
    public Collection<Element> getConfigXML() {
        ArrayList<Element> configXML = new ArrayList<>();
        Element element;
        element = new Element("pcap_file");
        if (pcapSendingFile == null)
            pcapSendingFile = new File("determine_file_here.pcap");
        File file = simulation.getCooja().createPortablePath(pcapSendingFile);
        element.setText(file.getPath().replaceAll("\\\\", "/"));
        element.setAttribute("EXPORT", "discard");
        configXML.add(element);

        return configXML;
    }

}
