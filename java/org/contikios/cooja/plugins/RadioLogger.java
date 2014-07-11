/*
 * Copyright (c) 2009, Swedish Institute of Computer Science.
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
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
package org.contikios.cooja.plugins;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Observable;
import java.util.Observer;
import java.util.Properties;
import java.util.regex.PatternSyntaxException;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.ButtonGroup;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JFileChooser;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.KeyStroke;
import javax.swing.RowFilter;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import org.apache.log4j.Logger;
import org.jdom.Element;

import org.contikios.cooja.ClassDescription;
import org.contikios.cooja.ConvertedRadioPacket;
import org.contikios.cooja.Cooja;
import org.contikios.cooja.Plugin;
import org.contikios.cooja.PluginType;
import org.contikios.cooja.RadioConnection;
import org.contikios.cooja.RadioMedium;
import org.contikios.cooja.RadioPacket;
import org.contikios.cooja.Simulation;
import org.contikios.cooja.VisPlugin;
import org.contikios.cooja.dialogs.TableColumnAdjuster;
import org.contikios.cooja.interfaces.Radio;
import org.contikios.cooja.plugins.analyzers.ICMPv6Analyzer;
import org.contikios.cooja.plugins.analyzers.IEEE802154Analyzer;
import org.contikios.cooja.plugins.analyzers.IPHCPacketAnalyzer;
import org.contikios.cooja.plugins.analyzers.IPv6PacketAnalyzer;
import org.contikios.cooja.plugins.analyzers.PacketAnalyzer;
import org.contikios.cooja.plugins.analyzers.RadioLoggerAnalyzerSuite;
import org.contikios.cooja.util.StringUtils;

/**
 * Radio logger listens to the simulation radio medium and lists all transmitted
 * data in a table.
 *
 * @author Fredrik Osterlind
 */
@ClassDescription("Radio messages")
@PluginType(PluginType.SIM_PLUGIN)
public class RadioLogger extends VisPlugin {

  private static Logger logger = Logger.getLogger(RadioLogger.class);
  private static final long serialVersionUID = -6927091711697081353L;

  private final static int COLUMN_NO = 0;
  private final static int COLUMN_TIME = 1;
  private final static int COLUMN_FROM = 2;
  private final static int COLUMN_TO = 3;
  private final static int COLUMN_DATA = 4;

  private JSplitPane splitPane;
  private JTextPane verboseBox = null;

  private boolean formatTimeString = true;

  private final static String[] COLUMN_NAMES = {
    "No.        ",
    "Time ms",
    "From",
    "To",
    "Data"
  };

  private final Simulation simulation;
  private final JTable dataTable;
  private TableRowSorter<TableModel> logFilter;
  private ArrayList<RadioConnectionLog> connections = new ArrayList<RadioConnectionLog>();
  private RadioMedium radioMedium;
  private Observer radioMediumObserver;
  private AbstractTableModel model;

  private HashMap<String, Action> analyzerMap = new HashMap<String, Action>();
  private String analyzerName = null;
  private ArrayList<PacketAnalyzer> analyzers = null;
  private IEEE802154Analyzer analyzerWithPcap;
  private File pcapFile;

  private JTextField searchField = new JTextField(30);

  public RadioLogger(final Simulation simulationToControl, final Cooja gui) {
    super("Radio messages", gui);
    setLayout(new BorderLayout());

    simulation = simulationToControl;
    radioMedium = simulation.getRadioMedium();

    /* Menus */
    JMenuBar menuBar = new JMenuBar();
    JMenu fileMenu = new JMenu("File");
    JMenu editMenu = new JMenu("Edit");
    JMenu analyzerMenu = new JMenu("Analyzer");
    JMenu payloadMenu = new JMenu("View");

    menuBar.add(fileMenu);
    menuBar.add(editMenu);
    menuBar.add(analyzerMenu);
    menuBar.add(payloadMenu);

    this.setJMenuBar(menuBar);

    ArrayList<PacketAnalyzer> lowpanAnalyzers = new ArrayList<PacketAnalyzer>();
    lowpanAnalyzers.add(new IEEE802154Analyzer(false));
    lowpanAnalyzers.add(new IPHCPacketAnalyzer());
    lowpanAnalyzers.add(new IPv6PacketAnalyzer());
    lowpanAnalyzers.add(new ICMPv6Analyzer());

    analyzerWithPcap = new IEEE802154Analyzer(true);
    ArrayList<PacketAnalyzer> lowpanAnalyzersPcap = new ArrayList<PacketAnalyzer>();
    lowpanAnalyzersPcap.add(analyzerWithPcap);
    lowpanAnalyzersPcap.add(new IPHCPacketAnalyzer());
    lowpanAnalyzersPcap.add(new IPv6PacketAnalyzer());
    lowpanAnalyzersPcap.add(new ICMPv6Analyzer());

    model = new AbstractTableModel() {

      private static final long serialVersionUID = 1692207305977527004L;

      public String getColumnName(int col) {
        if (col == COLUMN_TIME && formatTimeString) {
          return "Time";
        }
        return COLUMN_NAMES[col];
      }

      public int getRowCount() {
        return connections.size();
      }

      public int getColumnCount() {
        return COLUMN_NAMES.length;
      }

      public Object getValueAt(int row, int col) {
        if (row < 0 || row >= connections.size()) {
          return "";
        }
        RadioConnectionLog conn = connections.get(row);
        if (col == COLUMN_NO) {
          if (!showDuplicates && conn.hides > 0) {
            return (String) "" + (row + 1) + "+" + conn.hides;
          }
          return (String) "" + (row + 1);
        } else if (col == COLUMN_TIME) {
          if (formatTimeString) {
            return LogListener.getFormattedTime(conn.startTime);
          }
          return Long.toString(conn.startTime / Simulation.MILLISECOND);
        } else if (col == COLUMN_FROM) {
          return "" + conn.connection.getSource().getMote().getID();
        } else if (col == COLUMN_TO) {
          Radio[] dests = conn.connection.getDestinations();
          if (dests.length == 0) {
            return "-";
          }
          if (dests.length == 1) {
            return "" + dests[0].getMote().getID();
          }
          if (dests.length == 2) {
            return "" + dests[0].getMote().getID() + ',' + dests[1].getMote().getID();
          }
          return "[" + dests.length + " d]";
        } else if (col == COLUMN_DATA) {
          if (conn.data == null) {
            prepareDataString(connections.get(row));
          }
          if (aliases != null) {
            /* Check if alias exists */
            String alias = (String) aliases.get(conn.data);
            if (alias != null) {
              return alias;
            }
          }
          return conn.data;
        }
        return null;
      }

      public boolean isCellEditable(int row, int col) {
        if (col == COLUMN_FROM) {
          /* Highlight source */
          gui.signalMoteHighlight(connections.get(row).connection.getSource().getMote());
          return false;
        }

        if (col == COLUMN_TO) {
          /* Highlight all destinations */
          Radio dests[] = connections.get(row).connection.getDestinations();
          for (Radio dest: dests) {
            gui.signalMoteHighlight(dest.getMote());
          }
          return false;
        }
        return false;
      }

      public Class<?> getColumnClass(int c) {
        return getValueAt(0, c).getClass();
      }
    };

    dataTable = new JTable(model) {

      private static final long serialVersionUID = -2199726885069809686L;

      public String getToolTipText(MouseEvent e) {
        java.awt.Point p = e.getPoint();
        int rowIndex = rowAtPoint(p);
        if (rowIndex < 0) {
          return super.getToolTipText(e);
        }
        int modelRowIndex = convertRowIndexToModel(rowIndex);
        int colIndex = columnAtPoint(p);
        int modelColumnIndex = convertColumnIndexToModel(colIndex);
        if (modelRowIndex < 0 || modelColumnIndex < 0) {
          return super.getToolTipText(e);
        }

        /* TODO This entry may represent several hidden connections */
        RadioConnectionLog conn = connections.get(modelRowIndex);
        if (modelColumnIndex == COLUMN_TIME) {
          return "<html>"
                  + "Start time (us): " + conn.startTime
                  + "<br>"
                  + "End time (us): " + conn.endTime
                  + "<br><br>"
                  + "Duration (us): " + (conn.endTime - conn.startTime)
                  + "</html>";
        } else if (modelColumnIndex == COLUMN_FROM) {
          return conn.connection.getSource().getMote().toString();
        } else if (modelColumnIndex == COLUMN_TO) {
          Radio[] dests = conn.connection.getDestinations();
          if (dests.length == 0) {
            return "No destinations";
          }
          StringBuilder tip = new StringBuilder();
          tip.append("<html>");
          if (dests.length == 1) {
            tip.append("One destination:<br>");
          } else {
            tip.append(dests.length).append(" destinations:<br>");
          }
          for (Radio radio: dests) {
            tip.append(radio.getMote()).append("<br>");
          }
          tip.append("</html>");
          return tip.toString();
        } else if (modelColumnIndex == COLUMN_DATA) {
          if (conn.tooltip == null) {
            prepareTooltipString(conn);
          }
          return conn.tooltip;
        }
        return super.getToolTipText(e);
      }
    };

    /* Toggle time format */
    dataTable.getTableHeader().addMouseListener(new MouseAdapter() {
      public void mouseClicked(MouseEvent e) {
        int colIndex = dataTable.columnAtPoint(e.getPoint());
        int columnIndex = dataTable.convertColumnIndexToModel(colIndex);
        if (columnIndex != COLUMN_TIME) {
          return;
        }
        formatTimeString = !formatTimeString;
        dataTable.getColumnModel().getColumn(COLUMN_TIME).setHeaderValue(
                dataTable.getModel().getColumnName(COLUMN_TIME));
        repaint();
      }
    });

    dataTable.addKeyListener(new KeyAdapter() {
      public void keyPressed(KeyEvent e) {
        if (e.getKeyCode() == KeyEvent.VK_SPACE) {
          showInAllAction.actionPerformed(null);
        } else if (e.getKeyCode() == KeyEvent.VK_F
                && (e.getModifiers() & KeyEvent.CTRL_MASK) != 0) {
          searchField.setVisible(true);
          searchField.requestFocus();
          searchField.selectAll();
          revalidate();
        } else if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
          searchField.setVisible(false);
          dataTable.requestFocus();
          revalidate();
        }
      }
    });

    logFilter = new TableRowSorter<TableModel>(model);
    for (int i = 0, n = model.getColumnCount(); i < n; i++) {
      logFilter.setSortable(i, false);
    }
    dataTable.setRowSorter(logFilter);

    dataTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
      public void valueChanged(ListSelectionEvent e) {
        int row = dataTable.getSelectedRow();
        if (row < 0) {
          return;
        }
        int modelRowIndex = dataTable.convertRowIndexToModel(row);
        if (modelRowIndex >= 0) {
          RadioConnectionLog conn = connections.get(modelRowIndex);
          if (conn.tooltip == null) {
            prepareTooltipString(conn);
          }
          verboseBox.setText(conn.tooltip);
          verboseBox.setCaretPosition(0);
        }
      }
    });
    // Set data column width greedy
    dataTable.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);

    dataTable.setFont(new Font("Monospaced", Font.PLAIN, 12));

    editMenu.add(new JMenuItem(copyAllAction));
    editMenu.add(new JMenuItem(copyAction));
    editMenu.add(new JSeparator());
    editMenu.add(new JMenuItem(clearAction));

    payloadMenu.add(new JMenuItem(aliasAction));
    payloadMenu.add(new JCheckBoxMenuItem(showDuplicatesAction) {
      public boolean isSelected() {
        return showDuplicates;
      }
    });
    payloadMenu.add(new JCheckBoxMenuItem(hideNoDestinationAction) {
      public boolean isSelected() {
        return hideNoDestinationPackets;
      }
    });

    fileMenu.add(new JMenuItem(saveAction));

    JPopupMenu popupMenu = new JPopupMenu();

    JMenu focusMenu = new JMenu("Show in");
    focusMenu.add(new JMenuItem(showInAllAction));
    focusMenu.addSeparator();
    focusMenu.add(new JMenuItem(timeLineAction));
    focusMenu.add(new JMenuItem(logListenerAction));
    popupMenu.add(focusMenu);

    //a group of radio button menu items
    ButtonGroup group = new ButtonGroup();
    JRadioButtonMenuItem rbMenuItem = new JRadioButtonMenuItem(
            createAnalyzerAction("No Analyzer", "none", null, true));
    group.add(rbMenuItem);
    analyzerMenu.add(rbMenuItem);

    rbMenuItem = new JRadioButtonMenuItem(createAnalyzerAction(
            "6LoWPAN Analyzer", "6lowpan", lowpanAnalyzers, false));
    group.add(rbMenuItem);
    analyzerMenu.add(rbMenuItem);

    rbMenuItem = new JRadioButtonMenuItem(createAnalyzerAction(
            "6LoWPAN Analyzer with PCAP", "6lowpan-pcap", lowpanAnalyzersPcap, false));
    group.add(rbMenuItem);
    analyzerMenu.add(rbMenuItem);

    /* Load additional analyzers specified by projects (cooja.config) */
    String[] projectAnalyzerSuites
            = gui.getProjectConfig().getStringArrayValue(RadioLogger.class, "ANALYZERS");
    if (projectAnalyzerSuites != null) {
      for (String suiteName: projectAnalyzerSuites) {
        if (suiteName == null || suiteName.trim().isEmpty()) {
          continue;
        }
        Class<? extends RadioLoggerAnalyzerSuite> suiteClass
                = gui.tryLoadClass(RadioLogger.this, RadioLoggerAnalyzerSuite.class, suiteName);
        try {
          RadioLoggerAnalyzerSuite suite = suiteClass.newInstance();
          ArrayList<PacketAnalyzer> suiteAnalyzers = suite.getAnalyzers();
          rbMenuItem = new JRadioButtonMenuItem(createAnalyzerAction(
                  suite.getDescription(), suiteName, suiteAnalyzers, false));
          group.add(rbMenuItem);
          analyzerMenu.add(rbMenuItem);
          logger.debug("Loaded radio logger analyzers: " + suite.getDescription());
        } catch (InstantiationException e1) {
          logger.warn("Failed to load analyzer suite '" + suiteName + "': " + e1.getMessage());
        } catch (IllegalAccessException e1) {
          logger.warn("Failed to load analyzer suite '" + suiteName + "': " + e1.getMessage());
        }
      }
    }

    dataTable.setComponentPopupMenu(popupMenu);
    dataTable.setFillsViewportHeight(true);

    verboseBox = new JTextPane();
    verboseBox.setContentType("text/html");
    verboseBox.setEditable(false);
    verboseBox.setComponentPopupMenu(popupMenu);

    /* Search text field */
    searchField.setVisible(false);
    searchField.addKeyListener(new KeyAdapter() {
      public void keyPressed(KeyEvent e) {
        if (e.getKeyCode() == KeyEvent.VK_ENTER) {
          searchSelectNext(
                  searchField.getText(),
                  (e.getModifiers() & KeyEvent.SHIFT_MASK) != 0);
        } else if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
          searchField.setVisible(false);
          dataTable.requestFocus();
          revalidate();
        }
      }
    });

    splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                               new JScrollPane(dataTable), new JScrollPane(verboseBox));
    splitPane.setOneTouchExpandable(true);
    splitPane.setDividerLocation(150);
    add(BorderLayout.NORTH, searchField);
    add(BorderLayout.CENTER, splitPane);

    TableColumnAdjuster adjuster = new TableColumnAdjuster(dataTable);
    adjuster.setDynamicAdjustment(true);
    adjuster.packColumns();

    radioMedium.addRadioMediumObserver(radioMediumObserver = new Observer() {
      public void update(Observable obs, Object obj) {
        RadioConnection conn = radioMedium.getLastConnection();
        if (conn == null) {
          return;
        }
        final RadioConnectionLog loggedConn = new RadioConnectionLog();
        loggedConn.startTime = conn.getStartTime();
        loggedConn.endTime = simulation.getSimulationTime();
        loggedConn.connection = conn;
        loggedConn.packet = conn.getSource().getLastPacketTransmitted();
        java.awt.EventQueue.invokeLater(new Runnable() {
          public void run() {
            int lastSize = connections.size();
            // Check if the last row is visible
            boolean isVisible = false;
            int rowCount = dataTable.getRowCount();
            if (rowCount > 0) {
              Rectangle lastRow = dataTable.getCellRect(rowCount - 1, 0, true);
              Rectangle visible = dataTable.getVisibleRect();
              isVisible = visible.y <= lastRow.y && visible.y + visible.height >= lastRow.y + lastRow.height;
            }
            connections.add(loggedConn);
            if (connections.size() > lastSize) {
              model.fireTableRowsInserted(lastSize, connections.size() - 1);
            }
            if (isVisible) {
              dataTable.scrollRectToVisible(dataTable.getCellRect(dataTable.getRowCount() - 1, 0, true));
            }
            setTitle("Radio messages: showing " + dataTable.getRowCount() + "/" + connections.size() + " packets");
          }
        });
      }
    });

    setSize(500, 300);
    try {
      setSelected(true);
    } catch (java.beans.PropertyVetoException e) {
      // Could not select
    }
  }

  public void startPlugin() {
    super.startPlugin();
    rebuildAllEntries();
  }

  private void searchSelectNext(String text, boolean reverse) {
    if (text.isEmpty()) {
      return;
    }
    int row = dataTable.getSelectedRow();
    if (row < 0) {
      row = 0;
    }

    if (!reverse) {
      row++;
    } else {
      row--;
    }

    int rows = dataTable.getModel().getRowCount();
    for (int i = 0; i < rows; i++) {
      int r;
      if (!reverse) {
        r = (row + i + rows) % rows;
      } else {
        r = (row - i + rows) % rows;
      }
      String val = (String) dataTable.getModel().getValueAt(r, COLUMN_DATA);
      if (!val.contains(text)) {
        continue;
      }
      dataTable.setRowSelectionInterval(r, r);
      dataTable.scrollRectToVisible(dataTable.getCellRect(r, COLUMN_DATA, true));
      searchField.setBackground(Color.WHITE);
      return;
    }
    searchField.setBackground(Color.RED);
  }

  /**
   * Selects a logged radio packet close to the given time.
   *
   * @param time Start time
   */
  public void trySelectTime(final long time) {
    java.awt.EventQueue.invokeLater(new Runnable() {
      public void run() {
        if (dataTable.getRowCount() == 0) {
          return;
        }
        for (int ai = 0; ai < model.getRowCount(); ai++) {
          int index = dataTable.convertRowIndexToModel(ai);
          if (connections.get(index).endTime < time) {
            continue;
          }

          dataTable.scrollRectToVisible(dataTable.getCellRect(ai, 0, true));
          dataTable.setRowSelectionInterval(ai, ai);
          return;
        }
        dataTable.scrollRectToVisible(dataTable.getCellRect(dataTable.getRowCount() - 1, 0, true));
        dataTable.setRowSelectionInterval(dataTable.getRowCount() - 1, dataTable.getRowCount() - 1);
      }
    });
  }

  private void applyFilter() {
    for (RadioConnectionLog conn: connections) {
      conn.data = null;
      conn.tooltip = null;
      conn.hides = 0;
      conn.hiddenBy = null;
    }

    try {
      logFilter.setRowFilter(null);
      RowFilter<Object, Object> filter = new RowFilter<Object, Object>() {
        public boolean include(RowFilter.Entry<? extends Object, ? extends Object> entry) {
          int row = (Integer) entry.getIdentifier();
          RadioConnectionLog current = connections.get(row);
          byte[] currentData = current.packet.getPacketData();

          if (!showDuplicates && row > 0) {
            RadioConnectionLog previous = connections.get(row - 1);
            byte[] previousData = previous.packet.getPacketData();
            if (!showDuplicates
                    && Arrays.equals(previousData, currentData)
                    && previous.connection.getSource() == current.connection.getSource()
                    && Arrays.equals(previous.connection.getAllDestinations(), current.connection.getAllDestinations())) {
              if (connections.get(row - 1).hiddenBy == null) {
                connections.get(row - 1).hides++;
                connections.get(row).hiddenBy = connections.get(row - 1);
              } else {
                connections.get(row - 1).hiddenBy.hides++;
                connections.get(row).hiddenBy = connections.get(row - 1).hiddenBy;
              }
              return false;
            }
          }

          if (hideNoDestinationPackets) {
            if (current.connection.getDestinations().length == 0) {
              return false;
            }
          }

          return true;
        }
      };
      logFilter.setRowFilter(filter);
    } catch (PatternSyntaxException e) {
      logFilter.setRowFilter(null);
      logger.warn("Error when setting table filter: " + e.getMessage());
    }
  }

  private void prepareDataString(RadioConnectionLog conn) {
    byte[] data;
    if (conn.packet == null) {
      data = null;
    } else if (conn.packet instanceof ConvertedRadioPacket) {
      data = ((ConvertedRadioPacket) conn.packet).getOriginalPacketData();
    } else {
      data = conn.packet.getPacketData();
    }
    if (data == null) {
      conn.data = "[unknown data]";
      return;
    }

    StringBuffer brief = new StringBuffer();
    StringBuffer verbose = new StringBuffer();

    /* default analyzer */
    PacketAnalyzer.Packet packet = new PacketAnalyzer.Packet(data, PacketAnalyzer.MAC_LEVEL);

    if (analyzePacket(packet, brief, verbose)) {
      if (packet.hasMoreData()) {
        byte[] payload = packet.getPayload();
        brief.append(StringUtils.toHex(payload, 4));
        if (verbose.length() > 0) {
          verbose.append("<p>");
        }
        verbose.append("<b>Payload (")
                .append(payload.length).append(" bytes)</b><br><pre>")
                .append(StringUtils.hexDump(payload))
                .append("</pre>");
      }
      conn.data = (data.length < 100 ? (data.length < 10 ? "  " : " ") : "")
              + data.length + ": " + brief;
      if (verbose.length() > 0) {
        conn.tooltip = verbose.toString();
      }
    } else {
      conn.data = data.length + ": 0x" + StringUtils.toHex(data, 4);
    }
  }

  private boolean analyzePacket(PacketAnalyzer.Packet packet, StringBuffer brief, StringBuffer verbose) {
    if (analyzers == null) return false;
    try {
      boolean analyze = true;
      while (analyze) {
        analyze = false;
        for (int i = 0; i < analyzers.size(); i++) {
          PacketAnalyzer analyzer = analyzers.get(i);
          if (analyzer.matchPacket(packet)) {
            int res = analyzer.analyzePacket(packet, brief, verbose);
            if (packet.hasMoreData() && brief.length() > 0) {
              brief.append('|');
              verbose.append("<br>");
            }
            if (res != PacketAnalyzer.ANALYSIS_OK_CONTINUE) {
              /* this was the final or the analysis failed - no analyzable payload possible here... */
              return brief.length() > 0;
            }
            /* continue another round if more bytes left */
            analyze = packet.hasMoreData();
            break;
          }
        }
      }
    } catch (Exception e) {
      logger.debug("Error when analyzing packet: " + e.getMessage(), e);
      return false;
    }
    return brief.length() > 0;
  }

  private void prepareTooltipString(RadioConnectionLog conn) {
    RadioPacket packet = conn.packet;
    if (packet == null) {
      conn.tooltip = "";
      return;
    }

    if (packet instanceof ConvertedRadioPacket && packet.getPacketData().length > 0) {
      byte[] original = ((ConvertedRadioPacket) packet).getOriginalPacketData();
      byte[] converted = ((ConvertedRadioPacket) packet).getPacketData();
      conn.tooltip = "<html><font face=\"Monospaced\">"
              + "<b>Packet data (" + original.length + " bytes)</b><br>"
              + "<pre>" + StringUtils.hexDump(original) + "</pre>"
              + "</font><font face=\"Monospaced\">"
              + "<b>Cross-level packet data (" + converted.length + " bytes)</b><br>"
              + "<pre>" + StringUtils.hexDump(converted) + "</pre>"
              + "</font></html>";
    } else if (packet instanceof ConvertedRadioPacket) {
      byte[] original = ((ConvertedRadioPacket) packet).getOriginalPacketData();
      conn.tooltip = "<html><font face=\"Monospaced\">"
              + "<b>Packet data (" + original.length + " bytes)</b><br>"
              + "<pre>" + StringUtils.hexDump(original) + "</pre>"
              + "</font><font face=\"Monospaced\">"
              + "<b>No cross-level conversion available</b><br>"
              + "</font></html>";
    } else {
      byte[] data = packet.getPacketData();
      conn.tooltip = "<html><font face=\"Monospaced\">"
              + "<b>Packet data (" + data.length + " bytes)</b><br>"
              + "<pre>" + StringUtils.hexDump(data) + "</pre>"
              + "</font></html>";
    }
  }

  public void closePlugin() {
    if (radioMediumObserver != null) {
      radioMedium.deleteRadioMediumObserver(radioMediumObserver);
    }
  }

  public Collection<Element> getConfigXML() {
    ArrayList<Element> config = new ArrayList<Element>();

    Element element = new Element("split");
    element.addContent(Integer.toString(splitPane.getDividerLocation()));
    config.add(element);

    if (formatTimeString) {
      element = new Element("formatted_time");
      config.add(element);
    }

    element = new Element("showdups");
    element.addContent(Boolean.toString(showDuplicates));
    config.add(element);

    element = new Element("hidenodests");
    element.addContent(Boolean.toString(hideNoDestinationPackets));
    config.add(element);

    if (analyzerName != null && analyzers != null) {
      element = new Element("analyzers");
      element.setAttribute("name", analyzerName);
      config.add(element);
    }

    if (aliases != null) {
      for (Object key : aliases.keySet()) {
        element = new Element("alias");
        element.setAttribute("payload", (String) key);
        element.setAttribute("alias", (String) aliases.get(key));
        config.add(element);
      }
    }

    if (pcapFile != null) {
      element = new Element("pcap_file");
      File file = simulation.getCooja().createPortablePath(pcapFile);
      element.setText(pcapFile.getPath().replaceAll("\\\\", "/"));
      element.setAttribute("EXPORT", "discard");
      config.add(element);
    }

    return config;
  }

  public boolean setConfigXML(Collection<Element> configXML, boolean visAvailable) {
    for (Element element : configXML) {
      String name = element.getName();
      if ("alias".equals(name)) {
        String payload = element.getAttributeValue("payload");
        String alias = element.getAttributeValue("alias");
        if (aliases == null) {
          aliases = new Properties();
        }
        aliases.put(payload, alias);
      } else if ("split".equals(name)) {
        splitPane.setDividerLocation(Integer.parseInt(element.getText()));
      } else if ("formatted_time".equals(name)) {
        formatTimeString = true;
      } else if ("showdups".equals(name)) {
        showDuplicates = Boolean.parseBoolean(element.getText());
      } else if ("hidenodests".equals(name)) {
        hideNoDestinationPackets = Boolean.parseBoolean(element.getText());
      } else if ("analyzers".equals(name)) {
        String analyzerName = element.getAttributeValue("name");
        final Action action;
        if (analyzerName != null && ((action = analyzerMap.get(analyzerName)) != null)) {
          java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
              action.putValue(Action.SELECTED_KEY, Boolean.TRUE);
              action.actionPerformed(null);
            }
          });
        }
      } else if (name.equals("pcap_file")) {
        pcapFile = simulation.getCooja().restorePortablePath(new File(element.getText()));
        analyzerWithPcap.setPcapFile(pcapFile);
      }
    }
    return true;
  }

  private class RadioConnectionLog {

    long startTime;
    long endTime;
    RadioConnection connection;
    RadioPacket packet;

    RadioConnectionLog hiddenBy = null;
    int hides = 0;

    String data = null;
    String tooltip = null;

    public String toString() {
      if (data == null) {
        RadioLogger.this.prepareDataString(this);
      }
      return Long.toString(startTime / Simulation.MILLISECOND) + "\t"
              + connection.getSource().getMote().getID() + "\t"
              + getDestString(this) + "\t"
              + data;
    }
  }

  private static String getDestString(RadioConnectionLog c) {
    Radio[] dests = c.connection.getDestinations();
    if (dests.length == 0) {
      return "-";
    }
    if (dests.length == 1) {
      return "" + dests[0].getMote().getID();
    }
    StringBuilder sb = new StringBuilder();
    for (Radio dest: dests) {
      sb.append(dest.getMote().getID()).append(',');
    }
    sb.setLength(sb.length() - 1);
    return sb.toString();
  }

  private void rebuildAllEntries() {
    applyFilter();

    if (connections.size() > 0) {
      model.fireTableRowsUpdated(0, connections.size() - 1);
    }
    verboseBox.setText("");

    setTitle("Radio messages: showing " + dataTable.getRowCount() + "/" + connections.size() + " packets");
    simulation.getCooja().getDesktopPane().repaint();
  }

  private Action createAnalyzerAction(String name, final String actionName,
                                      final ArrayList<PacketAnalyzer> analyzerList, boolean selected) {
    Action action = new AbstractAction(name) {
      private static final long serialVersionUID = -608913700422638454L;

      public void actionPerformed(ActionEvent event) {
        if (analyzers != analyzerList) {
          analyzers = analyzerList;
          analyzerName = actionName;
          rebuildAllEntries();
        }
      }
    };
    action.putValue(Action.SELECTED_KEY, selected ? Boolean.TRUE : Boolean.FALSE);
    analyzerMap.put(actionName, action);
    return action;
  }

  private Action clearAction = new AbstractAction("Clear") {
    private static final long serialVersionUID = -6135583266684643117L;

    public void actionPerformed(ActionEvent e) {
      int size = connections.size();
      if (size > 0) {
        connections.clear();
        model.fireTableRowsDeleted(0, size - 1);
        setTitle("Radio messages: showing " + dataTable.getRowCount() + "/" + connections.size() + " packets");
      }
    }
  };

  private Action copyAction = new AbstractAction("Copy selected") {
    private static final long serialVersionUID = 8412062977916108054L;

    public void actionPerformed(ActionEvent e) {
      Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();

      int[] selectedRows = dataTable.getSelectedRows();

      StringBuilder sb = new StringBuilder();
      for (int i: selectedRows) {
        int iModel = dataTable.convertRowIndexToModel(i);
        sb.append(connections.get(iModel).toString() + "\n");
      }

      StringSelection stringSelection = new StringSelection(sb.toString());
      clipboard.setContents(stringSelection, null);
    }
  };

  private Action copyAllAction = new AbstractAction("Copy all") {
    private static final long serialVersionUID = 1905586689441157304L;

    public void actionPerformed(ActionEvent e) {
      Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();

      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < connections.size(); i++) {
        sb.append(connections.get(i).toString() + "\n");
      }

      StringSelection stringSelection = new StringSelection(sb.toString());
      clipboard.setContents(stringSelection, null);
    }
  };

  private Action saveAction = new AbstractAction("Save to file...") {
    private static final long serialVersionUID = -3942984643211482179L;

    public void actionPerformed(ActionEvent e) {
      JFileChooser fc = new JFileChooser();
      int returnVal = fc.showSaveDialog(Cooja.getTopParentContainer());
      if (returnVal != JFileChooser.APPROVE_OPTION) {
        return;
      }

      File saveFile = fc.getSelectedFile();
      if (saveFile.exists()) {
        String s1 = "Overwrite";
        String s2 = "Cancel";
        Object[] options = {s1, s2};
        int n = JOptionPane.showOptionDialog(
                Cooja.getTopParentContainer(),
                "A file with the same name already exists.\nDo you want to remove it?",
                "Overwrite existing file?", JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE, null, options, s1);
        if (n != JOptionPane.YES_OPTION) {
          return;
        }
      }

      if (saveFile.exists() && !saveFile.canWrite()) {
        logger.fatal("No write access to file: " + saveFile);
        return;
      }

      try {
        PrintWriter outStream = new PrintWriter(new FileWriter(saveFile));
        for (int i = 0; i < connections.size(); i++) {
          outStream.print(connections.get(i).toString() + "\n");
        }
        outStream.close();
      } catch (Exception ex) {
        logger.fatal("Could not write to file: " + saveFile);
        return;
      }

    }
  };

  private Action timeLineAction = new AbstractAction("Timeline") {
    private static final long serialVersionUID = -4035633464748224192L;

    public void actionPerformed(ActionEvent e) {
      int selectedRow = dataTable.getSelectedRow();
      if (selectedRow < 0) return;
      selectedRow = dataTable.convertRowIndexToModel(selectedRow);
      if (selectedRow < 0) return;

      long time = connections.get(selectedRow).startTime;

      Plugin[] plugins = simulation.getCooja().getStartedPlugins();
      for (Plugin p: plugins) {
        if (!(p instanceof TimeLine)) {
          continue;
        }

        /* Select simulation time */
        TimeLine plugin = (TimeLine) p;
        plugin.trySelectTime(time);
      }
    }
  };

  private Action logListenerAction = new AbstractAction("Mote output") {
    private static final long serialVersionUID = 1985006491187878651L;

    public void actionPerformed(ActionEvent e) {
      int selectedRow = dataTable.getSelectedRow();
      if (selectedRow < 0) return;
      selectedRow = dataTable.convertRowIndexToModel(selectedRow);
      if (selectedRow < 0) return;

      long time = connections.get(selectedRow).startTime;

      Plugin[] plugins = simulation.getCooja().getStartedPlugins();
      for (Plugin p: plugins) {
        if (!(p instanceof LogListener)) {
          continue;
        }

        /* Select simulation time */
        LogListener plugin = (LogListener) p;
        plugin.trySelectTime(time);
      }
    }
  };

  private Action showInAllAction = new AbstractAction("Timeline and mote output") {
    private static final long serialVersionUID = -3888292108886138128L;

    {
      putValue(ACCELERATOR_KEY, KeyStroke.getKeyStroke(KeyEvent.VK_SPACE, 0, true));
    }

    public void actionPerformed(ActionEvent e) {
      timeLineAction.actionPerformed(null);
      logListenerAction.actionPerformed(null);
    }
  };

  private Properties aliases = null;
  private Action aliasAction = new AbstractAction("Payload alias...") {
    private static final long serialVersionUID = -1678771087456128721L;

    public void actionPerformed(ActionEvent e) {
      int selectedRow = dataTable.getSelectedRow();
      if (selectedRow < 0) return;
      selectedRow = dataTable.convertRowIndexToModel(selectedRow);
      if (selectedRow < 0) return;

      String current = "";
      if (aliases != null && aliases.get(connections.get(selectedRow).data) != null) {
        current = (String) aliases.get(connections.get(selectedRow).data);
      }

      String alias = (String) JOptionPane.showInputDialog(
              Cooja.getTopParentContainer(),
              "Enter alias for all packets with identical payload.\n"
              + "An empty string removes the current alias.\n\n"
              + connections.get(selectedRow).data + "\n",
              "Create packet payload alias",
              JOptionPane.QUESTION_MESSAGE,
              null,
              null,
              current);
      if (alias == null) {
        /* Cancelled */
        return;
      }

      /* Should be null if empty */
      if (aliases == null) {
        aliases = new Properties();
      }

      /* Remove current alias */
      if (alias.equals("")) {
        aliases.remove(connections.get(selectedRow).data);

        /* Should be null if empty */
        if (aliases.isEmpty()) {
          aliases = null;
        }
        repaint();
        return;
      }

      /* (Re)define alias */
      aliases.put(connections.get(selectedRow).data, alias);
      repaint();
    }
  };

  private boolean showDuplicates = false;
  private AbstractAction showDuplicatesAction = new AbstractAction("Show duplicates") {
    public void actionPerformed(ActionEvent e) {
      showDuplicates = !showDuplicates;
      rebuildAllEntries();
    }
  };

  private boolean hideNoDestinationPackets = false;
  private AbstractAction hideNoDestinationAction = new AbstractAction("Hide airshots") {
    public void actionPerformed(ActionEvent e) {
      hideNoDestinationPackets = !hideNoDestinationPackets;
      rebuildAllEntries();
    }
  };

  public String getConnectionsString() {
    StringBuilder sb = new StringBuilder();
    RadioConnectionLog[] cs = connections.toArray(new RadioConnectionLog[0]);
    for (RadioConnectionLog c : cs) {
      sb.append(c.toString() + "\n");
    }
    return sb.toString();
  }

  public void saveConnectionsToFile(String fileName) {
    StringUtils.saveToFile(new File(fileName), getConnectionsString());
  }

}
