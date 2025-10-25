# -*- coding: utf-8 -*-
# BurpJSLinkFinder_Enhanced_with_Search.py
# Jython 2.7 - Enhanced JS Link Finder (adds live search for endpoints & logs)
# Drop into Burp Extender (Python) with Jython standalone JAR configured.

from burp import IBurpExtender, IHttpListener, ITab
from java.io import PrintWriter
from javax import swing
from java.awt import Font, Color, EventQueue, Desktop, Dimension
from java.awt.event import FocusAdapter, KeyAdapter, MouseAdapter, MouseEvent
from javax.swing import JTable, JScrollPane, JPopupMenu, JMenuItem, JFileChooser, JOptionPane
from javax.swing import RowFilter
from java.util import ArrayList
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from java.net import URI
import re
import threading
import time
import base64
import binascii
import json
import math
import os

# Config
JS_EXCLUDE = ['jquery', 'google-analytics', 'gpt.js', 'analytics.js', 'gtag', 'google-analytics.com']
MAX_RESULTS_PER_FILE = 300
HEAD_PROBE_ENABLED_DEFAULT = False
HEAD_PROBE_CONCURRENCY = 4
HEAD_PROBE_TIMEOUT_SECONDS = 5

# Helper small utilities
def safe_print(pw, msg):
    try:
        pw.println(msg)
    except:
        pass

def attempt_base64_decode(s):
    try:
        padding = len(s) % 4
        if padding:
            s += '=' * (4 - padding)
        dec = base64.b64decode(s)
        try:
            text = dec.decode('utf-8')
        except:
            text = None
        return text
    except Exception:
        return None

def attempt_hex_decode(s):
    try:
        if re.match('^[0-9a-fA-F]{6,}$', s):
            dec = binascii.unhexlify(s)
            try:
                return dec.decode('utf-8')
            except:
                return None
    except Exception:
        pass
    return None

# new: lightweight Shannon entropy estimator
def _shannon_entropy(s):
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = float(len(s))
    for v in freq.values():
        p = v / length
        entropy -= p * math.log(p, 2)
    return entropy

# KeyAdapter wrapper (must be defined for addKeyListener)
class SearchKeyAdapter(KeyAdapter):
    def __init__(self, outer):
        self.outer = outer

    def keyReleased(self, event):
        try:
            self.outer._on_search_key(event)
        except:
            pass

# FocusAdapter subclasses for Jython: define concrete classes to attach
class FilterFocusAdapter(FocusAdapter):
    def __init__(self, outer):
        self.outer = outer
    def focusGained(self, event):
        try:
            if self.outer.filterField.getText() == "Filter endpoints...":
                self.outer.filterField.setText("")
                self.outer.filterField.setForeground(Color.BLACK)
        except:
            pass
    def focusLost(self, event):
        try:
            if self.outer.filterField.getText().strip() == "":
                self.outer.filterField.setText("Filter endpoints...")
                self.outer.filterField.setForeground(Color.GRAY)
        except:
            pass

class SearchFocusAdapter(FocusAdapter):
    def __init__(self, outer):
        self.outer = outer
    def focusGained(self, event):
        try:
            if self.outer.searchField.getText() == "Live search...":
                self.outer.searchField.setText("")
                self.outer.searchField.setForeground(Color.BLACK)
        except:
            pass
    def focusLost(self, event):
        try:
            if self.outer.searchField.getText().strip() == "":
                self.outer.searchField.setText("Live search...")
                self.outer.searchField.setForeground(Color.GRAY)
        except:
            pass

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def __init__(self):
        # ...existing code...
        self._search_timer = None
        self._search_lock = threading.Lock()

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpJSLinkFinder-Enhanced")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        # register HTTP listener
        callbacks.registerHttpListener(self)

        # storage
        self._seen = set()
        self._all_rows = []
        self._probe_queue = []
        self._probe_lock = threading.Lock()
        self._probe_threads = []
        self._probe_enabled = HEAD_PROBE_ENABLED_DEFAULT
        self._probe_concurrency = HEAD_PROBE_CONCURRENCY

        # regexes & patterns - only Nuclei regexes will be used
        # disable built-in LinkFinder/simple/token detectors
        self.linkfinder_regex = None
        self.simple_patterns = []
        self.token_patterns = []
        # NEW: nuclei-style regex list (loaded/compiled)
        self.nuclei_regexes = []
        try:
            # try to load regex.txt from same directory as this script
            base_dir = os.path.dirname(__file__) if '__file__' in globals() else None
            candidates = []
            if base_dir:
                candidates.append(os.path.join(base_dir, 'regex.txt'))
            # add common absolute path used in this workspace as fallback
            candidates.append(r'd:\webugbounty\tools\regex.txt')
            loaded = False
            for p in candidates:
                if p and os.path.exists(p):
                    try:
                        self.nuclei_regexes = self._load_js_regex_file(p)
                        self.append_log("Loaded {} regex patterns from {}".format(len(self.nuclei_regexes), p))
                        loaded = True
                        break
                    except Exception as e:
                        safe_print(self.stderr, "Failed to load regex file {}: {}".format(p, e))
            if not loaded:
                self.append_log("regex.txt not found; nuclei-style rules disabled.")
        except Exception as e:
            safe_print(self.stderr, "Error initializing nuclei regexes: " + str(e))

        # build UI on EDT
        def create_ui():
            try:
                self.initUI()
                self._callbacks.addSuiteTab(self)
                self.append_log("Burp JS LinkFinder loaded (Enhanced).")
                safe_print(self.stdout, "[BurpJSLinkFinder] loaded (Enhanced)")
            except Exception as e:
                safe_print(self.stderr, "UI init error: " + str(e))
        EventQueue.invokeLater(create_ui)

        # start probe workers
        for i in range(self._probe_concurrency):
            t = threading.Thread(target=self._probe_worker)
            t.setDaemon(True)
            t.start()
            self._probe_threads.append(t)

    # ---------------- UI ----------------
    def initUI(self):
        self.panel = swing.JPanel()
        self.panel.setLayout(swing.BoxLayout(self.panel, swing.BoxLayout.Y_AXIS))

        # controls row: filter (existing), search (new), probe toggle, buttons
        top = swing.JPanel()
        top.setLayout(swing.BoxLayout(top, swing.BoxLayout.X_AXIS))

        # --- Filter field with placeholder ---
        self.filterField = swing.JTextField("Filter endpoints...")
        self.filterField.setForeground(Color.GRAY)
        self.filterField.setMaximumSize(self.filterField.getPreferredSize())
        self.filterField.setToolTipText("Filter endpoints (substring). Press Enter to apply.")
        self.filterField.addFocusListener(FilterFocusAdapter(self))
        self.filterField.addActionListener(self._on_filter)

        # --- Search field with placeholder ---
        self.searchField = swing.JTextField("Live search...")
        self.searchField.setForeground(Color.GRAY)
        self.searchField.setMaximumSize(self.searchField.getPreferredSize())
        self.searchField.setToolTipText("Live search: searches Endpoint, Source and Log. Type to search.")
        self.searchField.addFocusListener(SearchFocusAdapter(self))
        self.searchField.addKeyListener(SearchKeyAdapter(self))
        # allow Enter to run the live search as well
        self.searchField.addActionListener(self._on_search_action)

        self.clearSearchBtn = swing.JButton("Clear Search", actionPerformed=self._clear_search)

        # new: clear log button
        self.clearLogBtn = swing.JButton("Clear Log", actionPerformed=self._clear_log)

        # remaining controls
        self.probeToggle = swing.JToggleButton("Probe HEAD (off)", actionPerformed=self._toggle_probe)
        if self._probe_enabled:
            self.probeToggle.setSelected(True)
            self.probeToggle.setText("Probe HEAD (on)")
        self.clearBtn = swing.JButton("Clear", actionPerformed=self._clear_all)
        self.exportCsvBtn = swing.JButton("Export CSV", actionPerformed=self._export_csv)
        self.exportJsonBtn = swing.JButton("Export JSON", actionPerformed=self._export_json)

        # add controls to top panel
        top.add(self.filterField)
        top.add(self.searchField)
        top.add(self.clearSearchBtn)
        top.add(self.clearLogBtn)
        top.add(self.probeToggle)
        top.add(self.clearBtn)
        top.add(self.exportCsvBtn)
        top.add(self.exportJsonBtn)

        # table
        self.tableModel = DefaultTableModel(0, 4)
        self.tableModel.setColumnIdentifiers(["Endpoint", "Source JS", "Priority", "Status"])
        self.table = JTable(self.tableModel)
        self.table.setAutoCreateRowSorter(True)
        scroll = JScrollPane(self.table)
        scroll.setPreferredSize(Dimension(900, 300))

        # install table listeners & context menu
        self._install_table_listeners()

        # log area
        self.logArea = swing.JTextArea()
        self.logArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.logArea.setLineWrap(True)
        logScroll = JScrollPane(self.logArea)
        logScroll.setPreferredSize(Dimension(900, 150))

        self.panel.add(top)
        self.panel.add(scroll)
        self.panel.add(swing.JLabel("Log:"))
        self.panel.add(logScroll)

        class HighlightRenderer(DefaultTableCellRenderer):
            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
                try:
                    if column == 0 and value:
                        if str(value).startswith("[PRIVATE KEY FOUND]"):
                            c.setBackground(Color.RED)
                            c.setForeground(Color.WHITE)
                        elif str(value).startswith("[AWS KEY FOUND]"):
                            c.setBackground(Color.ORANGE)
                            c.setForeground(Color.BLACK)
                        elif str(value).startswith("[SUSPICIOUS ENDPOINT FOUND]"):
                            c.setBackground(Color(102, 0, 204))  # Purple
                            c.setForeground(Color.WHITE)
                        elif str(value).startswith("[CONFIG ENDPOINT FOUND]"):
                            c.setBackground(Color(0, 153, 153))  # Teal
                            c.setForeground(Color.WHITE)

                        # -- Added token highlights --
                        elif str(value).startswith("[JWT FOUND]"):
                            c.setBackground(Color(153, 0, 0))  # Dark red
                            c.setForeground(Color.WHITE)
                        elif str(value).startswith("[AUTH BEARER FOUND]"):
                            c.setBackground(Color(255, 102, 0))  # Orange
                            c.setForeground(Color.BLACK)
                        elif str(value).startswith("[NAMED TOKEN FOUND]"):
                            c.setBackground(Color(204, 102, 255))  # Light purple
                            c.setForeground(Color.BLACK)
                        elif str(value).startswith("[HIGH-ENTROPY TOKEN (context)]"):
                            c.setBackground(Color(255, 204, 0))  # Yellow
                            c.setForeground(Color.BLACK)
                        # -- end added token highlights --

                        else:
                            if isSelected:
                                c.setBackground(table.getSelectionBackground())
                                c.setForeground(table.getSelectionForeground())
                            else:
                                c.setBackground(Color.WHITE)
                                c.setForeground(Color.BLACK)
                    else:
                        if isSelected:
                            c.setBackground(table.getSelectionBackground())
                            c.setForeground(table.getSelectionForeground())
                        else:
                            c.setBackground(Color.WHITE)
                            c.setForeground(Color.BLACK)
                except:
                    pass
                return c

        self.table.getColumnModel().getColumn(0).setCellRenderer(HighlightRenderer())

    def getTabCaption(self):
        return "BurpJSLinkFinder"

    def getUiComponent(self):
        return self.panel

    # ----------------- filter action -----------------
    def _on_filter(self, event):
        try:
            text = str(self.filterField.getText()).strip()
            if text == "" or text.lower() == "filter endpoints...":
                # clear filter
                sorter = self.table.getRowSorter()
                if sorter:
                    sorter.setRowFilter(None)
            else:
                # create case-insensitive regex for endpoint column (col 0)
                pattern = "(?i).*" + re.escape(text) + ".*"
                sorter = self.table.getRowSorter()
                if sorter:
                    sorter.setRowFilter(RowFilter.regexFilter(pattern, 0))
            self.append_log("Filter applied: '{}'".format(text))
        except Exception as e:
            safe_print(self.stderr, "Filter error: " + str(e))

    # ----------------- search (live) action -----------------
    def _on_search_key(self, event):
        try:
            # Debounce: only apply search 200ms after last keypress
            def delayed_search():
                time.sleep(0.2)
                with self._search_lock:
                    if threading.current_thread() == self._search_timer:
                        EventQueue.invokeLater(lambda: self._apply_search(focus_log=False))
            with self._search_lock:
                if hasattr(self, '_search_timer') and self._search_timer:
                    self._search_timer = None  # Cancel previous
                t = threading.Thread(target=delayed_search)
                self._search_timer = t
                t.start()
        except Exception as e:
            safe_print(self.stderr, "Search error: " + str(e))

    def _on_search_action(self, event):
        try:
            safe_print(self.stdout, "[BurpJSLinkFinder] _on_search_action fired; text='%s'" % str(self.searchField.getText()))
            # Enter should optionally move focus to the log (so user can inspect)
            self._apply_search(focus_log=True)
        except:
            pass

    def _apply_search(self, focus_log=False):
        safe_print(self.stdout, "[BurpJSLinkFinder] _apply_search start; viewRows=%d" % self.table.getRowCount())
        text = str(self.searchField.getText()).strip()
        text_l = text.lower()
        placeholder = "live search..."
        if text_l == placeholder:
            text_l = ""
        safe_print(self.stdout, "[BurpJSLinkFinder] _apply_search text_l='%s'" % text_l)

        sorter = self.table.getRowSorter()
        if not sorter:
            return

        if not text_l:
            # clear any search filtering
            sorter.setRowFilter(None)
        else:
            # build case-insensitive filters across all columns and OR them
            filters = []
            pattern = "(?i).*" + re.escape(text_l) + ".*"
            cols = range(self.tableModel.getColumnCount())
            for c in cols:
                filters.append(RowFilter.regexFilter(pattern, int(c)))
            arr = ArrayList()
            for f in filters:
                arr.add(f)
            sorter.setRowFilter(RowFilter.orFilter(arr))

        # Only search/select in the log when Enter is pressed (not on every keypress)
        if text_l and focus_log:
            # Only search the last 100KB of the log for performance
            log_text = str(self.logArea.getText())
            max_search = 100000  # 100KB
            if len(log_text) > max_search:
                log_lower = log_text[-max_search:].lower()
                offset = len(log_text) - max_search
            else:
                log_lower = log_text.lower()
                offset = 0
            idx = log_lower.find(text_l)
            if idx != -1:
                start = offset + idx
                end = start + len(text_l)
                self.logArea.requestFocus()
                self.logArea.select(start, end)
                self.logArea.setCaretPosition(end)
            else:
                # Optionally, deselect if not found
                self.logArea.select(0, 0)
        elif not text_l:
            self.logArea.select(0, 0)

    def _clear_search(self, event):
        try:
            self.searchField.setText("Live search...")
            self.searchField.setForeground(Color.GRAY)
            # clear row filter (show all rows)
            sorter = self.table.getRowSorter()
            if sorter:
                sorter.setRowFilter(None)
            self.logArea.select(0, 0)
            self.append_log("Search cleared.")
        except Exception as e:
            safe_print(self.stderr, "Clear search error: " + str(e))

    # ---------------- table interactions & the rest (unchanged) ----------------
    def _install_table_listeners(self):
        self.popup = JPopupMenu()
        copyItem = JMenuItem("Copy", actionPerformed=self._copy_selected)
        repeaterItem = JMenuItem("Send to Repeater", actionPerformed=self._send_selected_to_repeater)
        openItem = JMenuItem("Open in Browser", actionPerformed=self._open_selected_in_browser)
        scopeItem = JMenuItem("Add to Target Scope", actionPerformed=self._add_selected_to_scope)
        self.popup.add(copyItem)
        self.popup.add(repeaterItem)
        self.popup.add(openItem)
        self.popup.add(scopeItem)

        class TableMouseAdapter(MouseAdapter):
            def __init__(self, outer):
                self.outer = outer

            def mouseClicked(self, event):
                try:
                    if event.getClickCount() == 2 and event.getButton() == MouseEvent.BUTTON1:
                        row = self.outer.table.rowAtPoint(event.getPoint())
                        if row != -1:
                            modelRow = self.outer.table.convertRowIndexToModel(row)
                            endpoint = self.outer.tableModel.getValueAt(modelRow, 0)
                            self.outer._copy_to_clipboard(endpoint)
                            self.outer.append_log("Copied to clipboard: " + str(endpoint))
                except Exception as e:
                    safe_print(self.outer.stderr, "Mouse click error: " + str(e))

            # show popup on both press and release (platform differences)
            def _maybe_show_popup(self, event):
                try:
                    if event.isPopupTrigger() or event.getButton() == MouseEvent.BUTTON3:
                        row = self.outer.table.rowAtPoint(event.getPoint())
                        if row != -1:
                            self.outer.table.getSelectionModel().setSelectionInterval(row, row)
                            self.outer.popup.show(event.getComponent(), event.getX(), event.getY())
                except Exception as e:
                    safe_print(self.outer.stderr, "Mouse popup error: " + str(e))

            def mousePressed(self, event):
                try:
                    self._maybe_show_popup(event)
                except:
                    pass

            def mouseReleased(self, event):
                try:
                    self._maybe_show_popup(event)
                except:
                    pass

        self.table.addMouseListener(TableMouseAdapter(self))

    def _copy_selected(self, event):
        sel = self.table.getSelectedRow()
        if sel == -1:
            return
        modelRow = self.table.convertRowIndexToModel(sel)
        endpoint = self.tableModel.getValueAt(modelRow, 0)
        self._copy_to_clipboard(endpoint)
        self.append_log("Copied to clipboard: " + str(endpoint))

    def _send_selected_to_repeater(self, event):
        sel = self.table.getSelectedRow()
        if sel == -1:
            return
        modelRow = self.table.convertRowIndexToModel(sel)
        endpoint = self.tableModel.getValueAt(modelRow, 0)
        self._send_to_repeater(endpoint)

    def _open_selected_in_browser(self, event):
        sel = self.table.getSelectedRow()
        if sel == -1:
            return
        modelRow = self.table.convertRowIndexToModel(sel)
        endpoint = self.tableModel.getValueAt(modelRow, 0)
        try:
            if Desktop.isDesktopSupported():
                Desktop.getDesktop().browse(URI(str(endpoint)))
                self.append_log("Opened in browser: " + str(endpoint))
        except Exception as e:
            self.append_log("Error opening URL: " + str(e))

    def _send_to_repeater(self, endpoint):
        """
        Try common sendToRepeater overloads. Only emit a single stderr line if ALL attempts fail.
        """
        errs = []
        try:
            from java.net import URL
            u = URL(str(endpoint))
            host = u.getHost()
            port = u.getPort()
            proto = u.getProtocol()
            useHttps = (proto == 'https')
            req = self._helpers.buildHttpRequest(u)
            service = self._helpers.buildHttpService(host, port if port != -1 else (443 if useHttps else 80), useHttps)

            # 1) Preferred: host/port/useHttps/request/title (5 args)
            try:
                self._callbacks.sendToRepeater(host, port if port != -1 else (443 if useHttps else 80), useHttps, req, "BurpJSLinkFinder")
                self.append_log("Sent to Repeater: " + endpoint)
                return
            except Exception as ex:
                errs.append("sendToRepeater(host,port,useHttps,req,title) failed: " + str(ex))

            # 2) Common older overload: sendToRepeater(IHttpService, byte[])
            try:
                self._callbacks.sendToRepeater(service, req)
                self.append_log("Sent to Repeater: " + endpoint)
                return
            except Exception as ex:
                errs.append("sendToRepeater(service,req) failed: " + str(ex))

            # 3) Some builds: sendToRepeater(host, port, useHttps, request) (4 args)
            try:
                self._callbacks.sendToRepeater(host, port if port != -1 else (443 if useHttps else 80), useHttps, req)
                self.append_log("Sent to Repeater: " + endpoint)
                return
            except Exception as ex:
                errs.append("sendToRepeater(host,port,useHttps,req) failed: " + str(ex))

        except Exception as e:
            errs.append("build request/service failed: " + str(e))

        # If we get here, all attempts failed — log a single combined message
        safe_print(self.stderr, "Send to Repeater failed for %s. Attempts:\n  - %s" % (endpoint, "\n  - ".join(errs)))
        self.append_log("Send to Repeater failed. See Extender stderr for details.")

    def _add_selected_to_scope(self, event):
        """
        Try includeInScope overloads quietly and only print if all fail.
        """
        sel = self.table.getSelectedRow()
        if sel == -1:
            return
        modelRow = self.table.convertRowIndexToModel(sel)
        endpoint = self.tableModel.getValueAt(modelRow, 0)
        errs = []
        try:
            from java.net import URL
            u = URL(str(endpoint))
            host = u.getHost()
            port = u.getPort()
            proto = u.getProtocol()
            useHttps = (proto == 'https')
            service = self._helpers.buildHttpService(host, port if port != -1 else (443 if useHttps else 80), useHttps)

            # 1) Preferred: includeInScope(URL)
            try:
                self._callbacks.includeInScope(u)
                self.append_log("Added URL to scope: " + str(u))
                return
            except Exception as ex:
                errs.append("includeInScope(URL) failed: " + str(ex))

            # 2) Some API variants accept IHttpService
            try:
                self._callbacks.includeInScope(service)
                self.append_log("Added host to scope (service): " + host)
                return
            except Exception as ex:
                errs.append("includeInScope(service) failed: " + str(ex))

        except Exception as e:
            errs.append("build URL/service failed: " + str(e))

        # All attempts failed — log a single combined message
        safe_print(self.stderr, "Add to Scope failed for %s. Attempts:\n  - %s" % (endpoint, "\n  - ".join(errs)))
        self.append_log("Add to Scope failed. See Extender stderr for details.")

    def _copy_to_clipboard(self, s):
        try:
            sel = StringSelection(s)
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, None)
        except Exception as e:
            self.append_log("Clipboard error: " + str(e))

    def _export_csv(self, event):
        chooser = JFileChooser()
        ret = chooser.showDialog(self.panel, "Save CSV")
        if chooser.getSelectedFile() is None:
            return
        filename = chooser.getSelectedFile().getCanonicalPath()
        try:
            f = open(filename, 'w')
            f.write("endpoint,source,priority,status\n")
            for endpoint, source, prio, status in self._all_rows:
                f.write('"%s","%s","%s","%s"\n' % (endpoint.replace('"','""'), source.replace('"','""'), prio, status))
            f.close()
            self.append_log("Exported CSV: " + filename)
        except Exception as e:
            self.append_log("Export error: " + str(e))

    def _export_json(self, event):
        chooser = JFileChooser()
        ret = chooser.showDialog(self.panel, "Save JSON")
        if chooser.getSelectedFile() is None:
            return
        filename = chooser.getSelectedFile().getCanonicalPath()
        try:
            with open(filename, 'w') as f:
                json.dump([{'endpoint':e,'source':s,'priority':p,'status':st} for (e,s,p,st) in self._all_rows], f, indent=2)
            self.append_log("Exported JSON: " + filename)
        except Exception as e:
            self.append_log("Export error: " + str(e))

    def _clear_all(self, event):
        self.tableModel.setRowCount(0)
        self._seen = set()
        self._all_rows = []
        self.append_log("Cleared results.")

    def _clear_log(self, event):
        try:
            # clear UI log
            self.logArea.setText("")
            # also clear the results table and internal storage so the UI above is cleared
            try:
                self.tableModel.setRowCount(0)
            except:
                pass
            self._seen = set()
            self._all_rows = []
            # print to stdout instead of appending to UI log (keeps log area empty)
            safe_print(self.stdout, "Log and results cleared.")
        except Exception as e:
            safe_print(self.stderr, "Clear log error: " + str(e))

    def append_log(self, text):
        try:
            self.logArea.append(str(text) + "\n")
        except:
            safe_print(self.stdout, str(text))

    # ----------------- core parsing & heuristics -----------------
    def _linkfinder_regex(self):
        return r'''
          (?:"|')
          (
            ((?:[a-zA-Z]{1,10}://|//)
            [^"'/]{1,}\.
            [a-zA-Z]{2,}[^"']{0,})
            |
            ((?:/|\.\./|\./)
            [^"'><,;| *()(%%$^/\\\[\]]
            [^"'><,;|()]{1,})
            |
            ([a-zA-Z0-9_\-/]{1,}/
            [a-zA-Z0-9_\-/]{1,}
            \.(?:[a-zA-Z]{1,4}|action)
            (?:[\?|/][^"|']{0,}|))
            |
            ([a-zA-Z0-9_\-]{1,}
            \.(?:php|asp|aspx|jsp|json|
                 action|html|js|txt|xml)
            (?:\?[^"|']{0,}|))
          )
          (?:"|')
        '''

    def parser_file(self, content):
        """
        Minimal parser: only apply Nuclei regexes loaded from regex.txt.
        Returns list of dicts: {"link": "[NUCLEI MATCH] <match>", "priority":"HIGH"}
        """
        items = []
        try:
            if getattr(self, 'nuclei_regexes', None):
                for rx in self.nuclei_regexes:
                    try:
                        for m in rx.finditer(content):
                            val = m.group(0)
                            if val:
                                items.append({"link": "[NUCLEI MATCH] " + val, "priority": "HIGH"})
                    except Exception:
                        continue
        except Exception:
            pass

        # dedupe per file
        seen = set()
        nodup = []
        for it in items:
            link = it.get('link')
            if link and link not in seen:
                seen.add(link)
                nodup.append(it)
        return nodup[:MAX_RESULTS_PER_FILE]

    def _parse_js_regex_literals(self, text):
        """
        Parse JS-style regex literals from text: /pattern/flags
        Returns list of (pattern, flags) tuples.
        """
        rules = []
        try:
            for m in re.finditer(r'/((?:\\.|[^/])*)/([gimsuy]*)', text):
                pat = m.group(1)
                flags = m.group(2) or ''
                rules.append((pat, flags))
        except Exception:
            pass
        return rules

    def _load_js_regex_file(self, path):
        """
        Load a regex file that may contain JS-style regex literals or plain lines.
        Returns list of compiled Python re objects.
        """
        out = []
        try:
            with open(path, 'r') as f:
                txt = f.read()
        except Exception as e:
            raise IOError("unable to read regex file: %s" % e)

        # Try JS-style literals first
        parsed = self._parse_js_regex_literals(txt)
        if parsed:
            for pat, flags in parsed:
                fl = 0
                if 'i' in flags: fl |= re.I
                if 'm' in flags: fl |= re.M
                if 's' in flags: fl |= re.S
                # ignore g, u, y (no direct Python equivalent)
                try:
                    out.append(re.compile(pat, fl))
                except Exception:
                    # best-effort: unescape \/ sequences then try again
                    try:
                        out.append(re.compile(pat.replace('\\/', '/'), fl))
                    except Exception:
                        continue
            return out

        # Fallback: each non-empty, non-comment line is a pattern
        for ln in txt.splitlines():
            line = ln.strip()
            if not line or line.startswith('#'):
                continue
            try:
                out.append(re.compile(line))
            except Exception:
                try:
                    out.append(re.compile(line, re.I))
                except Exception:
                    continue
        return out

    def _probe_worker(self):
        """
        Minimal probe worker to keep threads alive.
        Real probe implementation removed to keep extension focused on Nuclei matches.
        """
        while True:
            try:
                # Sleep to avoid busy loop; probe queue is unused in this minimal mode
                time.sleep(1.0)
            except Exception:
                break

    def _toggle_probe(self, event):
        """
        Toggle probe enabled flag and update button text (safe if UI not yet created).
        """
        try:
            self._probe_enabled = not getattr(self, '_probe_enabled', False)
            if hasattr(self, 'probeToggle') and self.probeToggle is not None:
                try:
                    self.probeToggle.setSelected(self._probe_enabled)
                    self.probeToggle.setText("Probe HEAD (on)" if self._probe_enabled else "Probe HEAD (off)")
                except Exception:
                    pass
            self.append_log("Probe HEAD set to: {}".format("on" if self._probe_enabled else "off"))
        except Exception as e:
            safe_print(self.stderr, "_toggle_probe error: " + str(e))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        IHttpListener callback — scan HTTP responses (only) with nuclei regexes.
        Only process textual responses (js/json/html/text). Adds deduped rows to the UI.
        """
        try:
            # Only handle responses
            if messageIsRequest:
                return

            # Make sure we have compiled nuclei rules
            if not getattr(self, 'nuclei_regexes', None):
                return

            resp = messageInfo.getResponse()
            if not resp:
                return

            # analyze response and skip non-textual content
            analyzed = self._helpers.analyzeResponse(resp)
            headers = analyzed.getHeaders()
            content_type = ''
            try:
                for h in headers:
                    if h and h.lower().startswith('content-type:'):
                        content_type = h.split(':', 1)[1].strip().lower()
                        break
            except Exception:
                content_type = ''

            if content_type and not any(x in content_type for x in ('text', 'javascript', 'json', 'html')):
                return

            # get response body as string
            body_offset = analyzed.getBodyOffset()
            resp_str = self._helpers.bytesToString(resp)
            body = resp_str[body_offset:] if body_offset < len(resp_str) else ''

            if not body:
                return

            # run parser (returns list of dicts {"link":..., "priority":...})
            try:
                matches = self.parser_file(body)
            except Exception as e:
                safe_print(self.stderr, "parser_file error: %s" % e)
                return

            if not matches:
                return

            # source (URL or host) for UI
            try:
                src = str(messageInfo.getUrl()) if messageInfo.getUrl() else str(messageInfo.getHttpService())
            except Exception:
                src = "response"

            # add matches to UI (dedupe globally using self._seen)
            def add_rows():
                try:
                    for it in matches:
                        endpoint = it.get('link') or ''
                        prio = it.get('priority') or ''
                        if not endpoint:
                            continue
                        if endpoint in self._seen:
                            continue
                        try:
                            self.tableModel.addRow([endpoint, src, prio, ""])
                        except Exception:
                            # fallback: append to internal storage only
                            pass
                        self._seen.add(endpoint)
                        self._all_rows.append((endpoint, src, prio, ""))
                        self.append_log("Found: {} (src={})".format(endpoint, src))
                except Exception as e:
                    safe_print(self.stderr, "add_rows error: %s" % e)

            EventQueue.invokeLater(add_rows)

        except Exception as e:
            safe_print(self.stderr, "processHttpMessage error: %s" % e)
