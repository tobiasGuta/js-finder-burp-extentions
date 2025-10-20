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
from javax.swing.table import DefaultTableModel
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from java.net import URI
import re
import threading
import time
import base64
import binascii
import json

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

        # regexes & patterns
        self.linkfinder_regex = re.compile(self._linkfinder_regex(), re.VERBOSE)
        self.simple_patterns = [
            re.compile(r'(https?://[A-Za-z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]+)'),
            re.compile(r'(["\'])(/[-A-Za-z0-9_\.~/\?\=&%]+)\1'),
        ]
        self.token_patterns = ['fetch(', 'axios.', 'XMLHttpRequest', '.open(', 'new WebSocket']

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
            safe_print(self.stdout, "[BurpJSLinkFinder] _on_search_key fired; text='%s'" % str(self.searchField.getText()))
            # live updates should NOT steal focus from the search field
            self._apply_search(focus_log=False)
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

        # Only move focus / select in the log when explicitly requested (Enter)
        if text_l and focus_log:
            log_lower = str(self.logArea.getText()).lower()
            idx = log_lower.find(text_l)
            if idx != -1:
                start = idx
                end = idx + len(text_l)
                self.logArea.requestFocus()
                self.logArea.select(start, end)
                self.logArea.setCaretPosition(end)
        elif not text_l:
            # keep log selection cleared, but don't steal focus
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
        items = [{"link": m.group(1)} for m in re.finditer(self.linkfinder_regex, content)]
        # also check simple patterns for faster catches or fallback
        for p in self.simple_patterns:
            for m in p.finditer(content):
                found = m.group(1) if m.groups() and m.group(1) else m.group(0)
                if found:
                    items.append({"link": found})
        # attempt to pull out strings built by concatenation "api/" + "v1/..."
        concat_matches = re.findall(r'(["\'])(.+?)\1\s*\+\s*["\'](.+?)["\']', content)
        for cm in concat_matches:
            try:
                composed = cm[1] + cm[2]
                items.append({"link": composed})
            except:
                pass
        # decoded content search (base64/hex)
        b64_cands = re.findall(r'["\']([A-Za-z0-9+/=]{20,})["\']', content)
        for cand in b64_cands:
            dec = attempt_base64_decode(cand)
            if dec:
                for m in re.finditer(self.linkfinder_regex, dec):
                    items.append({"link": m.group(1)})
        hex_cands = re.findall(r'["\']([0-9a-fA-F]{20,})["\']', content)
        for cand in hex_cands:
            dec = attempt_hex_decode(cand)
            if dec:
                for m in re.finditer(self.linkfinder_regex, dec):
                    items.append({"link": m.group(1)})
        # dedupe per file
        seen = set()
        nodup = []
        for it in items:
            link = it.get('link')
            if link and link not in seen:
                seen.add(link)
                nodup.append({'link': link})
        return nodup[:MAX_RESULTS_PER_FILE]

    # ----------------- probing (HEAD) -----------------
    def _probe_worker(self):
        while True:
            if not self._probe_enabled:
                time.sleep(0.5)
                continue
            item = None
            with self._probe_lock:
                if self._probe_queue:
                    item = self._probe_queue.pop(0)
            if not item:
                time.sleep(0.2)
                continue
            endpoint, source = item
            try:
                from java.net import URL
                u = URL(endpoint)
                host = u.getHost()
                port = u.getPort()
                proto = u.getProtocol()
                useHttps = (proto == 'https')
                # build request bytes and send (note: buildHttpRequest returns GET by default)
                req = self._helpers.buildHttpRequest(u)
                service = self._helpers.buildHttpService(host, port if port != -1 else (443 if useHttps else 80), useHttps)
                resp = self._callbacks.makeHttpRequest(service, req)
                if resp:
                    analyzed = self._helpers.analyzeResponse(resp.getResponse())
                    code = analyzed.getStatusCode()
                    status_str = str(code)
                else:
                    status_str = "no-response"
            except Exception as e:
                status_str = "err:" + str(e)
            self._update_status(endpoint, status_str)

    def _update_status(self, endpoint, status):
        for i, (e, s, pr, st) in enumerate(self._all_rows):
            if e == endpoint:
                self._all_rows[i] = (e, s, pr, status)
                def upd():
                    for r in range(self.tableModel.getRowCount()):
                        if self.tableModel.getValueAt(r, 0) == e:
                            self.tableModel.setValueAt(status, r, 3)
                            break
                EventQueue.invokeLater(upd)
                break

    # ----------------- Burp listener callback -----------------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        try:
            response = messageInfo.getResponse()
            if response is None:
                return
            analyzed = self._helpers.analyzeResponse(response)
            if analyzed is None:
                return
            mime = analyzed.getStatedMimeType()
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            url_str = str(url)
            is_js = False
            if mime and mime.lower() == 'script':
                is_js = True
            if url_str.lower().endswith(".js"):
                is_js = True
            if not is_js:
                return
            if any(x in url_str for x in JS_EXCLUDE):
                return
            body_offset = analyzed.getBodyOffset()
            body_bytes = response[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            results = self.parser_file(body)
            if not results:
                return
            for item in results:
                ep = item.get('link')
                if not ep:
                    continue
                if ep.startswith("//"):
                    ep = "https:" + ep
                if ep.startswith("/") and not ep.startswith("//"):
                    try:
                        from java.net import URL
                        base = URL(url_str)
                        proto = base.getProtocol()
                        host = base.getHost()
                        port = base.getPort()
                        if port == -1:
                            ep_full = "%s://%s%s" % (proto, host, ep)
                        else:
                            ep_full = "%s://%s:%d%s" % (proto, host, port, ep)
                        ep = ep_full
                    except:
                        pass
                ep = ep.strip('"\'` ')
                priority = "LOW"
                ctx = ""
                try:
                    mpos = body.find(item.get('link'))
                    if mpos != -1:
                        start = max(0, mpos - 80)
                        end = min(len(body), mpos + len(item.get('link')) + 80)
                        ctx = body[start:end].lower()
                except:
                    ctx = ""
                for tok in self.token_patterns:
                    if tok.lower() in ctx:
                        priority = "HIGH"
                if (not ep.startswith("http")) and re.match(r'^[A-Za-z0-9+/=]{20,}$', ep):
                    dec = attempt_base64_decode(ep)
                    if dec:
                        sub = self.parser_file(dec)
                        for sitem in sub:
                            s_ep = sitem.get('link')
                            if s_ep and s_ep not in self._seen:
                                self._add_result(s_ep, url_str, "DECODED", "unknown")
                if ep in self._seen:
                    continue
                self._seen.add(ep)
                self._add_result(ep, url_str, priority, "unknown")
                if self._probe_enabled:
                    with self._probe_lock:
                        self._probe_queue.append((ep, url_str))
        except Exception as e:
            safe_print(self.stderr, "Error in processHttpMessage: " + str(e))

    def _add_result(self, endpoint, source, priority, status):
        self._all_rows.append((endpoint, source, priority, status))
        def add_row():
            try:
                self.tableModel.addRow([endpoint, source, priority, status])
            except Exception as e:
                safe_print(self.stderr, "Add row error: " + str(e))
        EventQueue.invokeLater(add_row)
        self.append_log("Found: %s (priority=%s) from %s" % (endpoint, priority, source))

    def _send_to_repeater(self, endpoint):
        try:
            from java.net import URL
            u = URL(str(endpoint))
            host = u.getHost()
            port = u.getPort()
            proto = u.getProtocol()
            useHttps = (proto == 'https')
            req = self._helpers.buildHttpRequest(u)
            service = self._helpers.buildHttpService(host, port if port != -1 else (443 if useHttps else 80), useHttps)

            # Try multiple sendToRepeater overloads and log results
            try:
                # newer Burp: sendToRepeater(IHttpService, byte[])
                self._callbacks.sendToRepeater(service, req)
                self.append_log("Sent to Repeater (service) : " + endpoint)
                return
            except Exception as ex1:
                safe_print(self.stderr, "sendToRepeater(service) failed: " + str(ex1))

            try:
                # common overload: sendToRepeater(host, port, useHttps, request)
                self._callbacks.sendToRepeater(host, port if port != -1 else (443 if useHttps else 80), useHttps, req)
                self.append_log("Sent to Repeater (host/port) : " + endpoint)
                return
            except Exception as ex2:
                safe_print(self.stderr, "sendToRepeater(host,port) failed: " + str(ex2))

            try:
                # some Burp builds expect a title arg: sendToRepeater(host, port, useHttps, request, title)
                self._callbacks.sendToRepeater(host, port if port != -1 else (443 if useHttps else 80), useHttps, req, "BurpJSLinkFinder")
                self.append_log("Sent to Repeater (host/port/title) : " + endpoint)
                return
            except Exception as ex3:
                safe_print(self.stderr, "sendToRepeater(host,port,title) failed: " + str(ex3))

            # If we reach here, none of the overloads succeeded
            self.append_log("Send to Repeater: all attempts failed. See stderr for details.")
        except Exception as e:
            self.append_log("Send to Repeater error: " + str(e))

    def _toggle_probe(self, event):
        self._probe_enabled = not self._probe_enabled
        if self._probe_enabled:
            self.probeToggle.setText("Probe HEAD (on)")
            with self._probe_lock:
                for (e, s, p, st) in self._all_rows:
                    if st == "unknown":
                        self._probe_queue.append((e, s))
        else:
            self.probeToggle.setText("Probe HEAD (off)")
        self.append_log("Probe HEAD toggled: " + str(self._probe_enabled))

# End of file
