from burp import IBurpExtender
from burp import IScannerInsertionPoint
from burp import IScannerCheck
from burp import ITab
from burp import IScannerInsertionPointProvider
from javax.swing.event import DocumentListener
from java.awt.event import ActionListener
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JTextField
from javax.swing import JTabbedPane
from javax.swing import JPanel
from javax.swing import JFileChooser
from javax.swing import JCheckBox
from javax.swing import JScrollPane
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
import random
import os
import copy
import urllib
import imghdr
import mimetypes

class BurpExtender(IBurpExtender, ITab, DocumentListener, ActionListener, IScannerInsertionPointProvider):
    
    def	registerExtenderCallbacks(self, callbacks):
        print "Extension loaded!"
        self._callbacks = callbacks
        
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("HttpFuzzer")

        #Abusing functionality here :(
        #I would have prefered to have it implemented as an active scan module
        callbacks.registerScannerInsertionPointProvider(self)
        
        self._newline = "\r\n"
        
        #Options:
        self._random_mutations = 0
        self._known_fuzz_string_mutations = 0
        self._custom_fuzz_strings = None
        
        self._known_fuzz_strings = [
            "A" * 256, 
            "A" * 1024, 
            "A" * 4096, 
            "A" * 20000, 
            "A" * 65535,
            "%x" * 256, 
            "%n" * 256 , 
            "%s" * 256, 
            "%s%n%x%d" * 256, 
            "%s" * 256, 
            "%.1024d", 
            "%.2048d", 
            "%.4096d", 
            "%.8200d", 
            "%99999999999s", 
            "%99999999999d", 
            "%99999999999x", 
            "%99999999999n", 
            "%99999999999s" * 200, 
            "%99999999999d" * 200, 
            "%99999999999x" * 200, 
            "%99999999999n" * 200, 
            "%08x" * 100, 
            "%%20s" * 200,
            "%%20x" * 200,
            "%%20n" * 200,
            "%%20d" * 200, 
            "%#0123456x%08x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%08x", 
            "'", 
            "\\", 
            "<", 
            "+", 
            "%", 
            "$", 
            "`"
        ]
        
        #End Options
        
        #UI START
        
        self._main_jtabedpane = JTabbedPane()
        
        #Setup the options
        self._optionsJPanel = JPanel()
        gridBagLayout = GridBagLayout();
        gbc = GridBagConstraints()
        self._optionsJPanel.setLayout(gridBagLayout)
        
        self.JLabel_random_mutations = JLabel("Number of random bit and byte mutations: ")
        gbc.gridy += 1
        gbc.gridx = 0
        self._optionsJPanel.add(self.JLabel_random_mutations, gbc)
        gbc.gridx = 1
        self.JTextField_random_mutations = JTextField(str(self._random_mutations), 6)
        self.JTextField_random_mutations.getDocument().addDocumentListener(self)
        self._optionsJPanel.add(self.JTextField_random_mutations, gbc)
        callbacks.customizeUiComponent(self.JLabel_random_mutations)
        callbacks.customizeUiComponent(self.JTextField_random_mutations)
        
        self.JLabel_known_fuzz_string_mutations = JLabel("Number of tests with known fuzzing strings: ")
        gbc.gridy += 1
        gbc.gridx = 0
        self._optionsJPanel.add(self.JLabel_known_fuzz_string_mutations, gbc)
        gbc.gridx = 1
        self.JTextField_known_fuzz_string_mutations = JTextField(str(self._known_fuzz_string_mutations), 6)
        self.JTextField_known_fuzz_string_mutations.getDocument().addDocumentListener(self)
        self._optionsJPanel.add(self.JTextField_known_fuzz_string_mutations, gbc)
        callbacks.customizeUiComponent(self.JLabel_known_fuzz_string_mutations)
        callbacks.customizeUiComponent(self.JTextField_known_fuzz_string_mutations)
        
        self._filepath = ''
        self.JLabel_filepath = JLabel("Replacement for known fuzzing strings (one per line): ")
        gbc.gridy += 1
        gbc.gridx = 0
        gbc.gridwidth = 1
        self._optionsJPanel.add(self.JLabel_filepath, gbc)
        gbc.gridx = 1
        self.JTextField_filepath = JTextField(self._filepath, 25)
        self.JTextField_filepath.getDocument().addDocumentListener(self)
        self._optionsJPanel.add(self.JTextField_filepath, gbc)
        gbc.gridx = 2
        self.FileChooserButton_filepath = FileChooserButton()
        self.FileChooserButton_filepath.setup(self.JTextField_filepath, "Choose")
        self._optionsJPanel.add(self.FileChooserButton_filepath, gbc)
        callbacks.customizeUiComponent(self.JLabel_filepath)
        callbacks.customizeUiComponent(self.JTextField_filepath)
        callbacks.customizeUiComponent(self.FileChooserButton_filepath)
        
        about = "<html>"
        about += "Author: floyd, @floyd_ch, http://www.floyd.ch<br>"
        about += "<br>"
        about += "<h3>A simple random fuzzer</h3>"
        about += "<p style=\"width:500px\">"
        about += "This plugin adds ActiveScan checks. "
        about += "Using this fuzzer with any standard HTTP server (Apache, Nginx, etc.) is usually useless, but can be fun. "
        about += "It can be used to see the different error conditions a server and the web application code can run into. "
        about += "However, if you are targeting an embedded device HTTP server or anything more exotic you might be more lucky. "
        about += "The plugin does not do any checks and doesn't add any issues. It is recommended to install the Collect500, "
        about += "ResponseClusterer, Logger++ and Error Message Checks plugin. Additionally it is recommended to attach a debugger to the "
        about += "target program on the server (or use strace or another tool of your choice). <br>"
        about += "In it's default configuration the plugin will not do anything, as it is not considered efficient to fuzz every actively scanned request. "
        about += "You need to specify a higher value for the number of tests in the options tab to enable fuzzing. "
        about += "</p>"
        about += "</html>"
        self.JLabel_about = JLabel(about)
        self.JLabel_about.setLayout(GridBagLayout())
        self._aboutJPanel = JScrollPane(self.JLabel_about)

        # customize our UI components
        callbacks.customizeUiComponent(self._main_jtabedpane)
        callbacks.customizeUiComponent(self._optionsJPanel)
        callbacks.customizeUiComponent(self._aboutJPanel)

        self._main_jtabedpane.addTab("Options", None, self._optionsJPanel, None)
        self._main_jtabedpane.addTab("About & README", None, self._aboutJPanel, None)

        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        #UI END
        print "Extension registered!"        
    
    #
    # UI: implement ITab
    #
    
    def getTabCaption(self):
        return "HttpFuzzer"

    def getUiComponent(self):
        return self._main_jtabedpane

    #
    # UI: implement what happens when options are changed
    #

    def changedUpdate(self, document):
        pass

    def removeUpdate(self, document):
        self.insertUpdate(document)

    def insertUpdate(self, document):
        filepath = self.JTextField_filepath.getText().encode("utf-8")
        if filepath:
            try:
                self._custom_fuzz_strings = file(filepath, "rb").readlines()
            except:
                print "ERROR: Couldn't read file"
                self._custom_fuzz_strings = None
        print filepath
        
        try:
            self._random_mutations = int(self.JTextField_random_mutations.getText())
        except:
            print "Exception,", self.JTextField_random_mutations.getText(), "is not numeric"
            self._random_mutations = 0
        try:
            self._known_fuzz_string_mutations = int(self.JTextField_known_fuzz_string_mutations.getText())
        except:
            print "Exception,", self.JTextField_known_fuzz_string_mutations.getText(), "is not numeric"
            self._known_fuzz_string_mutations = 0
        print self._random_mutations, self._known_fuzz_string_mutations
    
    def actionPerformed(self, actionEvent):
        self.insertUpdate(None)
    
    #TODO: Is there another way to simply say "each active scanned HTTP request once"?
    #it seems not: https://support.portswigger.net/customer/en/portal/questions/16776337-confusion-on-insertionpoints-active-scan-module?new=16776337
    #So we are going to abuse a functionality of Burp called IScannerInsertionPoint
    #which is by coincidence always called once per request for every actively scanned item (with baseRequestResponse)
    #this is an ugly hack as the percentage of active scan is simply stuck until this plugin is done
    def getInsertionPoints(self, baseRequestResponse):
        self.do_fuzzing(baseRequestResponse)
    
    def do_fuzzing(self, baseRequestResponse):
        req = FloydsHelpers.jb2ps(baseRequestResponse.getRequest())
        fuzz_strings = self._custom_fuzz_strings or self._known_fuzz_strings
        for _ in xrange(0, self._known_fuzz_string_mutations):
            index = random.choice(xrange(0, len(req)))
            print "Inserted known fuzz string at byte index", index
            new_req = req[:index]+random.choice(fuzz_strings)+req[index+1:]
            try:
                self._send(baseRequestResponse, new_req)
            except Exception, e:
                print "Error occured. Ignoring and simply going on."
                print e
        for _ in xrange(0, self._random_mutations):
            index = random.randint(0, len(req)-1)
            new_req = req
            if random.choice((True, False)):
                #byte change
                print "At byte index", index, "changed to new byte"
                new_req = req[:index]+chr(random.randint(0, 255))+req[index+1:]
            else:
                #bit change
                bit_index = random.randint(0, 7)
                print "At byte index", index, "changed bit", bit_index
                new_byte = chr(ord(req[index]) ^ (2**bit_index))
                new_req = req[:index]+new_byte+req[index+1:]
            try:
                self._send(baseRequestResponse, new_req)
            except Exception, e:
                print "Error occured. Ignoring and simply going on."
                print e

    def _send(self, baseRequestResponse, req):
        offset = self._helpers.analyzeRequest(baseRequestResponse).getBodyOffset()
        method = self._helpers.analyzeRequest(baseRequestResponse).getMethod()
        status_headers, body = req[:offset], req[offset:]
        # We should not provide Content-Length on GET requests.
        if method != "GET":
            status_headers = FloydsHelpers.fix_http_content_length(status_headers, len(body), self._newline)
        new_req = status_headers + body
        self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), new_req)
    
class FloydsHelpers(object):
    @staticmethod
    def fix_http_content_length(headers, length, newline):
        h = list(headers.split(newline))
        for index, x in enumerate(h):
            #trick to keep capitalization of the Content-Type header:
            if "content-length:" == x[:len("content-length:")].lower():
                h[index] = x[:len("content-length:")]+" "+str(length)
                return newline.join(h)
        else:
            print "WARNING: Couldn't find Content-Length header in request, maybe it got destroyed with fuzzing? Simply adding this header."
            h.insert(1, "Content-Length: "+str(length))
            return newline.join(h)
    
    @staticmethod
    def jb2ps(arr):
        return ''.join(map(lambda x: chr(x % 256), arr))

class FileChooserButton(JButton, ActionListener):
    
    def setup(self, field, button_name):
        self.field = field
        self.addActionListener(self)
        self.setText(button_name)
    
    def actionPerformed(self, actionEvent):
        chooser = JFileChooser()
        #chooser.setCurrentDirectory(".")
        chooser.setDialogTitle("Choose file")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setAcceptAllFileFilterUsed(False)
        if chooser.showOpenDialog(self) == JFileChooser.APPROVE_OPTION:
            print chooser.getCurrentDirectory()
            print chooser.getSelectedFile()
            self.field.setText(str(chooser.getSelectedFile()))
        else:
            print "No file selected"
