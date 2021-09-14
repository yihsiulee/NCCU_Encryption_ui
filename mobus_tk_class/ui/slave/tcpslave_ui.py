from PyQt5.QtWidgets import * 
from PyQt5 import QtCore
import sys
import pyperclip
import pyDH
import time
# from aes import AES
import tcpslave 

class MainWindow(QWidget):
    slave = tcpslave.TcpSlave()
    algoSet = 0
    #DH = pyDH.DiffieHellman(5)
    #PK = DH.gen_public_key()
    global share
    # shareKey = ''
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Slave')
        self.__output = QTextEdit()
        self.__output.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOn)
        self.__output.verticalScrollBar().setValue(self.__output.verticalScrollBar().maximum())
        
        keyLabel = QLabel("Key:")
        self.__keyEdit = QLineEdit()
        msgLabel = QLabel("Msg:")
        self.__msgEdit = QLineEdit()
        #encryptButton = QPushButton("Encrypt")
        decryptButton = QPushButton("Decrypt")
        getKeyButton = QPushButton("Get Key")
        #copyButton = QPushButton("Copy")
        
        aesRadioButton = QRadioButton("AES")
        aesRadioButton.setChecked(True)
        aesRadioButton.toggled.connect(self.algoSelected)
        presentRadioButton = QRadioButton("PRESENT")
        presentRadioButton.toggled.connect(self.algoSelected)
        speckRadioButton = QRadioButton("Speck")
        speckRadioButton.toggled.connect(self.algoSelected)
        simonRadioButton = QRadioButton("Simon")
        simonRadioButton.toggled.connect(self.algoSelected)
        radioButtonLayout = QHBoxLayout()
        radioButtonLayout.addWidget(aesRadioButton)
        radioButtonLayout.addWidget(presentRadioButton)
        radioButtonLayout.addWidget(speckRadioButton)
        radioButtonLayout.addWidget(simonRadioButton)
        #radioButtonLayout.addStretch
        radioButtonLayout.setAlignment(QtCore.Qt.AlignCenter)
        
        
        vBoxLayout = QVBoxLayout()
        hBoxLayout = QHBoxLayout()
        

        formLayout = QFormLayout()
        formLayout.addRow(keyLabel,self.__keyEdit)
        #formLayout.addRow(msgLabel,self.__msgEdit)
        

        hBoxLayout.addWidget(getKeyButton)
        #hBoxLayout.addWidget(encryptButton)
        hBoxLayout.addWidget(decryptButton)
        
        
        
        vBoxLayout.addWidget(self.__output)
        vBoxLayout.addItem(formLayout)
        vBoxLayout.addItem(radioButtonLayout)
        vBoxLayout.addItem(hBoxLayout)
        #vBoxLayout.addWidget(copyButton)
        #encryptButton.setObjectName('encryptBtn')
        decryptButton.setObjectName('decryptBtn')
        getKeyButton.setObjectName('getKeyBtn')
        #copyButton.setObjectName('copyBtn')
        #encryptButton.clicked.connect(self.__handleEncryptClick)
        decryptButton.clicked.connect(self.__handleDecryptClick)
        getKeyButton.clicked.connect(self.__getKey)
        # copyButton.clicked.connect(self.__handleCopy) 
        

        self.setLayout(vBoxLayout)
        self.setStyleSheet(open('styles.css').read())
        self.setFixedSize(850,700)
        self.show()

    def __getKey(self):
        # self.shareKey = self.master.get_key()
        dhKey = self.slave.get_key()
        self.__keyEdit.setText(dhKey)
        self.show_log("The received shared key is " + str(dhKey))
        
    def __handleDecryptClick(self):
        
       #self.show_log("1The received values are " + str(self.slave.getServer().get_slave(self.slave_id)
        start_time = time.time()
        if self.algoSet == 0:
                values, result = self.slave.dec_AES()
                self.show_log("The receive values are" + str(values) )
                self.show_log("After AES decryption, the original value is " + str(result))
        elif self.algoSet == 1:
                values, result = self.slave.dec_present()
                self.show_log("The receive values are" + str(values) )
                self.show_log("After PRESENT encryption, the original value is " + str(result))
        elif self.algoSet == 2:
                values, result = self.slave.dec_speck()
                self.show_log("The receive values are" + str(values) )
                self.show_log("After SPECK encryption, the original value is " + str(result))
        else:
                values, result = self.slave.dec_simon()
                self.show_log("The receive values are" + str(values) )
                self.show_log("After Simon encryption, the original value is " + str(result))
        end_time = time.time()
        self.show_log("The decryption time is  " + str(end_time - start_time))
            
    def __handleEncryptClick(self):
        text = self.__msgEdit.text()
        self.show_log("The original value is " + str(text))
        if self.algoSet == 0:
                cts = self.master.enc_AES([text])
                self.show_log("After AES encryption, the values are " + str(cts))
        elif self.algoSet == 1:
                cts = self.master.enc_present([text])
                self.show_log("After PRESENT encryption, the values are " + str(cts))
        elif self.algoSet == 2:
                cts = self.master.enc_speck([text])
                self.show_log("After SPECK encryption, the values are " + str(cts))
        else:
                cts = self.master.enc_simon([text])
                self.show_log("After Simon encryption, the values are " + str(cts))
        
        self.master.send_to_slave(cts)
                


    def algoSelected(self):
        radioBtn = self.sender()
        if radioBtn.text() == 'AES' :
                self.algoSet = 0
        elif radioBtn.text() == 'PRESENT' :
                self.algoSet = 1
        elif radioBtn.text() == 'Speck' :
                self.algoSet = 2
        else:
                self.algoSet = 3
        
    def show_log(self,info):
        preText = self.__output.toPlainText()
        self.__output.document().setPlainText(preText+info+'\n\n')
        self.__output.verticalScrollBar().setValue(self.__output.verticalScrollBar().maximum())
        
    # def __handleCopy(self):
    #     pyperclip.copy(self.__output.document().toPlainText())
    #     pyperclip.paste()
    # def __handleDecryptClick(self):
    #     try:
    #         if(len(self.__output.toPlainText()) > 0):
    #             self.__output.document().clear()
    #         aes = AES(self.__keyEdit.text(),self.__msgEdit.text())
    #         aes.decrypt()k
    #         self.__output.document().setPlainText(aes.getOutput())
    #     except:
    #         pass
        
    # def __handleEncryptClick(self):
    #     try:
    #         if(len(self.__output.toPlainText()) > 0):
    #             self.__output.document().clear()
    #         aes = AES(self.__keyEdit.text(),self.__msgEdit.text())
    #         aes.encrypt()
    #         self.__output.document().setPlainText(aes.getOutput())
    #     except:
    #         pass


app = QApplication(sys.argv)
window = MainWindow()
sys.exit(app.exec_())
