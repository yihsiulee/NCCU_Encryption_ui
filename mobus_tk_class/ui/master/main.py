from PyQt5.QtWidgets import * 
from PyQt5 import QtCore
import sys
import pyperclip
# from aes import AES
import tcpmaster 
class MainWindow(QWidget):
    master = tcpmaster.TcpMaster()
    # shareKey = ''
    def __init__(self):
        # tcpmaster.main()
        super().__init__()
        self.setWindowTitle('Master')
        self.__output = QTextEdit()
        self.__output.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        #1e25364584fa98c6a8b230c3a589621d
        #8a78b010 238a35ef12916c6556232d21 
        keyLabel = QLabel("Key:")
        self.__keyEdit = QLineEdit()
        msgLabel = QLabel("Msg:")
        self.__msgEdit = QLineEdit()
        encryptButton = QPushButton("Encrypt")
        decryptButton = QPushButton("Decrypt")
        getKeyButton = QPushButton("Get Key")
        copyButton = QPushButton("Copy")
        
        aesRadioButton = QRadioButton("AES")
        aesRadioButton.setChecked(True)
        presentRadioButton = QRadioButton("PRESENT")
        speckRadioButton = QRadioButton("Speck")
        simonRadioButton = QRadioButton("Simon")
        radioButtonLayout = QHBoxLayout()
        radioButtonLayout.addWidget(aesRadioButton)
        radioButtonLayout.addWidget(presentRadioButton)
        radioButtonLayout.addWidget(speckRadioButton)
        radioButtonLayout.addWidget(simonRadioButton)
        #radioButtonLayout.addStretch
        radioButtonLayout.setAlignment(QtCore.Qt.AlignCenter)
        #aesRadioButton.toggled.connect(self.onClicked)
        
        vBoxLayout = QVBoxLayout()
        hBoxLayout = QHBoxLayout()
        

        formLayout = QFormLayout()
        formLayout.addRow(keyLabel,self.__keyEdit)
        formLayout.addRow(msgLabel,self.__msgEdit)
        

        hBoxLayout.addWidget(getKeyButton)
        hBoxLayout.addWidget(encryptButton)
        #hBoxLayout.addWidget(decryptButton)
        
        
        
        vBoxLayout.addWidget(self.__output)
        vBoxLayout.addItem(formLayout)
        vBoxLayout.addItem(radioButtonLayout)
        vBoxLayout.addItem(hBoxLayout)
        #vBoxLayout.addWidget(copyButton)
        encryptButton.setObjectName('encryptBtn')
        decryptButton.setObjectName('decryptBtn')
        getKeyButton.setObjectName('getKeyBtn')
        copyButton.setObjectName('copyBtn')
        encryptButton.clicked.connect(self.__set_AES_values)
        # decryptButton.clicked.connect(self.__handleDecryptClick)
        getKeyButton.clicked.connect(self.__getKey)
        # copyButton.clicked.connect(self.__handleCopy) 
        

        self.setLayout(vBoxLayout)
        self.setStyleSheet(open('styles.css').read())
        self.setFixedSize(850,700)
        self.show()

    def __getKey(self):
        # self.shareKey = self.master.get_key()
        self.__keyEdit.setText(self.master.get_key())

    def __set_AES_values(self):
        text = self.__msgEdit.text()
        cts = self.master.enc_AES([text])
        self.master.send_to_slave(cts)
    # def __handleCopy(self):
    #     pyperclip.copy(self.__output.document().toPlainText())
    #     pyperclip.paste()
    # def __handleDecryptClick(self):
    #     try:
    #         if(len(self.__output.toPlainText()) > 0):
    #             self.__output.document().clear()
    #         aes = AES(self.__keyEdit.text(),self.__msgEdit.text())
    #         aes.decrypt()
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
