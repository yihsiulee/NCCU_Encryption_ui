from PyQt5.QtWidgets import * 
from PyQt5 import QtCore
import sys
import pyperclip
from aes import AES
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Slave')
        self.__output = QTextEdit()
        self.__output.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)

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

        keyLabel = QLabel("Key:")
        self.__keyEdit = QLineEdit()
        msgLabel = QLabel("Msg:")
        self.__msgEdit = QLineEdit()
        encryptButton = QPushButton("Encrypt")
        decryptButton = QPushButton("Decrypt")
        getKeyButton = QPushButton("Get Key")
        copyButton = QPushButton("Copy")

        vBoxLayout = QVBoxLayout()
        hBoxLayout = QHBoxLayout()

        formLayout = QFormLayout()
        formLayout.addRow(keyLabel,self.__keyEdit)
        formLayout.addRow(msgLabel,self.__msgEdit)

        hBoxLayout.addWidget(getKeyButton)
        #hBoxLayout.addWidget(encryptButton)
        hBoxLayout.addWidget(decryptButton)
        
        
        vBoxLayout.addWidget(self.__output)
        vBoxLayout.addItem(formLayout)
        vBoxLayout.addItem(radioButtonLayout)
        vBoxLayout.addItem(hBoxLayout)
        #vBoxLayout.addWidget(copyButton)
        encryptButton.setObjectName('encryptBtn')
        decryptButton.setObjectName('decryptBtn')
        getKeyButton.setObjectName('getKeyBtn')
        copyButton.setObjectName('copyBtn')
        #encryptButton.clicked.connect(self.__handleEncryptClick)
        decryptButton.clicked.connect(self.__handleDecryptClick)
        getKeyButton.clicked.connect(self.__handleDecryptClick)
        copyButton.clicked.connect(self.__handleCopy) 

        self.setLayout(vBoxLayout)
        self.setStyleSheet(open('styles.css').read())
        self.setFixedSize(850,700)
        self.show()

    def __handleCopy(self):
        pyperclip.copy(self.__output.document().toPlainText())
        pyperclip.paste()
    def __handleDecryptClick(self):
        try:
            if(len(self.__output.toPlainText()) > 0):
                self.__output.document().clear()
            aes = AES(self.__keyEdit.text(),self.__msgEdit.text())
            aes.decrypt()
            self.__output.document().setPlainText(aes.getOutput())
        except:
            pass
        
    def __handleEncryptClick(self):
        try:
            if(len(self.__output.toPlainText()) > 0):
                self.__output.document().clear()
            aes = AES(self.__keyEdit.text(),self.__msgEdit.text())
            aes.encrypt()
            self.__output.document().setPlainText(aes.getOutput())
        except:
            pass
        

app = QApplication(sys.argv)
window = MainWindow()
sys.exit(app.exec_())
