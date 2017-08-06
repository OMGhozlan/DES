import sys
import base64
from DES import DES
from math import ceil
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox

class crypter(object):
    def init_ui(self, Dialog):
        Dialog.setObjectName("DES Encrypter/Decrypter")
        Dialog.resize(438, 300)
        self.op_select = QtWidgets.QComboBox(Dialog)
        self.op_select.setGeometry(QtCore.QRect(40, 240, 135, 22))
        self.op_select.addItems(['Decrypt', 'Encrypt'])
        # self.op_select.addItems()
        self.browse_btn = QtWidgets.QPushButton(Dialog)
        self.browse_btn.setGeometry(QtCore.QRect(310, 144, 75, 23))
        self.browse_btn.setObjectName("browse_btn")
        self.browse_btn.clicked.connect(self.browser_handler)
        self.path_label = QtWidgets.QLabel(Dialog)
        self.path_label.setGeometry(QtCore.QRect(20, 110, 101, 16))
        self.key_label = QtWidgets.QLabel(Dialog)
        self.key_label.setGeometry(QtCore.QRect(20, 175, 101, 16))
        self.path_label.setObjectName("path_label")
        self.title_label = QtWidgets.QLabel(Dialog)
        self.title_label.setGeometry(QtCore.QRect(110, 30, 231, 22))
        font = QtGui.QFont()
        font.setPointSize(11)
        font.setBold(True)
        font.setWeight(75)
        self.title_label.setFont(font)
        self.title_label.setAcceptDrops(False)
        self.title_label.setScaledContents(False)
        self.title_label.setObjectName("title_label")
        self.ok_btn = QtWidgets.QPushButton(Dialog)
        self.ok_btn.setGeometry(QtCore.QRect(250, 240, 75, 23))
        self.ok_btn.setObjectName("ok_btn")
        self.ok_btn.clicked.connect(self.op_handler)
        self.exit_btn = QtWidgets.QPushButton(Dialog)
        self.exit_btn.setGeometry(QtCore.QRect(340, 240, 75, 23))
        self.exit_btn.setObjectName("exit_btn")
        # self.exit_btn.clicked.connect(None)
        self.exit_btn.clicked.connect(Dialog.close)
        self.path_edit = QtWidgets.QLineEdit(Dialog)
        self.path_edit.setGeometry(QtCore.QRect(20, 144, 281, 26))
        self.path_edit.setObjectName("path_edit")
        self.key_edit = QtWidgets.QLineEdit(Dialog)
        self.key_edit.setGeometry(QtCore.QRect(20, 200, 281, 26))
        self.key_edit.setObjectName("key_edit")

        self.retranslate_ui(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslate_ui(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "DES Encrypter/Decrypter 13P6040"))
        self.op_select.setToolTip(_translate("Dialog", "<html><head/><body><p>Encrypt</p><p>Decrypt</p></body></html>"))
        self.op_select.setWhatsThis(_translate("Dialog", "<html><head/><body><p>Select operation</p></body></html>"))
        self.op_select.setCurrentText(_translate("Dialog", "Encrypt"))
        self.browse_btn.setText(_translate("Dialog", "Browse"))
        self.path_label.setText(_translate("Dialog", "Path to file:"))
        self.key_label.setText(_translate("Dialog", "Key (Optional):"))
        self.title_label.setText(_translate("Dialog", "DES File Encrypter/Decrypter"))
        self.ok_btn.setText(_translate("Dialog", "OK"))
        self.exit_btn.setText(_translate("Dialog", "Exit"))

    def op_handler(self):
        # print(self.op_select.currentIndex())
        path_f = self.path_edit.text()
        if len(path_f) == 0:
            self.notify('Please select a file!')
            return
        op = self.op_select.currentIndex()
        key_f = self.key_edit.text()
        if len(key_f) == 0:
            key = "keykeykey"
        else:
            key = key_f * ceil(8/len(key_f))
        # p_text= "Hello wo"
        # print("Key ", len(key))
        d = DES()
        global ciphertext, plaintext
        # with open(file_names, 'r') as file:
        #    data = file.read()
        if op == 1:
            ciphertext = d.encrypt(key, p_text, True)
            # print ("Ciphered: ", ciphertext.encode('ascii', 'ignore'))
            with open(new_file+'_enc.enc', 'wb') as file:
                file.write(ciphertext.encode('ascii', 'ignore'))
            self.notify('Encryption finished successfully!')
        else:
            plaintext = d.decrypt(key, ciphertext, True)
            with open(new_file+'_dec.txt', 'w') as file:
                file.write(plaintext)
            self.notify('Decryption finished successfully!')
            # print ("Deciphered: ", plaintext)

    def browser_handler(self):
      global p_text, new_file
      browser = QFileDialog()
      browser.setFileMode(QFileDialog.AnyFile)
      browser.setNameFilters(["Text files (*.txt)", "Images (*.png *.jpg)", "Encrypted Files (*.enc)"])
      browser.selectNameFilter("Text files (*.txt)")
      # file_names = QtWidgets.QStringList()
      if browser.exec_():
         file_names = browser.selectedFiles()
         self.path_edit.setText(file_names[0])
         new_file = file_names[0].split('/')[-1]
         new_file = new_file[:-4]
         with open(file_names[0], 'r') as file:
             p_text = file.read()
            # print(p_text)
            # self.contents.setText(data)
      # self.le.setPixmap(QPixmap(fname))

    def notify(self, message):
        info = QMessageBox()
        info.setIcon(QMessageBox.Information)
        info.setText(message)
        retval = info.exec_()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    crypt = QDialog()
    ui = crypter()
    ui.init_ui(crypt)
    crypt.show()
    sys.exit(app.exec_())
