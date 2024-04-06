import sys
import os
import zipfile
import shutil
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLineEdit, QLabel, QFileDialog, QMessageBox
from PyQt5.QtCore import pyqtSlot, Qt

class App(QWidget):
    def __init__(self):
        super().__init__()
        self.title = 'Decrypt PDX ZIP'
        self.initUI()
        
    def initUI(self):
        layout = QVBoxLayout()
        
        self.label = QLabel('Drop the encrypted .pdx.zip here and enter the key')
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setAcceptDrops(True)
        self.label.setFixedSize(400, 100)
        
        self.key_input = QLineEdit(self)
        self.key_input.setPlaceholderText('Enter the decryption key')
        
        self.decrypt_btn = QPushButton('Decrypt', self)
        self.decrypt_btn.clicked.connect(self.decrypt_file)

        layout.addWidget(self.label)
        layout.addWidget(self.key_input)
        layout.addWidget(self.decrypt_btn)
        
        self.setLayout(layout)
        self.setWindowTitle(self.title)
        self.setGeometry(100, 100, 450, 200)
        self.show()
        
        self.label.dragEnterEvent = self.dragEnterEvent
        self.label.dropEvent = self.dropEvent
        self.file_path = ''
        
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            
    def dropEvent(self, e):
        self.file_path = e.mimeData().urls()[0].toLocalFile()
        self.label.setText(f'Selected File:\n{self.file_path}')
        
    @pyqtSlot()
    def decrypt_file(self):
        error_occurred = False
        key_bytes = bytes.fromhex(self.key_input.text()[2:])
        temp_dir = 'temp_extracted/'
        
        with zipfile.ZipFile(self.file_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file in ['pdex.bin', 'main.pdz']:
                    file_to_decrypt = os.path.join(root, file)
                    
                    try:
                        decrypted = None
                        with open(file_to_decrypt, "rb") as pdex:
                            pdex.read(16)
                            aes = AESGCM(key_bytes)
                            decrypted = aes.decrypt(pdex.read(12), pdex.read(), None)
                        
                        with open(file_to_decrypt, "wb") as pdex:
                            if file == 'main.pdz':
                                pdex.write(b"Playdate PDZ\0\0\0\0")
                            pdex.write(decrypted)
                    except Exception as e:
                        error_occurred = True
                        QMessageBox.critical(self, "Error", f"Error decrypting {file} {e}")
                        break
        
        if error_occurred:
            shutil.rmtree(temp_dir)
            return
        
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file == 'pdxinfo':
                    pdxinfo_path = os.path.join(root, file)
                    with open(pdxinfo_path, 'r') as f:
                        lines = f.readlines()
                    with open(pdxinfo_path, 'w') as f:
                        for line in lines:
                            if "hash=" not in line:
                                f.write(line)
        
        output_zip_path = QFileDialog.getSaveFileName(self, "Save decrypted zip", "", "ZIP Files (*.zip)")[0]
        if not output_zip_path:
            return
        
        with zipfile.ZipFile(output_zip_path, 'w') as new_zip:
            for foldername, subfolders, filenames in os.walk(temp_dir):
                for filename in filenames:
                    filePath = os.path.join(foldername, filename)
                    new_zip.write(filePath, os.path.relpath(filePath, temp_dir))
        
        shutil.rmtree(temp_dir)
        self.label.setText('Decryption completed successfully!')
        self.key_input.clear()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = App()
    sys.exit(app.exec_())
