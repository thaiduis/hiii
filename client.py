import socket
import json
from music_encryption import MusicEncryption

def send_file(file_path, metadata, server_host='localhost', server_port=5000):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((server_host, server_port))
    except ConnectionRefusedError:
        print(f"Không thể kết nối đến server tại {server_host}:{server_port}")
        return
    
    # Handshake
    client.send("Hello!".encode())
    response = client.recv(1024).decode()
    
    if response != "Ready!":
        print("Lỗi handshake")
        client.close()
        return
    
    # Chuẩn bị và gửi package
    try:
        encryption = MusicEncryption()
        package = encryption.prepare_package(file_path, metadata, encryption.public_key)
        
        # Gửi package
        client.send(json.dumps(package).encode())
        
        # Nhận phản hồi
        response = client.recv(1024).decode()
        if response == "ACK":
            print("File đã được gửi và xác thực thành công!")
        else:
            print("Lỗi khi gửi file:", response)
            
    except Exception as e:
        print(f"Lỗi: {str(e)}")
    
    client.close()

if __name__ == "__main__":
    # Ví dụ metadata
    metadata = {
        "title": "Example Song",
        "artist": "Example Artist",
        "copyright": "© 2024 Example Copyright",
        "license": "All rights reserved"
    }
    
    # Thay đổi địa chỉ IP của server ở đây
    SERVER_HOST = '192.168.1.100'  # Thay bằng IP của máy ảo
    SERVER_PORT = 5000
    
    # Gửi file
    send_file("song.mp3", metadata, SERVER_HOST, SERVER_PORT) 