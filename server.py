import socket
import json
from music_encryption import MusicEncryption

def start_server(host='192.168.2.80', port=5000):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
    
    print(f"Server đang chạy tại {host}:{port} và chờ kết nối...")
    
    while True:
        client, addr = server.accept()
        print(f"Kết nối từ {addr}")
        
        # Handshake
        data = client.recv(1024).decode()
        if data == "Hello!":
            client.send("Ready!".encode())
        else:
            client.close()
            continue
        
        # Nhận package
        try:
            package_data = client.recv(4096).decode()
            package = json.loads(package_data)
            
            # Xử lý package
            encryption = MusicEncryption()
            success, result = encryption.verify_and_decrypt(package, encryption.public_key)
            
            if success:
                # Lưu file
                with open("received_song.mp3", "wb") as f:
                    f.write(result["data"])
                
                # Lưu metadata
                with open("metadata.json", "w") as f:
                    json.dump(result["metadata"], f)
                
                client.send("ACK".encode())
                print("File đã được nhận và xác thực thành công!")
            else:
                client.send("NACK".encode())
                print(f"Lỗi: {result}")
                
        except Exception as e:
            print(f"Lỗi: {str(e)}")
            client.send("NACK".encode())
        
        client.close()

if __name__ == "__main__":
    # Có thể thay đổi host và port ở đây
    start_server() 