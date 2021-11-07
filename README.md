*** Chuyển đổi từ file pcap sang file csv ***
```
python moninet.py -p [đường dẫn tới file pcap] -c [đường dẫn tới file csv] -o 2
```
*** Bắt các gói tin giao tiếp mạng theo thời gian thực và lưu vào file csv một cách liên tục ***
```
python moninet.py -c [đường dẫn tới file csv] -i [interface] -o 3
```
*** Phân tích phát hiện tấn công brute force từ file csv chứa dữ liệu thu thập được ***
```
python moninet.py -c [đường dẫn tới file csv] -a
```
*** Giám sát phát hiện tấn công brute force trực tiếp từ môi trường mạng ***
```
python moninet.py -m 1 - i [interface]
```