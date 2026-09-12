# Splunk-project

# Triển khai và Điều tra Sự cố với SIEM Splunk[cite: 1]

## 1. Cài đặt môi trường[cite: 1]
* **Máy chủ Linux (Splunk):** IP 192.168.2.10, cổng nhận log 9997.[cite: 1] Cài đặt TA windows addon for sysmon, splunk addon for microsoft windows, splunk CIM.[cite: 1] Tạo index `sysmon` và `windows_clientA`.[cite: 1]
* **Máy client (Windows 10):** IP 192.168.2.5, cài Splunk Universal Forwarder.[cite: 1] Cấu hình file `inputs.conf` và `outputs.conf` để đẩy log.[cite: 1]

## 2. Kịch bản mô phỏng tấn công[cite: 1]
* Kẻ tấn công host HTTP server tại `192.168.2.10:5000` chứa file giả mạo `update.exe`.[cite: 1]
* Người dùng tải và chạy `update.exe`, file này bí mật tải `backdoor.ps1` và `ncat.exe` vào `C:\Users\admin\AppData\Local\Temp\MicrosoftUpdates`.[cite: 1]
* Malware thiết lập persistence bằng cách thêm giá trị vào Registry Run Key: `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`.[cite: 1]

## 3. Xây dựng Rule phát hiện (MITRE ATT&CK - T1547.001)[cite: 1]
* **Phát hiện tương tác Run Key từ file lạ:**[cite: 1]
  `index="sysmon" EventCode=13 Image="*\\update.exe" TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftSystemUpdate"`[cite: 1]
* **Phát hiện PowerShell sử dụng policy bypass:**[cite: 1]
  `index=sysmon EventCode=1 Image="*\\powershell.exe" CommandLine="*-ExecutionPolicy*Bypass*"`[cite: 1]
* **Phát hiện Run Key trỏ vào thư mục tạm (Temp/AppData):**[cite: 1]
  `index="sysmon" EventCode=13 TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*" (Details="*\\Temp\\*" OR Details="*\\AppData\\*")`[cite: 1]
* **Phát hiện kết nối C2:**[cite: 1]
  `index="sysmon" EventCode=3 DestinationPort=4444`[cite: 1]

## 4. Điều tra và phân tích kết quả trên Splunk[cite: 1]
* **Phát hiện Persistence:** EventCode 13 ghi nhận `update.exe` sửa Registry, chèn lệnh PowerShell chạy `backdoor.ps1` ẩn (`-WindowStyle Hidden -ExecutionPolicy Bypass`).[cite: 1]
* **Truy xuất nguồn gốc:** EventCode 1 ghi nhận `update.exe` sinh ra từ `explorer.exe`.[cite: 1] EventCode 11 và luồng `Zone.Identifier` xác nhận file tải về từ Internet qua trình duyệt Edge (URL: `http://192.168.2.10:5000/update.exe`).[cite: 1]
* **Phân tích hành vi file:** EventCode 11 cho thấy `update.exe` trực tiếp sinh ra hai file `ncat.exe` và `backdoor.ps1` trong thư mục Temp.[cite: 1]
* **Xác nhận thực thi:** Đối chiếu EventCode 4624 (Logon) và EventCode 1 (Process Create), PowerShell kích hoạt `backdoor.ps1` thành công ngay khi người dùng đăng nhập lại, do `explorer.exe` gọi từ Run Key.[cite: 1]
