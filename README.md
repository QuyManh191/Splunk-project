# Splunk-project

# Triển khai và Điều tra Sự cố với SIEM Splunk

## 1. Cài đặt môi trường
* **Máy chủ Linux (Splunk):** IP 192.168.2.10, cổng nhận log 9997. Cài đặt TA windows addon for sysmon, splunk addon for microsoft windows, splunk CIM. Tạo index `sysmon` và `windows_clientA`.

![Splunk Indexes](./images/01-splunk-indexes.png)

* **Máy client (Windows 10):** IP 192.168.2.5, cài Splunk Universal Forwarder. Cấu hình file `inputs.conf` và `outputs.conf` để đẩy log.

![Cấu hình inputs](./images/02-forwarder-inputs.png)
![Cấu hình outputs](./images/03-forwarder-outputs.png)

* **Kiểm tra Log:** Log trả về thành công.

![Nhận log thành công](./images/04-log-ingestion.png)

## 2. Kịch bản mô phỏng tấn công
* Kẻ tấn công host HTTP server tại `192.168.2.10:5000` chứa file giả mạo `update.exe`.

![Trang web giả mạo](./images/05-attack-scenario.png)

* Người dùng tải và chạy `update.exe`, file này bí mật tải `backdoor.ps1` và `ncat.exe` vào `C:\Users\admin\AppData\Local\Temp\MicrosoftUpdates`.

![Tải malware](./images/06-malware-download.png)

* Malware thiết lập persistence bằng cách thêm giá trị vào Registry Run Key: `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`.

![Registry Runkey](./images/07-registry-runkey.png)

## 3. Xây dựng Rule phát hiện (MITRE ATT&CK - T1547.001)

![Detection Rules](./images/08-detection-rules.png)

* **Phát hiện tương tác Run Key từ file lạ:**
  `index="sysmon" EventCode=13 Image="*\\update.exe" TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\MicrosoftSystemUpdate"`
* **Phát hiện PowerShell sử dụng policy bypass:**
  `index=sysmon EventCode=1 Image="*\\powershell.exe" CommandLine="*-ExecutionPolicy*Bypass*"`
* **Phát hiện Run Key trỏ vào thư mục tạm (Temp/AppData):**
  `index="sysmon" EventCode=13 TargetObject="*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*" (Details="*\\Temp\\*" OR Details="*\\AppData\\*")`
* **Phát hiện kết nối C2:**
  `index="sysmon" EventCode=3 DestinationPort=4444`

## 4. Điều tra và phân tích kết quả trên Splunk
* **Phát hiện Persistence:** EventCode 13 ghi nhận `update.exe` sửa Registry, chèn lệnh PowerShell chạy `backdoor.ps1` ẩn (`-WindowStyle Hidden -ExecutionPolicy Bypass`).

![Phát hiện Registry](./images/09-registry-detection.png)

* **Truy xuất nguồn gốc:** EventCode 1 ghi nhận `update.exe` sinh ra từ `explorer.exe`. 

![Điều tra Process](./images/10-process-investigation.png)

EventCode 11 và luồng `Zone.Identifier` xác nhận file tải về từ Internet qua trình duyệt Edge (URL: `http://192.168.2.10:5000/update.exe`).

![Zone Identifier](./images/11-zone-identifier.png)

* **Phân tích hành vi file:** EventCode 11 cho thấy `update.exe` trực tiếp sinh ra hai file `ncat.exe` và `backdoor.ps1` trong thư mục Temp.

![Malware files](./images/12-malware-files.png)

* **Xác nhận thực thi:** Đối chiếu EventCode 4624 (Logon) và EventCode 1 (Process Create), PowerShell kích hoạt `backdoor.ps1` thành công ngay khi người dùng đăng nhập lại, do `explorer.exe` gọi từ Run Key.

![Thực thi Persistence](./images/13-persistence-execution.png)

* **Phát hiện kết nối C2 (Network):**

![Phát hiện C2](./images/14-c2-detection.png)
