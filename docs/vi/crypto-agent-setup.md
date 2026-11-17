# Cài đặt Crypto Agent

Mở **Manage Security Keys**, rồi chọn **Check Crypto Agent**. Làm theo bước
web hiển thị cho trình duyệt hoặc thiết bị. Danh sách chỉ hiện bộ cài quản trị
viên đã phát hành. Nếu web gợi ý một gói, kiểm tra kiến trúc máy trước khi tải.
Nếu nút kiểm tra bị vô hiệu hóa, quản trị viên cần bật Crypto Agent cho môi trường này.

1. Cài extension do công ty cung cấp trên Chrome hoặc Edge rồi tải lại trang CPQA.
2. Tải gói đúng hệ điều hành, đối chiếu SHA-256 hiển thị và giải nén. Với ZIP
   pilot, chạy `powershell -File .\install.ps1` trên Windows hoặc
   `bash ./install.sh` trên macOS/Linux từ thư mục đã giải nén. Script cài
   cho tài khoản hệ điều hành hiện tại và đăng ký Native Messaging.
3. Quay lại CPQA, chọn **Check Crypto Agent**, rồi **Register signing device**.
   Kiểm tra lại nếu đổi hồ sơ trình duyệt. Mỗi hồ sơ có tham chiếu đăng ký riêng.

## Phát hành bộ cài

Chạy workflow thủ công **Build Crypto Agent installers** với HTTPS origin của
CPQA và ID extension Chrome/Edge. Workflow build agent native và sinh ZIP bộ
cài, ZIP extension cùng mục catalog cho từng nền tảng. ZIP extension có thể
dùng cho triển khai có quản lý. Bản unpacked pilot cần public key DER Base64
tương ứng với ID đã cấu hình. Phân phối extension qua Chrome Web Store,
Microsoft Edge Add-ons hoặc chính sách trình duyệt của doanh nghiệp. Liên kết
trên web dẫn đến store tương ứng với ID đã cấu hình.

Để build pilot Windows ở local, chạy trong x64 Visual Studio developer shell
có Python và Rust. Thay ID minh họa bằng ID extension triển khai thực tế.

```powershell
python src/crypto_agent/package_agent.py --origin https://cloudsafe.cyberfortress.local --extension-id YOUR_EXTENSION_ID --ref v6.0.0 --output-dir src/crypto_agent/target/distribution
```

Với một nền tảng, chép bộ cài và `manifest.json` vào `config/crypto-agent/`
trên máy chủ CPQA. Với nhiều nền tảng, gộp thành một manifest có
`revision: 1` và một mục trong `packages` cho mỗi nền tảng. Đưa bộ cài theo
version lên trước, sau đó thay catalog. Compose mặc định cho Django đọc thư
mục này tại `/config/crypto-agent`. Chỉ cấp quyền ghi cho operator phát hành.

Trong môi trường deploy, đặt `CRYPTO_AGENT_ORIGIN` trùng với origin lúc đóng
gói. Cấu hình `CRYPTO_AGENT_CHROME_EXTENSION_ID` và có thể thêm
`CRYPTO_AGENT_EDGE_EXTENSION_ID`. Đặt `CRYPTO_AGENT_MIN_VERSION` là version
tối thiểu tương thích. Áp dụng Django migration, tạo lại container web với
`NATIVE_SIGNING_ENABLED=true` và kiểm tra luồng setup bằng tài khoản pilot.
Giữ `NATIVE_SIGNING_REQUIRED=false` cho đến khi đã kiểm tra phân phối và
đăng ký thiết bị cho người dùng.

### Cài Edge lần đầu trên máy pilot Windows

1. Chạy `install.ps1` từ gói agent đã giải nén để đăng ký Native Messaging
   cho tài khoản Windows hiện tại.
2. Giải nén `cpqa-crypto-agent-extension.zip` vào thư mục ổn định, ví dụ
   `%LOCALAPPDATA%\CPQA\Crypto Agent\extension`. Giữ nguyên thư mục này sau
   khi thêm extension.
3. Trong hồ sơ Edge dùng để đăng nhập CPQA, mở `edge://extensions`, bật
   **Developer mode**, bấm **Load unpacked** và chọn thư mục vừa giải nén.
   Luồng này dành cho pilot với extension build nội bộ.
4. Tải lại **Manage Security Keys**. Bấm **Check Crypto Agent**,
   **Register signing device**, rồi kiểm tra lại để thấy trạng thái **Ready**.

Khi ký bắt buộc đang tắt, tài khoản chưa đăng ký agent trên hồ sơ trình duyệt
này tiếp tục dùng luồng ký hiện tại. Sau khi đăng ký, upload trong hồ sơ đó
sử dụng Crypto Agent.

Môi trường local `https://cloudsafe.cyberfortress.local` dùng gói Windows x64
từ upstream release `v6.0.0`. ID Edge pilot và public key DER của extension
được lưu trong `config/crypto-agent/pilot-extension-identity.json` trên máy
dev. Khi build lại, giữ nguyên hai giá trị để Edge và Django tiếp tục nhận
đúng extension. Chạy từ x64 Visual Studio developer shell tại root repo.

```powershell
$identity = Get-Content -Raw config/crypto-agent/pilot-extension-identity.json | ConvertFrom-Json
python src/crypto_agent/package_agent.py --origin https://cloudsafe.cyberfortress.local --extension-id $identity.id --extension-key $identity.key --ref v6.0.0 --output-dir src/crypto_agent/target/windows-pilot-next
```

Sau khi chép gói mới cùng catalog vào `config/crypto-agent/`, có thể nạp lại
biến môi trường local bằng `rtk docker compose --project-directory . -f
docker/docker-compose.yml up -d --no-deps --force-recreate web`.

ZIP sinh ra dùng cho pilot. Dùng quy trình ký và phân phối phần mềm của
doanh nghiệp để phát hành bộ cài production. Yêu cầu ký có thời hạn và ràng
buộc hash của file upload với thiết bị đã đăng ký. Thiết bị lưu khóa ML-DSA
dưới dạng mã hóa và giữ khóa bọc trong kho credential của hệ điều hành.
Xác minh bảo vệ bằng phần cứng và hộp thoại xác nhận ở mỗi lần ký vẫn đang
chờ. Giao diện web hiển thị thông tin tài liệu cho người dùng.

[Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
· [Microsoft Edge Native Messaging](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging)
