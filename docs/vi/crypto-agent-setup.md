# Cài đặt Crypto Agent

Mở **Manage Security Keys**, rồi chọn **Check Crypto Agent**. Làm theo bước
web hiển thị cho trình duyệt hoặc thiết bị. Danh sách chỉ hiện bộ cài quản trị
viên đã phát hành. Nếu web gợi ý một gói, kiểm tra kiến trúc máy trước khi tải.
Nếu nút kiểm tra bị vô hiệu hóa, quản trị viên cần bật Crypto Agent cho môi trường này.

1. Đăng nhập CPQA và vào **Security Keys → Download Crypto Agent**. Tải ZIP
   đúng hệ điều hành, đối chiếu SHA-256 rồi giải nén. ZIP chứa agent, extension
   và hướng dẫn tiếng Anh `SETUP.md`.
2. Chạy setup một lần từ thư mục đã giải nén bằng tài khoản dùng trình duyệt.
   Trên Windows chạy `powershell -NoProfile -File .\setup.ps1`. Trên macOS và
   Linux chạy `bash ./setup.sh`. Script tự chọn thư mục cài.
3. Bật extension theo hướng dẫn cho trình duyệt bên dưới.
4. Quay lại CPQA và chọn **Check Crypto Agent**. Khi nền tảng cho phép đăng
   ký, chọn **Register signing device**. Mỗi hồ sơ có tham chiếu đăng ký riêng.

### Bật extension Chromium

1. Mở trang Extensions. Chrome và Chromium dùng `chrome://extensions`, Edge
   dùng `edge://extensions`, Brave dùng `brave://extensions`, Vivaldi dùng
   `vivaldi://extensions`.
2. Bật **Developer mode**, chọn **Load unpacked**, rồi chọn thư mục cục bộ
   `extension` mà setup in ra. Tải lại CPQA. Có thể xóa thư mục ZIP đã giải nén
   sau khi cài.

Setup đăng ký native host theo vị trí hồ sơ mặc định. Trình duyệt Chromium
tùy biến hoặc thiết bị được quản lý có thể cần quản trị viên cho phép Native
Messaging và extension dạng unpacked. Tuân thủ chính sách chạy script và
extension của thiết bị.

### Bật extension Safari trên macOS

Setup cài ứng dụng vào `~/Applications` và mở một lần. Nếu macOS yêu cầu
phê duyệt, mở ứng dụng từ Finder và làm theo hộp thoại của hệ thống.
Vào **Safari → Settings → Advanced**, bật **Show features for web developers**.
Trong **Developer**, chọn **Allow unsigned extensions**. Trong **Extensions**,
bật **CPQA Crypto Agent**, cấp quyền cho trang CPQA rồi tải lại. Gói Safari
dùng chế độ thử cục bộ của Apple.

Gói macOS và Linux hỗ trợ kiểm tra kết nối. Hai nền tảng này hiện từ chối đăng
ký và ký native cho tới khi có cơ chế bảo vệ khóa và xác minh người dùng.

## Phát hành bộ cài

Chạy workflow thủ công **Build Crypto Agent installers** với HTTPS origin của
CPQA. Workflow tạo một ZIP trọn bộ và mục catalog cho Windows x64, Linux x64,
Mac Intel và Apple silicon. ZIP Mac có Safari và Chromium. Không cần tài
khoản Apple hoặc ID extension. Build suy ra ID Chromium ổn định từ public key
đi kèm mã nguồn.

Sau khi workflow có trên GitHub, chạy từ CLI trên máy local. Đặt các biến shell
theo nhánh build và origin CPQA.

```powershell
rtk gh workflow run crypto-agent.yml --ref $releaseBranch -f "origin=$cpqaOrigin"
rtk gh run list --workflow crypto-agent.yml
rtk gh run watch $runId --exit-status
rtk gh run download $runId --pattern 'crypto-agent-*' --dir agent-artifacts
```

Bỏ `upstream_tag` để lấy release upstream hiện tại, hoặc truyền
`-f upstream_tag=v6.0.0` để dùng cùng
tag trên mọi runner. Khi build từ mã nguồn upstream tại máy local, dùng
`package_agent.py` với `--source source --ref` và các dependency build
của thư viện.

Để build pilot Windows ở local, chạy trong x64 Visual Studio developer shell
có Python và Rust.

```powershell
rtk python src/crypto_agent/package_agent.py --origin $cpqaOrigin --ref v6.0.0 --output-dir src/crypto_agent/target/distribution
```

Với một nền tảng, chép bộ cài và `manifest.json` vào `config/crypto-agent/`
trên máy chủ CPQA. Với nhiều nền tảng, gộp thành một manifest có
`revision: 1` và một mục trong `packages` cho mỗi nền tảng. Đưa bộ cài theo
version lên trước, sau đó thay catalog. Compose mặc định cho Django đọc thư
mục này tại `/config/crypto-agent`. Chỉ cấp quyền ghi cho operator phát hành.

Trong môi trường deploy, đặt `CRYPTO_AGENT_ORIGIN` trùng với origin lúc đóng
gói. CPQA đọc ID Chromium và trạng thái có Safari từ catalog đã phát hành.
Đặt `CRYPTO_AGENT_MIN_VERSION` là version
tối thiểu tương thích. Áp dụng Django migration, tạo lại container web với
`NATIVE_SIGNING_ENABLED=true` và kiểm tra luồng setup bằng tài khoản pilot.
Giữ `NATIVE_SIGNING_REQUIRED=false` cho đến khi đã kiểm tra phân phối và
đăng ký thiết bị cho người dùng.

### Cài Edge lần đầu trên máy pilot Windows

1. Chạy `setup.ps1` từ gói agent đã giải nén để cài agent và đăng ký Native
   Messaging cho tài khoản Windows hiện tại.
2. Trong hồ sơ Edge dùng để đăng nhập CPQA, mở `edge://extensions`, bật
   **Developer mode**, chọn **Load unpacked** rồi chọn
   `%LOCALAPPDATA%\CPQA\Crypto Agent\extension`.
3. Tải lại **Manage Security Keys**. Bấm **Check Crypto Agent**,
   **Register signing device**, xác minh bằng Windows Hello rồi kiểm tra
   trạng thái thiết bị trên web.

Khi ký bắt buộc đang tắt, tài khoản chưa đăng ký agent trên hồ sơ trình duyệt
này tiếp tục dùng luồng ký hiện tại. Sau khi đăng ký, upload trong hồ sơ đó
sử dụng Crypto Agent.

Môi trường local `https://cloudsafe.cyberfortress.local` dùng upstream release
`v6.0.0`. Build tự dùng lại ID Chromium của bản pilot Windows. Chạy từ x64
Visual Studio developer shell tại root repo.

```powershell
rtk python src/crypto_agent/package_agent.py --origin https://cloudsafe.cyberfortress.local --ref v6.0.0 --output-dir src/crypto_agent/target/windows-pilot-next
```

Sau khi chép gói mới cùng catalog vào `config/crypto-agent/`, có thể nạp lại
biến môi trường local bằng `rtk docker compose --project-directory . -f
docker/docker-compose.yml up -d --no-deps --force-recreate web`.

Áp dụng quy trình ký và phân phối phần mềm của doanh nghiệp. Gói macOS dùng
chữ ký ad hoc cho thử nghiệm cục bộ. Chữ ký
tài liệu dùng ML-DSA-87 của upstream. Bản pilot Windows dùng AES-256-GCM để
bảo vệ private key. Yêu cầu ký có thời hạn và ràng
buộc hash của file upload với thiết bị đã đăng ký. Thiết bị lưu khóa ML-DSA
dưới dạng mã hóa và giữ khóa bọc trong kho credential của hệ điều hành.
Từ agent 0.2.0, Windows 11 yêu cầu Windows Hello khi đăng ký và ở mỗi lần
ký. Đưa cửa sổ Edge hoặc Chrome lên trước khi thao tác. Windows chọn PIN,
vân tay hoặc khuôn mặt theo cấu hình máy. Nếu hủy hoặc hết hạn, thao tác dừng.
macOS và Linux cần cơ chế xác minh riêng trước khi có thể đăng ký hoặc ký.
Giao diện web hiển thị thông tin tài liệu, còn hộp thoại Windows Hello xác
minh người dùng. Khóa bọc hiện dùng kho credential của hệ điều hành.

[Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
· [Microsoft Edge Native Messaging](https://learn.microsoft.com/en-us/microsoft-edge/extensions/developer-guide/native-messaging)
· [Thử nghiệm Safari Web Extension cục bộ](https://developer.apple.com/documentation/safariservices/building-and-testing-a-safari-web-extension)
