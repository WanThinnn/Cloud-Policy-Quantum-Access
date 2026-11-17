# Chuẩn bị thư viện native cho Crypto Agent

Chạy các lệnh từ thư mục gốc CPQA bằng Python 3.10 trở lên. Windows và
Linux dùng gói x86-64. macOS hỗ trợ Intel và Apple silicon. Chạy công cụ
trong shell native của kiến trúc cần đóng gói.

```sh
# Tải release mới nhất đã phát hành
python src/crypto_agent/prepare_upstream.py

# Chốt phiên bản release để có thể đóng gói lại
python src/crypto_agent/prepare_upstream.py --ref v6.0.0 --output-dir src/crypto_agent/target/upstream/pinned

# Build mã nguồn gốc bằng Makefile và công cụ đóng gói của upstream
python src/crypto_agent/prepare_upstream.py --source source --ref v6.0.0 --jobs 4 --output-dir src/crypto_agent/target/upstream/from-source
```

Khi build source và bỏ `--ref`, script lấy nhánh mặc định của upstream.
Dùng Git commit nếu cần chốt chính xác revision. Cài toolchain theo README
upstream. Trên Windows, chạy từ x64 Native Tools prompt có GNU Make và các
dependency upstream. Chế độ release xác minh SHA-256 của archive theo GitHub
trước khi giải nén. Khi triển khai có kiểm soát, chốt release và lưu lại hash.

Đầu ra mặc định nằm ở `src/crypto_agent/target/upstream/<platform>-<arch>`.
Thư mục đích phải là thư mục mới. Gói chứa shared library theo hệ điều hành,
`libcpabe_tkn20.dll` trên Windows, thông báo giấy phép upstream và
`upstream-manifest.json`. Manifest ghi release tag hoặc Git commit đã resolve,
SHA-256 của archive, hệ điều hành và hash từng thư viện runtime. Đặt các
thư viện runtime cạnh executable của agent để FFI loader tìm thấy. Windows
cần thêm MSVC runtime. Lệnh này chuẩn bị gói thư viện. Đăng ký với trình
duyệt và cài executable của agent là các bước riêng.

[Mã nguồn và yêu cầu build](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library)
· [Release v6.0.0](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/releases/tag/v6.0.0)
