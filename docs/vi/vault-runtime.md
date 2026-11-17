# Danh tính Vault runtime cho CPQA production

Django production đọc token từ `/run/cpqa-vault/token`. Thư mục được gắn chỉ đọc từ `VAULT_RUNTIME_TOKEN_DIR`. Token cần policy duy nhất `cpqa-runtime` và TTL còn hiệu lực. Vault dùng HTTPS với CA hợp lệ. Giữ token operator và unseal shares ở nơi Django không thể truy cập.

## Chuẩn bị và chuyển đổi

1. Diễn tập trên staging trước. Sao lưu Raft, DB và object storage ở cùng điểm khôi phục. Giữ bản cài plugin và manifest dùng để đọc lịch sử. Thử restore trên mạng cô lập rồi kiểm tra một version cũ có chữ ký, một yêu cầu bị từ chối và ghi lại thời gian khôi phục.
2. Dùng danh tính operator để khởi tạo hoặc unseal Vault và đăng ký plugin. Nếu đang chuyển từ bản cũ, giữ nguyên authority, public metadata và field master key. Kiểm kê các version có `backend=native` trước khi ngừng luồng đó. Với triển khai mới, khởi tạo các authority và tạo bản ghi operator theo hướng dẫn CoverCrypt trước khi khởi động Django. Chuẩn bị schema thuộc tính từ catalog doanh nghiệp, sau đó chạy migration và tạo tài khoản quản trị bằng quy trình cấp tài khoản của doanh nghiệp.
3. Chạy `scripts/provision_vault_runtime.py --source-path crypto_access --token-out <runtime-dir>/token` từ môi trường operator có `hvac`, `VAULT_ADDR`, `VAULT_CACERT` và `VAULT_TOKEN`. Thư mục phải được tạo trước và được bảo vệ bằng quyền filesystem. Công cụ chỉ chép field master key và metadata công khai được cho phép sang `secret/data/cpqa-runtime`. Danh sách mount lấy từ manifest active và lịch sử. Có thể khai báo thêm mount đã phê duyệt bằng `--mount`.
4. Sau khi image upstream có `decrypt_with_attributes` đã được xác minh, cấu hình `VAULT_ABE_INTERNAL_DECRYPT=True`. Khi chuyển tiếp với plugin cũ, giữ setting này ở `False` và cấp quyền export có chủ đích bằng `--allow-exported-user-keys`. Sau rollout, chạy lại provision với chế độ mặc định để thu quyền `genkey` và `decrypt` cũ. Quyền policy cập nhật tác động lên các token mang cùng policy, nên dùng thời điểm cắt chuyển đã thống nhất.
5. Cấu hình `REDIS_PASSWORD` và CA của các dịch vụ. Chạy `python start.py --prod up`. Lệnh kiểm tra danh tính runtime và metadata. Các bước init/unseal/operator thực hiện ở kênh quản trị. Kiểm tra download/preview có chữ ký, version lịch sử sau rotation và Vault ACL từ chối setup, add-dimension, đọc KV operator và xuất User SK.
6. Xác nhận service hoạt động bằng danh tính mới rồi xử lý thông tin bootstrap cũ theo quy trình của operator. Token tạo dạng orphan với TTL ban đầu 8 giờ và tối đa 24 giờ. Dùng renew-self khi thích hợp hoặc provision token kế tiếp và nạp lại Django trước khi token hết hạn. Chỉ thu hồi token cũ sau khi xác nhận worker dùng token mới.

## Audit và khôi phục

Cấu hình quản trị Vault qua loopback hoặc một đường quản trị riêng. Operator có thể bật file audit trên volume `/vault/audit` với lệnh `vault audit enable file file_path=/vault/audit/audit.json`. Kiểm tra quyền ghi, dung lượng, retention và quyền đọc trước khi bật. Rà log để bảo đảm không ghi khóa, plaintext hoặc token thô. Tránh lưu snapshot, token và unseal shares cùng một nơi.

Khi active manifest hoặc authority history thay đổi, cập nhật bản ghi runtime từ nguồn operator đã xác minh và cấp quyền cho các mount lịch sử còn được tham chiếu. Khi rollback, dùng image và metadata tương thích đã kiểm thử. Việc cấp lại quyền export User SK là một quyết định vận hành có ghi nhận.
