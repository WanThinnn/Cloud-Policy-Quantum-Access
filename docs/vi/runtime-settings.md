# Cấu hình ứng dụng qua giao diện

Vào **System → System Settings** (`/manage/settings/`). Backend chỉ cho tài khoản có profile `super_admin`, user active và profile chưa hết hạn/bị đình chỉ đọc hoặc lưu. Django superuser flag riêng lẻ không thay thế vai trò này.

## Những mục đã chuyển lên UI

Trang quản lý 20 giá trị thông thường và 1 mật khẩu SMTP:

| Nhóm | Khóa | Hiệu lực |
| --- | --- | --- |
| Passkey | `WEBAUTHN_RP_NAME` | Tên hiển thị khi đăng ký passkey mới, không đổi RP ID/origin |
| Email | `EMAIL_DELIVERY_MODE` | SMTP hoặc console phát triển; console ghi cả nội dung OTP vào log |
| Email | `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER` | Máy chủ, cổng và tài khoản SMTP |
| Email | `EMAIL_SECURITY` | STARTTLS hoặc TLS trực tiếp, giữ xác minh chứng chỉ |
| Email | `DEFAULT_FROM_EMAIL` | Email người gửi; bỏ trống để dùng tài khoản SMTP |
| Email | `EMAIL_TIMEOUT_SECONDS` | Timeout SMTP 1–60 giây |
| Email | Mật khẩu SMTP | Nhập mới để lưu vào Vault; để trống để giữ nguyên; có lựa chọn quay về mật khẩu triển khai |
| AI | `AI_FEATURES_ENABLED`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL` | Bật assistant, chọn endpoint HTTPS và model đã cài |
| AI | `OLLAMA_KEEP_ALIVE` | `-1`, số giây nguyên, hoặc duration như `5m` |
| AI | `AI_REQUEST_TIMEOUT_SECONDS` | Timeout sinh đề xuất 10–600 giây |
| Documents | `UPLOAD_MAX_SIZE_MB` | Giới hạn upload/new version 1–40 MB; frontend và serializer đều dùng giá trị này |
| Documents | `CLAMAV_TIMEOUT_SECONDS` | Timeout scanner 5–120 giây; lỗi scanner vẫn chặn upload |
| Documents | `CPABE_ENCRYPT_PER_MINUTE` | Số upload/user/phút, 1–60 |
| Documents | `CPABE_DECRYPT_PER_MINUTE` | Hạn mức chung download/preview/user/phút, 1–120 |
| Login | `LOGIN_MAX_ATTEMPTS` | Chặn sau 3–20 lần đăng nhập sai |
| Login | `LOGIN_LOCKOUT_SECONDS` | Cửa sổ sau lần sai cuối, 60–3600 giây; counter cũ giữ expiry đã cấp |
| Login | `IMPOSSIBLE_TRAVEL_MINUTES` | Kiểm tra đổi public IP trong 1–1440 phút; giữ logic OTP hiện có |

Nút **Test SMTP connection** kết nối, thương lượng TLS và đăng nhập bằng dữ liệu đang nhập; không gửi email và không lưu cấu hình. Việc kiểm tra này không xác nhận domain người gửi đã được nhà cung cấp cho phép hoặc email chắc chắn tới inbox.

**Save settings** lưu toàn bộ giá trị trên form vào `SystemSetting`, kể cả các giá trị trước đó đang lấy từ mặc định triển khai. GET không tự seed hay thay `.env`. Thứ tự ưu tiên: bản ghi active đã lưu → cấu hình triển khai hiện có → mặc định hợp lệ. Các khóa mới về timeout/hạn mức có mặc định trong catalog, không bắt buộc thêm biến `.env`.

Sau khi lưu có thể quản lý những mục này hoàn toàn qua UI. Các biến cùng tên trong `.env` trở thành fallback, không tự ghi đè UI. Nếu muốn bỏ mật khẩu SMTP khỏi `.env`, trước tiên nhập/lưu mật khẩu trên trang để tạo reference Vault; chỉ lưu form với ô mật khẩu trống sẽ tiếp tục dùng mật khẩu triển khai.

## Những mục vẫn thuộc cấu hình triển khai

| Nhóm | Biến chính | Lý do |
| --- | --- | --- |
| Khởi động Django | `DJANGO_ENV`, `DJANGO_SECRET_KEY`, `DJANGO_ALLOWED_HOSTS`, `GUNICORN_CMD_ARGS` | Có hiệu lực trước khi đọc DB; ảnh hưởng signing/auth hoặc worker/process |
| Tài khoản khởi tạo | `DJANGO_SUPERUSER_USERNAME`, `DJANGO_SUPERUSER_PASSWORD`, `DJANGO_SUPERUSER_EMAIL` | Dùng khi initdata; thay đổi tài khoản có sẵn qua User Management |
| DB | `DATABASE_URL`, `DB_DIR`, `DB_REQUIRE_SSL` | DB chứa chính cấu hình runtime; chuyển DB cần quy trình backup/migration |
| Redis | `REDIS_URL`, `REDIS_PASSWORD`, `REDIS_USE_TLS`, `REDIS_CACERT` | Hạ tầng cache/session và TLS, cần khởi tạo connection pool |
| Storage | `STORAGE_VENDOR`, `SUPABASE_URL`, `SUPABASE_KEY`, `SUPABASE_SERVICE_KEY`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_S3_REGION_NAME`, `AWS_S3_ENDPOINT_URL`, `GCP_PROJECT_ID`, `GOOGLE_APPLICATION_CREDENTIALS`, `STORAGE_EMULATOR_HOST` | Vị trí/credential dữ liệu và adapter singleton. Record hiện chưa lưu một connection profile độc lập cho từng file; đổi backend có thể làm file cũ không truy cập được |
| Vault/khóa | `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_SECRET_PATH`, `VAULT_CACERT`, `KEYS_DIR`, `MASTER_FIELD_ENCRYPTION_KEY` | Bootstrap/trust root, khóa dữ liệu; không cung cấp editor tổng quát trên UI |
| Crypto | `FIELD_ENCRYPTION`, `ENABLE_PQC_FEATURES`, `USE_VAULT_ABE_PLUGIN`, `CPABE_SCHEME` | Liên quan định dạng ciphertext, key lifecycle và dữ liệu/version cũ |
| PKI/scanner | `PKI_SIGNER_URL`, `PKI_AUTH_TOKEN`, `PKI_CACERT`, `PQC_SSL_CA_KEY_FILE`, `CLAMAV_HOST`, `CLAMAV_PORT`, `CLAMAV_USE_TLS`, `CLAMAV_CACERT` | Định tuyến/trust giữa container và signer. UI chỉ chỉnh timeout quét |
| Domain và TLS | `DOMAIN_NAME`, `INTERNAL_DOMAIN`, `USE_EXTERNAL_TLS`, `CERTS_DIR`, `ROOT_CA_FILENAME`, `TLS_CERT_FILENAME`, `TLS_KEY_FILENAME`, `PQC_SSL_CA_FILE`, `PQC_SSL_CERT_FILE`, `PQC_SSL_KEY_FILE`, `NGINX_HTTP_PORT`, `NGINX_HTTPS_PORT`, `DOCKER_IPV4_SUBNET` | Compose/Nginx đọc trước khi web chạy; đổi phải tái cấu hình mạng/cert/container |
| Passkey/trust web | `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGIN`, `CORS_ALLOWED_ORIGINS` | Thay đổi phạm vi tin cậy hoặc khả năng dùng credential đã đăng ký |
| AI trust | `OLLAMA_CACERT` | Trust store/cert mount giữ ở deployment; endpoint/model chuyển được lên UI |
| Tunnel/VPN/cert tổ chức | `CLOUDFLARE_TUNNEL_ID`, `TUNNEL_DOMAIN`, `CLOUDFLARE_CONFIG`, `CLOUDFLARE_CREDENTIALS_FILE`, `VPN_PUBLIC_IP`, `VPN_PUBLIC_IP_V6`, `VPN_PROTO`, `COMPANY_NAME`, `COUNTRY`, `STATE`, `LOCALITY`, `ORG`, `ORG_UNIT` | Cần profile/container, file credential hoặc sinh lại certificate |

`ADMIN_EMAIL` trong mẫu cũ và `Supabase_Database_password` là tên không được application hiện tại đọc trực tiếp; chúng không tạo thêm chức năng nếu đưa lên UI. Database password thực tế nằm trong `DATABASE_URL`. Không xóa tự động file `.env` thật vì có thể còn được script riêng của chủ dự án sử dụng.

Bật AI trên UI không tự tạo container hay tải model. Profile `--ai` và việc cài model vẫn là bước triển khai ban đầu. `start.py ai_setup` hiện vẫn đọc model fallback từ `.env`; tên model mới trên UI phải tương ứng một model đã cài trên Ollama.

## Lưu trữ và quyền

- `services/runtime_settings.py` là allowlist và validation chung cho form/lúc sử dụng. Không có API đọc/ghi tùy ý mọi biến môi trường hoặc mọi `SystemSetting`.
- POST có CSRF; form có revision ký bằng Django secret, hết hạn sau 24 giờ. Save khóa revision row để chặn hai tab ghi đè nhau. Chỉnh trực tiếp DB/Django Admin không tăng revision này.
- Save cấu hình và audit là cùng một transaction DB; lỗi audit làm rollback cấu hình. Audit chỉ ghi các trường đã duyệt; mật khẩu chỉ có marker redacted.
- Mật khẩu mới ghi thành secret Vault KV v2 bất biến ở `secret/runtime-settings/smtp/<uuid>`, DB chỉ lưu path trong `_SMTP_PASSWORD_REFERENCE`. Runtime đọc lại Vault khi mở kết nối SMTP, không cache plaintext. Không có reference thì dùng `EMAIL_HOST_PASSWORD` từ deployment; có reference nhưng Vault lỗi thì không fallback sang mật khẩu cũ.
- Token Vault của backend cần quyền create/update/read ở `secret/data/runtime-settings/smtp/*`. Trình duyệt không nhận token Vault hay secret cũ; không tự mở rộng ACL Vault khi lưu form.
- DB và Vault không có transaction phân tán: nếu DB/audit lỗi sau khi Vault ghi thành công, secret mới có thể còn trong Vault nhưng chưa có reference active. Secret cũ và secret không còn reference không bị xóa tự động; đây là dữ liệu cần đưa vào chính sách retention/backup Vault.
- Cache settings TTL 300 giây, invalidation sau commit. Production dùng Redis chung để các worker nhận invalidation; môi trường locmem nhiều worker có thể giữ cache cũ tối đa TTL. Trang file đang mở cần reload để cập nhật giới hạn frontend.
- `signals.py` dùng post-save/post-delete và `transaction.on_commit`; rollback không làm mất cache của giá trị đã commit trước đó.

## Kiểm chứng

`src/security_tests/test_runtime_settings.py` kiểm tra quyền/CSRF/session JWT, validation/batch rollback, audit, revision tab cũ, cache, SMTP/Vault chỉ qua mock, AI, scanner timeout, passkey name và throttling qua router thật. Bộ test dùng SQLite/cache/keys cô lập và không gửi email/kết nối cloud thật.

Nguồn: `services/runtime_settings.py`, `runtime_secrets.py`, `email_backend.py`, `ai_policy_service.py`, `clamav_service.py`, `views/system_settings.py`, `views/auth.py`, `views/passkey.py`, `throttles.py`, `urls/admin_pages.py`, `templates/admin/system_settings.html`, `config/settings/`.
