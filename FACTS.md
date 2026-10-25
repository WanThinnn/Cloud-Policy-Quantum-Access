# Bối cảnh dự án: Cloud Policy Quantum Access

Đối chiếu mã nguồn ngày 2026-10-25. Bản đồ repository kết hợp đọc mã nguồn với những kiểm chứng runtime được nêu rõ bên dưới; không suy rộng các kiểm chứng này thành bảo đảm mọi luồng đã hoạt động hoặc mật mã đúng hoàn toàn. Các đường dẫn dưới đây tính từ root repository.

## Baseline release và lịch sử tính năng

Phiên bản ứng dụng hiện tại là **3.0.0**, theo `VERSION` và `release_note/release_3.0.0.md`. Đã đọc toàn bộ bốn release note có trong checkout; không tra cứu trạng thái GitHub Releases bên ngoài. Bảng sau tóm tắt nội dung công bố, còn cấu hình/giới hạn implementation được ghi riêng ở các mục dưới.

| Release note | Thay đổi được công bố và ý nghĩa khi tiếp tục phát triển |
| --- | --- |
| `release_note/release_2.1.0.md` | Thêm `USE_EXTERNAL_TLS`, HTTP local 8080, sửa kết nối PKI signer, cải thiện CLI/release pipeline; ClamAV early rejection trước mã hóa; ép web Linux AMD64 cho dependency native; đổi tên key cấu hình thành `MASTER_FIELD_ENCRYPTION_KEY`. |
| `release_note/release_2.2.0.md` | Đưa xử lý CP-ABE/MSK vào Vault plugin; bọc khóa user trong Redis bằng AES-GCM/HKDF/AAD; bỏ backup plaintext field master key trong init; init engine idempotent; sửa Supabase upload stream. Các tuyên bố cô lập MSK áp dụng cho plugin mode, không bao phủ nhánh ctypes còn tồn tại. |
| `release_note/release_2.3.0.md` | Chuyển kiểm tra ABAC sang AST/manual evaluation; bảo vệ tài khoản SuperAdmin và tự hạ quyền/khóa tài khoản; chặn tự gán/xóa thuộc tính; hiển thị lỗi 403 ở UI; sửa tải master public key. Giải thích luồng WebAuthn PRF mở khóa ký PQC và recovery. |
| `release_note/release_3.0.0.md` | AI Policy Assistant qua Ollama, metadata/priority và điều kiện phủ định; dual engine AC17/TKN20, chọn scheme theo file và tra cứu blind index; thêm S3/MinIO, GCS, local storage, `DB_REQUIRE_SSL`; tự cập nhật native libraries và source Vault plugin qua `start.py update`. |

Các quick start 2.x còn dùng tên repo `Cloud-Policy-Crypto-Access` và nhánh `feature/cloud-policy-quantum-access`; 3.0 dùng `Cloud-Policy-Quantum-Access`, bản non-PQC ở `legacy`. Không áp dụng nguyên xi lệnh switch nhánh hoặc namespace `abe/` từ release cũ vào 3.0.

## Mục đích và nền tảng

Hệ thống quản lý/chia sẻ file, có policy dựa trên thuộc tính người dùng, mã hóa CP-ABE kết hợp mã hóa đối xứng và các tính năng PQC. README mô tả nhánh `main` dành cho PQC; code vẫn có `ENABLE_PQC_FEATURES` để bật/tắt các bước chữ ký và hai đường triển khai native/plugin.

- Django `5.2.6`, DRF `3.15.2`, SimpleJWT `5.3.1`, PyCasbin `2.7.1`: `src/requirements.txt`.
- Docker runtime dùng Ubuntu 24.04/Python 3.12; stage build CSS dùng Node 20: `docker/Dockerfile`. Đây là môi trường container, không phải cam kết mọi Python version khác đều được hỗ trợ.
- Frontend dùng Django templates, JavaScript thuần, Tailwind 4/PostCSS: `src/templates/`, `src/static/js/`, `src/theme/static_src/package.json`.
- `VERSION` hiện là `3.0.0`; package CSS là `4.2.0`. README đề cập thư viện crypto `v4.0.0`; các số này không cùng một miền version.
- Có native library Windows/Linux trong `src/lib/`; mã Go/C++/CGO của Vault plugin nằm ở `src/vault-plugin/`. `go.mod` của plugin khai báo Go `1.25.7`.

## Bản đồ mã nguồn

| Khu vực | Vai trò/điểm bắt đầu |
| --- | --- |
| `start.py` | CLI điều phối Compose, TLS/profile VPN/tunnel/AI, migration, initdata, build/update và quản lý môi trường |
| `src/manage.py`, `src/config/settings/` | Entry Django; settings base/development/production |
| `src/config/urls.py`, `src/crypto_access/urls/` | Mount routes API và HTML |
| `src/crypto_access/models/` | Profile, thuộc tính, policies, file/version, session, PKI, audit, settings và encrypted fields |
| `src/crypto_access/serializers/`, `views/` | Validation/API và xử lý request theo miền nghiệp vụ |
| `src/crypto_access/services/casbin_service.py` | Đánh giá điều kiện AST, ABAC và kiểm tra quyền file |
| `src/crypto_access/services/cpabe_service.py` | Lazy service, ctypes bindings hoặc gọi Vault ABE plugin |
| `src/crypto_access/services/vault_service.py` | Đọc/ghi Vault KV và cấu hình kết nối |
| `src/crypto_access/services/storage/` | Interface, factory và adapters Supabase/S3/GCS/local |
| `src/crypto_access/services/clamav_service.py`, `pki_service.py` | Quét file và gọi dịch vụ ký PKI |
| `src/crypto_access/services/setting_service.py` | Settings động từ DB, cache 300 giây |
| `src/crypto_access/services/ai_policy_service.py`, `src/config/prompts/` | Tích hợp Ollama hỗ trợ tạo policy |
| `src/crypto_access/authentication.py`, `middleware/`, `permissions.py`, `decorators.py` | JWT, session, rate limiting và áp dụng quyền |
| `src/crypto_access/signals.py` | Lowercase username, thay thuộc tính/profile, thu hồi khóa/cache và xử lý xóa file |
| `src/static/js/files-manager.js`, `policy-builder.js`, `pqc-manager.js` | Quản lý file, policy builder và mật mã phía trình duyệt |
| `docker/`, `nginx/`, `config/` | Hạ tầng, reverse proxy, thư mục mount cấu hình/cert/khóa |
| `scripts/` | Script setup/release, Vault, relay và build plugin; có bản tương ứng của một số script trong `src/` |
| `docs/vi/`, `docs/en/`, `release_note/` | Đặc tả song ngữ và lịch sử phát hành; cần đối chiếu implementation |

## Các miền dữ liệu

- Django `User` và `UserProfile` chứa danh tính/trạng thái tài khoản; `UserType`, `AttributeDefinition`, `UserAttribute` biểu diễn loại người dùng và thuộc tính động. Nguồn: `models/base.py`, `models/attributes.py`.
- `AccessPolicy` chứa `subject_condition`, resource/action, allow/deny, priority và `cpabe_policy`; có logic chuyển điều kiện thành policy CP-ABE. Nguồn: `models/policy.py`.
- `StorageBucket`, `UploadedFile`, `FileVersion`, `FileAccessPolicy` chứa bucket, đường dẫn logic/vật lý, metadata, soft delete, phiên bản, chữ ký và gán policy file/folder. `UploadedFile.abe_scheme` ghi `ac17`/`tkn20` để chọn scheme khi đọc file. Nguồn: `models/storage.py`, migration `0030_*`.
- `UserPublicKey`, `WebAuthnCredential`, `ActiveSession` phục vụ khóa người dùng, passkey và thiết bị/session. Nguồn: `models/pki.py`, `webauthn.py`, `session.py`.
- `AccessLog` có hash chain và quick/deep verification; `KeyRevocation` lưu thu hồi khóa. Không suy ra quick verification kiểm chứng mọi bản ghi. Nguồn: `models/audit.py`.
- Các model được export qua `models/__init__.py`. Migration hiện có từ `0001` đến `0030`; không suy ra DB triển khai đã áp dụng hết.

## Quyền truy cập và luồng file

1. Request đi qua JWT middleware trước ABAC middleware; DRF dùng `CookieJWTAuthentication`. Authentication class thử Bearer header trước rồi cookie `access_token`. Kiểm tra thêm session middleware và views auth khi sửa login/logout. Nguồn: `settings/base.py`, `authentication.py`, `middleware/jwt_middleware.py`.
2. `CasbinService._check_abac` đọc policy đang active, sắp xếp priority tăng dần và trả kết quả của policy khớp đầu tiên. Điều kiện được đánh giá bằng AST qua `safe_eval_condition`; không phải chỉ dựa vào `enforcer.enforce()`. `check_access` bypass với superuser; các user còn lại bị từ chối nếu không có allow. Không có quy tắc toàn cục rằng mọi deny đều thắng mọi allow, bất kể priority. Nguồn: `services/casbin_service.py`.
3. Upload xử lý policy trực tiếp hoặc kế thừa folder, tính SHA3-256 plaintext và quét ClamAV trước mã hóa/upload. **Chỉ khi có `cpabe_policy_str` mới mã hóa CP-ABE**; nhánh không có policy đưa plaintext sang storage. Không mô tả mọi upload là ciphertext. Nguồn: `views/storage.py`, phương thức `upload`.
4. Nếu có policy, `CPABE_SCHEME` chọn scheme ghi file, còn `ENABLE_PQC_FEATURES` chọn encrypt/sign hoặc encrypt thường. Storage nhận physical path; DB lưu metadata và version/chữ ký liên quan. Nguồn: `views/storage.py`, `models/storage.py`.
5. Download/preview có kiểm tra quyền file và luồng giải mã; `_decrypt_file_if_needed` chọn scheme từ record. Cache khóa có dạng `cpabe_key_{scheme}_{user_id}_{attrs_hash}`, khóa được bọc trước khi cache, timeout tại đây là 3600 giây. Cần xem cả xử lý owner/fallback khi thay quyền. Nguồn: `views/storage.py`.
6. Gán policy có thể đọc lại dữ liệu, kết hợp policy và mã hóa lại. Rename/copy/move phải đồng bộ DB, blind index, physical path và versions tùy thao tác. Nguồn: `assign_policy`, `clipboard_action`, `rename_item` trong `views/storage.py`.

Mặc dù hashing chia chunk, upload hiện vẫn gọi `file.read()` để lấy toàn bộ plaintext vào bộ nhớ. Django upload handlers cũng chưa được chứng minh luôn tránh file tạm. Không coi các tuyên bố “streaming hoàn toàn”, “không bao giờ có plaintext trên disk” hay “RAM không phụ thuộc kích thước file” là bảo đảm từ lần đọc này.

## Mật mã và storage

- Native mode tải `libhybrid-pq-cp-abe.dll` trên Windows hoặc `.so` trên hệ khác từ `src/lib/`; service được khởi tạo lazy. Constructor thật gọi `_ensure_keys_exist`, có thể tương tác Vault/khóa. Nguồn: `services/cpabe_service.py`.
- `USE_VAULT_ABE_PLUGIN=False`, `CPABE_SCHEME=ac17`, `ENABLE_PQC_FEATURES=True` là defaults trong `settings/base.py`; `.env.example` cũng chọn plugin False/scheme AC17. Plugin mode 3.0 dùng hai mount `abe_ac17/`, `abe_tkn20/`, KV keys `CPABE_PK_AC17`, `CPABE_PK_TKN20` và endpoint `/v1/abe_{scheme}/setup|genkey|encrypt|decrypt`. Release 3.0 mô tả file mới mặc định TKN20 nhưng điều đó phụ thuộc cấu hình thực tế; không giả định native ctypes hỗ trợ TKN20 tương đương plugin. Nguồn: `scripts/vault_manager.py`, `services/cpabe_service.py`.
- Native service dùng tên `cpabe_pk.key`, `cpabe_msk.key`, `pqc_pk.key`, `pqc_sk.key`, với working keys ở `BASE_DIR/config/keys` và nhánh backup theo `KEYS_DIR`. Có code tạo/backup khóa và API file-based cũ; README không phải mô tả đầy đủ vòng đời khóa.
- Encrypted fields dùng AES-GCM, HKDF-SHA3-256 và blind index HMAC-SHA3-256. Key lookup ưu tiên Vault rồi `MASTER_FIELD_ENCRYPTION_KEY`; bật/tắt qua `FIELD_ENCRYPTION`. Nguồn: `models/fields.py`, `settings/base.py`.
- Factory nhận chính xác `supabase` (default), `aws_s3`, `google_cloud_storage`, `local_disk`; giá trị không nhận diện fallback Supabase. Instance storage là singleton. Nguồn: `services/storage/factory.py` và `adapters/`.
- R02 đã sửa ở `services/storage/adapters/local.py`: bucket phải là tên đơn hợp lệ; mọi path được resolve và giới hạn trong bucket thuộc MEDIA_ROOT. Adapter từ chối absolute/drive-relative/UNC path, parent/dot segment, backslash, ADS, NUL, symlink/junction và tên không an toàn trên Windows (device name, đuôi dấu chấm/khoảng trắng). List không trả entry symlink; batch delete kiểm tra toàn bộ path trước khi xóa. Đây là kiểm tra ranh giới path; storage root vẫn cần thuộc quyền quản lý của backend, không phải cơ chế chống mọi race từ tiến trình OS khác có quyền sửa filesystem.
- Đã sửa bypass TKN20 trong `views/storage.py`, `services/tkn20_policy.py` và `services/cpabe_service.py`. TKN20 Go bridge dùng map một value/label; bypass cũ cộng cả user_type super_admin/data_owner rồi đưa qua set khiến value cuối bị ghi đè ngẫu nhiên. Bypass hiện chọn một assignment nhất quán với policy and/or/not, chỉ áp dụng khi superuser hoặc owner; không sửa thuộc tính DB hay giả lập thuộc tính cho user thường. Cache dùng namespace `cpabe_key_tkn20_bypass_v2_*` để tránh khóa sai cũ.
- Keygen TKN20 hiện chuẩn hóa label/value, từ chối nhiều value xung đột cho cùng label, không mở rộng role/clearance thành nhiều value cùng label như AC17. AC17 vẫn giữ hierarchy expansion. Không suy ra TKN20 hỗ trợ mọi policy nhiều giá trị của AC17; điều kiện đồng thời yêu cầu hai value khác nhau cho một label không có assignment hợp lệ và bị từ chối.
- Frontend có liboqs JS/WASM và Argon2 assets; metadata version chứa user signature, timestamp và system signature. Chưa xác minh end-to-end cơ chế ký/verify chỉ bằng sự hiện diện của các trường này.
- Khóa ký ML-DSA của người dùng khác khóa giải mã CP-ABE backend: `pqc-manager.js` triển khai sinh khóa WASM, dùng WebAuthn PRF để mở blob secret key mã hóa và hỗ trợ recovery qua Argon2; thời gian tự khóa là 30 phút không hoạt động. Biometric/PIN mở khóa ký chứ không trực tiếp tạo chữ ký tài liệu. Không suy ra mọi passkey provider/browser đều hỗ trợ PRF từ bảng tương thích trong release note.

## AI Policy Assistant trong 3.0

- Routes: `GET /api/admin/ai/status/`, `POST /api/admin/ai/generate-policy/`. Cả hai yêu cầu `IsAuthenticated` và `IsSuperAdmin`; payload sinh policy có trường `prompt`. Nguồn: `urls/admin.py`, `views/ai_assistant.py` dưới `src/crypto_access/`.
- Service gửi schema thuộc tính/user types lấy từ DB (cache 300 giây), system prompt trong `src/config/prompts/ai_policy_system.md` và prompt người dùng tới Ollama `/api/chat`. Dùng JSON output schema, temperature 0.1; timeout default 120 giây và keep-alive default `-1`, hiện có thể chỉnh qua System Settings. Singleton đọc endpoint/model/feature flag/timeout động thay vì cố định lúc import. Nguồn: `services/ai_policy_service.py`, `services/runtime_settings.py`.
- Endpoint trả đề xuất gồm condition, CP-ABE policy, resources/action/effect, name/description/priority/explanation và validation; không gọi save để tự tạo `AccessPolicy`. Validation hiện parse AST và thử `_generate_cpabe_policy`, không chứng minh đề xuất đúng ý định/quyền trên dữ liệu thực tế.
- Thiết kế release dùng LLM local; service thực tế gửi đến `OLLAMA_BASE_URL` cấu hình. Cần xác nhận URL triển khai trước khi khẳng định dữ liệu không rời hệ thống.

## Cấu hình và hạ tầng

- Trang **System → System Settings**, GET/POST `/manage/settings/`, chỉ dành cho user active có profile `super_admin` còn hiệu lực. Có CSRF, cache-control no-store, revision ký/row lock chống tab cũ ghi đè và audit trong cùng transaction DB. Không có editor tùy ý `.env` hay `SystemSetting`. Nguồn: `views/system_settings.py`, `urls/admin_pages.py`, `templates/admin/system_settings.html`.
- Catalog runtime quản lý 20 giá trị thường và 1 mật khẩu SMTP: tên passkey, email/SMTP/TLS/timeout, endpoint/model/feature/keep-alive/timeout AI, max upload/timeout scanner/rate upload-download và ngưỡng login/OTP đổi IP. Save lần đầu chốt cả những giá trị đang lấy từ deployment vào DB; GET không seed. Ưu tiên DB active → deployment/default. Phân loại đầy đủ biến được giữ/chuyển: `docs/vi/runtime-settings.md`; validation chung: `services/runtime_settings.py`.
- Mật khẩu SMTP nhập trên UI là write-only, lưu Vault KV v2 tại path UUID riêng; DB chỉ giữ `_SMTP_PASSWORD_REFERENCE`, audit dùng marker redacted. Không có reference thì dùng mật khẩu deployment; reference có nhưng Vault lỗi thì không fallback cũ. DB rollback có thể để lại secret mới chưa được tham chiếu trong Vault; không tự xóa lịch sử secret. Nguồn: `services/runtime_secrets.py`, `services/email_backend.py`.
- Cả development/production dùng `RuntimeEmailBackend`, chọn console theo mặc định development và SMTP theo mặc định production; UI có thể override. Nút Test SMTP chỉ kết nối/TLS/login, không gửi mail. Hạ tầng DB/Redis/Vault/storage, crypto flags/trust roots, RP ID/origin và Compose/VPN/tunnel vẫn ở deployment. SMTP và AI endpoint có thể đổi qua UI, chứng chỉ trust vẫn ở deployment.
- Cache SystemSetting TTL 300 giây, invalidation chạy sau commit bằng post-save/post-delete. Redis chung đồng bộ invalidation giữa worker; locmem nhiều worker có thể giữ giá trị cũ tới TTL. `throttles.py` đọc runtime limits và `views/storage.py` gắn throttle bằng kwargs của `@action`, đã kiểm tra router trả 429 khi vượt mức. UI upload dùng cùng giới hạn với serializer; trang file đã mở cần reload để lấy giá trị mới.
- Kiểm chứng phần runtime settings: tổng **67 test** trong `security_tests` đã qua ở container với DB/cache/keys cô lập (38 regression cũ và 29 test cấu hình mới); Django system check và Tailwind production build thành công. Đã mở trang HTTPS bằng browser với super_admin và xác nhận liên kết trong menu System. SMTP/Vault credential I/O dùng mock trong test, chưa gửi email thật hoặc thay mật khẩu SMTP triển khai để thử.

- `BASE_DIR` là `src/`; `PROJECT_ROOT` là root repo. `settings/base.py` load `.env` ở root. Dùng `.env.example` làm mẫu, không đọc/chia sẻ secret thật để viết tài liệu.
- `manage.py` mặc định dùng `config.settings`; package này chọn theo `DJANGO_ENV` (default development). Development dùng `DATABASE_URL` nếu có, nếu không dùng SQLite `src/db.sqlite3`.
- Production yêu cầu `DJANGO_SECRET_KEY`, `DJANGO_ALLOWED_HOSTS`, `DATABASE_URL`. Không mặc định DB là Supabase: `.env.example` dùng SQLite URL cho container; Compose còn có PostgreSQL tùy cấu hình. Production dùng Redis khi có `REDIS_URL`, nếu không fallback locmem. Nguồn: `settings/production.py`.
- Với PostgreSQL, `DB_REQUIRE_SSL` default True; URL có `sslmode=disable`/`sslmode=require` override quyết định SSL. Biến này điều khiển kết nối DB, không tắt TLS các service khác. Nguồn: `settings/production.py`.
- Biến quan trọng khác: `STORAGE_VENDOR`, credentials backend tương ứng, `VAULT_ADDR`, `VAULT_SECRET_PATH`, `VAULT_TOKEN`/token file, `VAULT_CACERT`, `KEYS_DIR`, `MASTER_FIELD_ENCRYPTION_KEY`, `FIELD_ENCRYPTION`, `ENABLE_PQC_FEATURES`, `USE_VAULT_ABE_PLUGIN`, `CPABE_SCHEME`, `WEBAUTHN_*`, `PKI_SIGNER_URL`, `PKI_AUTH_TOKEN`, `AI_FEATURES_ENABLED`, `OLLAMA_*`. Không dùng giá trị mẫu làm cấu hình production.
- `start.py` mặc định chọn `docker/docker-compose.yml`; `--prod` chọn `docker-compose.prod.yml`. Cả hai đặt `DJANGO_SETTINGS_MODULE=config.settings.production` cho web, vì vậy “dev Compose” không đồng nghĩa Django development settings.
- Cả hai Compose dùng `DOCKER_IPV4_SUBNET` cho mạng `app-network`, default `172.30.0.0/16`; subnet IPv6 là `fd00:dead:beef::/48`. Dải IPv4 cũ `172.20.0.0/16` trùng mạng `pti-portal_default` trên máy phát triển và làm Docker báo `Pool overlaps`. Khi đổi subnet, đối chiếu mạng Docker và LAN/VPN hiện có; không xóa mạng của dự án khác để khắc phục.
- `start.py` thêm override `docker-compose.nossl.yml` nếu không bật external TLS hoặc thiếu cert/key. Các cờ `--vpn`, `--tunnel`, `--ai` kích hoạt profiles tương ứng. Kiểm tra đường dẫn bằng CLI vì Compose files nằm trong `docker/` và có relative build/mount paths.
- Stack có Django/Gunicorn, DB, Vault, Redis, ClamAV và TLS proxy, Nginx OQS, PKI signer; bổ sung Ollama/TLS proxy, Cloudflared, OpenVPN PQC và OpenVPN standard theo cấu hình/profile. Nguồn: Compose files và Dockerfiles tương ứng.
- `start.py initdata` khởi tạo/unseal Vault, migrate, chạy `init_data.py`, seed policies/test users và trích xuất PQC public key. Đây không phải lệnh kiểm tra chỉ đọc.
- URL gốc: `/admin/`, `/manage/`, `/auth/`, `/api/auth/`, `/api/storage/`, `/api/admin/`, `/api/pki/`, `/health/`. README nhắc `/api/docs/`, nhưng chưa thấy route đăng ký Swagger/OpenAPI trong URL configs đã đọc.
- Settings base khai báo WebAuthn hai lần; khai báo sau có hiệu lực và default dùng domain `cloudsafe.cyberfortress.local`. Timezone ứng dụng là `Asia/Ho_Chi_Minh`, khác cấu hình timezone máy người dùng.
- Log cấu hình tách JSON ECS cho `auth`, `storage`, `policy`, `user`, `attributes`, `audit`, `system`. Production ghi dưới `/app/logs/`. Nguồn: `settings/base.py`, `production.py`.

## Cách `start.py` thực sự vận hành

CLI dùng Python standard library, cú pháp `rtk python start.py [cờ toàn cục] <command> [tham số]`. `compose_cmd` luôn truyền `docker compose --project-directory <root>` rồi các `-f` và profile; `run` đặt cwd là root. `--dev` là nhãn chế độ mặc định; nếu truyền đồng thời `--prod`, lựa chọn file dựa trên `args.prod`. Parser không có cờ `--ipv4` dù docstring đầu file nhắc đến; IPv4 là mặc định.

| Command | Hành vi quan sát trong code |
| --- | --- |
| `help` hoặc không có command | In hướng dẫn. Không có nhánh `status`; dùng Compose `ps` để xem container. Cờ `-h/--help` được parse nhưng chưa có nhánh xử lý riêng để buộc hiển thị help. |
| `setup` | Gọi `scripts/setup.py`: kiểm tra Docker/Compose, copy `.env` nếu thiếu, kiểm tra cert và thử cài Root CA vào trust store OS; không phải thao tác chỉ đọc. |
| `build` | Compose build; chế độ prod chạy pull trước build. Không chạy native-library updater ở bước này. |
| `up`, `restart` | Compose up -d/restart, gọi Vault manager tối đa 10 lần với khoảng chờ 2 giây khi subprocess lỗi, trích xuất raw PQC root public key nếu cần, gọi warmup nếu `--ai`; có thể mở UDP6 relay trên Windows khi VPN IPv6/dual. |
| `down` | Dừng UDP6 relay rồi Compose down; nhánh này không truyền `-v`. |
| `logs` | Compose logs -f cho stack; không chuyển tiếp đối số service/filter từ `rest`. |
| `makemigrations`, `migrate`, `initsettings` | Chạy manage.py trong service `web`, chuyển tiếp đối số; `initsettings` gọi `init_settings`. |
| `initdata` | Vault manager → migrate → init_data.py → seed_policies → seed_test_data → trích xuất public key, warmup nếu bật; in thông tin tài khoản khởi tạo ra terminal. |
| `createsuperuser`, `shell`, `collectstatic` | Lần lượt gọi management command riêng `create_super_admin`, Django shell, collectstatic --noinput trong `web`. |
| `update` | git pull → cập nhật C++ libs → cập nhật source plugin → prod pull nếu có → Compose build → up -d → Vault manager/public key/warmup. Không phải nâng phiên bản được pin theo release ứng dụng 3.0. |
| `clean` | Hỏi chọn xóa container, volume DB/AI/keys+Vault/VPN/local media và docker system prune; khi chọn keys còn xóa host `vault_unseal_keys.json`, `vault_token.txt` trong `KEYS_DIR`. |
| `rebuild` | Compose down -v → build --no-cache → up -d, tiếp đó Vault manager/public key/warmup/relay; có thể mất dữ liệu, không tương đương build lại giữ volume. |
| `vpn_client <name>` | Tự bật profile VPN, chạy gen-client.sh ở hai service và copy `<name>_pqc.ovpn`, `<name>_classic.ovpn` ra cwd gọi CLI. Container phải đang chạy. |
| `gencerts <path>` | Tạo output directory, chạy `config/certs/generate_pq_certs_docker.sh` bằng image `openquantumsafe/curl`; nhánh này đọc `sys.argv[2]` nên không nên ghép cờ toàn cục trước command. |
| `ai_setup` | Gọi `ollama pull` trong service `ollama` theo `OLLAMA_MODEL` (fallback `qwen2.5-coder:3b`); không tự khởi động service. |

- `--ai` bật profile AI và ghi `AI_FEATURES_ENABLED=True` vào `.env`; bỏ cờ ở lần chạy sau không tự ghi False. Model phải được tải riêng, ví dụ `rtk python start.py --ai up` rồi `rtk python start.py --ai ai_setup`. `warmup_ai` dùng keep_alive từ env và gọi generate nền, nhưng hiện truyền **container name `ollama_server`** vào Compose exec trong khi service tên **`ollama`**; lỗi bị bỏ qua. Vì vậy có code warmup nhưng chưa thể coi warmup thực sự thành công.
- `--vpn`/`vpn_client` ghi `VPN_PROTO` vào `.env`: mặc định ipv4, `--ipv6` chọn ipv6, `--ipv46` chọn dual. Cờ được xử lý trước dispatch command; ngay cả `help` kèm `--vpn`/`--ai` cũng có thể sửa `.env`. `--vpn` không kèm cờ IP có thể đặt cấu hình đã lưu về ipv4.
- `--tunnel` chỉ bật khi có tunnel ID/domain và các file config/credentials cần thiết. Chỉ đặt biến tunnel trong env chưa tự bật profile.
- SSL external cần `USE_EXTERNAL_TLS` true và file cert/key tồn tại. Tên ưu tiên `SSL_CERT_FILE`/`SSL_KEY_FILE`, sau đó `PQC_SSL_CERT_FILE`/`PQC_SSL_KEY_FILE`, sau đó default classic. Không có kiểm tra handshake/chứng chỉ hợp lệ ở bước chọn này.
- Windows UDP6 relay chuyển UDP 53→1194 và 443→1195, dùng `scripts/udp6_relay.py`, log `.udp6_relay.log` và PID file `.udp6_relay.pid`; không chạy helper này trên Linux/macOS.
- `start.py` gọi `web:python vault_manager.py`; cả hai Compose mount **`scripts/vault_manager.py`** vào `/app/vault_manager.py`. File `src/vault_manager.py` trong checkout đang rỗng, nên phải đọc bản `scripts/` khi sửa luồng này. Prod manager khởi tạo mới theo 5 shares/threshold 3 và unseal cho setup ban đầu; Vault đã khởi tạo mà sealed ở lần sau sẽ yêu cầu unseal thủ công. Manager hiện xác nhận seal status sau khi gửi key, chờ authenticated mount API sẵn sàng và trả exit code 1 nếu thiếu key/token hoặc setup engine/plugin lỗi. Các nhánh up/restart/update/rebuild trả lỗi khi Vault manager thất bại. Không đổi ngưỡng Vault đã khởi tạo chỉ bằng cách chuyển --prod sang --dev.
- `update_cpp_libs` hỏi GitHub Releases latest của **thư viện upstream**, fallback `v5.2.0`, chọn ZIP Linux/Windows; chép lib vào `src/lib/`, Linux headers/libs vào `src/vault-plugin/`. Hàm xóa `include/` và `lib/` plugin trước khi tải xong, lỗi download chỉ in warning; cần kiểm tra output trước build. Đây là version thư viện, không phải release app 3.0.
- `update_vault_plugin` shallow clone repo thư viện upstream vào `tmp_plugin_repo`, copy `src/go/vault-plugin-abe` đè lên plugin local, sửa CGO include path và copy C++ headers, rồi dọn thư mục tạm. Không có pin commit trong lệnh clone. Các updater có thể bắt lỗi rồi cho luồng update tiếp tục; thông báo cuối thành công không chứng minh dependency update đầy đủ.
- `rebuild` tạo lại Compose command mà không truyền `use_ai`, nên profile AI có thể thiếu dù CLI nhận `--ai`. Các điểm lệch CLI nêu trên là quan sát tĩnh cần xác minh/sửa trong nhiệm vụ riêng; lần cập nhật tài liệu này không chạy updater, unseal, seed hay xóa volume.

## Kiểm thử, build và điểm cần kiểm chứng

- R01 đã sửa trong `views/storage.py` và `serializers/storage.py`: inline global policy ở cả upload/assign-policy yêu cầu `IsSuperAdmin` và ABAC `policy/*`, dùng validation của `AccessPolicySerializer`. Owner/admin chỉ có quyền gán file không tự được quyền tạo global policy. Assign kiểm tra target trước mọi write; upload chỉ lưu policy ở bước ghi metadata sau quét/mã hóa/upload. Hai endpoint dùng DB transaction, rollback khi xử lý file thất bại; từ chối chọn vừa policy_id vừa create_new_policy và bỏ đường tạo policy bằng name-only cũ. DB rollback không bao gồm rollback blob của dịch vụ storage; cleanup blob khi lỗi vẫn là phạm vi riêng.
- `src/security_tests/` có 23 regression test R01/R02 đã qua trong Linux container. Settings riêng dùng SQLite in-memory, locmem cache, key/media/BASE_DIR trong thư mục tạm, tắt kết nối Vault và mock native crypto/ClamAV/cloud storage. Chạy trong `src/` hoặc `/app`: `rtk python -m django test security_tests --settings=security_tests.settings --noinput`. Với stack test đang chạy: `rtk docker exec django_app python -m django test security_tests --settings=security_tests.settings --noinput`. Tests kiểm tra API thật qua DRF, DB rollback, local adapter với filesystem tạm và symlink thật; Windows path syntax được kiểm tra trên Linux, chưa chạy junction test trên Windows host. Không chạy migration lịch sử hoặc full end-to-end crypto trong suite này.
- Suite hiện thêm 15 test bypass/keygen TKN20, tổng 38 test. Đã kiểm tra trực tiếp plugin bằng dữ liệu giả trong RAM: cùng policy user_type:data_owner, thứ tự admin→owner giải mã được nhưng owner→admin bị 500 trước sửa, xác nhận lỗi duplicate label. File người dùng báo lỗi được upload sau reset nên không phải ciphertext dùng master key cũ. Sau sửa đã đăng nhập qua Nginx và preview đúng `01_core_buffer_vs_charm.png`: HTTP 200, Content-Type image/png, PNG signature hợp lệ; logout phiên kiểm tra. Không viết lại blob, policy hoặc master key của file.

- Backlog kiểm tra chuẩn bị 3.1 ở `docs/vi/release-3.1-readiness.md`, gồm kết quả kiểm tra cô lập và thứ tự ưu tiên sửa. Các mục trong đó chưa được coi là đã khắc phục nếu chưa có thay đổi/test tương ứng.
- Kiểm tra vận hành ngày 2026-10-25: Nginx từng mất network attachment; đã tạo lại riêng container và xác nhận proxy tới `/auth/login/` trả 200 qua HTTP nội bộ. Sau khi MISP dừng, cấu hình local quay về cổng 80/443. Vault cũ từng yêu cầu 3/5 shares trong khi file mount chỉ có 1; sau đó người dùng cho phép reset toàn bộ app test. Đã xóa container/volume thuộc riêng project, xóa hai file unseal/token cũ rồi khởi tạo Vault/DB mới theo chế độ dev; Vault mới unsealed/active, mount AC17/TKN20 thành công. Không lưu key/token trong tài liệu.
- Sau reset test: migrate/initdata thành công, seed 10 policies và 5 test users cùng super admin; login API qua Nginx trả 200 và cấp cookie, logout phiên kiểm tra trả 200, ClamAV healthy. Local `.env` đặt `GUNICORN_CMD_ARGS=--workers 3` vì cấu hình CPU-count trước đó mở khoảng 40 worker và backend restart trong lúc init (tiến trình init bị kết thúc mã 137; chưa kết luận OOM bằng container flag). File Supabase không bị xóa; reset chỉ xóa DB/trạng thái Vault và storage volume cục bộ. Đây là kiểm tra luồng auth/vận hành, không chứng minh luồng crypto/file đã qua integration test.
- `tests/test_vault_manager.py` có 9 test cô lập cho partial/duplicate shares, trạng thái unsealed, readiness/retry và lỗi KV. Chạy `rtk python -m unittest discover -s tests -p test_vault_manager.py -v`; đã qua cả 9 test. Chạy manager thật với file hiện tại xác nhận dừng ở 1/3 với exit code 1, không báo thành công giả.

- Test Django legacy nằm trong `src/crypto_access/tests.py`, chủ yếu health/profile; regression R01/R02 nằm riêng trong `src/security_tests/`. Chưa có độ bao phủ đầy đủ các luồng quyền/mật mã/storage còn lại.
- `src/pytest.ini` dùng header `[tool:pytest]` dù là file `.ini`, và `testpaths = crypto_access/tests` trong khi app có `tests.py`. Cần kiểm tra collection/config trước khi tin kết quả `pytest`; đừng suy ra không có lỗi từ việc không thu thập test.
- `src/tests/` chứa script thử nghiệm có `django.setup()`, đường dẫn Windows cũ, phụ thuộc user/policy đã seed, import module cũ; `test_hybrid.py` sửa policy ngay khi import, `test_assign_policy.py` có code upload dữ liệu. Không chạy chúng với DB/storage thật hoặc gom tất cả bằng pytest mà chưa xem tác dụng phụ.
- Lệnh kiểm tra có thể dùng sau khi cô lập môi trường được liệt kê trong `AGENTS.md`. Các kiểm tra đã chạy được ghi riêng ở trên; chưa build lại crypto hoặc chạy toàn bộ pytest legacy.
- Cache key trong `signals.get_cache_key_id` thiếu thành phần scheme so với `_decrypt_file_if_needed`; đây là điểm cần kiểm tra khi sửa revocation/cache, chưa xác nhận mức ảnh hưởng runtime.
- `src/theme/static_src/package-lock.json` đang được Git theo dõi dù `.gitignore` có rule `package-lock.json`; Docker dùng `npm ci`. Đừng xóa lockfile vì tưởng là file sinh không được quản lý.
- Plugin build helpers: `scripts/build_plugin_for_docker.ps1` và `.sh`; output Linux AMD64 ở `docker/vault/plugins/vault-plugin-abe`. Build còn cần native/static libraries và headers trong `src/vault-plugin/`.
- Workflow `.github/workflows/` hiện build/push app và Vault khi push tag `v*`, đọc `VERSION`, tạo GitHub Release, gán alias `latest`. README nói dual-track nhưng workflow đã đọc không thể hiện đủ cơ chế đó; prod Compose vẫn tham chiếu Vault `pqc-latest`. Kiểm tra workflow/Compose cụ thể trước khi release.
- README nêu yêu cầu trình duyệt PQ TLS cụ thể; đây là tuyên bố của tài liệu, chưa kiểm tra tương thích trình duyệt/cert/handshake. Khi xử lý kết nối, xem `nginx/`, cert thực tế và log thay vì coi số version browser trong README là bảo đảm.

## Cách cập nhật file này

Giữ các facts có thể truy về mã nguồn. Khi một điểm cần kiểm chứng đã được sửa hoặc xác minh, thay bằng kết quả cùng cách kiểm tra; không lưu kết quả test giả định hoặc giá trị môi trường riêng tư. Cập nhật ngày đối chiếu khi thực sự rà soát lại.
