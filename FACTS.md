# Bối cảnh dự án: Cloud Policy Quantum Access

**Current contract boundary (2026-11-14):** CPQA builds unmodified upstream crypto source. Upstream commit `a75c50e` provides Vault authority contract v1, including large authority storage, public-key references, read-only recovery and encryption metadata. CPQA consumes it in `services/vault_abe_contract.py`, `services/cpabe_service.py` and `services/version_crypto.py`. See `docs/en/covercrypt-vault-contract.md` and its Vietnamese counterpart.

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
- App `VERSION` is `3.0.0`; the CSS package is `4.2.0`. Crypto builds follow upstream Git HEAD (6.0.0 at inspection time); the resolved commit/version is recorded after building in `/opt/cpqa/crypto/source.env`. These versions describe different components.
- Docker builds the native library and Vault plugin from upstream source; `src/lib/` and `src/vault-plugin/` no longer contain vendored source, headers, or binaries. Sources: `docker/Dockerfile`, `docker/build-crypto.sh`.

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
2. `CasbinService._check_abac` đọc policy đang active, sắp xếp priority tăng dần và trả kết quả của policy khớp đầu tiên. Điều kiện được đánh giá bằng AST qua `safe_eval_condition`; không phải chỉ dựa vào `enforcer.enforce()`. `check_access` giữ bypass quản trị của superuser; bypass document của super_admin/superuser phụ thuộc `SUPER_ADMIN_REQUIRE_POLICY`. Khi không có bypass, cần policy allow. Không có quy tắc toàn cục rằng mọi deny đều thắng mọi allow, bất kể priority. Nguồn: `services/casbin_service.py`.
3. Upload xử lý policy trực tiếp hoặc kế thừa folder, tính SHA3-256 plaintext và quét ClamAV trước mã hóa/upload. **Chỉ khi có `cpabe_policy_str` mới mã hóa CP-ABE**; nhánh không có policy đưa plaintext sang storage. Không mô tả mọi upload là ciphertext. Nguồn: `views/storage.py`, phương thức `upload`.
4. Nếu có policy, `CPABE_SCHEME` chọn scheme ghi file, còn `ENABLE_PQC_FEATURES` chọn encrypt/sign hoặc encrypt thường. Storage nhận physical path; DB lưu metadata và version/chữ ký liên quan. Nguồn: `views/storage.py`, `models/storage.py`.
5. Download/preview có kiểm tra quyền file và luồng giải mã; `_decrypt_file_if_needed` chọn scheme từ record. Cache khóa có dạng `cpabe_key_{scheme}_{user_id}_{attrs_hash}`, khóa được bọc trước khi cache, timeout tại đây là 3600 giây. Cần xem cả xử lý owner/fallback khi thay quyền. Nguồn: `views/storage.py`.
6. Gán policy có thể đọc lại dữ liệu, kết hợp policy và mã hóa lại. Rename/copy/move phải đồng bộ DB, blind index, physical path và versions tùy thao tác. Nguồn: `assign_policy`, `clipboard_action`, `rename_item` trong `views/storage.py`.

Mặc dù hashing chia chunk, upload hiện vẫn gọi `file.read()` để lấy toàn bộ plaintext vào bộ nhớ. Django upload handlers cũng chưa được chứng minh luôn tránh file tạm. Không coi các tuyên bố “streaming hoàn toàn”, “không bao giờ có plaintext trên disk” hay “RAM không phụ thuộc kích thước file” là bảo đảm từ lần đọc này.

## Mật mã và storage

- Native mode loads `libhybrid-pq-cp-abe.dll` on Windows or `.so` elsewhere from `CPABE_LIBRARY_DIR` (Docker: `/opt/cpqa/crypto/lib`; host fallback: `src/lib/`). The service is lazy, but its constructor calls `_ensure_keys_exist` and may access Vault/keys. Sources: `services/cpabe_service.py`, `docker/Dockerfile`.
- CoverCrypt setup JSON is generated from active enum `AttributeDefinition` records plus a bounded `user_type` dimension derived from active `UserType` codes and legacy profile choices; dimensions are not duplicated in deployment settings. `services/covercrypt_config.py` creates deterministic non-hierarchical dimensions and fingerprints the canonical JSON plus source definition versions. `GET /api/admin/covercrypt/configuration/` requires `IsSuperAdmin`; the `covercrypt_config` management command can check or explicitly persist a non-secret manifest for an operator-specified Vault keyset/mount. Sources: `services/covercrypt_config.py`, `views/covercrypt.py`, `urls/admin.py`, `management/commands/covercrypt_config.py`.
- CoverCrypt maps user attributes as `dimension::value` and compiles a bounded ABAC AST subset in `AccessPolicy._generate_covercrypt_policy`: equality, membership, `and`, `or`, and parentheses. It rejects negative comparisons because missing-attribute semantics differ, and rejects ordering/chained/unconfigured expressions. Sources: `models/policy.py`, `services/cpabe_service.py`, `serializers/policy.py`.
- `services/abe_schemes.py` centrally validates `ac17`, `tkn20`, and `covercrypt` on native and Vault backends. CoverCrypt user keys use validated `dimension::value` attributes; Vault uses `abe_covercrypt` and sends `config_json` only to setup, while native uses upstream scheme-aware buffer APIs and a temporary DB-derived config file. Native CoverCrypt MSK/PQC signing material is persisted only in Vault KV, never local backup. Per-version metadata validates the ciphertext v2 scheme tag; historical CoverCrypt versions without metadata fail closed because the header does not encode signature mode. User-key cache identity includes the verified CoverCrypt config/public-key fingerprint. Sources: `services/abe_schemes.py`, `services/cpabe_service.py`, `views/storage.py`, `services/version_crypto.py`.
- `USE_VAULT_ABE_PLUGIN=False`, `CPABE_SCHEME=ac17`, `ENABLE_PQC_FEATURES=True` là defaults trong `settings/base.py`; `.env.example` cũng chọn plugin False/scheme AC17. Plugin mode 3.0 dùng hai mount `abe_ac17/`, `abe_tkn20/`, KV keys `CPABE_PK_AC17`, `CPABE_PK_TKN20` và endpoint `/v1/abe_{scheme}/setup|genkey|encrypt|decrypt`. Release 3.0 mô tả file mới mặc định TKN20 nhưng điều đó phụ thuộc cấu hình thực tế; không giả định native ctypes hỗ trợ TKN20 tương đương plugin. Nguồn: `scripts/vault_manager.py`, `services/cpabe_service.py`.
- Native service dùng tên `cpabe_pk.key`, `cpabe_msk.key`, `pqc_pk.key`, `pqc_sk.key`, với working keys ở `BASE_DIR/config/keys` và nhánh backup theo `KEYS_DIR`. Có code tạo/backup khóa và API file-based cũ; README không phải mô tả đầy đủ vòng đời khóa.
- Encrypted fields dùng AES-GCM, HKDF-SHA3-256 và blind index HMAC-SHA3-256. Key lookup ưu tiên Vault rồi `MASTER_FIELD_ENCRYPTION_KEY`; bật/tắt qua `FIELD_ENCRYPTION`. Nguồn: `models/fields.py`, `settings/base.py`.
- Factory nhận chính xác `supabase` (default), `aws_s3`, `google_cloud_storage`, `local_disk`; giá trị không nhận diện fallback Supabase. Instance storage là singleton. Nguồn: `services/storage/factory.py` và `adapters/`.
- Frontend có liboqs JS/WASM và Argon2 assets; metadata version chứa user signature, timestamp và system signature. Chưa xác minh end-to-end cơ chế ký/verify chỉ bằng sự hiện diện của các trường này.
- Khóa ký ML-DSA của người dùng khác khóa giải mã CP-ABE backend: `pqc-manager.js` triển khai sinh khóa WASM, dùng WebAuthn PRF để mở blob secret key mã hóa và hỗ trợ recovery qua Argon2; thời gian tự khóa là 30 phút không hoạt động. Biometric/PIN mở khóa ký chứ không trực tiếp tạo chữ ký tài liệu. Không suy ra mọi passkey provider/browser đều hỗ trợ PRF từ bảng tương thích trong release note.

## AI Policy Assistant trong 3.0

- Routes: `GET /api/admin/ai/status/`, `POST /api/admin/ai/generate-policy/`. Cả hai yêu cầu `IsAuthenticated` và `IsSuperAdmin`; payload sinh policy có trường `prompt`. Nguồn: `urls/admin.py`, `views/ai_assistant.py` dưới `src/crypto_access/`.
- Service gửi schema thuộc tính/user types lấy từ DB (cache 300 giây), system prompt trong `src/config/prompts/ai_policy_system.md` và prompt người dùng tới Ollama `/api/chat`. Dùng JSON output schema, temperature 0.1; timeout default 120 giây và keep-alive default `-1`, hiện có thể chỉnh qua System Settings. Singleton đọc endpoint/model/feature flag/timeout động thay vì cố định lúc import. Nguồn: `services/ai_policy_service.py`, `services/runtime_settings.py`.
- Endpoint trả đề xuất gồm condition, CP-ABE policy, resources/action/effect, name/description/priority/explanation và validation; không gọi save để tự tạo `AccessPolicy`. Validation hiện parse AST và thử `_generate_cpabe_policy`, không chứng minh đề xuất đúng ý định/quyền trên dữ liệu thực tế.
- Thiết kế release dùng LLM local; service thực tế gửi đến `OLLAMA_BASE_URL` cấu hình. Cần xác nhận URL triển khai trước khi khẳng định dữ liệu không rời hệ thống.

## Cấu hình và hạ tầng

- Cấu hình runtime hiện quản lý tại **System → System Settings**, chỉ dành cho super_admin active. Catalog hiện có 21 giá trị thường và 1 mật khẩu SMTP; `SUPER_ADMIN_REQUIRE_POLICY` điều khiển bypass document. Chi tiết triển khai/kiểm chứng nằm trong các task ngày 2026-10-25 bên dưới và `docs/vi/runtime-settings.md`.

- `BASE_DIR` là `src/`; `PROJECT_ROOT` là root repo. `settings/base.py` load `.env` ở root. Dùng `.env.example` làm mẫu, không đọc/chia sẻ secret thật để viết tài liệu.
- `manage.py` mặc định dùng `config.settings`; package này chọn theo `DJANGO_ENV` (default development). Development dùng `DATABASE_URL` nếu có, nếu không dùng SQLite `src/db.sqlite3`.
- Production yêu cầu `DJANGO_SECRET_KEY`, `DJANGO_ALLOWED_HOSTS`, `DATABASE_URL`. Không mặc định DB là Supabase: `.env.example` dùng SQLite URL cho container; Compose còn có PostgreSQL tùy cấu hình. Production dùng Redis khi có `REDIS_URL`, nếu không fallback locmem. Nguồn: `settings/production.py`.
- Với PostgreSQL, `DB_REQUIRE_SSL` default True; URL có `sslmode=disable`/`sslmode=require` override quyết định SSL. Biến này điều khiển kết nối DB, không tắt TLS các service khác. Nguồn: `settings/production.py`.
- Biến quan trọng khác: `STORAGE_VENDOR`, credentials backend tương ứng, `VAULT_ADDR`, `VAULT_SECRET_PATH`, `VAULT_TOKEN`/token file, `VAULT_CACERT`, `KEYS_DIR`, `MASTER_FIELD_ENCRYPTION_KEY`, `FIELD_ENCRYPTION`, `ENABLE_PQC_FEATURES`, `USE_VAULT_ABE_PLUGIN`, `CPABE_SCHEME`, `WEBAUTHN_*`, `PKI_SIGNER_URL`, `PKI_AUTH_TOKEN`, `AI_FEATURES_ENABLED`, `OLLAMA_*`. Không dùng giá trị mẫu làm cấu hình production.
- `start.py` mặc định chọn `docker/docker-compose.yml`; `--prod` chọn `docker-compose.prod.yml`. Cả hai đặt `DJANGO_SETTINGS_MODULE=config.settings.production` cho web, vì vậy “dev Compose” không đồng nghĩa Django development settings.
- Mạng `app-network` dùng `DOCKER_IPV4_SUBNET` (default `172.30.0.0/16`), IPv6 `fd00:dead:beef::/48`, trong cả hai Compose. Chẩn đoán lỗi subnet trùng nằm ở task Docker network ngày 2026-10-25 bên dưới.
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
| `build` | Compose build fetches/builds upstream crypto Git HEAD; prod first runs pull --ignore-buildable. Web/Vault use targets in the same Dockerfile; prod uses local images. |
| `up`, `restart` | Compose up -d/restart, gọi Vault manager tối đa 10 lần với khoảng chờ 2 giây khi subprocess lỗi, trích xuất raw PQC root public key nếu cần, gọi warmup nếu `--ai`; có thể mở UDP6 relay trên Windows khi VPN IPv6/dual. |
| `down` | Dừng UDP6 relay rồi Compose down; nhánh này không truyền `-v`. |
| `logs` | Compose logs -f cho stack; không chuyển tiếp đối số service/filter từ `rest`. |
| `makemigrations`, `migrate`, `initsettings` | Chạy manage.py trong service `web`, chuyển tiếp đối số; `initsettings` gọi `init_settings`. |
| `initdata` | Vault manager → migrate → init_data.py → seed_policies → seed_test_data → trích xuất public key, warmup nếu bật; in thông tin tài khoản khởi tạo ra terminal. |
| `createsuperuser`, `shell`, `collectstatic` | Lần lượt gọi management command riêng `create_super_admin`, Django shell, collectstatic --noinput trong `web`. |
| `update` | git pull --ff-only → prod pull --ignore-buildable, if selected → Compose build with latest upstream Git HEAD → up -d → Vault manager/public key/warmup. Build failures stop before recreation; no release ZIP downloads or local plugin source overwrites. |
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
- `docker/Dockerfile` configures the upstream URL through `CRYPTO_REPOSITORY`. BuildKit resolves Git HEAD and caches by commit; no revision is hardcoded. `docker/build-crypto.sh` checks tracked source matches HEAD and calls the original upstream Makefile without patches/source rewrites. Both artifacts come from one checkout; `source.env` records repository, commit, version and `CRYPTO_CPQA_PATCHES=none`. Toolchains: Go 1.25.7/Rust 1.89.0 with Cargo/Go caches. The separate local library checkout is inspected read-only, not used as an implicit runtime/build dependency.
- `docker/vault/entrypoint.sh` refreshes executable/.so artifacts in the plugin volume on every start without touching Vault data/keys. Web reads that executable to register its SHA256. The web native library lives outside `/app`; the anonymous `/app/lib` volume was removed. Instructions: `docs/en/crypto-source-build.md`, `docs/vi/crypto-source-build.md`.
- Upstream v6.0.0 includes native and Vault CoverCrypt. Native scheme selection is `CPABE_SCHEME_COVERCRYPT=2`; native setup reads `HCPABE_COVERCRYPT_CONFIG` and mode from process environment. Vault setup takes inline JSON and mode. Vault `setup` replaces the mount authority and is not idempotent; `add_dimension` grows an existing CoverCrypt authority. CPQA upload, keygen, re-encryption, preview, and download now dispatch CoverCrypt through the recorded file-version scheme. Contract details and safe fixtures: `docs/en/covercrypt-vault-contract.md`, `docs/vi/covercrypt-vault-contract.md`, `tests/fixtures/covercrypt-vault-contract/`.
- `rebuild` tạo lại Compose command mà không truyền `use_ai`, nên profile AI có thể thiếu dù CLI nhận `--ai`. Các điểm lệch CLI nêu trên là quan sát tĩnh cần xác minh/sửa trong nhiệm vụ riêng; lần cập nhật tài liệu này không chạy updater, unseal, seed hay xóa volume.

## Kiểm thử, build và điểm cần kiểm chứng

- Test Django legacy nằm trong `src/crypto_access/tests.py`, chủ yếu health/profile; regression R01/R02 nằm riêng trong `src/security_tests/`. Chưa có độ bao phủ đầy đủ các luồng quyền/mật mã/storage còn lại.
- `src/pytest.ini` dùng header `[tool:pytest]` dù là file `.ini`, và `testpaths = crypto_access/tests` trong khi app có `tests.py`. Cần kiểm tra collection/config trước khi tin kết quả `pytest`; đừng suy ra không có lỗi từ việc không thu thập test.
- `src/tests/` chứa script thử nghiệm có `django.setup()`, đường dẫn Windows cũ, phụ thuộc user/policy đã seed, import module cũ; `test_hybrid.py` sửa policy ngay khi import, `test_assign_policy.py` có code upload dữ liệu. Không chạy chúng với DB/storage thật hoặc gom tất cả bằng pytest mà chưa xem tác dụng phụ.
- Lệnh kiểm tra có thể dùng sau khi cô lập môi trường được liệt kê trong `AGENTS.md`. Các kiểm tra đã chạy được ghi trong mục **Các task đã hoàn thành theo ngày** bên dưới; chưa build lại crypto hoặc chạy toàn bộ pytest legacy.
- Cache key trong `signals.get_cache_key_id` thiếu thành phần scheme so với `_decrypt_file_if_needed`; đây là điểm cần kiểm tra khi sửa revocation/cache, chưa xác nhận mức ảnh hưởng runtime.
- `src/theme/static_src/package-lock.json` đang được Git theo dõi dù `.gitignore` có rule `package-lock.json`; Docker dùng `npm ci`. Đừng xóa lockfile vì tưởng là file sinh không được quản lý.
- `scripts/build_plugin_for_docker.ps1` and `.sh` export target `crypto-artifacts` to `build/crypto/`, including the native `.so`, plugin, and source manifest. `crypto-test` runs upstream native/Go backend tests in an isolated build container and exports only a success marker.
- `.github/workflows/docker.yml` builds/pushes web and Vault on `v*` tags using the shared Dockerfile/upstream Git source, web/vault targets, Linux AMD64, app `VERSION`, and the `latest` alias. Production Compose builds local images `cpqa-web:local` and `cpqa-vault:local`.
- README nêu yêu cầu trình duyệt PQ TLS cụ thể; đây là tuyên bố của tài liệu, chưa kiểm tra tương thích trình duyệt/cert/handshake. Khi xử lý kết nối, xem `nginx/`, cert thực tế và log thay vì coi số version browser trong README là bảo đảm.

## Các task đã hoàn thành theo ngày

### 2026-10-25

Các mốc 23 → 38 → 67 → 87 test là kết quả tại thời điểm hoàn thành từng nhóm công việc, không phải các tổng hiện tại khác nhau. Mốc mới nhất ở task strict SuperAdmin: **87 test `security_tests` đã qua**; 9 test Vault manager thuộc bộ riêng.

#### 01. Tài liệu bàn giao và đối chiếu release 3.0

- Tạo `AGENTS.md` hướng dẫn làm việc và `FACTS.md` làm bản đồ dự án cho AI tiếp theo. Đối chiếu `VERSION`, bốn release note 2.1.0 → 2.2.0 → 2.3.0 → 3.0.0 và `start.py`; baseline ứng dụng là 3.0.0. Bảng lịch sử release và phân tích CLI ở phần kiến thức nền phía trên.

#### 02. Rà soát chuẩn bị release 3.1

- Backlog kiểm tra chuẩn bị 3.1 ở `docs/vi/release-3.1-readiness.md`, gồm kết quả kiểm tra cô lập và thứ tự ưu tiên sửa. Các mục trong đó chưa được coi là đã khắc phục nếu chưa có thay đổi/test tương ứng.

#### 03. Sửa lỗi Docker network trùng subnet

- Cả hai Compose dùng `DOCKER_IPV4_SUBNET` cho mạng `app-network`, default `172.30.0.0/16`; subnet IPv6 là `fd00:dead:beef::/48`. Dải IPv4 cũ `172.20.0.0/16` trùng mạng `pti-portal_default` trên máy phát triển và làm Docker báo `Pool overlaps`. Khi đổi subnet, đối chiếu mạng Docker và LAN/VPN hiện có; không xóa mạng của dự án khác để khắc phục.

#### 04. Khôi phục Nginx và truy cập ứng dụng

- Nginx từng mất network attachment; đã tạo lại riêng container và xác nhận proxy tới `/auth/login/` trả 200 qua HTTP nội bộ. Sau khi MISP dừng, cấu hình local quay về cổng 80/443.

#### 05. Sửa vòng đời Vault và reset môi trường test

- Vault cũ từng yêu cầu 3/5 shares trong khi file mount chỉ có 1; sau đó người dùng cho phép reset toàn bộ app test. Đã xóa container/volume thuộc riêng project, xóa hai file unseal/token cũ rồi khởi tạo Vault/DB mới theo chế độ dev; Vault mới unsealed/active, mount AC17/TKN20 thành công. Không lưu key/token trong tài liệu.

- Sau reset test: migrate/initdata thành công, seed 10 policies và 5 test users cùng super admin; login API qua Nginx trả 200 và cấp cookie, logout phiên kiểm tra trả 200, ClamAV healthy. Local `.env` đặt `GUNICORN_CMD_ARGS=--workers 3` vì cấu hình CPU-count trước đó mở khoảng 40 worker và backend restart trong lúc init (tiến trình init bị kết thúc mã 137; chưa kết luận OOM bằng container flag). File Supabase không bị xóa; reset chỉ xóa DB/trạng thái Vault và storage volume cục bộ. Đây là kiểm tra luồng auth/vận hành, không chứng minh luồng crypto/file đã qua integration test.

- `tests/test_vault_manager.py` có 9 test cô lập cho partial/duplicate shares, trạng thái unsealed, readiness/retry và lỗi KV. Chạy `rtk python -m unittest discover -s tests -p test_vault_manager.py -v`; đã qua cả 9 test. Chạy manager thật với file hiện tại xác nhận dừng ở 1/3 với exit code 1, không báo thành công giả.

#### 06. R01 — Quyền tạo global policy từ upload/assign

- R01 đã sửa trong `views/storage.py` và `serializers/storage.py`: inline global policy ở cả upload/assign-policy yêu cầu `IsSuperAdmin` và ABAC `policy/*`, dùng validation của `AccessPolicySerializer`. Owner/admin chỉ có quyền gán file không tự được quyền tạo global policy. Assign kiểm tra target trước mọi write; upload chỉ lưu policy ở bước ghi metadata sau quét/mã hóa/upload. Hai endpoint dùng DB transaction, rollback khi xử lý file thất bại; từ chối chọn vừa policy_id vừa create_new_policy và bỏ đường tạo policy bằng name-only cũ. DB rollback không bao gồm rollback blob của dịch vụ storage; cleanup blob khi lỗi vẫn là phạm vi riêng.

#### 07. R02 — Giới hạn đường dẫn local storage

- R02 đã sửa ở `services/storage/adapters/local.py`: bucket phải là tên đơn hợp lệ; mọi path được resolve và giới hạn trong bucket thuộc MEDIA_ROOT. Adapter từ chối absolute/drive-relative/UNC path, parent/dot segment, backslash, ADS, NUL, symlink/junction và tên không an toàn trên Windows (device name, đuôi dấu chấm/khoảng trắng). List không trả entry symlink; batch delete kiểm tra toàn bộ path trước khi xóa. Đây là kiểm tra ranh giới path; storage root vẫn cần thuộc quyền quản lý của backend, không phải cơ chế chống mọi race từ tiến trình OS khác có quyền sửa filesystem.

- `src/security_tests/` có 23 regression test R01/R02 đã qua trong Linux container. Settings riêng dùng SQLite in-memory, locmem cache, key/media/BASE_DIR trong thư mục tạm, tắt kết nối Vault và mock native crypto/ClamAV/cloud storage. Chạy trong `src/` hoặc `/app`: `rtk python -m django test security_tests --settings=security_tests.settings --noinput`. Với stack test đang chạy: `rtk docker exec django_app python -m django test security_tests --settings=security_tests.settings --noinput`. Tests kiểm tra API thật qua DRF, DB rollback, local adapter với filesystem tạm và symlink thật; Windows path syntax được kiểm tra trên Linux, chưa chạy junction test trên Windows host. Không chạy migration lịch sử hoặc full end-to-end crypto trong suite này.

#### 08. Sửa bypass và keygen TKN20

- Đã sửa bypass TKN20 trong `views/storage.py`, `services/tkn20_policy.py` và `services/cpabe_service.py`. TKN20 Go bridge dùng map một value/label; bypass cũ cộng cả user_type super_admin/data_owner rồi đưa qua set khiến value cuối bị ghi đè ngẫu nhiên. Bypass hiện chọn một assignment nhất quán với policy and/or/not, chỉ áp dụng khi superuser hoặc owner; không sửa thuộc tính DB hay giả lập thuộc tính cho user thường. Cache dùng namespace `cpabe_key_tkn20_bypass_v2_*` để tránh khóa sai cũ.

- Keygen TKN20 hiện chuẩn hóa label/value, từ chối nhiều value xung đột cho cùng label, không mở rộng role/clearance thành nhiều value cùng label như AC17. AC17 vẫn giữ hierarchy expansion. Không suy ra TKN20 hỗ trợ mọi policy nhiều giá trị của AC17; điều kiện đồng thời yêu cầu hai value khác nhau cho một label không có assignment hợp lệ và bị từ chối.

- Ở mốc hoàn thành task này, suite thêm 15 test bypass/keygen TKN20, tổng 38 test. Đã kiểm tra trực tiếp plugin bằng dữ liệu giả trong RAM: cùng policy user_type:data_owner, thứ tự admin→owner giải mã được nhưng owner→admin bị 500 trước sửa, xác nhận lỗi duplicate label. File người dùng báo lỗi được upload sau reset nên không phải ciphertext dùng master key cũ. Sau sửa đã đăng nhập qua Nginx và preview đúng `01_core_buffer_vs_charm.png`: HTTP 200, Content-Type image/png, PNG signature hợp lệ; logout phiên kiểm tra. Không viết lại blob, policy hoặc master key của file.

#### 09. Thêm trang System Settings cho super_admin

- Trang **System → System Settings**, GET/POST `/manage/settings/`, chỉ dành cho user active có profile `super_admin` còn hiệu lực. Có CSRF, cache-control no-store, revision ký/row lock chống tab cũ ghi đè và audit trong cùng transaction DB. Không có editor tùy ý `.env` hay `SystemSetting`. Nguồn: `views/system_settings.py`, `urls/admin_pages.py`, `templates/admin/system_settings.html`.

#### 10. Mở rộng cấu hình UI, SMTP/Vault và giới hạn vận hành

- Catalog runtime quản lý 20 giá trị thường và 1 mật khẩu SMTP ở mốc hoàn thành task này: tên passkey, email/SMTP/TLS/timeout, endpoint/model/feature/keep-alive/timeout AI, max upload/timeout scanner/rate upload-download và ngưỡng login/OTP đổi IP. Save lần đầu chốt cả những giá trị đang lấy từ deployment vào DB; GET không seed. Ưu tiên DB active → deployment/default. Phân loại đầy đủ biến được giữ/chuyển: `docs/vi/runtime-settings.md`; validation chung: `services/runtime_settings.py`.

- Mật khẩu SMTP nhập trên UI là write-only, lưu Vault KV v2 tại path UUID riêng; DB chỉ giữ `_SMTP_PASSWORD_REFERENCE`, audit dùng marker redacted. Không có reference thì dùng mật khẩu deployment; reference có nhưng Vault lỗi thì không fallback cũ. DB rollback có thể để lại secret mới chưa được tham chiếu trong Vault; không tự xóa lịch sử secret. Nguồn: `services/runtime_secrets.py`, `services/email_backend.py`.

- Cả development/production dùng `RuntimeEmailBackend`, chọn console theo mặc định development và SMTP theo mặc định production; UI có thể override. Nút Test SMTP chỉ kết nối/TLS/login, không gửi mail. Hạ tầng DB/Redis/Vault/storage, crypto flags/trust roots, RP ID/origin và Compose/VPN/tunnel vẫn ở deployment. SMTP và AI endpoint có thể đổi qua UI, chứng chỉ trust vẫn ở deployment.

- Cache SystemSetting TTL 300 giây, invalidation chạy sau commit bằng post-save/post-delete. Redis chung đồng bộ invalidation giữa worker; locmem nhiều worker có thể giữ giá trị cũ tới TTL. `throttles.py` đọc runtime limits và `views/storage.py` gắn throttle bằng kwargs của `@action`, đã kiểm tra router trả 429 khi vượt mức. UI upload dùng cùng giới hạn với serializer; trang file đã mở cần reload để lấy giá trị mới.

- Kiểm chứng phần runtime settings: tổng **67 test** trong `security_tests` đã qua ở container với DB/cache/keys cô lập (38 regression cũ và 29 test cấu hình mới); Django system check và Tailwind production build thành công. Đã mở trang HTTPS bằng browser với super_admin và xác nhận liên kết trong menu System. SMTP/Vault credential I/O dùng mock trong test, chưa gửi email thật hoặc thay mật khẩu SMTP triển khai để thử.

#### 11. Công tắc strict SuperAdmin và tra cứu policy bằng blind index

- `SUPER_ADMIN_REQUIRE_POLICY` default False, thuộc nhóm Document access. True buộc super_admin/Django superuser qua general ABAC + policy file/folder, không dùng owner/grant bypass; browse/list tôn trọng deny priority, preview/download kiểm tra trước storage. AC17/TKN20 chỉ sinh khóa từ thuộc tính thật và cache namespace `strict_v1`, không tái dùng khóa giả lập thuộc tính. Flag đọc DB trực tiếp để tránh cache cũ; invalid active value xử lý strict. Control plane/settings và quyền owner thông thường giữ nguyên. Nguồn: `services/document_access.py`, `casbin_service.py`, `views/storage.py`, `middleware/abac_middleware.py`.

- `UploadedFile.find_by_path` dùng blind index khi bật field encryption; view lookup, file policy lookup và granted-user lookup dùng chung helper. Điều này sửa trường hợp mất policy riêng vì so sánh plaintext với cột path mã hóa. Strict chặn path không tìm được record và lọc từng file bằng evaluator trước pagination; chưa đo hiệu năng tập dữ liệu lớn. Nguồn: `models/storage.py`, `views/storage.py`.

- Sau bổ sung strict SuperAdmin, tổng **87 test security_tests** đã qua (thêm 20 regression), gồm AC17/TKN20/cache riêng, metadata mã hóa với key test thật, policy kế thừa/deny priority/inactive, owner/grant, plaintext, path không đăng ký và bật/tắt qua form mà không khóa trang settings. `makemigrations --check --dry-run` không có thay đổi schema. Native/Vault crypto trong test giải mã vẫn được mock; không xem đây là integration test mật mã.

### 2026-11-01

#### Build upstream crypto source in Docker

- Removed 261 obsolete vendored files, including native binaries, plugin source, and dependency headers/archives. `docker/Dockerfile` now fetches upstream Git HEAD and shares one crypto build across web/Vault targets. No source tag, commit, or version is hardcoded. BuildKit resolves HEAD again before using cache; an unchanged-source web rebuild completed in about 8 seconds on the development machine.
- Verified web/Vault image builds, native ctypes loading (version 6.0.0), 54 upstream CLI tests plus C++ CoverCrypt/API tests, and all seven Go backend tests, including legacy authority reads. `tests/smoke_crypto_image.py` passed signed/unsigned HTTP allow/deny checks for AC17, TKN20, and CoverCrypt, and stale plugin artifact replacement, against a disposable Vault container. Four isolated CLI update/build tests passed in `tests/test_crypto_build.py`.
- Development/production Compose configurations passed validation, including the no-external-TLS overrides; removed the web dependency on profile-only nginx and the no-TLS override's development-only Redis service name. `git diff --check` passed. Existing deployment services, keys, databases, and volumes were not changed; existing deployment ciphertext compatibility and full Django/storage/ClamAV integration were not tested.
- CoverCrypt is built in both the upstream native library and Vault plugin, and CPQA now has application-level scheme dispatch, metadata checks, configuration-bound user-key caching, and native/Vault key operations. The original build instructions are paired under `docs/en/crypto-source-build.md` and `docs/vi/crypto-source-build.md`; contract and integration planning are in the paired CoverCrypt guides. Root/module READMEs link to the build instructions. Documentation language/location conventions are recorded in `AGENTS.md`.

### 2026-11-06

#### CoverCrypt upstream contract review

- Read the local upstream v6.0.0 source, public header, Vault plugin, build Makefile, READMEs, release notes, and existing plugin tests. The built Windows DLL reports `6.0.0` and exports generic native scheme-selecting setup/keygen/encrypt/decrypt APIs; its explicit JSON setup helper is not exported, so native setup uses `HCPABE_COVERCRYPT_CONFIG` and `HCPABE_COVERCRYPT_MODE`. Source references: upstream `include/hybrid_pq_cp_abe/cpabe-scheme.h`, `include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h`, `src/core/abe-setup.cpp`, `src/schemes/covercrypt.cpp`, `plugins/vault/vault-plugin-abe/plugin/`.
- Recorded Vault setup/genkey/encrypt/decrypt payloads, Base64 transport, dimension schema, policy and attribute syntax, modes, error categories, v2 scheme indicator, and the separation between CoverCrypt KEM mode and optional ML-DSA signatures in paired `docs/{en,vi}/covercrypt-vault-contract.md`. Setup unconditionally replaces stored authority; do not call it as an idempotent initializer. No explicit maximum dimension/attribute count was found in the inspected Rust bridge.
- The upstream root README, Vault README, binding README, and v6.0.0 release notes already document native and plugin CoverCrypt, so no upstream source documentation edit was needed. Added sanitized request/response and invalid-request fixture templates in `tests/fixtures/covercrypt-vault-contract/`; fixture JSON and Base64 sentinels parsed successfully.
- Corrected the source-build guide during the initial contract review to distinguish upstream native/plugin support from CPQA application integration as it stood then. The upstream repo's `.git` status could not be read due filesystem permission; no upstream files were changed. No upstream build or tests were rerun for that review; the inspected DLL version and exports were checked directly.

#### Fix large CoverCrypt Vault authority writes

Historical implementation, superseded by the upstream-only correction below. The application-owned patch was removed; the storage issue requires an upstream solution.

- The reported setup error was Vault rejecting a 143,631,590-byte value at the 1 MiB per-value limit. Added a build-time patch to split large serialized authority state into immutable 768 KiB chunks and a checksummed manifest, committed only after all chunks are stored; legacy single-record state remains readable. Chunk operations stay under the existing `msk/` seal-wrapped prefix. Old chunk generations are retained after switching manifests to avoid races with in-flight readers.
- Docker verifies the patch applies to the fetched upstream HEAD before building; incompatibility fails the image build. Paired Vault-contract and source-build guides document this behavior and the guarded recovery command for this failed first setup. Verified patch application against upstream HEAD `12b86f7b9b1133391f8bf2ac25b13dea4af746e6`, ran `gofmt` and Python compilation, and successfully built web/Vault Docker images. The stack was not restarted and live Vault setup was not retried; deployment data and keys remain untouched.

### 2026-11-08

#### CoverCrypt public-key request limit and interrupted metadata recovery

Historical implementation, superseded by the upstream-only correction below. Private reference/recovery endpoints were removed from the app contract; previous patched-authority data must not be silently loaded by an unmodified plugin.

- The active six-dimension schema (cardinalities 4/3/6/4/5/6) produced a 35,952,472-byte native public key, or 47,936,632 bytes in Base64. Writing this value through `VaultService.put_secret` exceeds Vault's default 33,554,432-byte HTTP request limit. Reproduced the failed write with a synthetic same-size payload against a disposable Vault; live setup had already committed the authority before the KV write failed. The previous authority-chunk patch solves plugin storage size, not this public-key HTTP/KV boundary.
- Added `docker/patches/vault-covercrypt-public-reference.patch`, applied after authority chunking. CoverCrypt public responses now return an 87-character `vault-authority-sha256:<digest>` reference; encrypt validates it against the actual stored public key before native crypto. `GET /abe_covercrypt/authority` reads existing public metadata without replacing keys or exposing MSK/signing secrets. AC17/TKN20 public responses and legacy Base64 encrypt requests remain supported. Build records the additional patch checksum in `source.env`. Sources: `docker/build-crypto.sh`, `docker/Dockerfile`, paired `docs/{en,vi}/covercrypt-vault-contract.md`.
- `services/covercrypt_public_key.py` validates legacy Base64 keys/references and their fingerprints. `services/cpabe_service.py` persists the compact reference and can reconcile an interrupted first setup through the read-only authority endpoint only when the guard, active configuration, provisioning marker, mode, public-key fingerprint and signing state agree. Missing endpoints, absent authority or mismatches fail closed without retrying setup. Existing authorities and ciphertext were not reset during this fix.
- Verified web/Vault source builds, 54 upstream native CLI checks, all eight Go backend test groups, and disposable HTTP smoke tests for signed/unsigned AC17/TKN20/CoverCrypt plus the large six-dimension CoverCrypt case. Twelve isolated Python regression tests for references/recovery/cache identity pass. Four CLI build/update tests pass. The full Python suite run at the nine-new-test stage ran 126 tests with two pre-existing fixture failures: undeclared `finance` in the CoverCrypt compiler positive case, and missing `is_new_version` in the AC17/TKN20 upload-version case. These were not changed.
- Updated the local web/Vault images after registering their matching plugin checksum, unsealed with existing shares, and recovered the original authority's metadata. A guarded live crypto probe prohibited every `/setup` call and confirmed unchanged authority reference/revision, signed decrypt allow and wrong-key deny. A separate DRF upload probe returned 201 with real ClamAV/Supabase and a signed CoverCrypt round trip; its synthetic blob was deleted and its DB writes rolled back. This does not verify browser WebAuthn/user signatures or grant missing user attributes. Web health returned 200.

#### CoverCrypt concurrent initialization and KV metadata writes

- `services/vault_service.py` now uses KV v2 revision CAS for merges, with at most eight retries for CAS conflicts only. Related fields can be committed atomically with `put_secrets`; `claim_secret` grants one durable initialization owner without lease expiry. Deleted/destroyed records and unavailable reads fail closed. CoverCrypt state bypasses per-worker caches and supports a fresh multi-field snapshot. Missing-path detection also requires KV metadata read capability; application code does not broaden deployment ACLs.
- Both native and plugin CoverCrypt acquire the guard through CAS before setup and publish their complete keyset metadata/initialized marker in one revision. Plugin recovery only reads an existing authority. Sources: `services/cpabe_service.py`, paired Vault contract guides. No master keys, ciphertext formats or authority data were reset for this change.
- Regression tests reproduced lost concurrent writes and stale worker cache before the fix. The final isolated suite passes **139/139 tests**, including 22 keyset/CAS tests. Against a disposable real Vault, eight independent processes preserved all eight concurrent updates and exactly one acquired an initialization guard; the fixture record/container were cleaned up. Fixed two existing test fixtures (undeclared `finance`, missing new-version flag); the latter exposed a real duplicate policy-link failure on repeated upload, fixed with `get_or_create` while preserving rollback regression coverage. Sources: `security_tests/test_vault_concurrency.py`, `test_covercrypt_vault_keyset.py`, `test_covercrypt_configuration.py`, `test_version_crypto.py`, `test_policy_creation.py`, `views/storage.py`.
- Rebuilt/recreated the local web service with the Python fixes; no Vault reset or plugin change was needed. Live signed crypto allow/deny passed with every setup request prohibited and authority reference/revision unchanged. DRF uploads of a synthetic file and its second version using the same policy both returned 201 through real ClamAV/Supabase, retaining two versions and one policy link. Diagnostic blobs were deleted, DB writes rolled back, and health returned 200.

#### CoverCrypt non-strict document bypass

- Fixed CoverCrypt reads that incorrectly sent incomplete real administrator attributes to keygen despite an enabled non-strict bypass. `services/covercrypt_policy.py` validates and parses dimension-qualified positive Boolean policies against the active schema, performs bounded backtracking for one consistent value per dimension, and completes unconstrained dimensions deterministically. It neither authorizes users nor writes their attributes/policies. Contradictory/unconfigured/unsupported or excessive expressions fail closed.
- `views/storage.py` only invokes this assignment for an already-permitted non-strict administrator/owner bypass. Strict administrators, including owners, still require document authorization and real attributes; ordinary users have no new bypass. CoverCrypt bypass keys use `covercrypt_bypass_v1`, separate from strict/ordinary caches and bound to the assignment, user, authority/config fingerprint and backend. Existing signature verification remains mandatory for signed versions.
- Added 15 regression tests covering the actual mapper, superuser/profile-admin/owner behavior, ordinary-user denial, strict denial before cached-key use, strict cache isolation, parser validation, contradictory policies, OR backtracking and resource bounds. Full isolated suite: **154/154 passed**. Verified the reported existing PDF through the preview view using the actual SuperAdmin and unchanged runtime flag: HTTP 200/application/pdf, with contents suppressed from tool output. No DB attribute/policy or ciphertext changes were made. Sources: `security_tests/test_covercrypt_bypass.py`, paired configuration-lifecycle guides.

#### Restore the upstream-only library boundary

- Removed the authority-chunk, public-reference and unfinished version-metadata patches from Docker build/source. The build checks tracked upstream source matches HEAD before using its Makefile and records `CRYPTO_CPQA_PATCHES=none`. A CLI regression test prevents reintroducing a patch build path. The local `Hybrid-CP-ABE-Library` checkout remains unchanged (`git status --short` clean).
- CPQA accepts actual Base64 public keys and rejects the old private reference format. It does not call an invented authority endpoint, send an unsupported `sign` flag, or require a `crypto_metadata` response. Version metadata remains an application record derived from the envelope and known authority signing state. Incomplete initialization fails closed without repeating setup; oversized public keys are rejected before KV writes with an explicit upstream-update requirement. CAS, atomic app metadata writes, bounded document bypass and upload-version fixes remain in place.
- Withdrew unfinished stages 6–9 changes that depended on a private library contract. Detailed blockers and safe treatment of existing patched test authorities are recorded in paired `covercrypt-upstream-requirements.md` guides. The correction does not reset authorities, export MSKs, convert custom persisted state or replace the running patched plugin over its data volume.
- Isolated Python regression: **158/158 passed**. CLI/build regression: **5/5 passed**. The separate unmodified-source `vault` and `crypto-test` Docker targets built successfully, including upstream native and Go tests. Disposable HTTP smoke checks passed signed/unsigned allow/deny for AC17, TKN20 and small-configuration CoverCrypt, plus stale plugin replacement. The generated manifest records upstream version `6.0.0`, resolved commit `9b95b9a63069acf67bb27157f328b3981de55c6e` and `CRYPTO_CPQA_PATCHES=none`; the commit is an observed build result, not a build pin. No claim is made that production-sized CoverCrypt works with the inspected original upstream storage/transport.

### 2026-11-14

#### Adopt upstream Vault authority contract v1 in CPQA

- `services/cpabe_service.py` and `services/vault_abe_contract.py` check Vault setup capabilities before claiming first initialization, send `create_only=true`, and verify authority identity before reconciling public KV metadata. The `covercrypt_config` command supports read-only checks and public metadata reconciliation. Recovery retains an interrupted initialization guard when Vault cannot return the authority.
- `services/version_crypto.py` validates upstream encryption metadata against the payload header and the requested authority. New Vault versions use JSON schema 2 with signature mode, keyset fingerprint and revision. `views/storage.py` verifies authority identity before using the user-key cache for these versions.
- The disposable Vault image was built from upstream commit `a75c50eee4cb00bebb95452a311a36ed292b6ce5`. Its manifest records native version `6.0.0` and `CRYPTO_CPQA_PATCHES=none`. `tests/smoke_crypto_image.py` passed signed and unsigned allow/deny for all three schemes.
- The isolated Django suite passed 163 tests. The four opt-in tests skipped in that run passed separately with `tests/smoke_vault_contract.py` on a fresh single-node Raft Vault. They exercise six signed and unsigned versions across the three schemes, historical downloads, copy, policy assignment, public metadata recovery, wrong-key rejection and an outage before storage writes. The runner uses a small CoverCrypt schema, SQLite, an in-memory blob store and a scan stub. Existing deployment ciphertext, cloud storage and live rollout are outside that verification.

#### Roll out upstream Vault authority contract v1 on the reference dev stack

- The web and Vault images report upstream commit `a75c50eee4cb00bebb95452a311a36ed292b6ce5`, native version `6.0.0`, and `CRYPTO_CPQA_PATCHES=none`. The existing Vault Raft and plugin volumes were archived while Vault was stopped. Docker lacked the original image content digests of the stopped containers, so the separately tagged fallback images are the available pre-rollout images rather than exact copies of those container images.
- Reloaded the registered plugin on `abe_ac17/`, `abe_tkn20/` and `abe_covercrypt/` using the existing Raft volume. `covercrypt_config --check-vault` verified the existing CoverCrypt authority and `--reconcile-vault` published its public metadata. An initial read of the large authority timed out, and a later verification succeeded.
- Both existing CoverCrypt versions returned HTTP 200 through Gunicorn. A synthetic upload over the deployed API with ClamAV and Supabase returned 201, took the recorded Vault signing path, and downloaded with HTTP 200 and matching bytes. The synthetic blob, rows and session were cleaned up. Real signed CoverCrypt accepted matching attributes and rejected a mismatched key. The reference database had no historical AC17/TKN20 rows for a live download check. Both schemes were covered by the isolated suite.
- Gunicorn health returned 200, and Nginx returned 200 over TLS 1.3 with `X25519MLKEM768`, hostname verification and the deployment PQ CA. The Windows Schannel curl client failed its handshake. Multi-authority routing for schema-2 history still requires an implementation and separate verification before rotating or growing the active mount.

### 2026-11-15

- `start.py clean` checks which selected Docker volumes exist, propagates removal failures, and clears host Vault credentials only after selected volumes have been removed. The regression in `tests/test_crypto_build.py` covers an in-use Vault volume and verifies the credentials survive. During diagnosis, the newly created Vault container was still mounted to the Raft volume created on 2026-11-08. Vault repeatedly panicked while checking bbolt page ordering. This does not establish the cause of the underlying page corruption.

- On the local six-dimension Vault setup, an upload hit Nginx's 60-second upstream wait while first-time CoverCrypt setup also failed near Vault's 90-second request limit. `start.py initdata` now calls `covercrypt_config --initialize-vault` after seeding dimensions when configured for CoverCrypt/Vault. The upload path requires a ready authority. `docker/vault/config.hcl` gives the Vault listener 300 seconds and the CoverCrypt setup client allows 310 seconds. The interrupted local mount was moved aside before provisioning a fresh mount. Verification used the deployed API, ClamAV, Vault and Supabase. Synthetic upload returned 201 in 17 seconds, download returned 200 with matching bytes, and the test file and records were cleaned up.

#### Audit the CoverCrypt completion checklist

- `views/storage.py` scopes user-key cache entries to the newest persisted revocation ID, so a committed revocation invalidates lookup even when attributes are unchanged. Attribute status changes in `signals.py` also record revocation. The cache still enforces scheme, backend, authorization mode and authority/config identity. This does not revoke key material outside CPQA.
- `services/version_crypto.py` rejects a plaintext metadata claim when a file version has a CP-ABE policy. Copy, rename, trash restore and policy re-encryption passed the version checks.

### 2026-11-15 — CoverCrypt rotation and version restore

- `management/commands/covercrypt_config.py --rotate-vault` promotes a separately provisioned authority through the upstream contract v1. `services/cpabe_service.py` and `services/vault_service.py` atomically publish the active manifest and record retired public authority metadata in `COVERCRYPT_AUTHORITY_HISTORY_v1`. Reads use the recorded fingerprint/revision, configuration, mount and verifier before keygen, cache access or decrypt. CoverCrypt schema 1 without an authority identity requires recovery after rotation.
- `views/storage.py` and the file history UI restore an older version with compatible policy, scheme, backend, signature state and dimensions. The endpoint checks update and read/decrypt rights, rescans plaintext in memory, then writes the source ciphertext and metadata to a separate object and version.
- The isolated Django run passed 166 security tests. All seven CPQA/Vault Raft integration tests passed separately, including signed historical reads after rotation and version restore with storage cleanup on DB failure. The plugin image smoke passed signed/unsigned allow and deny for AC17, TKN20 and CoverCrypt. The integration test uses an isolated SQLite database, in-memory blob storage and a ClamAV stub.
- 166 isolated Django tests passed. The six opt-in tests passed separately on real disposable Vault Raft with SQLite and an in-memory blob store and a ClamAV stub. The Vault image smoke passed signed/unsigned allow/deny for three schemes, contract metadata, config, and invalid requests. `.github/workflows/docker.yml` resolves the upstream revision once for smoke and both published image builds. CI publishing was not exercised. Native CoverCrypt was not part of the release verification.

## Cách cập nhật file này


Giữ phần kiến thức nền theo chủ đề. Kết quả công việc mới ghi trong mục **Các task đã hoàn thành theo ngày**, dùng heading ngày `### YYYY-MM-DD` và heading task `#### Tên task`; công việc cùng ngày dùng chung heading ngày. Mỗi task ghi kết quả, file nguồn, kiểm chứng và giới hạn; không ghi hội thoại hoặc nhật ký thao tác chi tiết. Chỉ ghi ngày đã biết, không suy đoán ngày cho công việc cũ.

Giữ các facts có thể truy về mã nguồn. Khi một điểm cần kiểm chứng đã được sửa hoặc xác minh, thay bằng kết quả cùng cách kiểm tra; không lưu kết quả test giả định hoặc giá trị môi trường riêng tư. Cập nhật ngày đối chiếu khi thực sự rà soát lại.
