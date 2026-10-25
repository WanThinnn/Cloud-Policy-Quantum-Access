# Hướng dẫn cho AI làm việc trong repository

## Đọc trước khi sửa

- Đọc [FACTS.md](FACTS.md) để nắm kiến trúc, cấu hình, giới hạn và vị trí mã nguồn.
- Baseline hiện tại là release **3.0.0** (`VERSION`, `release_note/release_3.0.0.md`). Khi sửa chức năng, đọc thêm release note liên quan từ 2.1.0 → 2.2.0 → 2.3.0 → 3.0.0 và đối chiếu `start.py`; không dùng quick start/namespace của release cũ thay cấu hình hiện tại.
- Đọc các file liên quan trực tiếp trước khi đưa ra kết luận. Ưu tiên implementation, routes, migration và cấu hình hiện tại khi chúng khác README hoặc tài liệu đặc tả.
- Trên máy của chủ dự án, đọc thêm `C:\Users\WanThinnn\.codex\RTK.md` nếu tồn tại. Quy tắc hiện tại của file này: mọi lệnh shell đều bắt đầu bằng `rtk`; dùng `rtk proxy <command>` khi cần chạy nguyên lệnh không qua bộ lọc. Không coi đường dẫn Windows cá nhân này là dependency của ứng dụng.
- Khi nhận việc, kiểm tra `rtk git status --short`. Giữ nguyên thay đổi có sẵn của người dùng; không tự commit, push, release hoặc triển khai nếu nhiệm vụ chưa yêu cầu.

## Quy ước triển khai

- Backend là Django/DRF trong `src/`; đặt logic nghiệp vụ dùng lại trong `crypto_access/services/`, validation/API contract trong serializers, endpoint trong views và urls tương ứng.
- Models, serializers, views và urls đều chia theo miền nghiệp vụ. Kiểm tra `__init__.py` tương ứng khi thêm hoặc đổi tên thành phần được export.
- Giao diện dùng Django templates và JavaScript thuần; không mặc định đây là ứng dụng React/Next.js. Sửa nguồn Tailwind ở `src/theme/static_src/src/styles.css`; CSS build nằm trong `src/theme/static/css/dist/`.
- Khi thay schema, tạo migration mới và xem xét dữ liệu hiện có. Không sửa lại migration lịch sử để né migration mới.
- Thay đổi nhỏ, đúng phạm vi; tránh format lại toàn repository hoặc nâng dependency không liên quan. `src/setup.cfg` ghi quy ước Python/isort với độ dài dòng 120; kiểm tra riêng khả năng công cụ đọc cấu hình Black trước khi dùng.
- Giữ tương thích giữa frontend, serializers, API và backend storage. Dùng factory `crypto_access.services.storage.get_storage_service` thay vì import module `storage_service` cũ.

## Các ràng buộc cần giữ
- Cấu hình runtime đi qua allowlist/validation ở `services/runtime_settings.py`; UI `/manage/settings/` chỉ cho profile super_admin active, có CSRF và revision khi ghi. Giữ nguyên credentials/trust bootstrap trong deployment. Secret SMTP phải là write-only với reference tới Vault qua `runtime_secrets.py`; không đưa plaintext vào SystemSetting, cache, form initial, audit hay exception/log. Khi thêm setting phải nối tới consumer thực tế, không chỉ thêm ô giao diện. Xem `docs/vi/runtime-settings.md`.

- Giữ các lớp kiểm tra riêng biệt: authentication/session, quyền ABAC ở ứng dụng, policy file/folder và giải mã bằng CP-ABE. Một lớp cho phép không chứng minh các lớp còn lại cho phép.
- Kiểm tra thứ tự middleware: JWT trước ABAC; route ABAC cụ thể trước route tổng quát. Trong `check_access`, user thường cần policy cho phép; bypass document của super_admin/superuser phải qua `services/document_access.py` và công tắc `SUPER_ADMIN_REQUIRE_POLICY`. Khi strict bật, không cho owner/grant hay khóa cache bypass vượt policy, không giả lập thuộc tính để giải mã. Giữ quyền mở settings/control plane để đổi chế độ; không tự khôi phục fallback RBAC từ comment cũ.
- Khi sửa policy, thuộc tính hoặc thu hồi khóa, đọc cả `signals.py`, `casbin_service.py` và đường cache khóa trong `views/storage.py`. Đối chiếu đầy đủ scheme, user ID, attribute hash và invalidation; không giả định các cache key hiện tại đã đồng bộ.
- Giữ `UploadedFile.abe_scheme` khi xử lý file cũ; không giải mã tất cả file theo `CPABE_SCHEME` hiện tại. Phân biệt chế độ native ctypes với Vault ABE plugin.
- Trong plugin mode của 3.0, giữ hai mount `abe_ac17/` và `abe_tkn20/`, cùng KV public key tương ứng. Release note mô tả file mới dùng TKN20, nhưng defaults mã nguồn/mẫu env vẫn là AC17; phải đọc cấu hình có hiệu lực trước khi kết luận scheme đang chạy.
- AI Policy Assistant trả policy đề xuất và validation; không tự lưu/áp dụng quyền từ output LLM. Giữ kiểm tra quyền endpoint, AST và bước biên dịch CP-ABE. Khi sửa chữ ký, phân biệt khóa CP-ABE phía backend với khóa ký ML-DSA của người dùng được mở bằng WebAuthn PRF/recovery ở browser.
- Giữ thứ tự quét ClamAV trước mã hóa/upload và các bước kiểm tra chữ ký hiện có. Không bỏ xác minh hoặc trả thành công giả để vượt lỗi tích hợp.
- Trường mã hóa có blind index riêng. Khi đổi cách lưu/đổi tên/copy path hoặc filename, kiểm tra cả hash tra cứu, AAD, physical path và version; không dùng phép so sánh plaintext thông thường để thay truy vấn blind index.
- Không thay khóa master, định dạng ciphertext, trust root, thuật toán hoặc ABI native như một thao tác dọn mã. Phải xem xét khả năng đọc dữ liệu cũ và cách di chuyển dữ liệu.
- Không ghi secret, token, private key, `.env` thật, nội dung file riêng tư hoặc credential cloud vào mã/tài liệu/log. Dùng `.env.example` để tham khảo tên biến. Không tự sinh lại khóa/cert, unseal Vault, chạy seed/reset hay xóa Docker volume chỉ để kiểm tra một thay đổi thông thường.
- Không chỉnh trực tiếp binary native/WASM, header thư viện bên thứ ba hoặc asset minified. Với Vault plugin, sửa source rồi dùng quy trình build; kiểm tra output/kiến trúc trước khi thay binary được phân phối.

## Chạy và kiểm tra

Các lệnh dưới đây là hướng dẫn cho nhiệm vụ tương ứng, không phải yêu cầu tự khởi động hoặc khởi tạo hệ thống mỗi phiên.

| Mục đích | Thư mục chạy | Lệnh |
| --- | --- | --- |
| Kiểm tra thay đổi | root | `rtk git diff --check` |
| Cài Python dependency vào môi trường riêng | root | `rtk python -m pip install -r src/requirements.txt` |
| Django system checks | `src/` | `rtk python manage.py check --settings=config.settings.development` |
| Test Django hiện có, DB test riêng | `src/` | `rtk python manage.py test crypto_access --settings=config.settings.development` |
| Regression R01/R02, DB/keys/storage cô lập | `src/` | `rtk python -m django test security_tests --settings=security_tests.settings --noinput` |
| Xem migration model còn thiếu, không tạo file | `src/` | `rtk python manage.py makemigrations --check --dry-run --settings=config.settings.development` |
| Cài frontend dependency | `src/theme/static_src/` | `rtk npm ci` |
| Build Tailwind | `src/theme/static_src/` | `rtk npm run build` |
| Build/chạy stack phát triển | root | `rtk python start.py build`, sau đó `rtk python start.py up` |
| Xem hướng dẫn CLI | root | `rtk python start.py help` (không kèm cờ `--ai`/`--vpn` để tránh ghi `.env`) |
| Trạng thái container, Compose mặc định | root | `rtk docker compose --project-directory . -f docker/docker-compose.yml ps` |

- Django vẫn đọc `.env` ở root dù chọn settings development. Chỉ chạy test với DB, credentials, cache và storage đã cô lập; không dùng dịch vụ production để kiểm thử.
- Django checks không chứng minh Vault, ClamAV, native crypto hay cloud storage hoạt động. Báo rõ kiểm tra nào thực sự chạy và dependency nào còn thiếu.
- Không chạy pytest toàn bộ một cách mù quáng: xem mục kiểm thử trong `FACTS.md`. Các script trong `src/tests/` không phải toàn bộ là test cô lập an toàn.
- Với thay đổi quyền/mật mã, kiểm tra cả trường hợp cho phép và từ chối; với storage kiểm tra scheme/file cũ, metadata và version khi có liên quan. Chạy kiểm tra phù hợp phạm vi, không tự sửa mọi lỗi lịch sử ngoài nhiệm vụ.
- `start.py initdata` có tác dụng ghi dữ liệu, seed test users/policies và khởi tạo Vault; chỉ dùng khi nhiệm vụ cần khởi tạo môi trường. `start.py clean` có thể xóa container và volume chứa dữ liệu/khóa.
- `start.py` không hỗ trợ lệnh `status`; dùng Compose `ps` với đúng file/profile đang chạy. Đặt cờ toàn cục trước tên lệnh, ví dụ `rtk python start.py --ai up`; `rest` phía sau tên lệnh được argparse thu làm tham số chuyển tiếp.
- `up`/`restart` có thể gọi Vault manager và ghi public key trích xuất; `--prod` truyền tiếp cho Vault manager, vốn không tự unseal Vault đã khởi tạo sau restart. Không coi thông báo CLI thành công là xác nhận Vault đã sẵn sàng.
- `--ai` ghi `AI_FEATURES_ENABLED=True` vào `.env`; `--vpn`/`vpn_client` có thể ghi `VPN_PROTO`. Không dùng những cờ này cho thao tác chỉ xem thông tin. Bỏ `--ai` ở lần chạy sau không tự đặt feature flag về False.
- `start.py update` thực hiện git pull, tải binary mới và thay source plugin/header/lib rồi build/chạy lại stack; không dùng như lệnh refresh vô hại khi đang sửa mã. `rebuild` chạy `down -v`, có thể mất dữ liệu và khóa; build không cache mà giữ volume cần quy trình riêng.

## Bàn giao và duy trì tài liệu

- Báo những gì đã đổi, mục đích, kiểm tra đã thực hiện và phần chưa xác minh. Không gọi một đặc tính bảo mật là được bảo đảm chỉ dựa trên README/comment.
- Cập nhật `FACTS.md` khi thay kiến trúc, cấu hình, luồng mật mã, entrypoint hoặc quy trình kiểm thử. Mỗi fact quan trọng cần chỉ ra file nguồn để AI sau kiểm chứng.
- `AGENTS.md` chứa hướng dẫn làm việc; `FACTS.md` chứa thông tin đã quan sát về dự án. Không biến hai file thành nhật ký phiên hoặc nơi lưu secrets.
