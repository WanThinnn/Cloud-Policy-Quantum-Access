# Kế hoạch tích hợp CoverCrypt

[English](../en/covercrypt-integration-plan.md) · [Build source mật mã](crypto-source-build.md)

## Mục tiêu và phạm vi

Tích hợp scheme CoverCrypt upstream vào luồng upload file, policy, cấp khóa và download của CPQA, đồng thời giữ nguyên khả năng đọc ciphertext AC17/TKN20 hiện có và bảo toàn Vault mounts.

Upstream v6.0.0 cung cấp CoverCrypt qua cả native C ABI và Vault plugin. Adapter `ctypes` hiện tại của CPQA vẫn bind các entry point AC17/TKN20 hiện có, nên native support cần được bổ sung vào adapter và kiểm thử; không suy ra app đã hỗ trợ chỉ vì enum upstream có CoverCrypt. Windows DLL có các export `*_with_scheme` tổng quát để chọn CoverCrypt, còn cấu hình setup native được truyền qua file và environment variables `HCPABE_COVERCRYPT_CONFIG`/mode theo tài liệu upstream. Vault API nhận `config_json` và `mode` ngay trong request setup. Chế độ KEM CoverCrypt và tùy chọn ký ML-DSA là hai tính năng riêng, cần cấu hình và ghi metadata riêng.

Vault `setup` thay thế authority đang lưu tại mount, không phải thao tác kiểm tra/khởi tạo idempotent. CPQA không được gọi setup trên mount đã có authority; khi cần mở rộng dimensions, dùng `add_dimension` của plugin nếu phù hợp, còn đổi authority/key cần quy trình có chủ đích.

Docker hiện build thư viện từ nhánh upstream có thể thay đổi. Giữ cách cập nhật đó và dùng manifest được tạo sau build để biết chính xác commit/version upstream trong từng image. Không pin commit trong kế hoạch tích hợp này.

## Các điểm tích hợp hiện tại

- `src/crypto_access/services/cpabe_service.py` khởi tạo AC17/TKN20, gọi Vault endpoint theo scheme, tạo user key và mã hóa/giải mã buffer file.
- `scripts/vault_manager.py` tạo các mount `abe_ac17/` và `abe_tkn20/`. Giữ hai mount cùng KV key hiện tại.
- `src/crypto_access/models/policy.py` chuyển điều kiện ABAC thành chuỗi policy AC17/TKN20.
- `src/crypto_access/services/version_crypto.py` xác thực crypto metadata theo version và parse header ciphertext AC17/TKN20 hiện tại.
- `src/crypto_access/views/storage.py` chọn scheme cho ciphertext mới và scheme đã lưu khi đọc; nơi đây cũng xử lý cache khóa và bypass đặc quyền.
- `UploadedFile.abe_scheme` hiện là field tối đa 10 ký tự. `FileVersion.crypto_metadata` là JSON. Cần xác nhận chúng biểu diễn được metadata CoverCrypt cuối cùng trước khi quyết định có cần migration hay không.
- `tests/smoke_crypto_image.py` đã kiểm tra CoverCrypt qua Vault mount tạm. Test gửi `config_json` có dimensions và kiểm tra allow/deny có/không chữ ký. Điều này xác nhận đường plugin, chưa xác nhận tích hợp app.
- Upstream checkout đã đọc có `VERSION` 6.0.0. Windows DLL trả về `getVersion() == 6.0.0` và export các hàm native tổng quát chọn scheme. Helper `hybrid_cpabe_covercrypt_setupBuffer_from_json` riêng không được export trong DLL đó; native setup dùng file cấu hình/environment path theo tài liệu.
- Chi tiết contract và fixture mẫu không chứa secret: [Contract CoverCrypt upstream](covercrypt-vault-contract.md) và [`tests/fixtures/covercrypt-vault-contract/`](../../tests/fixtures/covercrypt-vault-contract/README.md).

## Checklist triển khai

### 0. Xác nhận và mô tả contract upstream

- [x] Đọc source và build output upstream hiện tại để xác định chính xác entry point CoverCrypt; phân biệt API thư viện native với API Go/Vault plugin.
- [x] Ghi lại request/response Vault cho `setup`, `genkey`, `encrypt`, `decrypt`, gồm tên field, encoding, lỗi trả về và `pqc` có bật chữ ký cho CoverCrypt hay không.
- [x] Xác nhận schema `config_json`, cú pháp dimension/attribute, grammar encryption policy, grammar user-key attributes và giới hạn số dimension/attribute. Không thấy giới hạn số lượng dimension/attribute được khai báo tường minh trong bridge đã đọc; giới hạn parser/tài nguyên native vẫn áp dụng.
- [x] Xác nhận setup không idempotent, không so cấu hình với authority đang có và thay authority tại mount; mô tả `add_dimension` hiện có cùng yêu cầu quy trình rotation rõ ràng.
- [x] Xác nhận envelope/header nhận diện scheme/format và phân biệt chúng với metadata chữ ký theo từng version.
- [x] Kiểm tra README gốc, Vault README, binding README và release notes v6.0.0. Các tài liệu đã mô tả API native/Vault, cấu hình/mode và cú pháp policy; không cần sửa tài liệu upstream.
- [x] Lưu request/response mẫu hợp lệ và không hợp lệ trong fixture không chứa secret để viết contract test.

**Tiêu chí hoàn tất:** tích hợp app có contract upstream được mô tả và có test native/Vault sẵn có; hành vi mới trong app vẫn cần regression test riêng. Không suy diễn serialization hay policy chỉ dựa trên tên scheme.

### 1. Thiết kế dimensions và vòng đời cấu hình CoverCrypt

- [x] Xác định nguồn và ánh xạ ban đầu: `AttributeDefinition` enum active cùng `user_type` hữu hạn lấy từ profile thành dimension non-hierarchical theo thứ tự tên xác định; loại `location` tự do. Xem [vòng đời cấu hình](covercrypt-configuration-lifecycle.md).
- [x] Quy định một user có thể có một hay nhiều giá trị cho mỗi dimension; quy định cách xử lý giá trị thiếu, không biết, trùng hoặc xung đột. Model hiện tại unique theo `(user, attribute)`, nên chỉ có một giá trị; giá trị thiếu không cấp CoverCrypt attribute, dữ liệu sai fail closed.
- [x] Thêm nguồn cấu hình CoverCrypt không secret và có validation. CPQA sinh một setup JSON từ enum definition active; không lặp dimensions trong deployment settings và không nhận runtime JSON tùy ý.
- [x] Tính và lưu fingerprint/version cấu hình ổn định cùng keyset Vault tương ứng để restart không ghép nhầm khóa cũ với dimensions mới. Manifest Vault không secret được kiểm tra trước khi dùng và không bị ghi đè khi không tương thích.
- [x] Xác định quy trình rõ ràng cho operator/admin khi đổi dimension và xoay khóa. Đổi cấu hình fail closed; không gọi setup ngầm.
- [x] Xác định cách backup/recovery nhận diện cấu hình cần thiết cho mỗi keyset CoverCrypt mà không export MSK khỏi Vault. Keyset manifest Vault liên kết config không secret, mode, mount và keyset identifier.

**Tiêu chí hoàn tất:** đã đạt cho phần chuẩn bị vòng đời cấu hình. Deployment có thể validate authority lặp lại, phát hiện manifest không tương thích và theo quy trình rotation đã tài liệu hóa. Provision authority plugin vẫn là công việc giai đoạn 3.

### 2. Bổ sung chọn scheme nhưng giữ nguyên mặc định cũ

- [x] Thêm `covercrypt` vào registry scheme tập trung, validation tại CP-ABE service dispatch và trước upload. Hiện chưa có UI chọn scheme; runtime settings không expose `CPABE_SCHEME`.
- [x] Fail closed với `CPABE_SCHEME=covercrypt` cho đến khi backend CPQA triển khai và kiểm chứng contract setup/config. Upstream hỗ trợ không đồng nghĩa app đã dispatch.
- [x] Giữ mặc định `ac17` và hành vi AC17/TKN20 hiện có.
- [x] Rà `UploadedFile.abe_scheme` và consumer: `max_length=10` vừa `covercrypt`; serializer không nhận/expose field này để ghi, còn crypto metadata hiện chỉ chấp nhận AC17/TKN20. Không cần migration độ dài field, nhưng metadata CoverCrypt thuộc giai đoạn 6.
- [x] Xác nhận runtime-setting allowlist không expose `CPABE_SCHEME`; `.env.example` giữ mặc định deployment `ac17` và toggle Vault/native hiện tại.

**Tiêu chí hoàn tất:** đạt cho bước chọn scheme trước dispatch. Tổ hợp scheme/backend chưa hỗ trợ bị từ chối trước upload; deployment hiện tại giữ nguyên scheme đã chọn. CoverCrypt vẫn chưa khả dụng cho tới khi giai đoạn 3/5 triển khai backend CPQA.

### 3. Tạo Vault engine và key material CoverCrypt

- [x] Mở rộng Vault provisioning để tạo `abe_covercrypt/`, giữ nguyên `abe_ac17/`, `abe_tkn20/` cùng dữ liệu hiện có.
- [x] Chỉ setup CoverCrypt với dimensions đã validate cho mount được ghi nhận vừa tạo và khi KV chưa có keyset state; setup bị gián đoạn sẽ bị chặn retry tự động.
- [x] Lưu/đọc public key CoverCrypt và PQC verification key ở các Vault KV key riêng. MSK vẫn nằm trong plugin storage được seal-wrapped.
- [x] Cập nhật `_ensure_keys_exist` để khởi tạo/xác minh authority CoverCrypt khi startup ở Vault-plugin mode.
- [x] Xác minh fingerprint public key/cấu hình ở từng lần encrypt và keygen. Hai thao tác CoverCrypt vẫn bị tắt cho đến phase 5 triển khai app dispatch.
- [x] Hiển thị lỗi setup Vault và fail closed; startup raise nếu setup hoặc kiểm tra state thất bại.

**Tiêu chí hoàn tất:** đã triển khai mount provisioning và guarded authority setup; giữ nguyên các mount AC17/TKN20. Kiểm tra key/config ở từng thao tác được thực hiện tại service boundary của CoverCrypt.

### 4. Ánh xạ thuộc tính CPQA và biên dịch policy

- [x] Viết mapper CoverCrypt từ thuộc tính user thực tế sang `dimension::value`. Bắt buộc đúng một giá trị hợp lệ cho mỗi dimension, gồm `user_type` lấy từ profile.
- [x] Viết policy compiler CoverCrypt từ tập con ABAC AST sang grammar dimension-qualified upstream.
- [x] Quy định toán tử: hỗ trợ `==`, `in`, `and`, `or`, ngoặc; từ chối `!=`, `not in` vì khác ngữ nghĩa khi thiếu attribute; từ chối so sánh thứ tự, chained comparison, phủ định đơn ngôi và literal không phải chuỗi.
- [x] Bảo đảm compiler dùng cùng service cấu hình đã validate với authority setup, không đọc `os.environ` độc lập.
- [x] Validate policy trước khi lưu qua model/serializer hiện có; output AI vẫn là gợi ý và qua cùng compiler.
- [x] Thêm test tập trung cho mapper, biểu thức được hỗ trợ và trường hợp fail closed.

**Tiêu chí hoàn tất:** mapper và compiler dùng cùng config, ngữ nghĩa không hỗ trợ bị từ chối. Ngữ nghĩa key generation/encryption end-to-end cần kiểm thử ở giai đoạn 5/8.

### 5. Tích hợp CoverCrypt vào upload, keygen và decrypt

- [x] Định tuyến request setup/keygen/encrypt/decrypt tới mount CoverCrypt; chỉ gửi cấu hình ở bước mà upstream contract yêu cầu.
- [x] Dùng đúng encoding public key/user key đã xác nhận; giữ cách xử lý temporary-file và cache khóa mã hóa hiện tại.
- [x] Dùng chính xác policy và attribute syntax CoverCrypt. Không fallback sang cú pháp AC17/TKN20 khi CoverCrypt lỗi.
- [x] Tách bật chữ ký PQC khỏi chọn scheme ABE. Xác minh ciphertext có chữ ký bằng đúng key CoverCrypt và từ chối khi thiếu/sai verification key.
- [x] Mở rộng native `ctypes` adapter để gọi các hàm tổng quát `*_with_scheme` với `CPABE_SCHEME_COVERCRYPT`, đồng thời cung cấp config file/mode đã validate qua deployment config. Tách biệt với Vault setup nhận inline `config_json`.
- [x] Rà mọi caller của `encrypt_version`, `generate_user_key`, `encrypt_buffer` và decrypt để upload, preview, download, policy assignment/re-encryption và đọc file version dùng cùng contract theo scheme.

**Tiêu chí hoàn tất:** file CoverCrypt mới upload được giải mã chỉ qua scheme đã ghi và user key phù hợp; API AC17/TKN20 không đổi hành vi.

### 6. Mở rộng metadata theo version và giữ ciphertext lịch sử

- [ ] Định nghĩa metadata CoverCrypt gồm scheme, backend, ciphertext format/version, chế độ chữ ký và ID keyset/cấu hình không chứa secret cần thiết để đọc đúng.
- [ ] Mở rộng `validate_metadata` và lưu metadata nhưng không diễn giải envelope CoverCrypt thành format `hybrid-v1`/`hybrid-v2` hiện tại của AC17/TKN20.
- [ ] Thêm parser hoặc contract metadata tin cậy từ plugin để xác thực scheme/format thật của ciphertext. Từ chối metadata/ciphertext không khớp hoặc format lạ; không đoán theo `CPABE_SCHEME` hiện tại.
- [ ] Đảm bảo version AC17/TKN20 cũ vẫn đọc được khi scheme hiện tại là CoverCrypt và ngược lại.
- [ ] Rà luồng copy, rename, restore version, policy assignment và re-encryption để giữ metadata của ciphertext được copy và chỉ ghi metadata mới cho version vừa mã hóa.
- [ ] Chỉ tạo migration nếu có thay đổi schema quan hệ cụ thể. JSON metadata đổi format thì xử lý bằng validation có version rõ ràng, không rewrite ciphertext hay backfill lịch sử chưa biết.

**Tiêu chí hoàn tất:** mỗi version cũ luôn dùng đúng backend/scheme/format đã ghi; ciphertext lịch sử không rõ vẫn bị từ chối thay vì phân loại đoán.

### 7. Rà authorization, bypass, cache và lifecycle khóa

- [ ] Định nghĩa hành vi CoverCrypt với owner/privileged user ở chế độ thường và `SUPER_ADMIN_REQUIRE_POLICY` strict.
- [ ] Không giả mạo thuộc tính CoverCrypt bằng cách trích token từ policy string. Nếu giữ bypass non-strict hiện có, cần một đường satisfaction giới hạn, bảo toàn ngữ nghĩa và có test; nếu chưa làm được thì từ chối bypass CoverCrypt.
- [ ] Đưa scheme, danh tính user, thuộc tính đã chuẩn hóa, backend và phiên bản key/config vào cache identity khi cần.
- [ ] Invalidate user-key cache bị ảnh hưởng khi đổi thuộc tính, thu hồi khóa, rotation cấu hình/keyset CoverCrypt hoặc đổi backend.
- [ ] Kiểm thử user bị từ chối vẫn không giải mã được dù còn cache key; strict policy không bị vượt qua qua owner/grant/cache.
- [ ] Không ghi secret key hoặc plaintext vào log, error response, telemetry hay persistent Django settings.

**Tiêu chí hoàn tất:** CoverCrypt không làm yếu các lớp authentication, ABAC, file-policy hay kiểm soát mật mã của ứng dụng.

### 8. Bổ sung regression và end-to-end coverage

- [ ] Unit test parsing dimensions, attribute normalization, policy compilation, metadata validation và native mode chưa hỗ trợ.
- [ ] Mở rộng plugin smoke test cho dimensions cấu hình, user key đúng/sai, request lỗi, config mismatch, thao tác ký/không ký và error response.
- [ ] Thêm test CPQA upload/download cô lập cho user được phép/bị từ chối, xen kẽ version AC17/TKN20/CoverCrypt, và đọc version cũ sau khi đổi scheme hiện tại.
- [ ] Test policy assignment/re-encryption, copy/restore, signature verification, cache invalidation, key revocation và privileged access strict/non-strict.
- [ ] Xác nhận setup CoverCrypt lỗi hoặc Vault outage thì fail closed, không lưu plaintext như thể mã hóa thành công.
- [ ] Chạy security test và Docker crypto/plugin smoke test phù hợp trong môi trường cô lập; ghi rõ test đã chạy và dịch vụ ngoài nào chưa có.

**Tiêu chí hoàn tất:** test chứng minh cả allow và deny, đồng thời bảo vệ scheme và ciphertext lịch sử hiện có.

### 9. Viết tài liệu triển khai và phát hành

- [ ] Mô tả dimensions CoverCrypt, cú pháp policy, cấu hình deployment, Vault mount/KV path, khởi tạo, backup/recovery và rotation trong tài liệu cặp `docs/en/` và `docs/vi/`.
- [ ] Chỉ cập nhật `.env.example`, operator help và lựa chọn scheme trong API/UI khi cấu hình đã hoàn tất; không đưa secret/private key vào tài liệu.
- [ ] Nêu rõ hỗ trợ ban đầu chỉ qua Vault plugin trừ khi native ABI được triển khai và xác minh riêng.
- [ ] Sau khi code hoàn thành, cập nhật project facts và release notes với nguồn triển khai và giới hạn đã xác minh.
- [ ] Xác nhận Docker/CI build ghi commit/version upstream đã resolve vào manifest sinh tự động và kiểm thử contract plugin mà không hardcode commit.

**Tiêu chí hoàn tất:** operator có thể deploy/rotate CoverCrypt mà không nhầm với AC17/TKN20 hoặc chữ ký ML-DSA; nội dung release khớp hành vi đã kiểm thử.

## Định nghĩa hoàn thành

- [ ] File CoverCrypt mới upload/download thành công qua Vault với dimensions đã validate và policy translation.
- [ ] User có quyền phù hợp giải mã được; user không có quyền bị từ chối.
- [ ] Metadata theo version chọn đúng backend/scheme/format qua các lần đổi scheme, copy và đọc lịch sử.
- [ ] Mount, key và ciphertext AC17/TKN20 hiện có tiếp tục đọc được.
- [ ] Strict authorization, cache invalidation, signature verification và xử lý lỗi có regression coverage.
- [ ] Tài liệu, cấu hình operator, source manifest và release notes khớp phạm vi đã triển khai/kiểm thử.
