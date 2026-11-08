# Contract CoverCrypt upstream (v6.0.0)

[English](../en/covercrypt-vault-contract.md) · [Kế hoạch tích hợp](covercrypt-integration-plan.md)

Tài liệu này ghi lại contract quan sát được trong source upstream checkout cục bộ tại `D:\Documents\ABE\Hybrid-CP-ABE-Library`, có file `VERSION` là `6.0.0`. Thư viện Windows đã build tại `lib/libhybrid-pq-cp-abe.dll` trả về `6.0.0` qua `getVersion()` và export các hàm C tổng quát chọn scheme được liệt kê bên dưới. Đây là kiểm tra checkout/build đó, không khẳng định mọi build HEAD trong tương lai giữ nguyên ABI. Docker ghi revision source đã resolve vào manifest sinh sau build.

## Native C ABI và Vault plugin là hai caller riêng

Upstream định nghĩa `CPABE_SCHEME_AC17 = 0`, `CPABE_SCHEME_TKN20 = 1`, `CPABE_SCHEME_COVERCRYPT = 2`. Generic ABI công khai có các hàm setup, keygen và encrypt chọn scheme; decrypt đọc scheme trong ciphertext header. Windows DLL đã kiểm tra export `hybrid_cpabe_setupBuffer_with_scheme`, `hybrid_cpabe_setupBuffer_with_pqc_scheme`, `hybrid_cpabe_genkeyBuffer_with_scheme`, `hybrid_cpabe_encryptBuffer_with_scheme`, `hybrid_cpabe_decryptBuffer` và `hybrid_cpabe_decryptBuffer_and_verify`.

Native CoverCrypt setup cần file JSON cấu hình tại `HCPABE_COVERCRYPT_CONFIG`; `HCPABE_COVERCRYPT_MODE` nhận `classic`, `post_quantum`, `hybridized`, mặc định `hybridized`. Windows DLL đã kiểm tra **không** export helper cấp thấp `hybrid_cpabe_covercrypt_setupBuffer_from_json`. Native public path là API tổng quát chọn scheme cùng process environment/config file được mô tả. Không tự giả định helper inline JSON hiện diện trong `ctypes` trên mọi nền tảng.

Vault plugin là caller Go/CGO của native library. Plugin nhận inline `config_json` khi setup, lưu authority trong Vault, và có các path tương đối với mount như `abe_covercrypt/`. Contract endpoint:

| Thao tác | Request fields | `data` khi thành công | Ghi chú |
| --- | --- | --- | --- |
| `PUT /v1/abe_covercrypt/setup` | `scheme: "covercrypt"`; `config_json`: **chuỗi chứa JSON**; `mode` tùy chọn (`classic`, `post_quantum`, `hybridized`, mặc định `hybridized`); `pqc` boolean tùy chọn (khóa ký ML-DSA, mặc định `false`) | `public_key` (base64); `scheme`; `pqc`; `native_version`; `revision`; có thể có `pqc_public_key` (base64); CoverCrypt còn trả `config_json` (JSON text) và `mode` | Response không trả MSK. `pqc` bật/tắt ký ML-DSA, tách biệt với mode KEM CoverCrypt. |
| `PUT /v1/abe_covercrypt/genkey` | `scheme: "covercrypt"`; `attributes`: chuỗi biểu thức | `secret_key` (base64); `attributes`; `scheme` | Cần authority đã tồn tại và cùng scheme. Ví dụ CoverCrypt: `Department::IT Level::ADMIN`. |
| `PUT /v1/abe_covercrypt/encrypt` | `scheme: "covercrypt"`; `plaintext` (base64); `policy`; `public_key` (base64); `pqc_private_key` tùy chọn (base64) | `ciphertext` (base64) | Nếu bỏ khóa ký tùy chọn, plugin dùng signing secret lưu trong authority của mount nếu có. CPQA không nên gửi private signing key. |
| `PUT /v1/abe_covercrypt/decrypt` | `ciphertext` (base64); `secret_key` (base64); `pqc_public_key` tùy chọn (base64) | `plaintext` (base64) | Decrypt không có field `scheme`; native decrypt dispatch theo scheme indicator trong ciphertext. File có chữ ký cần verifier key. |

`data` ở trên là object `data` trong HTTP response của Vault. JSON như `config_json` phải giữ dạng chuỗi trong body request. Dữ liệu nhị phân public/secret/ciphertext truyền qua HTTP dưới dạng Base64 chuẩn. Giá trị trong fixture chỉ là sentinel theo schema, không phải khóa mật mã hay ciphertext dùng được.

## Ngữ nghĩa setup, lưu trữ và rotation

- `setup` **không idempotent** và không so config request với cấu hình đã lưu. Handler upstream mô tả thao tác là thay authority tại mount, sinh khóa mới và luôn lưu authority mới. Gọi setup lần nữa có thể khiến ciphertext mã hóa bằng public key cũ không giải mã được bằng key mới. CPQA cần guarded first-time initialization, không gọi setup như thao tác “ensure keys” định kỳ và phải có quy trình rotation do operator kiểm soát.
- Authority CoverCrypt lưu MSK, public key tương ứng, ML-DSA keys tùy chọn, config JSON, mode, scheme và revision cùng nhau trong Vault storage được seal-wrap dưới prefix `msk/`. Authority nhỏ dùng một bản ghi tương thích định dạng cũ. Authority lớn dùng các chunk bất biến 768 KiB và một manifest có checksum, chỉ ghi manifest sau cùng, vì Vault từ chối một giá trị storage vượt 1 MiB. Manifest là điểm commit; các chunk ghi chưa hoàn tất không được kích hoạt. Các thế hệ chunk cũ được giữ sau khi đổi manifest để không làm hỏng reader đang chạy. Response chỉ trả public/config data, không trả MSK.
- Setup lần đầu thất bại để lại initialization guard. Chỉ xóa guard sau khi xác nhận mount chưa lưu authority và KV chưa có manifest/public keys của keyset. Với deployment hiện tại, sau khi build và restart stack, chạy `docker compose --project-directory . -f docker/docker-compose.yml exec web python manage.py covercrypt_config --recover-failed-initialization --confirm-no-authority --keyset-id primary --vault-mount abe_covercrypt`, sau đó restart service `web` để xóa Vault cache trong bộ nhớ rồi thử upload lại. Command từ chối recovery nếu đã có metadata keyset hoặc fingerprint guard không khớp dimensions đang bật.
- `add_dimension` là thao tác mở rộng authority hiện có. Nó cập nhật cùng authority/MSK và public key, giữ signing keys, tăng revision và trả config/mode đã cập nhật. Nó không tương đương full secret rotation và không thu hồi quyền đã cấp.
- Vault plugin kiểm tra JSON text parse được và có dimensions dùng được. Rust bridge từ chối field JSON không nhận biết. `dimensions` phải không rỗng; mỗi dimension cần `name` ASCII không rỗng và `attributes` không rỗng; mỗi attribute phải ASCII không rỗng. `hierarchical` mặc định `false`; khi bật, danh sách attribute theo thứ tự từ thấp lên cao. Không tìm thấy giới hạn tối đa được khai báo tường minh cho số dimension/attribute hay độ dài chuỗi trong bridge đã kiểm tra. Ứng dụng nên giới hạn kích thước config và dựa vào native validation cho tính hợp lệ mật mã.
- JSON mỗi dimension có dạng `{ "name": "Department", "attributes": ["IT", "HR"], "hierarchical": false }`. Ở root, field duy nhất được nhận là `dimensions`.

## Grammar policy và attributes

Native adapter nhận CoverCrypt policy tạo từ attribute có dimension-qualified như `Department::IT` cùng toán tử `AND`/`and`/`&&`, `OR`/`or`/`||` và ngoặc. Adapter chuẩn hóa AND thành `&&`, OR thành `||`. Tên dương không qualified được chuyển thành chữ thường `<name>::present`; cách này hữu ích với boolean dimensions, không thay thế cho ánh xạ dimensions của CPQA. `NOT` không quote bị adapter từ chối. Không chuyển cú pháp phủ định TKN20 sang CoverCrypt.

Genkey nhận một chuỗi attributes. Các giá trị phân cách bằng whitespace được nối thành conjunction; giá trị qualified như `Department::IT Level::ADMIN` được giữ nguyên. Giá trị trần chuyển thành `<name>::present`. Tên dimension/value qualified phải khớp chính xác config (bridge yêu cầu ASCII). Upstream mô tả thứ tự attribute của hierarchical dimension từ thấp lên cao và hỗ trợ `hierarchical: true` trong config.

KEM mode CoverCrypt là `classic`, `post_quantum`, hoặc `hybridized`. Trong implementation upstream này, hybridized kết hợp Curve25519 với ML-KEM-768; post-quantum mode dùng đường CoverCrypt hậu lượng tử. Field Vault setup riêng `pqc=true` tạo ML-DSA keys dùng cho ký Sign-then-Encrypt tùy chọn. Vì vậy signature mode của file không đồng nghĩa với KEM mode CoverCrypt.

## Nhận diện ciphertext và metadata chữ ký

Envelope v2 của thư viện có byte scheme indicator: `0` AC17, `1` TKN20, `2` CoverCrypt. CoverCrypt dùng envelope hybrid v2 có tag scheme; parser header CPQA cần nhận `scheme=covercrypt` trong v2 và tiếp tục từ chối giá trị lạ. V1 cũ không có scheme byte và tiếp tục là AC17.

Header nhận diện format và ABE scheme; **không** ghi việc có bật ký ML-DSA hay không. Response Vault `encrypt` chỉ trả `ciphertext`, nên caller phải ghi signature mode theo chính key/config dùng cho encryption trong metadata từng version. Version đã ghi signed phải gửi đúng verification public key và yêu cầu verify thành công khi decrypt. Không đoán signature mode từ `CPABE_SCHEME`, setting `pqc` hiện tại hay ABE header.

## Phần mở rộng public-key reference của CPQA

CPQA áp dụng `docker/patches/vault-covercrypt-public-reference.patch` sau patch
chia nhỏ authority. Riêng CoverCrypt, response setup và add_dimension trả
`public_key` dạng `vault-authority-sha256:<64 ký tự hex thường>`, tham chiếu tới
đúng public key đã serialize trong plugin storage. Serialization AC17/TKN20 và
native C ABI không đổi. Plugin vẫn nhận request mã hóa dùng public key Base64 cũ.

`GET /v1/abe_covercrypt/authority` đọc public response hiện có: reference, config,
mode, revision, trạng thái ký và verification public key ML-DSA nếu có. Endpoint
không chạy setup, không ghi authority và không xuất MSK/signing secret. Encrypt
nhận reference trong `public_key`, bắt buộc scheme CoverCrypt và fingerprint
khớp chính xác authority trước khi dùng public key bên trong để mã hóa.

Schema ứng dụng có số giá trị mỗi dimension 4/3/6/4/5/6 đã tạo public key
35.952.472 byte, thành 47.936.632 byte khi Base64, vượt giới hạn HTTP request
33.554.432 byte mặc định của Vault. Chia nhỏ authority không xử lý ranh giới
request này. KV nay chỉ lưu reference nhỏ, verification key và manifest chứa
fingerprint config/key; encrypt cũng không gửi lại public key lớn.

Sau lần khởi tạo đầu bị gián đoạn, CPQA chỉ đọc `/authority` để hoàn tất public
metadata khi guard khớp config active và provisioning đã ghi nhận mount mới.
Scheme, config, mode, reference, trạng thái ký và các key đã ghi đều được kiểm
tra. Endpoint thiếu/không hỗ trợ hoặc dữ liệu không khớp thì từ chối, không gọi
setup lại. Nâng cấp đồng thời web và Vault, giữ volume dữ liệu/khóa. Không gỡ
guard khi authority đã tồn tại. Token triển khai cần quyền read trên
`abe_covercrypt/authority`; ứng dụng không tự mở rộng ACL.

Khởi tạo dùng guard bền vững qua CAS của KV v2: chỉ worker lấy được guard mới
được chạy setup. Guard không có lease/hết hạn, tránh worker khác setup lại khi
request trước có thể còn chạy. Reference, verifier, manifest và guard hoàn tất
được ghi cùng một revision có CAS. Native CoverCrypt cũng dùng claim và ghi
keyset nguyên tử. Các trường liên quan được đọc từ một revision Vault mới,
không dùng cache riêng của worker; Vault lỗi không bị coi là chưa có khóa.

`VaultService.put_secret` merge bằng CAS, tối đa tám lần retry khi xung đột và
đọc lại record mới mỗi lần. Không retry lỗi khác CAS và không tái tạo record đã
xóa/hủy thành record trống. Token triển khai tối thiểu cần quyền read/create/update
KV data phù hợp và read metadata để phân biệt path chưa có với state bị xóa/lỗi.

## Cách trả lỗi

Lỗi validation plugin và lỗi native trả về dưới dạng Vault logical error response (Vault HTTP API thường biểu diễn thành error response, phổ biến là HTTP 400 có mảng `errors`). Các nhóm lỗi ổn định thấy trong source:

- Thiếu hoặc sai `config_json` CoverCrypt: yêu cầu JSON text hợp lệ có dimensions array.
- Gửi `config_json` cho AC17/TKN20: chỉ CoverCrypt hỗ trợ field này.
- `mode` không hỗ trợ: phải là `classic`, `post_quantum` hoặc `hybridized`.
- Dimensions/attributes rỗng hoặc sai: native CoverCrypt bridge từ chối và ánh xạ lỗi validation cấu trúc thành error code tổng quát `Invalid parameter`.
- Attributes rỗng hoặc chưa có authority khi keygen; scheme request không khớp authority.
- Plaintext/public key/ciphertext/secret key/signing key không phải Base64: bị từ chối trước khi gọi native crypto.
- Policy không thỏa: native trả lỗi `Policy mismatch - attributes do not satisfy policy`.
- Thiếu/sai verifier cho ciphertext có chữ ký: native verification failure; app phải fail closed.

Test nên kiểm tra status/category và error shape an toàn thay vì cố định toàn bộ chuỗi native error. C++ adapter có thể gộp lỗi chi tiết từ Rust parser thành error code tổng quát. Không để key thật hay plaintext trong error fixture.

## Bằng chứng upstream hiện có và tài liệu

Upstream root README, Vault README, CoverCrypt binding README, release notes v6.0.0 và Go backend tests đã mô tả native CoverCrypt, Vault endpoints, dimensions/config, modes, policies và allow/deny có/không chữ ký. Không cần sửa tài liệu upstream trong giai đoạn này. Backend tests upstream có luồng ký/không ký hợp lệ, input setup CoverCrypt không hợp lệ, isolation scheme và mở rộng dimension. Tài liệu này không khẳng định các test đó đã được chạy lại trong lượt hiện tại.

Xem [`tests/fixtures/covercrypt-vault-contract/README.md`](../../tests/fixtures/covercrypt-vault-contract/README.md) để biết template JSON đã loại secret và quy tắc thay chúng thành contract test thật.

## Tham chiếu source upstream

- [Public C API header](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/include/hybrid_pq_cp_abe/hybrid-pq-cp-abe.h) và [scheme enum](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/include/hybrid_pq_cp_abe/cpabe-scheme.h)
- [Native adapter CoverCrypt](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/src/schemes/covercrypt.cpp) và [dispatch native setup](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/src/core/abe-setup.cpp)
- Vault [setup](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/plugins/vault/vault-plugin-abe/plugin/path_setup.go), [keygen](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/plugins/vault/vault-plugin-abe/plugin/path_genkey.go), [encrypt/decrypt](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/plugins/vault/vault-plugin-abe/plugin/path_crypto.go), và [lưu authority](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/plugins/vault/vault-plugin-abe/plugin/authority.go)
- Upstream [Vault API guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/plugins/vault/README.md), [CoverCrypt binding guide](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/bindings/covercrypt/README.md), và [release notes v6.0.0](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/blob/main/release_notes/v6.0.0.md)
