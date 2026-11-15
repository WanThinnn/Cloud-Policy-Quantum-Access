# Vòng đời cấu hình CoverCrypt

[English](../en/covercrypt-configuration-lifecycle.md) · [Kế hoạch tích hợp](covercrypt-integration-plan.md) · [Contract Vault](covercrypt-vault-contract.md)

CoverCrypt setup nhận một object `config_json` dạng `{"dimensions":[...]}`. CPQA sinh JSON này từ các bản ghi enum `AttributeDefinition` active được seed trong `start.py initdata`. Không lặp lại dimension, value, mode, keyset ID hay Vault mount trong `.env`, `settings/base.py` hoặc System Settings.

Cú pháp upstream `config_json=@path/to/file.json` của Vault CLI đọc file trên máy CLI client rồi gửi text JSON trong request. Vault server không tự đọc file hoặc cấu hình mount vào. CPQA setup phải gửi JSON canonical do service schema tạo ra.

Các `AttributeDefinition` enum active thành dimension; definition chuỗi tự do như `location` bị loại. CPQA cũng tạo dimension giới hạn `user_type` từ code `UserType` active cộng với `UserProfile.USER_TYPE_CHOICES` legacy, vì policy seed dùng `user_type` lấy từ profile. Mọi dimension dùng `hierarchical: false`; schema hiện chưa có field hierarchy. `UserAttribute` unique theo `(user, attribute)`, nên mapper yêu cầu đủ một giá trị hợp lệ cho mọi dimension trước khi yêu cầu CoverCrypt user key. Giá trị sai hoặc thiếu sẽ fail closed.

Các `AccessPolicy` seed sẵn vẫn là đầu vào phân quyền và policy của CPQA. Chúng không nằm trong JSON setup authority: setup config mô tả tập attribute, còn policy compiler dịch policy expression sang grammar CoverCrypt. CRUD policy vẫn validate qua serializer hiện có; output AI chỉ là gợi ý và được kiểm tra qua cùng compiler.

Compiler hỗ trợ so sánh chuỗi bằng `==`, membership trong literal list/tuple/set không rỗng, `and`, `or` và ngoặc. Nó kiểm tra dimension/value theo chính setup config đã validate. `!=` và `not in` bị từ chối: evaluator CPQA có thể xem attribute thiếu là khác giá trị, trong khi key CoverCrypt cần attribute dương để thỏa policy phủ định dạng bù. Compiler cũng từ chối so sánh thứ tự, chained comparison, phủ định đơn ngôi, literal không phải chuỗi và attribute chưa cấu hình.

## Bypass tài liệu và chế độ strict

Khi lớp ứng dụng đã cho phép bypass non-strict của administrator/owner,
`services/covercrypt_policy.py` parse policy của version thành biểu thức Boolean
dương có giới hạn, rồi chọn đúng một giá trị hợp lệ mỗi dimension để thỏa toàn
bộ biểu thức. Dimension không bị ràng buộc dùng giá trị thật hợp lệ hoặc giá trị
cấu hình xác định. Assignment chỉ dùng cấp khóa tạm, không sửa thuộc tính/policy
trong DB. Biểu thức mâu thuẫn, sai cấu hình/cú pháp hoặc quá phức tạp bị từ chối.
Helper này không tự cấp quyền ở lớp ứng dụng.

Khóa bypass dùng namespace `covercrypt_bypass_v1` riêng, kèm user, assignment,
fingerprint authority và backend. Khi bật `SUPER_ADMIN_REQUIRE_POLICY`, admin
phải qua document authorization và dùng thuộc tính thật trong namespace strict,
kể cả khi là owner. User thường không nhận assignment thỏa policy trừ khi có
quyền owner bypass hiện hữu áp dụng rõ ràng.

## Discovery có phân quyền

Sau `start.py initdata`, super administrator có thể xem setup document được sinh qua `GET /api/admin/covercrypt/configuration/`. Endpoint yêu cầu authentication và `IsSuperAdmin`; đây là API được hỗ trợ để review JSON. Client không query database trực tiếp.

Cùng service đã validate có thể chạy qua lệnh operator:

```text
python manage.py covercrypt_config
```

Lệnh in setup JSON canonical và fingerprint. Nó không setup plugin và không ghi Vault.

## Fingerprint và keyset manifest

CPQA fingerprint JSON setup canonical cùng version các `AttributeDefinition` nguồn. Fingerprint đổi khi dimension được tạo hoặc version schema nguồn thay đổi.

Operator có thể kiểm tra keyset đã ghi hoặc khôi phục public metadata khớp authority:

```text
python manage.py covercrypt_config --check-vault --keyset-id primary --vault-mount abe_covercrypt
python manage.py covercrypt_config --reconcile-vault --keyset-id primary --vault-mount abe_covercrypt
```

Với môi trường CoverCrypt mới, `start.py initdata` khởi tạo authority sau khi
seed dimensions. Nếu đã seed, chạy
`python manage.py covercrypt_config --initialize-vault --keyset-id primary --vault-mount abe_covercrypt`
trong web container. Raft có thể cần vài phút. Upload cần authority đã sẵn sàng.
Nếu setup bị gián đoạn, dùng reconcile cho authority hiện có. Nếu không đọc
được authority, guard vẫn được giữ lại.

Manifest không secret được lưu dưới key `COVERCRYPT_KEYSET_MANIFEST_<keyset-id>` trong Vault KV path đã cấu hình. Nó liên kết authority với fingerprint, version definition nguồn và mount. Mismatch sẽ fail closed; không gọi `setup` hoặc ghi đè authority.

Backup giữ Vault data path, mount, keyset ID, manifest và schema nguồn. Recovery khôi phục authority/manifest tương ứng rồi chạy `--check-vault`. Không export MSK vào Django hay backup metadata.

## Rotation giữ khả năng đọc lịch sử

Mount ban đầu là `abe_covercrypt/` và `VAULT_SECRET_PATH` mặc định là
`secret/data/crypto_access`. Manifest primary chỉ định mount đang dùng.
Trước khi đổi danh mục thuộc tính, chạy `--check-vault --keyset-id primary` và
ghi lại fingerprint public key hiện hành. Sao lưu Vault Raft, registry trong KV
và unseal material tương ứng. Bố trí thời gian tạm dừng ghi nếu đổi danh mục
thuộc tính. Mã hóa mới bị chặn khi schema chưa khớp authority.

1. Chọn mount chưa dùng, ví dụ `abe_covercrypt_20261115`. Chạy
   `python manage.py covercrypt_config` với cấu hình dự kiến và lưu riêng đối
   tượng `configuration.config` vào `covercrypt.json`.
2. Dùng quyền operator Vault và plugin contract v1 để tạo mount riêng. Chọn
   trạng thái ký phù hợp với file mới.

   ```sh
   vault secrets enable -path=abe_covercrypt_20261115 vault-plugin-abe
   vault write abe_covercrypt_20261115/setup scheme=covercrypt mode=hybridized \
     config_json=@covercrypt.json pqc=true create_only=true public_key_format=reference
   ```

3. Cấp quyền ứng dụng gọi `authority`, `encrypt`, `genkey` và `decrypt` trên
   mount mới. Giữ quyền gọi `authority`, `genkey` và `decrypt` trên từng mount
   lịch sử. Chạy lệnh bằng danh tính được phép ghi vào KV đã cấu hình.

   ```sh
   python manage.py covercrypt_config --rotate-vault --keyset-id primary \
     --vault-mount abe_covercrypt_20261115 --expected-fingerprint OLD_FINGERPRINT
   python manage.py covercrypt_config --check-vault --keyset-id primary
   ```

4. Xác minh upload/download file mới, download version lịch sử, và trường hợp
   từ chối user thiếu thuộc tính. Giữ đúng authority và verifier mà mỗi
   version đang tham chiếu.

Khi chuyển mount, CPQA cập nhật bản ghi primary và lưu public metadata cũ vào
`COVERCRYPT_AUTHORITY_HISTORY_v1` trong một lần ghi nguyên tử. Registry tra theo
fingerprint và revision. CPQA dùng mount tương ứng để tạo user key và giải mã.
Dùng mount riêng cho rotation. Chạy `setup` hoặc `add_dimension` tại chỗ sẽ đổi
identity. Nếu mount bị mất, khôi phục từ bản sao Vault tương ứng. Sau rotation,
version CoverCrypt thiếu identity cần operator recovery. User vẫn cần thuộc
tính còn hiệu lực và hợp lệ trong dimensions lịch sử. Xem [hướng dẫn contract Vault](covercrypt-vault-contract.md).

## Khôi phục một version file

Chọn **Restore** trong lịch sử version hoặc gửi
`POST /api/storage/files/<id>/restore_version/` với `{"version_number": 1}`.
Owner hoặc admin cần quyền cập nhật tài liệu và phải vượt qua các bước kiểm
tra quyền đọc và giải mã. Version nguồn phải cũ hơn, dùng cùng policy, scheme
và backend với version hiện tại. Nếu version hiện tại có chữ ký thì nguồn cũng
phải có chữ ký. Khi hai authority CoverCrypt khác nhau, tên dimensions phải
trùng và các tập giá trị lịch sử phải là tập con của tập hiện tại. Sau khi
giải mã và quét mã độc, CPQA ghi lại đúng bytes nguồn đã xác minh thành version
mới với metadata mật mã và chữ ký của nguồn.
