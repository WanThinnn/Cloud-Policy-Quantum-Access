# Vòng đời cấu hình CoverCrypt

[English](../en/covercrypt-configuration-lifecycle.md) · [Kế hoạch tích hợp](covercrypt-integration-plan.md) · [Contract Vault](covercrypt-vault-contract.md)

CoverCrypt setup nhận một object `config_json` dạng `{"dimensions":[...]}`. CPQA sinh JSON này từ các bản ghi enum `AttributeDefinition` active được seed trong `start.py initdata`. Không lặp lại dimension, value, mode, keyset ID hay Vault mount trong `.env`, `settings/base.py` hoặc System Settings.

Cú pháp upstream `config_json=@path/to/file.json` của Vault CLI đọc file trên máy CLI client rồi gửi text JSON trong request. Vault server không tự đọc file hoặc cấu hình mount vào. CPQA setup phải gửi JSON canonical do service schema tạo ra.

Các `AttributeDefinition` enum active thành dimension; definition chuỗi tự do như `location` bị loại. CPQA cũng tạo dimension giới hạn `user_type` từ code `UserType` active cộng với `UserProfile.USER_TYPE_CHOICES` legacy, vì policy seed dùng `user_type` lấy từ profile. Mọi dimension dùng `hierarchical: false`; schema hiện chưa có field hierarchy. `UserAttribute` unique theo `(user, attribute)`, nên mapper yêu cầu đủ một giá trị hợp lệ cho mọi dimension trước khi yêu cầu CoverCrypt user key. Giá trị sai hoặc thiếu sẽ fail closed.

Các `AccessPolicy` seed sẵn vẫn là đầu vào phân quyền và policy của CPQA. Chúng không nằm trong JSON setup authority: setup config mô tả tập attribute, còn policy compiler dịch policy expression sang grammar CoverCrypt. CRUD policy vẫn validate qua serializer hiện có; output AI chỉ là gợi ý và được kiểm tra qua cùng compiler.

Compiler hỗ trợ so sánh chuỗi bằng `==`, membership trong literal list/tuple/set không rỗng, `and`, `or` và ngoặc. Nó kiểm tra dimension/value theo chính setup config đã validate. `!=` và `not in` bị từ chối: evaluator CPQA có thể xem attribute thiếu là khác giá trị, trong khi key CoverCrypt cần attribute dương để thỏa policy phủ định dạng bù. Compiler cũng từ chối so sánh thứ tự, chained comparison, phủ định đơn ngôi, literal không phải chuỗi và attribute chưa cấu hình.

## Discovery có phân quyền

Sau `start.py initdata`, super administrator có thể xem setup document được sinh qua `GET /api/admin/covercrypt/configuration/`. Endpoint yêu cầu authentication và `IsSuperAdmin`; đây là API được hỗ trợ để review JSON. Client không query database trực tiếp.

Cùng service đã validate có thể chạy qua lệnh operator:

```text
python manage.py covercrypt_config
```

Lệnh in setup JSON canonical và fingerprint. Nó không setup plugin và không ghi Vault.

## Fingerprint và keyset manifest

CPQA fingerprint JSON setup canonical cùng version các `AttributeDefinition` nguồn. Fingerprint đổi khi dimension được tạo hoặc version schema nguồn thay đổi.

Khi triển khai provision, operator truyền rõ keyset ID và mount đã duyệt:

```text
python manage.py covercrypt_config --write-manifest --keyset-id <keyset-id> --vault-mount <mount>
python manage.py covercrypt_config --check-vault --keyset-id <keyset-id> --vault-mount <mount>
```

Manifest không secret được lưu dưới key `COVERCRYPT_KEYSET_MANIFEST_<keyset-id>` trong Vault KV path đã cấu hình. Nó liên kết authority với fingerprint, version definition nguồn và mount. Mismatch sẽ fail closed; không gọi `setup` hoặc ghi đè authority.

Backup giữ Vault data path, mount, keyset ID, manifest và schema nguồn. Recovery khôi phục authority/manifest tương ứng rồi chạy `--check-vault`. Không export MSK vào Django hay backup metadata.

Xem mọi thay đổi fingerprint là không tương thích cho đến khi được review. Mở rộng dimension theo hỗ trợ upstream thì dùng `add_dimension`, sau đó cập nhật manifest. Với thay đổi không tương thích, provision mount/keyset mới và giữ keyset cũ cho ciphertext lịch sử. Không gọi setup trên authority đã có vì upstream setup sẽ thay thế authority.
