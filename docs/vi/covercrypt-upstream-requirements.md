# Yêu cầu tích hợp cần xử lý tại upstream CoverCrypt

[English](../en/covercrypt-upstream-requirements.md)

CPQA tuân thủ contract của `Hybrid-PQ-CP-ABE-Library`. Không patch source trong
Docker, thêm endpoint riêng, diễn giải lại serialization của key hoặc bắt buộc
response field mà lib không cung cấp. Thay đổi cần thiết phải thực hiện tại dự
án lib với review, test và nguồn build/release của dự án đó.

## Các điểm chặn đã quan sát

1. **Lưu authority lớn.** Sáu dimensions có số giá trị 4/3/6/4/5/6 của ứng dụng
   đã tạo authority serialize khoảng 143 MB. `plugin/authority.go` upstream được
   đọc ghi một record JSON; Vault/Raft đã từ chối record vì giới hạn mỗi entry.
   Lib cần cơ chế lưu chính thức và test tương thích dữ liệu.
2. **Truyền public key lớn.** Phép đo native cho public key 35.952.472 byte,
   thành 47.936.632 byte khi Base64. API gốc trả key Base64 và yêu cầu gửi lại
   khi encrypt, vượt giới hạn request HTTP 32 MiB của deployment và không phù
   hợp record KV dùng chung. Lib cần quyết định giải pháp/contract chính thức;
   CPQA sẽ tích hợp theo contract đó.
3. **Setup bị gián đoạn.** Plugin đã đọc có setup, add_dimension, genkey,
   encrypt, decrypt; không có endpoint chỉ đọc để phục hồi public authority.
   Setup thay khóa. Recovery phải giữ authority, không xuất MSK/signing secret
   và không dựa vào gọi setup lần hai.
4. **Chọn chế độ ký.** Encrypt tự ký khi authority có signing key; không có
   field request `sign` hoặc response `crypto_metadata`. CPQA kiểm tra trạng
   thái ký đã biết, lưu metadata riêng của ứng dụng và từ chối request không
   khớp. Chọn ký theo từng request hoặc metadata ký do plugin xác nhận cần thay
   đổi contract tại upstream.

## Trạng thái test local từng dùng patch

Các image CPQA trước đây có patch chia nhỏ authority và reference public key do
ứng dụng tự thêm. Nay đã gỡ các patch khỏi source/build. Kết quả test trước đây
không chứng minh plugin nguyên bản đọc được dữ liệu do các patch đó tạo.

Không thay plugin patched đang chạy bằng plugin gốc trên cùng volume rồi giả
định tương thích. Giữ dữ liệu/khóa/image cũ cho tới khi dự án lib cung cấp và
kiểm thử reader/migration tương thích. CPQA từ chối encoding reference riêng cũ,
không đoán key hay gọi setup lại. Việc chỉnh contract này không bao gồm reset
dữ liệu hoặc xuất secret.

Giai đoạn 6–9 trong kế hoạch vẫn chưa hoàn tất. Deployment dùng schema lớn và
migration dữ liệu lịch sử phải xử lý ở dự án lib trước. Kiểm thử build dùng
image/container tạm riêng, không thay hoặc khởi tạo authority triển khai.
