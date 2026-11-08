# Build thư viện native và Vault plugin từ source upstream

[English](../en/crypto-source-build.md)

CPQA chỉ cấu hình URL GitHub upstream qua `CRYPTO_REPOSITORY` trong
`docker/Dockerfile`. Không ghim tag, commit hoặc version thư viện. Mỗi lần build,
Docker lấy **HEAD mới nhất của nhánh mặc định upstream**, rồi build native library
và Vault plugin từ checkout đó bằng Makefile upstream (`make vault`, phụ thuộc
`make shared`). Không lưu binary, header hay source plugin trong `src/`.

## Clone, build và update

```bash
git clone https://github.com/WanThinnn/Cloud-Policy-Quantum-Access.git
cd Cloud-Policy-Quantum-Access
# Chuẩn bị .env và chứng chỉ theo hướng dẫn deployment hiện có.
python start.py build
python start.py up
# Cập nhật CPQA, lấy source crypto mới nhất, build rồi recreate các service:
python start.py update
```

Đặt `--prod` trước command để dùng Compose production. Cả dev và prod đều build
web/Vault từ source. Prod dùng image local `cpqa-web:local`, `cpqa-vault:local`;
bước pull bỏ qua service có cấu hình build. Luôn chạy build trước up sau clone.

Clone CPQA chỉ tải CPQA. Docker mới tải source thư viện trong bước build, nên
không cần checkout thư viện bên cạnh hoặc toolchain C++/Rust/Go trên host. Build
lần đầu cần mạng, dung lượng cho toolchain và nhiều thời gian hơn lần dùng cache.
Docker Linux AMD64 là nền tảng được hỗ trợ hiện tại.

## Cache và đồng bộ artifact

BuildKit lấy Git source bằng `ADD --keep-git-dir=true`, resolve HEAD mỗi lần build
và dùng commit thực tế làm định danh cache. Commit upstream mới sẽ build lại
crypto dù CPQA không đổi; không cần `--no-cache` để refresh source. HEAD không
đổi thì tái sử dụng stage crypto. Cache Cargo/Go giảm thời gian build tiếp theo.
`CRYPTO_BUILD_JOBS` trong môi trường Compose điều khiển số job (default 4; có thể
giảm còn 2 trên máy ít RAM).
Resolve HEAD upstream mới nhất vẫn cần mạng kể cả khi có cache build.

Stage `crypto-builder` chung cung cấp artifact cho targets `web`, `vault` và
`crypto-artifacts`. Native `.so` và plugin lấy từ cùng checkout của stage này.
Commit/version thực tế được ghi **sau build** vào `/opt/cpqa/crypto/source.env`
để tra cứu; đây là metadata đầu ra, không phải cấu hình ghim source. Có thể đổi
URL upstream bằng Docker build argument `CRYPTO_REPOSITORY`.

Native library web nằm ở `/opt/cpqa/crypto/lib`, ngoài bind mount `/app` của dev.
`CPABE_LIBRARY_DIR` nối consumer ctypes tới đó. Không còn anonymous volume
`/app/lib`. Mỗi lần start, Vault entrypoint cập nhật executable và `.so` tương
ứng trong volume plugin để volume cũ không che artifact của image mới. Web đọc
executable đó để đăng ký đúng SHA256 với Vault.

Update chạy git pull --ff-only và build trước khi recreate các service. Lỗi build
dừng trước up. Không tải ZIP release, sửa CGO path hay ghi đè source plugin local.
Giữ nguyên Vault data, credentials, trust roots, master keys, mounts AC17/TKN20
và public keys KV. Upstream 6.0.0 có nhánh đọc storage plugin cũ trong
`plugin/authority.go`; việc theo HEAD không chứng minh mọi version tương lai đều
tương thích dữ liệu deployment. Không gọi setup để thử nâng cấp trên authority
đang có dữ liệu.

CPQA không patch source, header, ABI, endpoint hoặc storage của upstream.
Trước Makefile gốc, build kiểm tra tracked source còn khớp HEAD. `source.env`
ghi `CRYPTO_CPQA_PATCHES=none` cùng repository/commit/version thực tế. Thay đổi
cần thiết ở lib phải thực hiện và kiểm thử tại dự án lib, không chèn khi build
ứng dụng. Xem [yêu cầu upstream](covercrypt-upstream-requirements.md).

## Kiểm thử và export

```bash
docker build --platform linux/amd64 --target crypto-test -f docker/Dockerfile -t cpqa-crypto-test:latest .
docker build --platform linux/amd64 --target vault -f docker/Dockerfile -t cpqa-vault-test:latest .
python tests/smoke_crypto_image.py --image cpqa-vault-test:latest
python -m unittest discover -s tests -p test_crypto_build.py -v
```

`crypto-test` chạy native tests và Go backend tests upstream với crypto thật và
dữ liệu giả trong build container. Smoke test tự tạo/xóa container Vault riêng,
kiểm tra HTTP AC17/TKN20/CoverCrypt có/không chữ ký, allow/deny và thay artifact cũ. Không
dùng DB/Vault/storage/volume deployment. Các kiểm tra này không chứng minh đọc
được mọi ciphertext thực tế trong deployment.

Upstream v6.0.0 có CoverCrypt native và Vault plugin adapter. Vault setup cần
`config_json` mô tả dimensions của authority; native setup đọc file JSON đã cấu
hình qua `HCPABE_COVERCRYPT_CONFIG`. Cả hai có CoverCrypt mode `classic`,
`post_quantum`, `hybridized`. Flag Vault `pqc` tùy chọn điều khiển chữ ký ML-DSA,
tách biệt với CoverCrypt KEM mode.

CPQA tích hợp CoverCrypt bằng dimensions đã validation từ thuộc tính CSDL đang
hoạt động, policy compiler giới hạn, scheme metadata theo file và backend Vault
hoặc native theo cấu hình deployment. Chỉ build artifact upstream chưa khởi tạo
authority ứng dụng hoặc cấu hình dimensions lấy từ CSDL. Xem [hướng dẫn vòng đời
CoverCrypt](covercrypt-configuration-lifecycle.md), [kế hoạch tích hợp](covercrypt-integration-plan.md)
và [contract upstream](covercrypt-vault-contract.md).

Hai helper `scripts/build_plugin_for_docker.sh` và `.ps1` export target
`crypto-artifacts` vào `build/crypto/`, gồm `lib/`, `plugin/`, `source.env`. Chạy
Python native trên Windows vẫn cần build Makefile upstream cho Windows; đặt
`CPABE_LIBRARY_DIR` trỏ tới `lib/` chứa DLL chính và `libcpabe_tkn20.dll`. Artifact
Linux trong Docker không thay thế DLL Windows.
