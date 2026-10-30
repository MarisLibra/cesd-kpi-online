# CESD KPI Online – bản triển khai thử nghiệm

Mã gốc dựa trên `cesd_kpi_python.py`, bổ sung giao diện website, Chủ hệ thống, quản trị tài khoản, thu hồi token, mật khẩu, khóa nội dung và nhật ký.

## Chạy tại máy cá nhân

1. Tạo môi trường Python 3.12, cài `pip install -r requirements.txt`.
2. Đặt biến `JWT_SECRET` (chuỗi ngẫu nhiên dài), `CESD_ADMIN_EMAIL` và `CESD_ADMIN_PASSWORD` trước **lần chạy đầu**. Không để mật khẩu thật trong mã nguồn hoặc commit .env.
3. Trong thư mục này chạy `uvicorn cesd_kpi_python:app --host 127.0.0.1 --port 8000`.
4. Mở http://127.0.0.1:8000, đăng nhập bằng tài khoản chủ hệ thống vừa tạo. Vào **Nhân sự** để khai báo các tổ/phòng, chức danh, cấp tài khoản. Có thể vào `/docs` để thao tác KPI chuyên sâu.

## Đưa lên Internet (Render, Railway, VPS hoặc Cloud Run)

1. Tạo dịch vụ triển khai Docker từ thư mục này.
2. Tạo **PostgreSQL có sao lưu**; gán `DATABASE_URL=postgresql+psycopg://...`.
3. Cấu hình `JWT_SECRET`, `CESD_ADMIN_EMAIL`, `CESD_ADMIN_PASSWORD` là biến môi trường bí mật; không công khai.
4. Cấu hình HTTPS, gắn domain và chỉ dùng 1 cơ sở dữ liệu chung. Dùng volume bền vững cho `CESD_UPLOAD_DIR`, hoặc thay lưu tệp bằng object storage riêng tư. Container không có volume sẽ mất tệp tải lên khi tái triển khai.
5. Truy cập URL nhà cung cấp cấp. Không mở cổng PostgreSQL ra Internet công cộng.

## Quyền
- **owner**: chủ hệ thống (khởi tạo lần đầu từ biến môi trường), cấp admin và các cấp khác, thu hồi phiên, reset mật khẩu, khóa nội dung.
- **admin**: quản trị dữ liệu, nhân sự và KPI nhưng không tạo admin hay khóa nội dung.
- **manager**: quản lý phòng được gán; phải gán `department_managers` bằng `/docs` sau khi tạo tài khoản.
- **user**: xem và thao tác đối tượng thuộc quyền.

## Các giới hạn quan trọng trước khi sử dụng thực tế
- Đây là phiên bản **MVP chưa qua kiểm thử xâm nhập**, không bảo đảm tương đương Supabase RLS. Chưa có MFA, email mời tài khoản, khôi phục mật khẩu tự động, rate limit theo IP, migrations Alembic, kiểm thử tải, quy trình sao lưu tự động hay bảo vệ chống sửa/xóa log ở cấp cơ sở dữ liệu.
- Giao diện web hỗ trợ nghiệp vụ cơ bản. Một số thao tác KPI chuyên sâu vẫn dùng `/docs`; việc chấm KPI đầy đủ cần mở rộng giao diện.
- Khi dùng PostgreSQL, phải quản lý quyền DB, sao lưu và phân tách vai trò người dùng DB; không dùng SQLite cho nhiều người ghi đồng thời qua Internet.
- Không đưa dữ liệu nhân sự thật lên máy chủ dùng chung khi chưa thiết lập HTTPS, bảo mật hosting, sao lưu và kiểm tra phân quyền.
