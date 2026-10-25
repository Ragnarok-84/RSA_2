import os
import re

print("--- ĐANG KIỂM TRA MỐI QUAN HỆ GIỮA CÁC FILE ---")

# Lấy tất cả các file .py có trong dự án
for root, dirs, files in os.walk('.'):
    for file in files:
        if file.endswith('.py') and file != 'check_link.py':
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Tìm các dòng gọi file khác (import ...)
                    imports = re.findall(r'^(?:import|from)\s+([a-zA-Z0-9_\.]+)', content, re.MULTILINE)
                    if imports:
                        # Lọc lại tên các module nội bộ trong dự án
                        internal_imports = [imp for imp in imports if not imp in ['os', 'sys', 'math', 'random', 'hashlib', 'base64', 'json', 'time', 'datetime']]
                        if internal_imports:
                            print(f"📁 File '{file_path}' đang gọi tới các file/thư viện: {set(internal_imports)}")
            except Exception as e:
                pass

print("--- HOÀN TẤT KIỂM TRA ---")
