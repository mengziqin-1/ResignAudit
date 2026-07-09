import os
import re
import shutil

def organize_reports():
    reports_dir = 'reports'
    
    if not os.path.exists(reports_dir):
        print('reports文件夹不存在')
        return
    
    files = os.listdir(reports_dir)
    
    pattern = re.compile(r'离职安全审计报告_([^_]+)_')
    
    for filename in files:
        if filename.endswith('.pdf') or filename.endswith('.html'):
            match = pattern.search(filename)
            if match:
                employee_name = match.group(1)
                employee_dir = os.path.join(reports_dir, employee_name)
                
                if not os.path.exists(employee_dir):
                    os.makedirs(employee_dir)
                
                src_path = os.path.join(reports_dir, filename)
                dst_path = os.path.join(employee_dir, filename)
                
                shutil.move(src_path, dst_path)
                print(f'移动 {filename} → {employee_name}/')
            else:
                print(f'跳过 {filename}（无法识别员工姓名）')
    
    print('\n整理完成！')

if __name__ == '__main__':
    organize_reports()
