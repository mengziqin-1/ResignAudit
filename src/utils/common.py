import os
import re
import hashlib
from datetime import datetime, timedelta

def get_file_hash(file_path, hash_type='md5', chunk_size=8192):
    hash_obj = hashlib.new(hash_type)
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def format_file_size(size):
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"

def is_night_time(dt):
    return 0 <= dt.hour < 6

def is_work_time(dt):
    return 9 <= dt.hour < 18

def get_date_range_days(days):
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    return start_date, end_date

def sanitize_filename(filename):
    return re.sub(r'[\\/:*?"<>|]', '_', filename)

def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
    return directory

def merge_dicts(*dicts):
    result = {}
    for d in dicts:
        result.update(d)
    return result

def remove_duplicates(lst, key='file_path'):
    seen = set()
    result = []
    for item in lst:
        if isinstance(item, dict):
            value = item.get(key)
        else:
            value = str(item)
        
        if value not in seen:
            seen.add(value)
            result.append(item)
    return result

def sort_by_timestamp(lst, timestamp_key='timestamp'):
    return sorted(lst, key=lambda x: x.get(timestamp_key, datetime.min) if isinstance(x, dict) else datetime.min)

def filter_by_date_range(lst, start_date, end_date, timestamp_key='timestamp'):
    result = []
    for item in lst:
        if isinstance(item, dict):
            timestamp = item.get(timestamp_key)
            if timestamp and start_date <= timestamp <= end_date:
                result.append(item)
    return result