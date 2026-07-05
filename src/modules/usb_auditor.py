import os
import re
import json
try:
    import winreg
except ImportError:
    winreg = None
import pandas as pd
from datetime import datetime

class USBAuditor:
    def __init__(self):
        self.usb_devices = []
        self.usb_operations = []
    
    def audit_usb_devices(self, progress_callback=None, mock_json_path=None):
        self.usb_devices = []
        self.usb_operations = []

        if mock_json_path and os.path.exists(mock_json_path):
            self._load_mock_usb_events(mock_json_path)
            if progress_callback:
                progress_callback(f"USB使用记录样本解析完成，共发现 {len(self.usb_devices)} 个设备事件、{len(self.usb_operations)} 条操作")
            return self.usb_devices, self.usb_operations

        if winreg is None:
            if progress_callback:
                progress_callback("当前环境不支持 Windows 注册表读取，已跳过真实 USB 注册表审计")
            return self.usb_devices, self.usb_operations
        
        try:
            self._scan_usbstor_registry(progress_callback)
        except Exception:
            pass
        
        try:
            self._scan_usb_registry(progress_callback)
        except Exception:
            pass
        
        try:
            self._scan_portable_devices(progress_callback)
        except Exception:
            pass
        
        try:
            self._scan_usb_operation_logs(progress_callback)
        except Exception:
            pass
        
        return self.usb_devices, self.usb_operations

    def _load_mock_usb_events(self, mock_json_path):
        with open(mock_json_path, 'r', encoding='utf-8') as f:
            events = json.load(f)

        for event in events:
            event_time = self._parse_event_time(event.get('event_time'))
            device_info = {
                'device_path': mock_json_path,
                'device_type': 'MOCK_USB_STORAGE',
                'first_insert_time': event_time,
                'last_insert_time': event_time,
                'device_name': event.get('device_name', '未知USB设备'),
                'vendor_id': '',
                'product_id': '',
                'serial_number': event.get('serial_number', ''),
                'event_type': event.get('event_type', 'unknown'),
                'timestamp': event_time or datetime.now()
            }
            self.usb_devices.append(device_info)

            if event.get('event_type') in ('copy', 'write', 'archive_copy'):
                file_count = int(event.get('file_count', 1) or 1)
                self.usb_operations.append({
                    'operation_type': event.get('event_type'),
                    'device_id': event.get('serial_number', ''),
                    'device_info': event.get('description', ''),
                    'file_count': file_count,
                    'timestamp': event_time or datetime.now()
                })

    def _parse_event_time(self, value):
        if not value:
            return None
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y/%m/%d %H:%M:%S'):
            try:
                return datetime.strptime(str(value), fmt)
            except ValueError:
                continue
        return None
    
    def _scan_usbstor_registry(self, progress_callback=None):
        try:
            reg_path = r'SYSTEM\CurrentControlSet\Enum\USBSTOR'
            hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
            
            try:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(hkey, i)
                        subkey_path = f'{reg_path}\\{subkey_name}'
                        self._parse_usbstor_subkey(subkey_path)
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(hkey)
        except WindowsError:
            pass
    
    def _parse_usbstor_subkey(self, subkey_path):
        try:
            hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path)
            
            try:
                j = 0
                while True:
                    try:
                        device_id = winreg.EnumKey(hkey, j)
                        device_path = f'{subkey_path}\\{device_id}'
                        device_info = self._get_device_info(device_path)
                        if device_info:
                            self.usb_devices.append(device_info)
                        j += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(hkey)
        except WindowsError:
            pass
    
    def _get_device_info(self, device_path):
        try:
            hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_path)
            
            try:
                info = {
                    'device_path': device_path,
                    'device_type': 'USB_STORAGE',
                    'first_insert_time': None,
                    'last_insert_time': None,
                    'device_name': '',
                    'vendor_id': '',
                    'product_id': '',
                    'serial_number': ''
                }
                
                try:
                    device_name, _ = winreg.QueryValueEx(hkey, 'FriendlyName')
                    info['device_name'] = device_name
                except WindowsError:
                    pass
                
                match = re.match(r'USBSTOR\\([^\\]+)\\([^\\]+)', device_path)
                if match:
                    info['vendor_id'] = match.group(1)
                    info['serial_number'] = match.group(2)
                
                try:
                    first_install, _ = winreg.QueryValueEx(hkey, 'DeviceInstallDate')
                    info['first_insert_time'] = self._parse_registry_time(first_install)
                except WindowsError:
                    pass
                
                try:
                    last_access, _ = winreg.QueryValueEx(hkey, 'LastAccessTime')
                    info['last_insert_time'] = self._parse_registry_time(last_access)
                except WindowsError:
                    pass
                
                return info
            finally:
                winreg.CloseKey(hkey)
        except WindowsError:
            return None
    
    def _scan_usb_registry(self, progress_callback=None):
        try:
            reg_path = r'SYSTEM\CurrentControlSet\Enum\USB'
            hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
            
            try:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(hkey, i)
                        subkey_path = f'{reg_path}\\{subkey_name}'
                        self._parse_usb_subkey(subkey_path)
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(hkey)
        except WindowsError:
            pass
    
    def _parse_usb_subkey(self, subkey_path):
        try:
            hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path)
            
            try:
                j = 0
                while True:
                    try:
                        device_id = winreg.EnumKey(hkey, j)
                        device_path = f'{subkey_path}\\{device_id}'
                        device_info = self._get_usb_device_info(device_path)
                        if device_info:
                            self.usb_devices.append(device_info)
                        j += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(hkey)
        except WindowsError:
            pass
    
    def _get_usb_device_info(self, device_path):
        try:
            hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_path)
            
            try:
                info = {
                    'device_path': device_path,
                    'device_type': 'USB_DEVICE',
                    'first_insert_time': None,
                    'last_insert_time': None,
                    'device_name': '',
                    'vendor_id': '',
                    'product_id': '',
                    'serial_number': ''
                }
                
                try:
                    device_name, _ = winreg.QueryValueEx(hkey, 'FriendlyName')
                    info['device_name'] = device_name
                except WindowsError:
                    pass
                
                match = re.match(r'USB\\([^&]+)&([^\\]+)\\([^\\]+)', device_path)
                if match:
                    info['vendor_id'] = match.group(1)
                    info['product_id'] = match.group(2)
                    info['serial_number'] = match.group(3)
                
                try:
                    first_install, _ = winreg.QueryValueEx(hkey, 'DeviceInstallDate')
                    info['first_insert_time'] = self._parse_registry_time(first_install)
                except WindowsError:
                    pass
                
                return info
            finally:
                winreg.CloseKey(hkey)
        except WindowsError:
            return None
    
    def _scan_portable_devices(self, progress_callback=None):
        try:
            reg_path = r'SOFTWARE\Microsoft\Windows Portable Devices\Devices'
            hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
            
            try:
                i = 0
                while True:
                    try:
                        device_id = winreg.EnumKey(hkey, i)
                        device_path = f'{reg_path}\\{device_id}'
                        self._parse_portable_device(device_path)
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(hkey)
        except WindowsError:
            pass
    
    def _parse_portable_device(self, device_path):
        try:
            hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_path)
            
            try:
                info = {
                    'device_path': device_path,
                    'device_type': 'PORTABLE_DEVICE',
                    'first_insert_time': None,
                    'last_insert_time': None,
                    'device_name': '',
                    'vendor_id': '',
                    'product_id': '',
                    'serial_number': ''
                }
                
                try:
                    device_name, _ = winreg.QueryValueEx(hkey, 'FriendlyName')
                    info['device_name'] = device_name
                except WindowsError:
                    pass
                
                info['serial_number'] = os.path.basename(device_path)
                
                return info
            finally:
                winreg.CloseKey(hkey)
        except WindowsError:
            pass
    
    def _scan_usb_operation_logs(self, progress_callback=None):
        try:
            reg_path = r'SYSTEM\CurrentControlSet\Services\usbhub\Enum'
            hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
            
            try:
                i = 0
                while True:
                    try:
                        value_name = winreg.EnumKey(hkey, i)
                        try:
                            value, _ = winreg.QueryValueEx(hkey, value_name)
                            self.usb_operations.append({
                                'operation_type': 'HUB_ENUM',
                                'device_id': value_name,
                                'device_info': value,
                                'timestamp': datetime.now()
                            })
                        except WindowsError:
                            pass
                        i += 1
                    except OSError:
                        break
            finally:
                winreg.CloseKey(hkey)
        except WindowsError:
            pass
    
    def _parse_registry_time(self, time_value):
        if isinstance(time_value, str):
            try:
                return datetime.strptime(time_value, '%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                try:
                    return datetime.strptime(time_value, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    return None
        elif isinstance(time_value, bytes):
            try:
                return datetime.fromtimestamp(int.from_bytes(time_value, 'little'))
            except:
                return None
        return None
    
    def get_usb_insertions_count(self, days=30):
        cutoff_date = datetime.now() - pd.Timedelta(days=days)
        count = 0
        for device in self.usb_devices:
            if device['last_insert_time'] and device['last_insert_time'] >= cutoff_date:
                count += 1
        return count
    
    def get_usb_file_copies(self):
        total = 0
        for operation in self.usb_operations:
            total += int(operation.get('file_count', 1) or 1)
        return total
    
    def get_summary(self):
        return {
            'total_devices': len(self.usb_devices),
            'device_types': {},
            'recent_insertions': self.get_usb_insertions_count(30),
            'operation_count': len(self.usb_operations)
        }
