import threading
import time
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template
from flask_socketio import SocketIO
import subprocess
import re
import asyncio
from bleak import BleakScanner, BleakClient, BleakError
import bluetooth
import pytz

# Assuming SERVICE_UUIDS is imported or defined here
# from uuids import SERVICE_UUIDS
# For completeness, include it if needed, but assume it's there.

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
socketio = SocketIO(app)

# Конфигурация
CONFIG = {
    'scan_interval': 5,  # Интервал сканирования в секундах
    'cleanup_timeout': 3600,  # Время хранения старых устройств в секундах (60 мин)
    'wifi_interface': 'wlan0',  # Интерфейс Wi-Fi
}

# Хранилище устройств
devices = {}
devices_lock = threading.Lock()


def get_service_name(uuid):
    """Получить имя сервиса по UUID"""
    uuid_lower = uuid.lower()
    return SERVICE_UUIDS.get(uuid_lower, uuid)

def check_bluetooth_security(mac):
    """Улучшенная проверка безопасности Bluetooth устройства с использованием bluetoothctl"""
    try:
        result = subprocess.run(
            ['bluetoothctl', 'info', mac],
            capture_output=True,
            text=True,
            timeout=5
        )

        output = result.stdout.lower()
        security = 'Unknown'

        if 'paired: yes' in output:
            security = 'Paired (Secure)'
        elif 'bonded: yes' in output:
            security = 'Bonded (Secure)'
        elif 'trusted: yes' in output:
            security = 'Trusted (Secure)'
        else:
            security = 'Unpaired'

        # Дополнительная проверка на legacy pairing или secure connections
        if 'legacy pairing: yes' in output:
            security += ' - Legacy Pairing (Potentially Vulnerable)'
        elif 'secure connections: yes' in output:
            security += ' - Secure Connections'
        elif 'legacy pairing: no' in output:
            security += ' - Secure Simple Pairing Supported'

        return security
    except Exception as e:
        logger.error(f"Error checking BT security for {mac}: {e}")
        return 'Unknown'

async def check_ble_security(device):
    """Улучшенная проверка безопасности BLE устройства с подключением для сканирования служб и проверки доступа"""
    security = 'Unknown'
    services = []

    public_services = [
        '00001800-0000-1000-8000-00805f9b34fb',  # GAP
        '00001801-0000-1000-8000-00805f9b34fb'   # GATT
    ]

    try:
        async with BleakClient(device.address) as client:
            is_connected = await client.connect(timeout=5)
            if is_connected:
                # Получаем службы
                ble_services = await client.get_services()
                services = [get_service_name(str(s.uuid)) for s in ble_services.services.values()]

                # Heuristic for protected services
                protected_heuristic = any(
                    'secure' in name.lower() or 'auth' in name.lower() or 'bond' in name.lower()
                    for name in services
                )

                # Improved check: try to read a non-public characteristic
                access_secure = False
                has_readable_char = False
                for service in ble_services.services.values():
                    if str(service.uuid) in public_services:
                        continue
                    for char in service.characteristics:
                        if 'read' in char.properties:
                            has_readable_char = True
                            try:
                                await client.read_gatt_char(char.uuid)
                                # If read succeeds without pairing, open access
                            except BleakError as read_err:
                                error_str = str(read_err).lower()
                                if 'authentication' in error_str or 'encryption' in error_str or 'permission' in error_str:
                                    access_secure = True
                                break
                    if access_secure:
                        break

                if access_secure:
                    security = 'Authentication Required (Secure)'
                elif has_readable_char:
                    security = 'Open Access (Unsecure)'
                elif protected_heuristic:
                    security = 'Protected Services (Secure)'
                else:
                    security = 'Open Services (Unsecure)'

                # Additional metadata check
                if device.metadata.get('pairing_required', False):
                    security += ' - Pairing Required'
                elif device.metadata.get('paired', False):
                    security = 'Paired (Secure)'
                elif device.metadata.get('bonded', False):
                    security = 'Bonded (Secure)'

            else:
                # Fallback to metadata
                if device.metadata.get('paired', False):
                    security = 'Paired (Secure)'
                elif device.metadata.get('bonded', False):
                    security = 'Bonded (Secure)'
                uuids = device.metadata.get('uuids', [])
                if any(uuid.lower() in public_services for uuid in uuids):
                    security = 'Secure Connection Required'
                else:
                    security = 'Open (Unsecure)'

    except Exception as e:
        logger.error(f"Error checking BLE security for {device.address}: {e}")
        security = 'Unknown'

    return security, services

def freq_to_channel(freq):
    """Преобразование частоты в канал Wi-Fi"""
    if 2412 <= freq <= 2484:
        return (freq - 2412) // 5 + 1
    elif freq == 2484:
        return 14
    elif 5170 <= freq <= 5825:
        return (freq - 5170) // 5 + 34
    else:
        return 0

def parse_wifi_scan(output):
    """Парсинг результатов сканирования Wi-Fi с улучшенной проверкой безопасности"""
    wifi_devices = {}
    current_bss = None

    for line in output.splitlines():
        line = line.strip()

        if line.startswith('BSS'):
            match = re.search(r'BSS (\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2})', line)
            if match:
                current_bss = match.group(1) + "_wifi"
                wifi_devices[current_bss] = {
                    'type': 'wifi',
                    'last_seen': datetime.now().isoformat(),
                    'last_detected': datetime.now().isoformat(),
                    'ssid': 'Hidden',
                    'channel': 0,
                    'security': 'Open (Unsecure)',
                    'rssi': -100,
                    'online': True
                }

        elif current_bss:
            if 'freq:' in line:
                match = re.search(r'freq: (\d+)', line)
                if match:
                    freq = int(match.group(1))
                    wifi_devices[current_bss]['channel'] = freq_to_channel(freq)

            elif 'SSID:' in line:
                match = re.search(r'SSID: (.+)', line)
                if match:
                    wifi_devices[current_bss]['ssid'] = match.group(1).strip()

            elif 'signal:' in line:
                match = re.search(r'signal: ([-0-9.]+) dBm', line)
                if match:
                    wifi_devices[current_bss]['rssi'] = float(match.group(1))

            # Улучшенная проверка безопасности
            elif 'RSN:' in line:
                wifi_devices[current_bss]['security'] = 'WPA2/WPA3 (Secure)'
            elif 'WPA:' in line:
                wifi_devices[current_bss]['security'] = 'WPA (Legacy Secure)'
            elif 'capability: privacy' in line:
                wifi_devices[current_bss]['security'] = 'WEP (Vulnerable)'

    return wifi_devices

def wifi_scan():
    """Сканирование Wi-Fi устройств"""
    while True:
        try:
            result = subprocess.run(
                ['sudo', 'iw', 'dev', CONFIG['wifi_interface'], 'scan'],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                wifi_devices = parse_wifi_scan(result.stdout)
                with devices_lock:
                    for mac in list(devices.keys()):
                        if devices[mac]['type'] == 'wifi':
                            devices[mac]['online'] = False
                    for mac, info in wifi_devices.items():
                        if mac in devices:
                            devices[mac].update(info)
                        else:
                            devices[mac] = info
            else:
                logger.warning(f"Wi-Fi scan failed with code {result.returncode}")
        except Exception as e:
            logger.error(f"Wi-Fi scan error: {e}")
        time.sleep(CONFIG['scan_interval'])

def bt_scan():
    """Сканирование Bluetooth устройств"""
    while True:
        try:
            nearby_devices = bluetooth.discover_devices(
                duration=8,
                lookup_names=True,
                flush_cache=True,
                lookup_class=True
            )
            current_time = datetime.now().isoformat()
            with devices_lock:
                for mac in list(devices.keys()):
                    if devices[mac]['type'] == 'bt':
                        devices[mac]['online'] = False
                for addr, name, device_class in nearby_devices:
                    mac = addr + "_bt"
                    security = check_bluetooth_security(addr)
                    # Get services via SDP
                    try:
                        sdp_services = bluetooth.find_service(address=addr)
                        services = [rec.get('name', 'Unknown') for rec in sdp_services]
                    except:
                        services = []
                    info = {
                        'type': 'bt',
                        'last_seen': current_time,
                        'last_detected': current_time,
                        'name': name or 'Unknown',
                        'protocol': 'BT Classic',
                        'security': security,
                        'class': device_class,
                        'services': services,
                        'online': True
                    }
                    if mac in devices:
                        devices[mac].update(info)
                    else:
                        devices[mac] = info
        except Exception as e:
            logger.error(f"BT scan error: {e}")
        time.sleep(CONFIG['scan_interval'])

async def ble_discover():
    """Обнаружение BLE устройств"""
    return await BleakScanner.discover(return_adv=True, scanning_mode="active")

def ble_scan():
    """Сканирование BLE устройств"""
    while True:
        try:
            discovered_devices = asyncio.run(ble_discover())
            with devices_lock:
                for mac in list(devices.keys()):
                    if devices[mac]['type'] == 'ble':
                        devices[mac]['online'] = False
                for device, adv_data in discovered_devices.values():
                    mac = device.address + "_ble"
                    security, services = asyncio.run(check_ble_security(device))
                    current_time = datetime.now().isoformat()
                    info = {
                        'type': 'ble',
                        'last_seen': current_time,
                        'last_detected': current_time,
                        'name': device.name or 'Unknown',
                        'protocol': 'BLE',
                        'security': security,
                        'rssi': adv_data.rssi,
                        'services': services,
                        'online': True
                    }
                    if mac in devices:
                        devices[mac].update(info)
                    else:
                        devices[mac] = info
        except Exception as e:
            logger.error(f"BLE scan error: {e}")
        time.sleep(CONFIG['scan_interval'])

def background_scanner():
    """Запуск сканеров в фоновых потоках"""
    threading.Thread(target=wifi_scan, daemon=True).start()
    threading.Thread(target=bt_scan, daemon=True).start()
    threading.Thread(target=ble_scan, daemon=True).start()

@app.route('/')
def index():
    """Главная страница"""
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    """Обработка WebSocket подключения"""
    threading.Thread(target=send_device_updates).start()

def send_device_updates():
    """Отправка обновлений устройств через SocketIO"""
    while True:
        with devices_lock:
            sorted_devices = sorted(
                devices.items(),
                key=lambda x: ('0' if x[1]['online'] else '1') + ":" + x[1]['type'] + ":" + x[1].get('name', '-')
            )
            devices_dict = {mac: info for mac, info in sorted_devices}
            socketio.emit('devices_update', devices_dict)
        time.sleep(1)

def cleanup_old_devices():
    """Очистка старых устройств"""
    while True:
        now = datetime.now()
        with devices_lock:
            for mac in list(devices.keys()):
                last_seen = datetime.fromisoformat(devices[mac]['last_seen'])
                if (now - last_seen).total_seconds() > CONFIG['cleanup_timeout']:
                    del devices[mac]
        time.sleep(60)

if __name__ == '__main__':
    background_scanner()
    threading.Thread(target=cleanup_old_devices, daemon=True).start()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
