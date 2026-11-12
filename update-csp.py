#!/usr/bin/env python3
"""อัปเดต Content Security Policy ใน index.html ให้ตรงกับโค้ด <script> ภายในไฟล์

ทุกครั้งที่แก้โค้ด JavaScript ใน index.html ต้องรันสคริปต์นี้ใหม่ ไม่เช่นนั้นเบราว์เซอร์จะไม่ยอมรันโค้ดที่แก้
    python3 update-csp.py
"""
import base64, hashlib, re, pathlib

path = pathlib.Path(__file__).with_name('index.html')
html = path.read_text(encoding='utf-8')

# hash ของ <script> แบบฝังในไฟล์ (ไม่มี src)
inline = re.findall(r'<script>(.*?)</script>', html, flags=re.S)
hashes = ["'sha256-%s'" % base64.b64encode(hashlib.sha256(s.encode('utf-8')).digest()).decode() for s in inline]

# อนุญาตเฉพาะไฟล์ไลบรารีที่ระบุ URL เต็ม (ซึ่งมี integrity กำกับไว้แล้ว)
externals = re.findall(r'<script src="(https://[^"]+)"', html)
worker = re.search(r"url: '(https://[^']+pdf\.worker[^']*)'", html).group(1)

policy = '; '.join([
    "default-src 'none'",
    'script-src ' + ' '.join(hashes + externals),
    "style-src 'unsafe-inline' https://fonts.googleapis.com",
    'font-src https://fonts.gstatic.com data: blob:',
    'img-src data: blob:',
    'connect-src ' + worker + ' data: blob:',
    'worker-src blob:',
    'frame-src blob:',
    'child-src blob:',
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
])

new, n = re.subn(r'(<meta http-equiv="Content-Security-Policy" content=")[^"]*(">)',
                 lambda m: m.group(1) + policy + m.group(2), html, count=1)
if not n:
    raise SystemExit('ไม่พบแท็ก Content-Security-Policy ใน index.html')
path.write_text(new, encoding='utf-8')
print('อัปเดต CSP แล้ว: %d inline script, %d ไลบรารี' % (len(hashes), len(externals)))
