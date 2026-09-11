import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage

message = EmailMessage()
message['From'] = 'sender@attacktrace.lab'
message['To'] = 'receiver@attacktrace.lab'
message['Subject'] = 'Isolated DMZ service verification'
message.set_content('Synthetic coursework test only. ' + datetime.now(timezone.utc).isoformat())
with smtplib.SMTP('192.168.60.50', 25, timeout=5) as smtp:
    print('EHLO:', smtp.ehlo())
    print('Rejected recipients:', smtp.send_message(message))
    print('SMTP message accepted by DMZ mail server')
