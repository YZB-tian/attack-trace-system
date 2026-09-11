#!/usr/bin/python3
import asyncio
import json
import os
import pwd
import time
import uuid

LOG_PATH = "/var/log/attacktrace/smtp-events.jsonl"
SPOOL_PATH = "/var/spool/attacktrace-mail"


def record(event):
    event["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with open(LOG_PATH, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=True) + "\n")


async def reply(writer, text):
    writer.write((text + "\r\n").encode("ascii"))
    await writer.drain()


async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername")
    source_ip = peer[0] if peer else "unknown"
    sender = ""
    recipients = []
    record({"event": "smtp_connect", "source_ip": source_ip})
    await reply(writer, "220 mail01.attacktrace.lab ESMTP ready")
    try:
        while not reader.at_eof():
            raw = await reader.readline()
            if not raw:
                break
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            command, _, value = line.partition(" ")
            command = command.upper()
            record({"event": "smtp_command", "source_ip": source_ip, "command": command, "value": value[:512]})
            if command in {"EHLO", "HELO"}:
                await reply(writer, "250-mail01.attacktrace.lab")
                await reply(writer, "250 SIZE 1048576")
            elif command == "MAIL" and value.upper().startswith("FROM:"):
                sender = value[5:].strip()
                recipients = []
                await reply(writer, "250 sender accepted")
            elif command == "RCPT" and value.upper().startswith("TO:"):
                recipients.append(value[3:].strip())
                await reply(writer, "250 recipient accepted")
            elif command == "DATA" and sender and recipients:
                await reply(writer, "354 end data with <CR><LF>.<CR><LF>")
                lines = []
                size = 0
                while size <= 1048576:
                    item = await reader.readline()
                    if item in {b".\r\n", b".\n"}:
                        break
                    if item.startswith(b".."):
                        item = item[1:]
                    lines.append(item)
                    size += len(item)
                message_id = f"{int(time.time())}-{uuid.uuid4().hex}.eml"
                message_path = os.path.join(SPOOL_PATH, message_id)
                with open(message_path, "wb") as stream:
                    stream.write(b"X-AttackTrace-Source: " + source_ip.encode("ascii", "replace") + b"\r\n")
                    stream.write(b"X-AttackTrace-From: " + sender.encode("utf-8", "replace") + b"\r\n")
                    stream.write(b"X-AttackTrace-To: " + ", ".join(recipients).encode("utf-8", "replace") + b"\r\n")
                    stream.writelines(lines)
                record({"event": "smtp_message", "source_ip": source_ip, "sender": sender,
                        "recipients": recipients, "bytes": size, "file": message_path})
                await reply(writer, "250 message queued")
            elif command == "RSET":
                sender = ""
                recipients = []
                await reply(writer, "250 reset")
            elif command == "NOOP":
                await reply(writer, "250 ok")
            elif command == "QUIT":
                await reply(writer, "221 closing connection")
                break
            else:
                await reply(writer, "500 unsupported command")
    finally:
        writer.close()
        await writer.wait_closed()
        record({"event": "smtp_disconnect", "source_ip": source_ip})


async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", 25)
    account = pwd.getpwnam("mail")
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
