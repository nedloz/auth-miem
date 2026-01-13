from __future__ import annotations

def send_email(to: str, subject: str, body: str) -> None:
    # Пока что выводим в консоль. Позже подключим SMTP.
    print(f"\n[EMAIL]\nTo: {to}\nSubject: {subject}\n\n{body}\n")
