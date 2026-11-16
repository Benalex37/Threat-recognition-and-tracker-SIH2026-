def fetch_message_headers(message_id: str, access_token: str) -> dict:
    return {
        "messageId": message_id,
        "subject": "Sample subject",
        "from": "sender@example.com",
        "received": [
            "from mail-wm1-f66.google.com (mail-wm1-f66.google.com [209.85.183.66]) by mx.google.com with ESMTPS id abc",
            "by 10.0.0.1 with SMTP id abc",
        ],
        "authentication-results": "spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass",
        "content-type": "text/plain",
    }


def get_profile(access_token: str) -> dict:
    return {
        "emailAddress": "user@example.com",
        "messagesTotal": 1234,
        "threadsTotal": 456,
    }
