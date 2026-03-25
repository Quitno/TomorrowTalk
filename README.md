# David's Connect

A mobile-first Flask chat app starter with:

- invite/code-based joining
- unique email enforcement
- login/register flow
- admin bootstrap and admin dashboard
- chat threads, edit/delete, chat deletion, theme per chat
- avatar upload
- PWA install prompt and service worker cache
- password hashing with Werkzeug `scrypt`
- message encryption at rest with Fernet/AES-based cryptography

## Run

```bash
pip install -r requirements.txt
python app.py
```

Open:

- `/` for sign in / sign up
- `/app` for the chat UI
- `/admin` for admin bootstrap / admin dashboard

## Notes

- The app uses standard cryptography instead of a custom encryption scheme.
- Voice/video call UI is included as a scaffold; full multi-user realtime calling needs a separate signaling layer.
- Change the admin bootstrap secret in `app.py` before deploying.
