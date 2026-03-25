# David's connect PWA

Routes:
- `/` users authentication page
- `/69c3de35-f164-832e-ae50-fdf6bc0939f9` first-time admin setup, then admin login only
- `/app` user home
- `/chat/<user_id>` chat screen
- `/settings` profile and invite settings
- `/admin/dashboard` admin control panel

Files:
- `app.db` user data
- `admin.db` admin data
- `Procfile` and `wsgi.py` for Gunicorn deployment
- `requirements.txt` for install

Notes:
- The admin route is intentionally hidden and does not load the PWA manifest/service worker.
- Set a strong `SECRET_KEY` in production.
- The standalone logo is saved outside the app bundle as `logo.png`.

Admin path:
`69c3de35-f164-832e-ae50-fdf6bc0939f9`
