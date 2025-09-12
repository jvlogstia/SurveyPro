# SurveyCraft Pro — Flask + SQLite (secure baseline)

## Quickstart
```bash
cd surveycraft_flask
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit if needed
flask --app app.py init-db
python app.py
```
Visit: http://127.0.0.1:8000/

## Notes
- Security headers & CSP provided by Flask-Talisman. For production, host JS/CSS locally and tighten CSP.
- Auth endpoints:
  - POST /auth/signup  {name,email,password}
  - POST /auth/login   {email,password}
  - POST /auth/logout
- Surveys:
  - POST /api/surveys  {"title": "My Survey"}
  - GET  /api/surveys
- Share:
  - POST /api/share/generate {"survey_id": 1}
