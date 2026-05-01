FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY app.py backup_db.py static.css ./

EXPOSE 8000

CMD ["python", "app.py"]
