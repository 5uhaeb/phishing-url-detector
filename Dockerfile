FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 PORT=5000 MODEL_PATH=/app/release/current/runtime-model.joblib \
    EVALUATION_PATH=/app/release/current/evaluation.json MODEL_MMAP=1 \
    PUBLIC_FEED_KEYS=phishing_database
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 linkguard
COPY requirements.txt dependencies.lock.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r dependencies.lock.txt
COPY *.py ./
COPY templates ./templates
COPY static ./static
COPY licenses ./licenses
COPY release/current ./release/current
RUN python release.py verify && mkdir -p data/feeds && chown -R linkguard:linkguard /app
USER linkguard
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.getenv('PORT','5000')+'/health',timeout=4)"
CMD ["python", "app.py"]
