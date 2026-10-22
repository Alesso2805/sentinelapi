FROM python:3.12-slim

WORKDIR /app

# System deps for building wheels stay minimal; sentinelapi's own deps are pure Python
RUN pip install --no-cache-dir --upgrade pip

COPY pyproject.toml README.md ./
COPY sentinelapi ./sentinelapi
COPY examples ./examples

RUN pip install --no-cache-dir ".[demo,redis,postgres]"

EXPOSE 8000

CMD ["uvicorn", "examples.demo_app.main:app", "--host", "0.0.0.0", "--port", "8000"]
