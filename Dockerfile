FROM python:3.13.5-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates
ADD https://astral.sh/uv/install.sh /uv-installer.sh
# Run the installer then remove it
RUN sh /uv-installer.sh && rm /uv-installer.sh
ENV PATH="/root/.local/bin/:$PATH"

ADD pyproject.toml /code/pyproject.toml
ADD uv.lock /code/uv.lock
WORKDIR /code
RUN uv sync --locked


ADD . /code

ENV PATH="/code/.venv/bin:$PATH"

#CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]
CMD ["uv", "run", "/code/app/main.py"]