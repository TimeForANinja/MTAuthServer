FROM python:3.14-alpine

WORKDIR /app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# install dependencies
COPY ./requirements.txt .
RUN pip install -r requirements.txt

COPY ./mtauthserver ./mtauthserver

EXPOSE 8080
CMD ["gunicorn", "--workers", "5", "--threads", "2",  "--bind", "0.0.0.0:8080", "mtauthserver.app:app"]
