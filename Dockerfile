FROM python:3.12.3-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt update --fix-missing && apt install -y --no-install-recommends gcc

WORKDIR /usr/src/chakra

RUN python -m pip install --upgrade pip

COPY ./requirements.txt /usr/src/chakra/

RUN pip install -r requirements.txt

COPY . .

ARG USERNAME=noob
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

USER $USERNAME

EXPOSE 8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
