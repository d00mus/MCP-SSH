# Используем официальный легкий образ Python
FROM python:3.11-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файл зависимостей
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код
COPY src/ ./src/

# Обозначаем, что этот контейнер будет запускать наш скрипт
ENTRYPOINT ["python", "mcp-server.py"]
