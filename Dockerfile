# Используем официальный легкий образ Python
FROM python:3.11-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файл зависимостей
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем основной скрипт сервера
COPY mcp-server.py .

# Создаем директорию для кэша и логов сессий
RUN mkdir -p .ssh-cache && chmod 777 .ssh-cache

# Обозначаем, что этот контейнер будет запускать наш скрипт
# Мы используем ENTRYPOINT, чтобы аргументы командной строки передавались напрямую в скрипт
ENTRYPOINT ["python", "mcp-server.py"]
