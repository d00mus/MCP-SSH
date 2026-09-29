# MCP SSH Gateway

**SSH-терминалы для ИИ-агентов, которые знают, когда команда закончилась.**

Шесть инструментов, настоящие оболочки с состоянием, код возврата в ту же секунду, когда команда завершилась, и ответы, по которым может действовать даже небольшая модель. Одна прямая зависимость (`paramiko`), никаких демонов, ничего в облаке.

[![CI](https://github.com/d00mus/MCP-SSH/actions/workflows/ci.yml/badge.svg)](https://github.com/d00mus/MCP-SSH/actions/workflows/ci.yml) [![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/) [![PyPI](https://img.shields.io/pypi/v/mcp-ssh-gateway.svg)](https://pypi.org/project/mcp-ssh-gateway/) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[English](README.md) · Русский

## Почему именно он

- **Он знает, когда команда закончилась.** Об окончании и коде возврата сообщает сама оболочка, поэтому `echo hi` возвращается за миллисекунды, упавшая команда отвечает `exit_code: 2`, а трёхминутная сборка через 10 секунд отвечает `running`, и результат забирается через `read`. Никаких `sleep` и догадок по тишине.
- **Терминалы с состоянием.** Сессия — это одна настоящая оболочка: `cd`, переменные и виртуальные окружения сохраняются между вызовами. `run` без `session_id` открывает новую оболочку, так что ничего не делится случайно.
- **Сделан для небольших моделей.** Шесть инструментов, всего около 1,6 тыс. токенов описаний. Каждая остановка подсказывает, что делать дальше (`hint`), пейджеры отключены, индикатор прогресса занимает одну строку, на неверный аргумент приходит ответ с названием правильного вызова, а длинный вывод отдаётся страницами (`has_more`, `tail`, `offset`).
- **Вопросы не подвешивают сеанс.** `Continue? [y/N]`, запрос пароля или незакрытая кавычка возвращают `waiting_input`. Агент отвечает через `signal` или нажимает Ctrl+C, а оболочка сохраняет состояние.
- **И роутеры тоже.** CLI роутера Keenetic (`show interface`, `--More--` обрабатывается) или его Linux-оболочка — теми же инструментами.
- **Проверен на настоящем `sshd`.** Контейнеры с логин-оболочками bash, BusyBox ash, zsh, dash, fish и tcsh и хост без SFTP запускаются в CI при каждом пуше.

## Быстрый старт

Нужны [uv](https://docs.astral.sh/uv/getting-started/installation/) (или Python 3.11+ и `pip`) и SSH-доступ к хосту, которым вы управляете.

**Уже есть `~/.ssh/config`?** Добавьте это в MCP-клиент, и каждый хост из файла станет сервером (вход по ключу или через ssh-agent):

```json
{
  "mcpServers": {
    "ssh": {
      "command": "uvx",
      "args": ["mcp-ssh-gateway", "--import-ssh-config"]
    }
  }
}
```

Это формат Cursor (`~/.cursor/mcp.json`) и Claude Desktop (`claude_desktop_config.json`); [другие клиенты](#другие-клиенты) описаны ниже. Перезапустите клиент и спросите: *«Покажи мои SSH-серверы и занятое место на диске на web.»*

**Нужен вход по паролю, роутер или хост только для чтения?** Напишите `servers.json`:

```json
{
  "servers": {
    "web": {"host": "192.168.1.10", "user": "deploy", "key_path": "~/.ssh/id_ed25519"},
    "router": {"host": "192.168.1.1", "user": "admin", "password": "${ROUTER_PASSWORD}"}
  }
}
```

и укажите его шлюзу: `"args": ["mcp-ssh-gateway", "--servers-config", "/absolute/path/to/servers.json"]`. Путь нужен абсолютный (клиенты запускаются не в вашей папке; в Windows обратные слэши в JSON экранируются), а переменные, на которые ссылается файл, передайте шлюзу в блоке `"env"` записи клиента. В [`servers.json.example`](https://github.com/d00mus/MCP-SSH/blob/master/servers.json.example) есть ещё и боевой хост только для чтения. Без uv: `pip install mcp-ssh-gateway` и `"command": "mcp-ssh-gateway"`.

### Другие клиенты

**Claude Code**

```bash
claude mcp add ssh --scope user -- uvx mcp-ssh-gateway --import-ssh-config
```

**VS Code** (`.vscode/mcp.json`: верхний ключ называется `servers`)

```json
{
  "servers": {
    "ssh": {"type": "stdio", "command": "uvx", "args": ["mcp-ssh-gateway", "--import-ssh-config"]}
  }
}
```

**Codex** (`~/.codex/config.toml` или `codex mcp add ssh -- uvx mcp-ssh-gateway --import-ssh-config`)

```toml
[mcp_servers.ssh]
command = "uvx"
args = ["mcp-ssh-gateway", "--import-ssh-config"]
startup_timeout_sec = 30   # при первом запуске uvx скачивает пакет
```

## Что видит агент

Ответы в том виде, в каком их получает клиент; сняты в Debian-контейнере из набора тестов (адрес хоста и цифры диска заменены примерами):

```text
server_list()
→ {"servers":[{"server":"web","host":"192.168.1.10:22","user":"deploy"}]}

run(server="web", command="df -h /")                  # без session_id: открывается новая оболочка
→ {"session_id":"web/1","status":"completed","exit_code":0,
   "output":"$ df -h /\nFilesystem      Size  Used Avail Use% Mounted on\n/dev/vda1        40G   31G  7.2G  82% /\n"}

run(session_id="web/1", command="ls /nonexistent")    # та же оболочка; ненулевой код — это результат
→ {"session_id":"web/1","status":"completed","exit_code":2,
   "output":"$ ls /nonexistent\nls: cannot access '/nonexistent': No such file or directory\n"}

run(session_id="web/1", command="read -p 'Continue? [y/N] ' a; echo got:$a")
→ {"session_id":"web/1","status":"waiting_input",
   "output":"$ read -p 'Continue? [y/N] ' a; echo got:$a\nContinue? [y/N] ",
   "hint":"The program waits for input. Answer with signal action=stdin text=..., or stop it with signal ctrl_c."}

signal(session_id="web/1", action="stdin", text="y")
→ {"session_id":"web/1","status":"completed","output":"got:y\n","exit_code":0}

run(session_id="web/1", command="seq 1 500", lines=5)  # длинный вывод приходит страницами
→ {"session_id":"web/1","status":"completed","output":"$ seq 1 500\n1\n2\n3\n4\n","exit_code":0,"has_more":496}

read(session_id="web/1", tail=3)                       # только конец
→ {"session_id":"web/1","status":"completed","output":"498\n499\n500\n","exit_code":0,"skipped_lines":493}

read(session_id="web/1", offset=-20, lines=3)          # прокрутка назад; позиция непрочитанного не двигается
→ {"session_id":"web/1","status":"completed","output":"481\n482\n483\n","exit_code":0}

run(session_id="web/1", command="sleep 30", wait=1)
→ {"session_id":"web/1","status":"running","output":"$ sleep 30\n",
   "hint":"Still running. Call read(session_id='web/1') again, or stop it with signal ctrl_c."}

signal(session_id="web/1", action="ctrl_c")
→ {"session_id":"web/1","status":"interrupted","output":"\n","process_stopped":true}
```

Ошибка в вызове получает ответ, который называет правильный вызов. Вот что читает модель, придумавшая для `run` аргумент `cwd`:

```json
{"error": "run has no argument 'cwd'. It takes: command, server, session_id, shell, wait, timeout, lines. To work in a folder, start the command with 'cd /path && '."}
```

Подсказки и тексты ошибок шлюз отдаёт модели по-английски.

| Поле | Значение |
| --- | --- |
| `status` | `completed`, `running`, `waiting_input`, `interrupted`, `timed_out`, `failed` или `idle`. |
| `exit_code` | Только при `completed`. Ненулевой код — это результат, а не ошибка инструмента. |
| `has_more` | Сколько непрочитанных строк осталось в сессии; `read` вернёт их. |
| `hint` | Что делать дальше, когда агенту иначе пришлось бы гадать. |
| `skipped_lines` | Более старые непрочитанные строки, которые пропустила новая команда или `read(tail=…)`. Ничего не потеряно: `read(offset=0)` прокручивает к ним назад. |
| `dropped_data` | Непрочитанный вывод, потерянный безвозвратно: переполнился буфер сессии (хранятся последние 4 миллиона символов). |

## Инструменты

| Инструмент | Что делает |
| --- | --- |
| `server_list` | Серверы и их открытые сессии. |
| `run` | Запускает команду. Возвращается, когда она закончилась, или через `wait` секунд (по умолчанию 10) со статусом `running`. Без `session_id` открывает новую оболочку. |
| `read` | Следующие непрочитанные строки сессии (ждёт до `wait` секунд, пока команда работает); `tail` — конец, `offset` — прокрутка назад. |
| `signal` | `stdin` отвечает на вопрос, `ctrl_c` останавливает команду, `ctrl_d` завершает её ввод. |
| `session_close` | Закрывает оболочку. Сервер допускает их немного (`max_sessions`, по умолчанию 8). |
| `file` | `list`, `read`, `write` и `edit` удалённых файлов по SFTP или через оболочку, если на хосте нет SFTP. Чтение умеет фильтровать (`contains`, `tail_lines`); правка — это замена точного текста, которую можно защитить через `expected_sha256`. |
| `server_add` | Только с `--allow-add-server`: добавляет сервер в `servers.json`. |

Сессии называются `server/N`. У оболочки есть состояние (папка, переменные), поэтому «оболочки по умолчанию» нет: `run` без `session_id` всегда открывает новую оболочку и возвращает её id, а этот id продолжает ту же оболочку. Закрывайте оболочки, которые больше не нужны.

## С чем работает

| Хост | Статус |
| --- | --- |
| Linux с логин-оболочкой bash, dash, BusyBox ash или zsh | Работает. Проверено на настоящих контейнерах с `sshd` (Debian, Alpine, входы через zsh и dash). |
| Логин-оболочка fish или tcsh | Работает с `"shell": "bash"` в `servers.json` (после входа шлюз выполняет `exec bash`). Без этой опции шлюз сразу отказывает и объясняет почему. |
| Роутер Keenetic (CLI NDM и Linux-оболочка за ним) | Работает. В тестах покрыт скриптовой имитацией, а на настоящем роутере используется каждый день. |
| Другие CLI роутеров (Cisco IOS, Junos, …) | Пока нет: [#1](https://github.com/d00mus/MCP-SSH/issues/1). Обычный вендорский CLI может заработать, но не проверялся. |
| Хосты за бастионом (`ProxyJump`) | Пока нет: [#2](https://github.com/d00mus/MCP-SSH/issues/2). `--import-ssh-config` игнорирует `ProxyJump`. |
| Windows-хосты, где SSH-оболочка — cmd или PowerShell | Не поддерживаются: шлюзу нужна POSIX-оболочка. |

Сам шлюз работает везде, где работает Python 3.11+ (Linux, macOS, Windows).

## Безопасность

У агента столько прав, сколько у SSH-учётной записи, которую вы ему дали. Всё ниже уменьшает ущерб от ошибок, но не заменяет ограниченную учётную запись.

- **Ограничители защищают от ошибок, а не от злого умысла.** `read_only` и `command_blacklist` (буквальные слова без учёта регистра) смотрят на текст команды. Приёмы оболочки, `base64` или `python -c` их обходят. Настоящую границу даёт ограниченная SSH-учётная запись: оболочка только для чтения, `ForceCommand`, отдельные учётные данные для каждого уровня доверия.
- **Локальные файлы выключены.** `local_path` (загрузка и скачивание) работает только после запуска шлюза с `--project-root <папка>` и только внутри этой папки.
- **Ключи хостов:** новый хост принимается при первом подключении, а его ключ сохраняется в `known_hosts` в каталоге кэша; изменившийся ключ отвергается. `verify_host: false` отключает проверку.
- **Секреты:** пишите в `servers.json` ссылки `${NAME}`, а не сами значения. В логах значения, похожие на пароли, замаскированы (`--log-output off` не пишет логи вообще).
- **Нет открытого порта:** шлюз говорит по MCP только через stdio. Инструмента `server_add` нет, пока вы не запустите шлюз с `--allow-add-server`, и он только добавляет.

Полная политика и как сообщить о проблеме: [SECURITY.md](SECURITY.md).

## Настройка

Поля `servers.json`: `host`, `user`, `port` (22), `key_path` (работают `~` и `${NAME}`), `password` и `key_passphrase` (заменяются только ссылки `${NAME}`, остальное берётся как написано), `verify_host` (true), `description`, `extra_path` (добавляется в `PATH`), `read_only`, `command_blacklist`, `max_sessions` (8), `shell` (POSIX-оболочка, которую надо запустить через `exec` после входа, для учётных записей с fish или tcsh). Файл перечитывается, пока шлюз работает; у неизменённых серверов сессии сохраняются.

Командная строка (обязателен только источник серверов):

| Опция | Значение |
| --- | --- |
| `--servers-config` | Путь к `servers.json` или сам JSON. Также `$SSH_SERVERS_CONFIG`; иначе `./servers.json`. |
| `--import-ssh-config` | Дополнительно предложить хосты из `~/.ssh/config` (вход по ключу или через ssh-agent). |
| `--read-only`, `--command-blacklist a,b` | Ограничители для всех серверов (или `$SSH_READ_ONLY`, `$SSH_COMMAND_BLACKLIST`). |
| `--log-output meta\|full\|off` | Что писать в лог-файлы (по умолчанию `meta`: команды и жизненный цикл). |
| `--cache-dir` | Логи и `known_hosts`. По умолчанию — пользовательский каталог кэша (`$SSH_MCP_CACHE_DIR`). |
| `--project-root` | Локальная папка, в которой инструмент `file` может читать и писать (`local_path`). Без неё локальные файлы выключены; на сервере инструмент работает. |
| `--allow-add-server`, `--allow-system-temp`, `--allow-gateway-dir` | Необязательные расширения. |

Логи: один JSON-lines-файл на сессию и один на команду в каталоге кэша; старые файлы удаляются по возрасту и размеру.

## Как это устроено

Шлюз открывает интерактивную оболочку с PTY и одной установочной строкой переводит её в тихий машиночитаемый режим: без эха и с приглашением, которое печатает маркер с кодом возврата. Когда маркер появился, команда завершена, и код возврата у агента. Так обрабатываются и синтаксические ошибки, и фоновые задачи, и Ctrl+C. Незакрытую кавычку или heredoc распознаёт второй маркер.

У роутеров, где при входе открывается вендорский CLI (Keenetic NDM), такой оболочки нет. Там шлюз узнаёт приглашение из баннера входа, убирает эхо набранной команды, нажимает пробел на `--More--` и считает стабильное приглашение концом команды. `run(shell=false)` работает с CLI, `run(shell=true)` заходит в Linux-оболочку за ним; сессия остаётся в одном режиме.

Вывод попадает в один построчный буфер на сессию с единственной позицией «непрочитанного». `run` и `read` двигают её; `tail` прыгает в конец; `offset` только смотрит. Строки длиннее 1024 символов режутся, чтобы страницы оставались предсказуемыми.

## Ограничения

- Оболочка выполняет одну команду за раз. Чтобы делать два дела одновременно, откройте две оболочки (или пусть клиент вызывает `run` параллельно).
- Оболочка, запущенная внутри сессии (`sudo -s`, `su`, `bash`), скрывает, где заканчиваются команды, поэтому шлюз говорит агенту выйти из неё. Для root используйте `sudo <команда>`.
- Пока нет промежуточных хостов ([#2](https://github.com/d00mus/MCP-SSH/issues/2)) и других CLI роутеров ([#1](https://github.com/d00mus/MCP-SSH/issues/1)).
- В шлюзе нет подтверждений, движка политик и журнала аудита. Если они нужны, смотрите ниже.

## Другие SSH-серверы для MCP

У них другие компромиссы (по состоянию на сентябрь 2026; прочитайте их README перед выбором):

- [tufantunc/ssh-mcp](https://github.com/tufantunc/ssh-mcp): безопасность прежде всего. Классификация команд, политика по ролям и хостам, подтверждение человеком, журнал аудита, `ProxyJump`, SSH CA и потоковый SFTP; 14 инструментов. Выбирайте для боевых парков, которым нужны подтверждения и аудит.
- [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server): 4 инструмента на Node (`npx`), белый список команд, SOCKS- и HTTP-прокси, режим бастиона и MFA. Выбирайте для самой простой установки на Node, если нужны прокси или MFA.
- [bvisible/mcp-ssh-manager](https://github.com/bvisible/mcp-ssh-manager): 37 инструментов, DevOps-набор с бэкапами, базами данных и мониторингом. Выбирайте, если нужны готовые сценарии.

Этот шлюз выбирает другой край: мало инструментов, оболочки с состоянием и ответ на каждую ситуацию, в которой агент застревает.

## Docker

```bash
docker build -t mcp-ssh-gateway .
docker run -i --rm \
  -v /absolute/path/to/servers.json:/app/servers.json:ro \
  -v /absolute/path/to/.ssh:/root/.ssh:ro \
  -v /absolute/path/to/cache:/app/.ssh-cache \
  mcp-ssh-gateway --servers-config /app/servers.json --cache-dir /app/.ssh-cache
```

Том с кэшем сохраняет `known_hosts` и логи между запусками.

## Разработка

```bash
pip install -r requirements.txt ruff mypy
python -m unittest discover -s tests -t .     # модульные тесты; интеграционным нужен Docker
ruff check . && mypy
```

Интеграционные тесты поднимают настоящие контейнеры с `sshd` и работают со шлюзом через ту же точку входа JSON-RPC, что и клиент. Без Docker они пропускаются сами (`MCP_SSH_IT=0` пропускает намеренно). См. [CONTRIBUTING.md](CONTRIBUTING.md) и [журнал изменений](CHANGELOG.md). Лицензия MIT.
