#!/usr/bin/env sh
set -eu

PROGRAM_NAME="multitest"
PREFIX="${MULTITEST_PREFIX:-/usr/local}"
DEFAULT_SCRIPT_URL="https://raw.githubusercontent.com/SirScroogee/vpn-server-multitest/main/server_audit.py"
SCRIPT_URL="${MULTITEST_SCRIPT_URL:-$DEFAULT_SCRIPT_URL}"
INSTALL_DEPENDENCIES=1
TEMP_SCRIPT=""

show_help() {
    cat <<'EOF'
Установка Server Suitability Audit как команды multitest.

Использование:
  sudo sh install.sh
  sudo sh install.sh --skip-deps
  curl -fsSL https://raw.githubusercontent.com/SirScroogee/vpn-server-multitest/main/install.sh | sudo sh

Параметры:
  --skip-deps          не устанавливать системные программы
  --script-url URL     скачать server_audit.py по указанному HTTPS-адресу
  --prefix PATH        установить в другой prefix (по умолчанию /usr/local)
  -h, --help           показать эту справку
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --skip-deps)
            INSTALL_DEPENDENCIES=0
            ;;
        --script-url)
            shift
            [ "$#" -gt 0 ] || { echo "После --script-url нужен URL" >&2; exit 2; }
            SCRIPT_URL="$1"
            ;;
        --prefix)
            shift
            [ "$#" -gt 0 ] || { echo "После --prefix нужен путь" >&2; exit 2; }
            PREFIX="$1"
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Неизвестный параметр: $1" >&2
            show_help >&2
            exit 2
            ;;
    esac
    shift
done

install_dependencies() {
    [ "$INSTALL_DEPENDENCIES" -eq 1 ] || return 0

    echo "Устанавливаю программы для сетевых и системных тестов..."
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y python3 iputils-ping mtr-tiny traceroute iperf3 openssl procps iproute2 curl ca-certificates
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 iputils mtr traceroute iperf3 openssl procps-ng iproute curl ca-certificates
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3 iputils mtr traceroute iperf3 openssl procps-ng iproute curl ca-certificates
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache python3 iputils mtr traceroute iperf3 openssl procps iproute2 curl ca-certificates
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --needed --noconfirm python iputils mtr traceroute iperf3 openssl procps-ng iproute2 curl ca-certificates
    else
        echo "Пакетный менеджер не распознан; зависимости не установлены автоматически." >&2
        echo "Сам скрипт будет установлен, а недостающие программы он покажет перед тестом." >&2
    fi
}

find_source_script() {
    installer_dir=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd || pwd)
    local_script="$installer_dir/server_audit.py"
    if [ -f "$local_script" ]; then
        SOURCE_SCRIPT="$local_script"
        return 0
    fi

    if [ -z "$SCRIPT_URL" ]; then
        echo "Рядом с install.sh не найден server_audit.py." >&2
        echo "Запустите установщик из клонированного репозитория или передайте --script-url." >&2
        exit 1
    fi
    case "$SCRIPT_URL" in
        https://*) ;;
        *) echo "--script-url должен начинаться с https://" >&2; exit 2 ;;
    esac
    command -v curl >/dev/null 2>&1 || { echo "Для загрузки нужен curl" >&2; exit 1; }
    TEMP_SCRIPT=$(mktemp)
    curl -fL "$SCRIPT_URL" -o "$TEMP_SCRIPT"
    SOURCE_SCRIPT="$TEMP_SCRIPT"
}

cleanup() {
    if [ -n "$TEMP_SCRIPT" ] && [ -f "$TEMP_SCRIPT" ]; then
        rm -f "$TEMP_SCRIPT"
    fi
}
trap cleanup EXIT HUP INT TERM

install_dependencies
find_source_script

APP_DIR="${MULTITEST_APP_DIR:-$PREFIX/lib/multitest}"
BIN_DIR="${MULTITEST_BIN_DIR:-$PREFIX/bin}"
mkdir -p "$APP_DIR" "$BIN_DIR"
install -m 0755 "$SOURCE_SCRIPT" "$APP_DIR/server_audit.py"
ln -sfn "$APP_DIR/server_audit.py" "$BIN_DIR/$PROGRAM_NAME"

python3 "$APP_DIR/server_audit.py" --version >/dev/null

echo
echo "Готово: команда $PROGRAM_NAME установлена."
echo "Запуск: $PROGRAM_NAME"
echo "Версия: $($BIN_DIR/$PROGRAM_NAME --version)"
