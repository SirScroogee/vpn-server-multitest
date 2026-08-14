# Подготовка и безопасная установка Remnawave Node

Подробный практический гайд для нового Linux VPS. Он рассчитан на отдельную
Remnawave-ноду, через которую будет проходить пользовательский VPN-трафик. Панель
Remnawave уже должна быть установлена на другом сервере.

Гайд актуален на 14 августа 2026 года. Перед установкой новой версии Remnawave
сверяйтесь с [официальной документацией](https://docs.rw/install/remnawave-node/).

## Что получится в конце

- обновлённый Ubuntu/Debian;
- отдельный администратор с доступом по SSH-ключу;
- firewall, открывающий только SSH, VPN-порты и Node API для IP панели;
- Docker с Compose;
- работающий контейнер Remnawave Node;
- автоматические обновления безопасности ОС;
- ограниченные по размеру журналы;
- понятная процедура проверки, обновления, резервного копирования и восстановления.

## Важные обозначения

В командах ниже заменяйте значения на свои:

| Значение | Пример | Что это |
|---|---:|---|
| `NODE_IP` | `198.51.100.20` | публичный IP новой ноды |
| `PANEL_IP` | `203.0.113.10` | публичный IP сервера Remnawave Panel |
| `SSH_PORT` | `22` | реальный порт SSH на ноде |
| `NODE_PORT` | `2222` | внутренний API Remnawave Node для панели |
| `VPN_TCP_PORT` | `443` | публичный TCP-порт inbound из Config Profile |
| `VPN_UDP_PORT` | `443` | публичный UDP-порт, только если он нужен профилю |

Адреса из диапазонов `198.51.100.0/24` и `203.0.113.0/24` являются примерами. Не
копируйте их в реальную конфигурацию.

> **Главное правило:** не закрывайте root/password-доступ и не включайте firewall,
> пока не проверили вход по ключу в отдельном SSH-окне. Сохраните доступ к аварийной
> консоли VPS у провайдера.

## Этап 1. Соберите данные и сделайте точку восстановления

До изменения сервера подготовьте:

1. IP новой ноды.
2. IP панели. Если панель находится за Cloudflare, нужен адрес, **с которого панель
   реально подключается к ноде**, а не IP прокси Cloudflare для сайта.
3. SSH-порт.
4. Node Port из формы создания ноды.
5. Все TCP/UDP-порты inbound из выбранного Config Profile.
6. Доступ к веб-консоли/Rescue Mode хостинга.
7. Snapshot чистого VPS, если провайдер поддерживает snapshots.

Проверьте, где вы находитесь и под каким пользователем работаете:

```bash
whoami
hostnamectl
cat /etc/os-release
uname -r
uname -m
ip -br address
```

Этот гайд предназначен для актуальных Ubuntu/Debian на `x86_64` или `arm64`. По
официальным требованиям Remnawave Node достаточно 1 vCPU и 1 ГБ RAM, но для реального
многопользовательского трафика разумнее начинать с 2 vCPU и 2 ГБ RAM. Основная нагрузка
создаётся Xray-core, поэтому нужные ресурсы зависят от трафика, протокола и числа
одновременных соединений.

## Этап 2. Проверьте VPS через `multitest`

Установите наш тестер:

```bash
curl -fsSL https://raw.githubusercontent.com/SirScroogee/vpn-server-multitest/main/install.sh | sudo sh
multitest
```

Для первой оценки запустите пункт `2 — Быстрая предварительная проверка`. Если IP и
сеть выглядят нормально, запустите пункт `1 — Полная проверка сервера`. Отдельно полезны:

| Пункт | Проверка | На что смотреть |
|---:|---|---|
| 3 | Ping | выберите 200 запросов; важны средняя задержка, потери и стабильность |
| 4 | MTR | смотрите прежде всего на потери и задержку конечного хопа |
| 8 | iperf3 TCP | upload/download с 1 и 4 потоками, скорость и TCP-повторы |
| 10 | Длительный тест | нет ли провалов спустя несколько минут и burst-лимита |
| 11 | Система/CPU/crypto | CPU steal, AES, ChaCha, RAM и заполнение Conntrack |
| 12 | Диск | отсутствие ошибок и нормальная запись журналов |
| 13 | IP | страна, ASN, провайдер, hosting/proxy/abuse-сигналы |
| 14 | Сервисы | нужны ли вам Gemini, ChatGPT, Google, Spotify и другие сервисы |
| 15 | DPI | нет ли признаков фильтрации нужных направлений |
| 16 | DNS | доступны ли обычные DNS, DoH и DoT |

### Как принимать решение

- **Ping:** для ближайшего региона меньше — лучше. Нулевые потери являются нормальной
  целью; повторяющиеся потери от 1% уже требуют перепроверки. Один ping не показывает
  стабильность, поэтому используйте 200 запросов.
- **MTR:** потери только на промежуточном хопе часто означают ограничение ICMP самим
  маршрутизатором. Проблема убедительнее, если потери продолжаются до конечного адреса.
- **iperf3:** один поток хорошо показывает качество одного TCP-соединения, четыре потока
  — доступную суммарную полосу. Проверяйте обе стороны. Публичная точка сама может быть
  перегружена, поэтому слабый результат и TCP-повторы перепроверяйте на другой точке и
  в другое время.
- **Длительный тест:** скорость и задержка не должны резко ухудшаться через несколько
  минут. Такое ухудшение может указывать на перегрузку хоста или burst-ограничение тарифа.
- **CPU steal:** меньше 2% — хорошо; 2–5% — повод перепроверить вечером; 5% и выше —
  плохой сигнал о конкуренции с соседними VPS.
- **Шифрование:** от 1500 Мбит/с — хорошо, 500–1499 Мбит/с — предупреждение, меньше
  500 Мбит/с — слабый CPU для заметной VPN-нагрузки. Это короткий benchmark, а не
  гарантированная скорость VPN.
- **Conntrack:** заполнение меньше 70% нормально, 70–89% требует внимания, 90% и выше
  опасно для новых соединений.
- **IP:** один флаг `hosting` или `proxy` не означает автоматический отказ. Важнее
  фактическая доступность нужных сервисов, правильная страна и отсутствие множества
  независимых abuse-сигналов.

Ping/MTR, запущенные на VPS, показывают путь **от VPS к цели**, а не путь клиента до
VPS. Для окончательной оценки желательно проверить задержку до ноды из предполагаемых
регионов пользователей.

Не продолжайте установку, если наблюдаются постоянные потери, сильный CPU steal,
регулярные провалы скорости, неверная страна IP или недоступен критически важный для вас
сервис. Смена VPS обычно быстрее и надёжнее попыток «исправить» плохой маршрут программно.

## Этап 3. Обновите систему

На свежем сервере:

```bash
sudo apt update
sudo apt full-upgrade
sudo apt install -y sudo ca-certificates curl openssl jq nano ufw logrotate unattended-upgrades
```

Если обновление сообщает о необходимости перезагрузки:

```bash
test -f /var/run/reboot-required && cat /var/run/reboot-required
sudo reboot
```

После перезагрузки подключитесь снова и убедитесь, что система обновилась:

```bash
uname -r
apt list --upgradable
```

На уже работающей ноде сначала сделайте backup и планируйте `full-upgrade` на окно
обслуживания. Не перезагружайте сразу все ноды одного региона.

## Этап 4. Настройте отдельного администратора и SSH-ключ

Если провайдер выдал только `root`, создайте отдельного пользователя:

```bash
sudo adduser nodeadmin
sudo usermod -aG sudo nodeadmin
```

На своём компьютере создайте ключ Ed25519, если его ещё нет:

```bash
ssh-keygen -t ed25519
```

Передайте публичный ключ на сервер. В Linux/macOS обычно используется:

```bash
ssh-copy-id -p 22 nodeadmin@NODE_IP
```

В PuTTY ключ можно создать через PuTTYgen. Публичную часть добавьте одной строкой в
`/home/nodeadmin/.ssh/authorized_keys`, а приватную храните только на своём компьютере.
Правильные права на сервере:

```bash
sudo chown -R nodeadmin:nodeadmin /home/nodeadmin/.ssh
sudo chmod 700 /home/nodeadmin/.ssh
sudo chmod 600 /home/nodeadmin/.ssh/authorized_keys
```

Откройте **второе** окно терминала и проверьте вход:

```bash
ssh -p 22 nodeadmin@NODE_IP
sudo -v
```

Первое root-соединение пока не закрывайте.

### Отключение небезопасных способов входа

Только после успешной проверки ключа создайте файл:

```bash
sudo nano /etc/ssh/sshd_config.d/99-node-hardening.conf
```

Содержимое:

```text
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
MaxAuthTries 3
AllowUsers nodeadmin
```

Проверьте синтаксис **до** перезагрузки SSH:

```bash
sudo sshd -t
sudo sshd -T | grep -E 'pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|permitrootlogin|allowusers'
sudo systemctl reload ssh
```

Снова откройте новое SSH-соединение. Если оно не работает, отмените изменения из старой
сессии или через консоль провайдера.

Менять порт 22 только ради безопасности необязательно: ключи, запрет паролей и firewall
важнее. Если провайдер уже использует другой порт, везде указывайте его фактическое
значение.

## Этап 5. Включите базовый firewall

Сначала узнайте, какие процессы уже слушают сеть:

```bash
sudo ss -lntup
```

Установите переменные для своей конфигурации:

```bash
SSH_PORT=22
PANEL_IP="203.0.113.10"
NODE_PORT=2222
VPN_TCP_PORT=443
```

Создайте правила. Сначала обязательно разрешите SSH:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow "${SSH_PORT}/tcp" comment 'SSH'
sudo ufw allow from "${PANEL_IP}" to any port "${NODE_PORT}" proto tcp comment 'Remnawave Panel to Node API'
sudo ufw allow "${VPN_TCP_PORT}/tcp" comment 'Xray inbound TCP'
sudo ufw enable
sudo ufw status verbose
```

UDP открывайте только если конкретный inbound его использует:

```bash
VPN_UDP_PORT=443
sudo ufw allow "${VPN_UDP_PORT}/udp" comment 'Xray inbound UDP'
```

Если inbound-портов несколько, добавьте отдельное правило для каждого. Не открывайте
диапазон `1:65535` и не разрешайте Node Port всему интернету.

После включения firewall снова проверьте вход в новом SSH-окне. Аналогичные правила
создайте во внешнем firewall/security group в панели хостинг-провайдера, если он есть.

> Docker предупреждает, что контейнерные порты, опубликованные через `ports:`, могут
> обходить часть правил UFW. Официальный compose Remnawave Node использует
> `network_mode: host`, но после каждого изменения всё равно проверяйте реальные
> слушающие порты через `ss` и доступность с другого компьютера.

## Этап 6. Установите Docker и Compose

Remnawave требует Docker Engine и Compose plugin. Простой официальный способ:

```bash
curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
less /tmp/get-docker.sh
sudo sh /tmp/get-docker.sh
rm /tmp/get-docker.sh
```

В `less` нажмите `q`, чтобы выйти после просмотра. Затем:

```bash
sudo systemctl enable --now docker
sudo docker version
sudo docker compose version
sudo docker run --rm hello-world
```

Не добавляйте обычного администратора в группу `docker` без необходимости: членство в
этой группе фактически даёт root-доступ. Для обслуживания используйте `sudo docker ...`.

## Этап 7. Создайте ноду в Remnawave Panel

В панели откройте:

```text
Nodes → Management → + Create new node
```

Заполните:

- страну;
- внутреннее понятное имя;
- IP или домен ноды;
- `Node Port`, например `2222`.

`Node Port` используется панелью для управления нодой. Клиенты к нему не подключаются.
Нажмите `Copy docker-compose.yml`. Используйте именно конфигурацию, созданную вашей
панелью: в ней находятся согласованные `NODE_PORT` и `SECRET_KEY`.

## Этап 8. Установите Remnawave Node

Создайте каталог. Сам compose позже будет доступен только `root`, потому что содержит
секрет:

```bash
sudo install -d -m 755 /opt/remnanode
cd /opt/remnanode
sudo touch /opt/remnanode/docker-compose.yml
sudo chmod 600 /opt/remnanode/docker-compose.yml
sudo nano docker-compose.yml
```

Вставьте compose из панели, сохраните файл и ограничьте доступ:

```bash
sudo chmod 600 /opt/remnanode/docker-compose.yml
sudo docker compose config --quiet
```

Команда проверки должна завершиться без ошибок. Не публикуйте `docker-compose.yml` в
GitHub, чатах или отчётах: внутри находится секрет ноды.

Убедитесь, что firewall уже разрешает `NODE_PORT` только с `PANEL_IP`, а все порты
inbound из будущего Config Profile открыты для клиентов. Затем запустите контейнер:

```bash
cd /opt/remnanode
sudo docker compose pull
sudo docker compose up -d
sudo docker compose ps
sudo docker compose logs --tail 100
```

Вернитесь в форму создания ноды в панели, нажмите `Next`, выберите нужный Config Profile
и завершите создание. Через несколько секунд нода должна стать доступной, а панель —
показать версии Node и Xray-core.

Для Reality отдельный TLS-сертификат на ноде обычно не требуется. Если Config Profile
использует обычный TLS-транспорт, настройте сертификаты по официальной инструкции
Remnawave: панель должна получить файлы и передать их ноде. Не устанавливайте Certbot на
каждую ноду автоматически, если выбранная схема его не требует.

## Этап 9. Проверьте порты и состояние

На ноде:

```bash
sudo docker compose -f /opt/remnanode/docker-compose.yml ps
sudo docker compose -f /opt/remnanode/docker-compose.yml logs --tail 100
sudo ss -lntup
sudo ufw status numbered
```

Проверьте следующее:

| Проверка | Ожидаемый результат |
|---|---|
| Remnawave Panel | нода отображается подключённой |
| `docker compose ps` | контейнер работает и не перезапускается циклически |
| Node Port с панели | доступен |
| Node Port с постороннего IP | закрыт или отфильтрован |
| VPN TCP/UDP-порты | доступны клиентам согласно Config Profile |
| SSH | доступен только предусмотренным способом |
| Остальные входящие порты | закрыты |

Проверку портов лучше выполнять с другого сервера или компьютера: проверка собственного
публичного IP с самой ноды может зависеть от hairpin-маршрутизации провайдера.

После этого подключите тестового пользователя к ноде и проверьте:

1. Устанавливается ли VPN-соединение.
2. Меняется ли внешний IP клиента на IP ноды.
3. Открываются ли обычные сайты.
4. Работают ли DNS, IPv4 и, если настроен, IPv6.
5. Нет ли утечки DNS относительно выбранной схемы.
6. Отображается ли трафик пользователя в панели.

## Этап 10. Ограничьте рост журналов

Минимально настройте ротацию Docker-логов для сервиса `remnanode`. В блок сервиса в
`docker-compose.yml` можно добавить:

```yaml
logging:
  driver: json-file
  options:
    max-size: "10m"
    max-file: "5"
```

После изменения обязательно:

```bash
cd /opt/remnanode
sudo docker compose config --quiet
sudo docker compose up -d
```

Если в Xray Config Profile включена запись access/error logs в файлы, примонтируйте
`/var/log/remnanode` согласно официальной документации и создайте отдельное правило
`logrotate`. Без ротации файловые логи могут заполнить диск.

Контролируйте объём:

```bash
sudo docker system df
sudo du -sh /var/lib/docker /var/log 2>/dev/null
df -h
```

Не запускайте по расписанию `docker system prune -a`: оно может удалить нужные образы и
усложнить быстрый откат.

## Этап 11. Включите обновления безопасности ОС

На Ubuntu security-обновления обычно уже включены. Проверьте:

```bash
sudo systemctl status unattended-upgrades --no-pager
systemctl list-timers 'apt-daily*'
sudo dpkg-reconfigure unattended-upgrades
```

Логи находятся в:

```text
/var/log/unattended-upgrades/
```

Не включайте автоматическую перезагрузку одиночной ноды без продуманного окна
обслуживания. Security-пакеты ОС можно устанавливать автоматически, а обновления
Remnawave/Docker-образа лучше проводить контролируемо, по одной ноде.

## Этап 12. Необязательные оптимизации

### BBR

Сначала посмотрите доступные алгоритмы:

```bash
sysctl net.ipv4.tcp_available_congestion_control
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.default_qdisc
```

Если ядро поддерживает BBR, можно создать `/etc/sysctl.d/99-vpn-node.conf`:

```text
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
```

Применение и проверка:

```bash
sudo sysctl --system
sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc
```

BBR не исправляет плохой маршрут и не гарантирует прирост для каждого протокола. Сделайте
iperf3 и длительный тест до и после изменения. Не копируйте большие случайные наборы
`sysctl` из интернета: завышенные буферы и Conntrack могут зря расходовать память.

### Swap

Проверьте:

```bash
free -h
swapon --show
```

Для VPS с 1–2 ГБ RAM небольшой swap может спасти процесс от немедленного OOM, но он не
заменяет RAM и не ускоряет ноду. Если память регулярно уходит в swap, нужен более мощный
тариф или разбор причины.

### Fail2ban

При отключённых SSH-паролях его польза меньше, но он может сократить шум в логах:

```bash
sudo apt install fail2ban
sudo nano /etc/fail2ban/jail.d/sshd.local
```

Пример содержимого; замените `22` на фактический SSH-порт:

```ini
[sshd]
enabled = true
port = 22
maxretry = 5
findtime = 10m
bantime = 1h
```

Примените и проверьте:

```bash
sudo systemctl restart fail2ban
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
```

Если используется нестандартный SSH-порт, сначала настройте его в jail. Fail2ban не
заменяет SSH-ключи и firewall.

## Этап 13. Финальная проверка после перезагрузки

Перезагрузите ноду в окно обслуживания:

```bash
sudo reboot
```

После подключения:

```bash
systemctl is-active ssh
systemctl is-active docker
sudo docker compose -f /opt/remnanode/docker-compose.yml ps
sudo ufw status verbose
sudo ss -lntup
timedatectl status
df -h
free -h
```

Проверьте тестового VPN-пользователя и состояние ноды в панели. Затем снова запустите:

```bash
multitest
```

Полезно повторить пункты `3`, `8`, `10`, `11`, `14` и `16`. Результаты должны быть не
хуже первоначальных; CPU steal, потери, Conntrack и свободное место не должны переходить
в предупреждение.

## Регулярное обслуживание

### Раз в неделю

```bash
sudo docker compose -f /opt/remnanode/docker-compose.yml ps
sudo docker compose -f /opt/remnanode/docker-compose.yml logs --tail 100
df -h
free -h
sudo ufw status
```

Просматривайте состояние и трафик ноды в панели.

### Обновление Remnawave Node

Сначала сохраните compose:

```bash
sudo install -d -m 700 /root/remnanode-backups
sudo cp -a /opt/remnanode/docker-compose.yml "/root/remnanode-backups/docker-compose.yml.$(date +%Y%m%d-%H%M%S)"
```

Затем обновите одну ноду:

```bash
cd /opt/remnanode
sudo docker compose config --quiet
sudo docker compose pull
sudo docker compose up -d
sudo docker compose ps
sudo docker compose logs --tail 100
```

Проверьте подключение пользователя и панель. Только после этого обновляйте следующую
ноду. Не используйте бесконтрольное автоматическое обновление всех контейнеров.

### Что сохранять в backup

- `/opt/remnanode/docker-compose.yml`;
- дополнительные geo-файлы и сертификаты, если вы их подключали;
- SSH/firewall/logrotate-настройки;
- отдельную запись с IP, портами и назначением ноды.

Backup содержит секреты. Храните его зашифрованным, с доступом только администратора.
Статистика, пользователи и основные профили находятся в панели, поэтому отдельно
резервируйте и сервер Remnawave Panel.

## Быстрая диагностика проблем

### Панель не видит ноду

```bash
sudo docker compose -f /opt/remnanode/docker-compose.yml ps
sudo docker compose -f /opt/remnanode/docker-compose.yml logs --tail 200
sudo ss -lntp
sudo ufw status numbered
```

Проверьте `PANEL_IP`, `NODE_PORT`, внешний firewall провайдера и совпадение `SECRET_KEY` с
compose, выданным панелью. Не печатайте сам секрет в сообщениях поддержки.

### Панель видит ноду, но клиент не подключается

Проверьте:

- выбран ли Config Profile;
- включён ли нужный inbound;
- совпадают ли порт и протокол в профиле и firewall;
- открыт ли порт во внешнем firewall провайдера;
- правильно ли настроены домен, SNI/Reality и время сервера;
- нет ли ошибки Xray в логах;
- добавлен ли пользователь в нужный Internal Squad.

### После включения firewall пропал SSH

Не перезагружайте VPS повторно. Откройте web/VNC/serial console у провайдера и выполните:

```bash
sudo ufw status numbered
sudo ufw allow 22/tcp
sudo sshd -t
sudo systemctl restart ssh
```

Если SSH использует не 22, разрешите фактический порт. Затем исправьте правила и только
после проверки снова ограничивайте доступ.

### Conntrack почти заполнен

Сначала найдите причину роста соединений и убедитесь, что это реальная нагрузка, а не
атака или зависшие соединения:

```bash
sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max
sudo ss -s
```

Не увеличивайте лимит вслепую: таблица использует память ядра. Сначала проверьте firewall,
характер трафика и объём RAM.

## Финальный чек-лист

- [ ] ОС обновлена, необходимость reboot проверена.
- [ ] Есть snapshot или доступ к Rescue Console.
- [ ] Работает отдельный sudo-пользователь с SSH-ключом.
- [ ] Вход по ключу проверен во втором окне.
- [ ] Пароли и root-вход SSH отключены.
- [ ] Firewall разрешает SSH до включения deny policy.
- [ ] Node Port доступен только с IP панели.
- [ ] Открыты только нужные TCP/UDP inbound-порты.
- [ ] Проверен внешний firewall хостинга.
- [ ] Docker и Compose установлены и запускаются после reboot.
- [ ] `docker-compose.yml` имеет права `600` и не опубликован.
- [ ] Нода подключена к панели и получила Config Profile.
- [ ] Тестовый пользователь подключается, трафик учитывается.
- [ ] Настроено ограничение размера логов.
- [ ] Включены security-обновления ОС без внезапного reboot.
- [ ] Создан backup конфигурации.
- [ ] После установки повторены основные тесты `multitest`.

## Официальные источники

- [Требования Remnawave](https://docs.rw/install/requirements/)
- [Установка Remnawave Node](https://docs.rw/install/remnawave-node/)
- [Docker Engine для Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
- [Docker Compose plugin](https://docs.docker.com/compose/install/linux/)
- [OpenSSH Server — Ubuntu](https://ubuntu.com/server/docs/how-to/security/openssh-server/)
- [Firewall — Ubuntu Server](https://documentation.ubuntu.com/server/how-to/security/firewalls/)
- [Автоматические обновления Ubuntu](https://documentation.ubuntu.com/server/how-to/software/automatic-updates/)
