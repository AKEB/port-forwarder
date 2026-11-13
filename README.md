# Port Forwarder

Небольшая служба для Linux, которая настраивает перенаправление входящих TCP- и UDP-портов через `iptables`.

Правила задаются в YAML-файле. Для каждого правила указываются:

- входящий порт или диапазон портов на прокси-сервере;
- IP-адрес и порт или диапазон портов сервера назначения;
- протокол `tcp` или `udp`.

Программа создаёт собственные цепочки `iptables`, добавляет DNAT, MASQUERADE и разрешающие правила FORWARD, а также включает IPv4 forwarding. Управление выполняется напрямую или через `systemd`.

## Требования

- Linux с `systemd`;
- Python 3;
- `iptables`;
- права `root`.

Для Debian и Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 iptables
```

## Конфигурация

Боевой `config.yaml` намеренно исключён из Git, поскольку содержит реальные IP-адреса и порты.

Создайте конфигурацию из примера:

```bash
sudo install -d -m 0750 /etc/port-forwarder
sudo install -m 0600 config.example.yaml /etc/port-forwarder/config.yaml
sudo editor /etc/port-forwarder/config.yaml
```

Формат правила:

```yaml
mappings:
  - name: example_udp
    source_port: 41000
    destination_ip: 192.0.2.10
    destination_port: 42000
    protocol: udp
```

Диапазоны задаются через дефис и разворачиваются в точные соответствия порт-в-порт:

```yaml
mappings:
  - name: wireguard_udp_range
    source_port: "60020-60029"
    destination_ip: 192.0.2.10
    destination_port: "60020-60029"
    protocol: udp
```

Исходный и целевой диапазоны должны содержать одинаковое количество портов. Например,
`60020-60029` можно перенаправить в `61020-61029`. Одиночные порты остаются
совместимыми с прежним форматом. Также принимается разделитель `:`, но для YAML
рекомендуется заключённая в кавычки запись с дефисом.

Поддерживаются протоколы `tcp` и `udp`. Порты должны находиться в диапазоне `1-65535`. Текущая реализация правил `iptables` рассчитана на IPv4, поэтому в `destination_ip` следует указывать IPv4-адрес.

## Установка на прод

Запускайте команды из корня репозитория:

```bash
sudo install -m 0755 port-forwarder.py /usr/local/sbin/port-forwarder
sudo install -m 0644 port-forwarder.service /etc/systemd/system/port-forwarder.service
sudo systemctl daemon-reload
sudo systemctl enable --now port-forwarder.service
```

Проверка состояния:

```bash
sudo systemctl status port-forwarder.service
sudo /usr/local/sbin/port-forwarder status
sudo /usr/local/sbin/port-forwarder check
```

## Управление

После изменения `/etc/port-forwarder/config.yaml` примените правила заново:

```bash
sudo systemctl reload port-forwarder.service
```

Остальные команды:

```bash
sudo systemctl start port-forwarder.service
sudo systemctl restart port-forwarder.service
sudo systemctl stop port-forwarder.service
sudo systemctl status port-forwarder.service
```

При остановке службы созданные программой цепочки и правила удаляются. Конфигурация и системный параметр IPv4 forwarding при этом остаются на диске.

## Обновление установленной версии

```bash
sudo install -m 0755 port-forwarder.py /usr/local/sbin/port-forwarder
sudo install -m 0644 port-forwarder.service /etc/systemd/system/port-forwarder.service
sudo systemctl daemon-reload
sudo systemctl restart port-forwarder.service
```

Перед обновлением сохраните текущий `/etc/port-forwarder/config.yaml`. Не добавляйте боевую конфигурацию в Git.
