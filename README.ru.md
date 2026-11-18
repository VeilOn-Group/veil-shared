<p align="center">
  <img src="brand/dist/mark-128.png" width="96" alt="VeilOn">
</p>

<h1 align="center">veil-shared</h1>

<p align="center">
  Открытое ядро VeilOn: подписи, генераторы конфигураций, правила приватности
  и элементы дизайна, общие для приложений и серверов.
</p>

<p align="center">
  <a href="README.md"><img src="https://img.shields.io/badge/English-1f2937?style=for-the-badge" alt="English"></a>
  <a href="README.ru.md"><img src="https://img.shields.io/badge/%D0%A0%D1%83%D1%81%D1%81%D0%BA%D0%B8%D0%B9-6d28d9?style=for-the-badge" alt="Русский"></a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MPL--2.0-blue" alt="MPL-2.0"></a>
  <img src="https://img.shields.io/badge/Go-1.24%2B-00ADD8" alt="Go 1.24+">
</p>

---

Здесь лежит код, который определяет, как устроено подключение к VeilOn и что
вообще разрешено хранить. Именно этот код используют клиент
[Veil Connect](https://github.com/VeilOn-Group/Veil-Connect), серверы VeilOn и
VPN-ноды, поэтому по нему можно понять, как ведёт себя весь сервис, а не одно
приложение.

## Что внутри

| Пакет | Что делает |
|---|---|
| `pkg/sign` | подписи Ed25519 поверх канонического JSON (RFC 8785), наборы ключей и офлайн корневые ключи |
| `pkg/profile` | подписанный профиль клиента: ноды, протоколы, DNS и маршрутизация, с валидацией и зеркалом на protobuf в `proto/` |
| `pkg/singbox`, `pkg/xray`, `pkg/tmpl` | генераторы конфигов клиента и ноды для sing-box 1.13 и Xray 26.9, шаблоны, пресеты DNS over HTTPS |
| `pkg/redact`, `pkg/crash` | очистка логов и отчётов о сбоях: убираются IP-адреса, домены, пути и идентификаторы |
| `pkg/nonroot` | запрещает серверным программам работать от root |
| `pkg/release` | подписанные метаданные релизов и сравнение версий для обновлений приложений |
| `pkg/apitypes`, `pkg/nodeproto` | типы запросов и ответов API и сообщения между API и агентами нод |
| `pkg/inventory`, `pkg/schemalint` | реестр данных и проверки его полноты |
| `pkg/tokens`, `design/`, `brand/` | дизайн-токены, цвета и иконки VeilOn |
| `mobile/` | мост gomobile для приложения на Android |
| `assets/rulesets/` | закреплённый список geosite `category-ru` для раздельного туннелирования |
| `build/*.lock` | закреплённые релизы sing-box и Xray с хешами SHA-256 |

## Гарантии приватности в коде

- **Реестр данных.** В [`data-inventory.yaml`](data-inventory.yaml) перечислено
  всё, с чем работает VeilOn: колонки базы данных, поля логов, метрики, ключи
  кеша, что приложения хранят на устройстве и какие внешние сервисы что
  видят. Если в схеме базы появится что-то, чего нет в реестре, CI не
  пропустит изменение. Приложения показывают понятную выжимку из него
  ([`design/dist/what-we-store.json`](design/dist/what-we-store.json)).
- **Конфиги без логов.** Генераторы отказываются собирать конфиг, который
  пишет трафик, хранит историю соединений или кеширует DNS-ответы на диске.
  Те же проверки применяются к пользовательским шаблонам нод. `make nolog`
  прогоняет эталонные конфиги через настоящие закреплённые бинарники
  sing-box и Xray.
- **Без трекеров.** `cmd/trackerscan` роняет сборку, если среди зависимостей
  появляется SDK аналитики, трекинга или отчётов о сбоях.
- **Подписано всё.** Профили, наборы ключей и релизы подписаны. Корневой ключ
  хранится офлайн, так что даже взломанный сервер не сможет выдать поддельный
  профиль или вредоносное обновление.

## Подключение

Путь модуля `github.com/veilon/veil-shared`. Проекты, которые от него
зависят, ожидают копию рядом с собой и используют директиву `replace`:

```
workspace/
  veil-shared/
  Veil-Connect/
```

```go
// go.mod
require github.com/veilon/veil-shared v0.0.0
replace github.com/veilon/veil-shared => ../veil-shared
```

## Разработка

```bash
make test vet lint          # юнит-тесты, go vet, golangci-lint
make singbox xray           # скачать закреплённые ядра и сверить хеши
make nolog                  # тесты zero-log на этих ядрах
make generate               # пересобрать дизайн-токены и сводку «что мы храним»
make license-check nodash   # заголовки MPL и проверка типографики
make ci                     # всё, что запускает CI
```

Все цели показывает `make help`.

## Лицензия

Код распространяется под [Mozilla Public License 2.0](LICENSE). Его можно
сочетать с кодом под GPL (например, с клиентом) и с проприетарным кодом,
если сами файлы под MPL остаются открытыми. Подробности и сторонние файлы со
своей лицензией описаны в [NOTICE.md](NOTICE.md).

Название VeilOn, логотип и иконки из `brand/` под лицензию не попадают.
Форкам нужно использовать собственное оформление.
