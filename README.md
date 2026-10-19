# RoscomVPN whitelist → sing-box (.srs)

Небольшой проект, который следит за whitelist-файлами двух репозиториев
[roscomvpn-geosite](https://github.com/hydraponique/roscomvpn-geosite) и
[roscomvpn-geoip](https://github.com/hydraponique/roscomvpn-geoip), собирает из них
свои `geosite.srs` и `geoip.srs` в формате sing-box и публикует по постоянным ссылкам.

Готовые файлы подходят для Podkop в поля **«Внешние списки доменов»** и
**«Внешние списки подсетей»**.

## Готовые ссылки

Репозиторий: [BranchSeeker/rkn-whitelist-srs](https://github.com/BranchSeeker/rkn-whitelist-srs).
Ссылки на готовые файлы:

| Файл | Назначение | Постоянная ссылка |
| --- | --- | --- |
| `geosite.srs` | домены (domain / domain_suffix / keyword / regex) | `https://github.com/BranchSeeker/rkn-whitelist-srs/releases/latest/download/geosite.srs` |
| `geoip.srs` | IPv4/IPv6 подсети (`ip_cidr`) | `https://github.com/BranchSeeker/rkn-whitelist-srs/releases/latest/download/geoip.srs` |
| `manifest.json` | происхождение, счётчики и SHA-256 | `https://github.com/BranchSeeker/rkn-whitelist-srs/releases/latest/download/manifest.json` |

Ссылки не меняются: каждая успешная сборка создаёт новый релиз и помечает его
latest, поэтому `releases/latest/download/...` всегда указывает на актуальные файлы.

> Репозиторий должен быть публичным — иначе Podkop не сможет скачать файлы без токена.
> До первого успешного запуска workflow ссылки будут отдавать 404.

## Подключение в Podkop

1. Откройте настройки секции Podkop.
2. В **«Внешние списки доменов»** добавьте ссылку на `geosite.srs`.
3. В **«Внешние списки подсетей»** добавьте ссылку на `geoip.srs`.
4. Если GitHub плохо открывается с роутера, включите в Podkop
   **«Скачивать списки через Proxy/VPN»**.
5. Запустите обновление списков и проверьте диагностику Podkop.

Podkop требует sing-box **1.12.0+**. Файлы собираются sing-box 1.12.12 в формате
SRS версии 3 — это тот же формат, который Podkop читает и разбирает через
`sing-box rule-set decompile`.

## Что именно собирается

Берутся только whitelist-файлы:

- `data/whitelist` из `roscomvpn-geosite` (ветка `master`);
- `text/whitelist.txt` из `roscomvpn-geoip` (ветка `release`).

Домены разбираются по правилам v2fly/domain-list:

| Строка в источнике | Что попадает в `geosite.srs` |
| --- | --- |
| `domain:example.com` | `domain_suffix` |
| `example.com` (без префикса) | `domain_suffix` |
| `full:example.com` | `domain` |
| `keyword:tracker` | `domain_keyword` |
| `regexp:^ads\.` | `domain_regex` |
| `include:...`, комментарии, `@attributes` | пропускаются |

Подсети нормализуются через `ipaddress` (убираются дубли, хост-биты приводятся
к сети), поддерживаются IPv4 и IPv6.

В сборку **не** входят `direct`, `private`, `category-ru` и другие категории —
только whitelist. Если нужны дополнительные домены/подсети, их можно добавить
в исходный список отдельным шагом.

## Как работает автоматика

Workflow `.github/workflows/build.yml`:

- запускается по расписанию **каждый час** (`17 * * * *`), вручную
  (`workflow_dispatch`, есть флаг принудительной публикации) и при пуше в `main`;
- скачивает исходники, зафиксированные на конкретный commit (в manifest
  сохраняются repo/ref/commit/URL/SHA-256);
- собирает `geosite.srs` и `geoip.srs` заранее закреплённым sing-box 1.12.12
  (SHA-256 архива проверяется);
- проверяет результат: распаковывает SRS обратно, считает элементы, проверяет
  версию формата и отсутствие чужих типов правил;
- сравнивает SHA-256 новых файлов с уже опубликованным `manifest.json` и
  публикует релиз только при изменении;
- загружает файлы в черновик нового релиза, и только после полной загрузки
  публикует его и помечает latest; старый релиз продолжает отдавать файлы,
  пока новый не готов.

Если upstream временно отдал пустой/битый файл или изменил формат, сборка
падает до публикации — старая рабочая версия в релизе остаётся нетронутой.

Артефакты сборки (`build/`, `dist/`) в git не попадают. В репозитории нет
планов и локальных заметок — только код, тесты, workflow и README.

## Локальная сборка

Нужен Python 3.11+ и sing-box 1.12.x.

```bash
python -m unittest discover -s tests -v

python scripts/build.py \
  --sing-box /path/to/sing-box \
  --out dist \
  --work build \
  --repo BranchSeeker/rkn-whitelist-srs
```

В Windows:

```powershell
python -m unittest discover -s tests -v
python scripts\build.py --sing-box .\sing-box.exe --out dist --work build --repo BranchSeeker/rkn-whitelist-srs
```

Проверить готовый файл вручную:

```bash
sing-box rule-set decompile dist/geosite.srs -o /tmp/geosite.json
sing-box rule-set decompile dist/geoip.srs  -o /tmp/geoip.json
```

`--parse-only` позволяет скачать и разобрать списки без компиляции:

```bash
python scripts/build.py --parse-only
```

## Источники и ограничения

- [roscomvpn-geosite: data/whitelist](https://github.com/hydraponique/roscomvpn-geosite/blob/master/data/whitelist)
- [roscomvpn-geoip: release/text/whitelist.txt](https://github.com/hydraponique/roscomvpn-geoip/blob/release/text/whitelist.txt)
- [Podkop](https://github.com/itdoginfo/podkop) — требования к спискам и sing-box.

Проект не является официальным проектом RoscomVPN или Podkop. Списки и права на
них принадлежат авторам источников; geosite распространяется по MIT, у geoip
отдельная лицензия не указана. Код сборщика можно использовать и менять на свой
страх и риск, без гарантий.
