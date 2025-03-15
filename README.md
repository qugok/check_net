# check_net
Скрипт для проверки доступности по сети

## Порядок работы
* проверяем что резолвится хоть что-то, как только нашли хоть что-то, идём к след пункту
* проверяем доступность по различным портам и протоколам через nmap
* проверяем доступность через ping (4 запроса)
 
## Параметры
```
Usage: check [options] <file>

  <file> - config file path

  Options:
  --print-config, -p  print default config to config file
  --help, -h          display help
```