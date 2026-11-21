# Attack Surface Intelligence

Lekki, lokalny szablon do testowania projektu. Pokazuje różne usługi oraz zmiany, 
które skaner powinien zauważyć między kolejnymi przebiegami.

Nie uruchamiaj wszystkich środowisk jednocześnie. Wybierz jeden stack.

## Dostępne środowiska

| Plik | Przykładowe usługi i porty |
|---|---|
| `docker-compose-modern.yml` | WordPress `8080`, phpMyAdmin `8081`, Redis `6379`, Nginx Proxy Manager `80/81/443` |
| `docker-compose-modern-proxy.yml` | WordPress przez proxy `8085`, dashboard Traefika `8086`, API Toxiproxy `8474` |
| `docker-compose-vulnerable.yml` | FTP `21`, WordPress `8088`, Adminer `8089`, DVWA `8090` |
| `docker-compose-custom-network.yml` | httpbin `8888`, PostgreSQL `15432`, RabbitMQ `5673/15673`, Gitea `3001/2223`, lekka usługa HTTP `8787` |

## Uruchomienie

Uruchom wybrany stack, na przykład:

```bash
docker compose -f docker-compose-custom-network.yml pull
docker compose -f docker-compose-custom-network.yml up -d
```

Sprawdź stan:

```bash
docker compose -f docker-compose-custom-network.yml ps
```

Przy pierwszym uruchomieniu pobieranie obrazów może potrwać kilka minut.
Niektóre usługi potrzebują dodatkowego czasu na inicjalizację.

Stack proxy wymaga pliku `.env`:

```bash
cp -n .env.example .env
# W .env ustaw: ENABLE_LATENCY=true oraz LATENCY_MS=500
docker compose --env-file .env -f docker-compose-modern-proxy.yml down
docker compose --env-file .env -f docker-compose-modern-proxy.yml up -d
```

## Quickstart: wykrywanie znikającej i powracającej usługi

To jest podstawowy scenariusz demonstracyjny. Uruchamia trzy usługi: lekką
usługę HTTP, Gitea oraz RabbitMQ.

1. Uruchom usługę:

   ```bash
   ./quickstart.sh up
   ```

2. Wykonaj pierwszy skan:

   ```bash
   nmap -Pn -sV -p 8787 localhost
   ```

   Porty `2223`, `3001`, `5673`, `8787` i `15673` powinny być otwarte.

3. Zatrzymaj usługę:

   ```bash
   ./quickstart.sh change
   ```

4. Wykonaj drugi skan. Port `8787` powinien być zamknięty lub oznaczony jako
   niedostępny, a pozostałe usługi powinny nadal być widoczne.

5. Przywróć usługę:

   ```bash
   ./quickstart.sh up
   ```

6. Wykonaj trzeci skan. Port `8787` powinien pojawić się ponownie, razem z
   pozostałymi usługami.

7. Po zakończeniu pracy usuń kontenery i sieci:

   ```bash
   ./quickstart.sh down
   ```

## Toxiproxy

Toxiproxy pozwala symulować opóźnienia, timeouty i wolniejsze przesyłanie danych między skanerem a usługą. W stacku `modern-proxy` skopiuj `.env.example` do `.env` i ustaw na przykład `ENABLE_LATENCY=true` oraz `LATENCY_MS=500`, a następnie uruchom stack ponownie. Przy skanowaniu aplikacja powinna odnotować dłuższy czas odpowiedzi.

```bash
cp -n .env.example .env
docker compose --env-file .env -f docker-compose-modern-proxy.yml up -d
```

## Zatrzymanie i reset

```bash
docker compose -f docker-compose-custom-network.yml down
```

Usunięcie również danych zapisanych w wolumenach:

```bash
docker compose -f docker-compose-custom-network.yml down -v
```

Środowisko jest przeznaczone wyłącznie do lokalnych testów. Stack vulnerable
zawiera celowo stare usługi i domyślne, niebezpieczne dane dostępowe — nie
wystawiaj go do Internetu.
