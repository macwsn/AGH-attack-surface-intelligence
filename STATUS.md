# Stan projektu (wersja robocza, 21.11 wieczór)

ASI (Attack Surface Intelligence): narzędzie do cyklicznego skanowania discovery dużych sieci dla CBI AGH.
To jest migawka w trakcie pracy. Rdzeń działa i jest sprawdzony testami; część UI i kilka funkcji jeszcze powstaje.
Wymagania z zadania: `docs/requirements.md`. Decyzje architektoniczne: `docs/architecture.md`. Kontrakty CLI,
eksportu, diffu i sygnatur: `docs/contracts.md`.

## Jak uruchomić

```bash
export ASI_MASTER_KEY=$(openssl rand -base64 32)
docker compose up -d --build --wait
printf 'haslo-min-12-znakow\n' | docker compose exec -T asi asi user create --username admin --role admin --password-stdin
```

UI: http://127.0.0.1:8080 (logowanie kontem z kroku wyżej). Role wbudowane: `admin`, `editor`, `operator`, `viewer`.

Skan z linii poleceń (w kontenerze `asi`, który ma nmapa):

```bash
docker compose exec -T asi asi scan run --targets-file /sciezka/targets.txt --ports 22,80,443,8080 --name skan-1 --max-rate 300 --wait
docker compose exec -T asi asi export --format json --out /tmp/export.json
docker compose exec -T asi asi diff --from skan-1 --to skan-2 --format json --out /tmp/diff.json
```

Testy: `go test ./...`; integracyjne (potrzebują Postgresa z `docker-compose.test.yml`):
`ASI_TEST_DATABASE_URL='postgres://asi:asi-test@127.0.0.1:55432/asi?sslmode=disable' go test -tags integration ./...`.
Test akceptacyjny na labie (trzy skany ze zmianami pomiędzy, porównanie z `lab/expected.json`): `lab/run.sh`.

## Co działa (zmergowane, z testami; lab akceptacyjny przechodzi)

- Wczytanie adresów IP, CIDR, zakresów i domen; wykluczenia; podział na grupy o adaptacyjnym rozmiarze.
- Skan przez nmap z pulą workerów: wykrywanie hostów i usług, tylko po wskazanych portach.
- Jeden limit tempa na cały przebieg (pakiety nmapa i żądania HTTP razem).
- Sonda HTTP/HTTPS: tytuł, kod, nagłówki, ciasteczka (bez wartości), przekierowania, certyfikat TLS, hash favicony.
  Tylko GET/HEAD, bez przekierowań na obce hosty.
- Detekcja technologii i silnik własnych sygnatur (YAML) z regułami bezpieczeństwa wymuszanymi przy wczytaniu.
- Inventory: hosty, usługi, obserwacje per przebieg; statusy `active` / `unstable` / `inactive` (nieaktywny po N
  pominiętych przebiegach); edycje analityka (tagi, notatki) nie są nadpisywane przez kolejne skany.
- Diff między przebiegami: nowe, znikające, wracające i zmienione hosty oraz usługi; zmienne nagłówki (np. `Date`)
  nie dają fałszywych zmian.
- Eksport JSON i CSV; wstrzymanie i wznowienie skanu; grupy po przekroczeniu czasu są dzielone i ponawiane.
- Szyfrowanie wrażliwych pól w bazie (AES-256-GCM, klucz z `ASI_MASTER_KEY`, rotacja kluczy).
- Konta lokalne (argon2id), sesje, CSRF, role i uprawnienia (własne role też), log audytowy.
- UI: logowanie, nawigacja wg uprawnień, zarządzanie sygnaturami (z testem na zapisanych danych), definicje skanów
  z harmonogramem (okna czasowe, częstotliwość, zatrzymanie na końcu okna i wznowienie w następnym).

## W trakcie (jeszcze nie w tym repo)

- Strony inventory i dashboard, widok zmian w czasie, import CSV/JSON i formularz ręczny, eksport do DefectDojo.
- Wbudowana paczka sygnatur prawdziwych produktów (WordPress, phpMyAdmin, Gitea, RabbitMQ, Traefik...) i rodzaj
  ustalenia „przestarzała wersja".
- Zakresy i presety portów, skan pojedynczego hosta z wieloma usługami (scenariusz z `lab-agh/`), pomiar czasu
  odpowiedzi i obsługa wolnych usług.
- Wyróżniki: tryb pełny i kontrolny skanu z profilem dostępności hosta w ciągu doby, retro-hunt (sygnatura sprawdzana
  na zapisanej historii bez wysyłania pakietów), samoczynne zwalnianie skanera i podgląd planu skanu.
- README i dokumentacja techniczna, raport z ewaluacji, prezentacja.

## Co już zmierzone

- Lab akceptacyjny (`lab/`): 12 usług, trzy przebiegi; wynik zgodny z oczekiwanym, zero fałszywych zmian.
- Symulowana sieć /18 (`eval/bignet/`, 16 384 adresy, 485 żywych hostów, 594 usługi, 16 workerów, limit 1000/s):
  100% hostów i usług, zero fałszywych; 92 wyłączone hosty zgłoszone jako znikające i potem jako wracające.
  Pełny skan trwał 73 s przed wspólnym limitem tempa i 126 s po nim (nmap dostaje teraz połowę budżetu; pomiar robiony
  na obciążonej maszynie, do powtórzenia). Szczyt pamięci skanera 490-670 MiB.
- Porównanie z gotowymi narzędziami na tym samym labie: `eval/results/comparison/comparison.md`.

## Znane braki i uwagi

- Dwie migracje mają numer 0005 (działa, bo są stosowane po nazwie; do przenumerowania).
- Są dwie strony przebiegu (`/runs/{id}` i `/runs/by-name/{name}`), do scalenia w jedną.
- Formularz definicji skanu przyjmuje limit tempa 1, a minimum to 2.
- Hasła i klucze w `lab/`, `lab-agh/`, `eval/` i `docker-compose.test.yml` są wyłącznie testowe.
- `lab-agh/` to materiały organizatorów; ich stacki wystawiają porty na wszystkie interfejsy, więc uruchamiaj je tylko
  w zaufanej sieci.
