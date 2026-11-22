# Jak pracować w tym repo

## Zanim zaczniesz

Potrzebujesz Go 1.27, Dockera z Compose i nmapa (tylko do ręcznych skanów poza kontenerem; testy go nie używają).

```bash
docker compose -f docker-compose.test.yml up -d --wait
go build ./... && go vet ./... && test -z "$(gofmt -l .)"
go test ./...
ASI_TEST_DATABASE_URL='postgres://asi:asi-test@127.0.0.1:55432/asi?sslmode=disable' go test -tags integration ./...
LAB_SLOT=1 lab/run.sh
```

To samo robi CI (`.github/workflows/ci.yml`) na każdym pull requeście. Zmiana jest gotowa, gdy wszystkie pięć
kroków przechodzi.

## Zasady, które trzymają projekt w całości

- `docs/contracts.md` to stały interfejs: CLI, format eksportu, diffu i sygnatur. Można go rozszerzać (nowa flaga,
  nowe opcjonalne pole), nie wolno zmieniać nazw ani usuwać. Rozszerzenie dopisz do tego pliku w tym samym PR.
- `lab/` jest definicją „działa": znane usługi, trzy skany ze zmianami pomiędzy i oczekiwany wynik w
  `lab/expected.json`. Jeśli lab nie zgadza się z kodem, błędny jest kod. `lab/expected.json` zmieniaj tylko wtedy,
  gdy świadomie zmieniasz oczekiwane zachowanie, i napisz to w opisie PR.
- Bezpieczeństwo skanera jest cechą produktu: tylko skonfigurowane porty, tylko `GET`/`HEAD`, zawsze limit tempa,
  żadnych prób logowania ani payloadów, żadnych żądań HTTP do portów z listy „nigdy nie sonduj" (przemysłowe,
  drukarki). Zmiana, która to luzuje, wymaga osobnego przeglądu.
- nmap jest schowany za interfejsem (`internal/scan/nmap`), testy jednostkowe używają nagranego XML. Testy nigdy nie
  skanują prawdziwych sieci.
- Testy integracyjne mają tag `integration`, czytają `ASI_TEST_DATABASE_URL` i tworzą własny schemat na pakiet, więc
  mogą iść równolegle.
- Migracje: nowy plik w `internal/store/migrations/` z kolejnym wolnym numerem; nigdy nie edytuj już wydanej.
- UI: szablony `html/template` + htmx, jeden plik `internal/web/static/app.css`. CSP zabrania skryptów i stylów
  inline. Wzorce komponentów: `docs/ui-conventions.md` i strona `/styleguide`.
- Każda trasa HTTP deklaruje wymagane uprawnienie; test przechodzi po tablicy tras i pada na trasie bez deklaracji.
- Błędy opakowuj kontekstem (`fmt.Errorf("…: %w", err)`), bez `panic` poza `main`, bez stanu globalnego.
- Zależności: czyste Go, nieliczne. Nową zależność nazwij w opisie PR.

## Gdzie co jest

`docs/architecture.md` (decyzje i mapa pakietów), `docs/technical.md` (jak to działa), `docs/operations.md`
(wdrożenie i obsługa), `docs/signatures.md` (pisanie sygnatur), `docs/requirements-coverage.md` (wymaganie → gdzie
jest zrobione i jak sprawdzone), `docs/evaluation-report.md` (pomiary), `specs/` (zachowanie per funkcja).

Znane braki są w Issues. Sekrety w `lab/`, `lab-agh/`, `eval/` i `docker-compose.test.yml` są wyłącznie testowe.
