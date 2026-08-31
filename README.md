# Neto Kube Auditor — paczka instalacyjna

Agent audytowy dla OpenShift: buduje się jako obraz kontenera, ląduje w rejestrze
klastra i instaluje interaktywnym instalatorem `scripts/deploy.sh`.

## Szybki start na maszynie z dostępem do OCP

```bash
git clone git@github.com:marekdevops/ocp-audit-agent-client-package.git
cd ocp-audit-agent-client-package
oc login <api-klastra>

./build.sh all        # build + push + deploy
```

`all` to skrót na trzy kroki, które można odpalić osobno:

```bash
./build.sh build      # zbuduj obraz lokalnie (podman, jak jest w PATH; inaczej docker)
./build.sh push       # wepchnij do rejestru klastra
./build.sh deploy     # interaktywny instalator z podstawionym obrazem
```

Budowanie wymaga dostępu do internetu (obraz bazowy `python:3.12-slim` + pip).
Na maszynie bez internetu patrz „Przenoszenie offline" niżej.

`push` sam wybiera drogę do rejestru:

1. `REGISTRY`, jeśli ustawione,
2. route `default-route` w `openshift-image-registry`, jeśli ktoś ją wystawił,
3. w przeciwnym razie tunel `oc port-forward` na `127.0.0.1:5000` —
   nie wymaga żadnej zmiany w klastrze, tylko prawa do port-forward.

`./build.sh push-local` wymusza od razu ścieżkę z tunelem.

## Przenoszenie offline

Na maszynie z internetem:

```bash
./build.sh build
./build.sh package    # dist/*.tar.gz + podział na kawałki po 90M do image/
```

Kawałki z `image/` przenosisz na maszynę docelową (nośnik albo commit — limit
GitHuba to 100 MB na plik, stąd `CHUNK_SIZE=90M`), a tam:

```bash
./build.sh unpack     # weryfikacja sum kontrolnych, sklejenie, import obrazu
./build.sh push
./build.sh deploy
```

Sam plik `.tar.gz`, bez dzielenia, importuje się przez `./build.sh load <plik.tar.gz>`.

## Obcy rejestr

```bash
# wcześniej: podman login rejestr.firma.local
REGISTRY=rejestr.firma.local ./build.sh push
REGISTRY=localhost:5000 REGISTRY_INSECURE=1 ./build.sh push

AUDIT_DEFAULT_IMAGE=rejestr.firma.local/ocp-audit/ocp-audit-agent:latest ./build.sh deploy
```

## Odinstalowanie

```bash
./build.sh uninstall  # scripts/deploy.sh --uninstall
```

## Zmienne środowiskowe

| Zmienna | Domyślnie | Znaczenie |
| --- | --- | --- |
| `IMAGE_NAME` | `ocp-audit-agent` | nazwa obrazu |
| `IMAGE_TAG` | `latest` | tag obrazu |
| `NAMESPACE` | `ocp-audit` | namespace, do którego trafia obraz i workload |
| `ENGINE` | `podman`, inaczej `docker` | silnik kontenerów |
| `SUDO` | puste | ustaw `SUDO=sudo`, gdy silnik potrzebuje roota |
| `REGISTRY` | puste | rejestr docelowy zamiast rejestru klastra |
| `REGISTRY_INSECURE` | puste | pomiń weryfikację TLS przy `REGISTRY` |
| `AUDIT_DEFAULT_IMAGE` | referencja wewnętrzna | obraz podstawiany instalatorowi |
| `CHUNK_SIZE` | `90M` | rozmiar kawałka przy `package` |
| `LOCAL_PORT` | `5000` | port lokalny tunelu do rejestru |

Nie uruchamiaj całego skryptu przez `sudo ./build.sh` — `oc` straci wtedy twój
kubeconfig i rejestr odrzuci logowanie. Gdy silnik potrzebuje roota, użyj
`SUDO=sudo ./build.sh ...`.

Pełny opis instalacji po stronie klienta: [INSTRUKCJA_INSTALACJI_KLIENTA.md](INSTRUKCJA_INSTALACJI_KLIENTA.md).
