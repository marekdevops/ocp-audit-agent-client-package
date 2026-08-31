# Neto Kube Auditor — instrukcja budowy i instalacji

Dokument opisuje instalację Neto Kube Auditor na OpenShift, OKD, RKE2 albo
standardowym Kubernetesie. Instalacja działa w trybie read-only wobec
audytowanego klastra. Domyślne uprawnienia RBAC obejmują wyłącznie operacje
`get`, `list` i `watch`.

## 1. Zawartość paczki

Paczka instalacyjna zawiera wyłącznie:

- kod aplikacji w `app/`;
- bazowe manifesty w `deploy/`;
- interaktywny instalator `scripts/deploy.sh`;
- pliki wymagane do zbudowania obrazu: `Dockerfile`, `.dockerignore` i
  `pyproject.toml`;
- tę instrukcję.

Paczka nie zawiera testów, danych z klastra, danych uwierzytelniających,
wewnętrznego skryptu `deploy-neto.sh` ani historii Git.

## 2. Wymagania

Na stacji administracyjnej potrzebne są:

- Linux albo inny system z powłoką Bash;
- Docker z działającym demonem;
- `kubectl` albo `oc`;
- aktywny `kubeconfig` wskazujący właściwy klaster;
- dostęp do rejestru obrazów OCI/Docker oraz uprawnienia do push i pull;
- uprawnienia klastrowe pozwalające tworzyć Namespace, ClusterRole,
  ClusterRoleBinding, Role, RoleBinding, ServiceAccount, Deployment,
  StatefulSet, CronJob, Service, Secret i PVC;
- dla OpenShift, opcjonalnie, uprawnienie do tworzenia Route.

Budowa obrazu wymaga dostępu do obrazu bazowego `python:3.12-slim` oraz do
repozytorium pakietów Python. W środowisku odciętym od Internetu należy
wcześniej skonfigurować wewnętrzne mirrory Docker Registry i PyPI.

Domyślna instalacja z PVC wymaga:

- 10 Gi dla danych i raportów aplikacji;
- 20 Gi dla PostgreSQL;
- StorageClass obsługującego wolumeny `ReadWriteOnce`;
- na węźle mieszczącym serwer i watcher około 8 CPU requests oraz 2 Gi pamięci
  requests. PostgreSQL żąda dodatkowo 250 mCPU i 512 MiB pamięci.

## 3. Rozpakowanie

```sh
tar -xzf ocp-audit-agent-client-package.tar.gz
cd ocp-audit-agent-client-package
```

Jeżeli paczka została dostarczona jako ZIP:

```sh
unzip ocp-audit-agent-client-package.zip
cd ocp-audit-agent-client-package
```

Sprawdź, czy widoczne są wymagane pliki:

```sh
ls -la
ls app deploy scripts
```

## 4. Przygotowanie registry i nazwy obrazu

W poniższych przykładach `registry.example.com` i `customer-project` należy
zastąpić wartościami przekazanymi przez administratora registry. Zalecany jest
unikalny tag wersji, a nie `latest`.

```sh
export AUDIT_REGISTRY="registry.example.com"
export AUDIT_IMAGE="${AUDIT_REGISTRY}/customer-project/ocp-audit-agent:0.1.0"
```

Zaloguj się do registry. Hasła lub tokenu nie należy wpisywać bezpośrednio do
historii powłoki:

```sh
docker login "${AUDIT_REGISTRY}"
```

Dla GitLab Container Registry można użyć Personal Access Token albo Deploy
Token z uprawnieniem `read_registry` i, dla osoby budującej obraz,
`write_registry`.

## 5. Budowa i wysłanie obrazu

W katalogu głównym rozpakowanej paczki wykonaj:

```sh
docker build --pull -t "${AUDIT_IMAGE}" .
docker push "${AUDIT_IMAGE}"
```

Potwierdź, że obraz jest dostępny w registry:

```sh
docker buildx imagetools inspect "${AUDIT_IMAGE}"
```

Zapisz wyświetlony digest do dokumentacji wdrożenia. Interaktywny instalator
przyjmuje referencję z tagiem, dlatego podczas instalacji podaj wartość
`${AUDIT_IMAGE}`, a nie referencję `@sha256:...`.

## 6. Weryfikacja połączenia z klastrem

Dla Kubernetes/RKE2:

```sh
kubectl config current-context
kubectl cluster-info
kubectl auth can-i create clusterroles
kubectl auth can-i create deployments --namespace ocp-audit
```

Dla OpenShift/OKD:

```sh
oc whoami
oc project
oc auth can-i create clusterroles
oc auth can-i create deployments --namespace ocp-audit
```

Przed kontynuacją upewnij się, że kontekst wskazuje klaster klienta przeznaczony
do audytu.

## 7. Uruchomienie instalatora

Uruchom:

```sh
bash scripts/deploy.sh
```

Rekomendowane odpowiedzi:

1. `Namespace`: `ocp-audit`.
2. `Image`: pełna wartość `${AUDIT_IMAGE}`, np.
   `registry.example.com/customer-project/ocp-audit-agent:0.1.0`.
3. `Cluster type`: `openshift`, `okd`, `kubernetes` albo `rke2`.
4. `Storage mode`: `pvc` dla instalacji trwałej.
5. `StorageClass name`: pozostaw puste, aby użyć domyślnej klasy klastra, albo
   wpisz uzgodnioną nazwę.
6. `NodePort`: zaakceptuj `30800` albo pozostaw puste, aby klaster przydzielił
   port automatycznie.
7. `Image pull secret`:
   - `none` — tylko gdy obraz jest publiczny albo ServiceAccount ma już dostęp;
   - `existing` — gdy sekret registry istnieje już w namespace;
   - `create` — aby instalator utworzył sekret typu
     `kubernetes.io/dockerconfigjson`.
8. Przy trybie `create` podaj host registry bez `https://` i bez ścieżki
   projektu, np. `registry.example.com`, następnie username oraz token/hasło.
9. `Enable output anonymization by default`: zalecane `yes`, szczególnie gdy
   raporty mogą opuścić środowisko klienta.
10. `Allow WebUI anonymization toggle`: `no`, jeżeli użytkownik WebUI nie może
    zobaczyć oryginalnych nazw; w innym przypadku `yes`.
11. `Enable optional Secret audit RBAC`: zalecane `no`. Włączenie daje
    ServiceAccountowi aplikacji techniczną możliwość odczytu całych Secretów,
    ponieważ RBAC nie zapewnia dostępu wyłącznie do ich metadanych. Aplikacja
    nie zapisuje ani nie wyświetla wartości Secretów.
12. `Enable read-only Pod log audit RBAC`: włącz tylko po akceptacji klienta.
    Dostęp pozostaje read-only, ale logi aplikacji mogą zawierać informacje
    wrażliwe.
13. Dla OpenShift `Also create OpenShift Route`: `yes`, jeżeli WebUI ma być
    dostępne przez router OpenShift.
14. `Apply generated manifests now`: `yes`.

Instalator:

- utworzy namespace i losowe hasło PostgreSQL, jeżeli jeszcze nie istnieje;
- wygeneruje overlay w `overlays/generated/`;
- skonfiguruje wybrany obraz i opcjonalny imagePullSecret;
- zastosuje manifesty;
- poczeka na rollout PostgreSQL oraz serwera.

Kontenery serwera, watchera i snapshotu mają `initContainer`, który nie pozwala
uruchomić głównego procesu aplikacji, dopóki PostgreSQL nie odpowiada na
`pg_isready`.

## 8. Instalacja bez trwałego storage

Jeżeli klaster nie ma działającego StorageClass ani dostępnych PV, wybierz
`emptydir`.

Ten tryb jest przeznaczony wyłącznie do instalacji tymczasowych:

- dane PostgreSQL zostaną utracone po odtworzeniu jego Poda;
- historia audytu i raporty nie są trwale zachowane;
- po udostępnieniu storage należy ponownie wdrożyć aplikację w trybie `pvc`.

## 9. Weryfikacja wdrożenia

Ustaw polecenie odpowiednie dla klastra:

```sh
export KUBE_CLI="kubectl"
# Dla OpenShift można użyć:
# export KUBE_CLI="oc"
```

Sprawdź zasoby:

```sh
${KUBE_CLI} get pods -n ocp-audit -o wide
${KUBE_CLI} get pvc -n ocp-audit
${KUBE_CLI} get svc -n ocp-audit
${KUBE_CLI} get cronjob -n ocp-audit
```

Poczekaj na gotowość:

```sh
${KUBE_CLI} rollout status statefulset/ocp-audit-postgres -n ocp-audit --timeout=5m
${KUBE_CLI} rollout status deployment/ocp-audit-agent-server -n ocp-audit --timeout=10m
${KUBE_CLI} rollout status deployment/ocp-audit-agent-watcher -n ocp-audit --timeout=10m
```

Oczekiwany stan:

- `ocp-audit-postgres-0`: `Running`, `READY 1/1`;
- Pod serwera: `Running`, `READY 1/1`;
- Pod watchera: `Running`, `READY 1/1`;
- CronJob `ocp-audit-agent-snapshot` jest widoczny i uruchamia snapshot co
  15 minut.

Sprawdź logi:

```sh
${KUBE_CLI} logs statefulset/ocp-audit-postgres -n ocp-audit --tail=100
${KUBE_CLI} logs deployment/ocp-audit-agent-server -n ocp-audit --tail=100
${KUBE_CLI} logs deployment/ocp-audit-agent-watcher -n ocp-audit --tail=100
```

Sprawdź endpointy aplikacji lokalnym port-forwardem:

```sh
${KUBE_CLI} port-forward -n ocp-audit service/ocp-audit-agent 8080:8080
```

W drugim terminalu:

```sh
curl -f http://127.0.0.1:8080/healthz
curl -f http://127.0.0.1:8080/readyz
```

WebUI będzie dostępne pod `http://127.0.0.1:8080/`.

## 10. Dostęp przez NodePort albo OpenShift Route

Numer NodePort:

```sh
${KUBE_CLI} get service ocp-audit-agent -n ocp-audit \
  -o jsonpath='{.spec.ports[0].nodePort}'; echo
```

Adresy węzłów:

```sh
${KUBE_CLI} get nodes -o wide
```

WebUI: `http://<adres-węzła>:<nodePort>/`. Firewall i reguły sieciowe muszą
zezwalać na dostęp do wybranego NodePort.

Jeżeli podczas instalacji OpenShift wybrano Route:

```sh
oc get route ocp-audit-agent -n ocp-audit
oc get route ocp-audit-agent -n ocp-audit \
  -o jsonpath='https://{.spec.host}'; echo
```

## 11. Typowe problemy

### Pod ma stan `ImagePullBackOff`

```sh
${KUBE_CLI} describe pod -n ocp-audit <nazwa-poda>
${KUBE_CLI} get serviceaccount ocp-audit-agent -n ocp-audit -o yaml
${KUBE_CLI} get secret -n ocp-audit
```

Sprawdź zgodność hosta w imagePullSecret z hostem obrazu oraz ważność tokenu
`read_registry`. Nie umieszczaj tokenu w zgłoszeniu serwisowym ani logach.

### PVC ma stan `Pending`

```sh
${KUBE_CLI} get storageclass
${KUBE_CLI} describe pvc ocp-audit-postgres -n ocp-audit
${KUBE_CLI} describe pvc ocp-audit-data -n ocp-audit
```

Wygeneruj instalację ponownie z prawidłowym StorageClass albo wybierz tymczasowy
tryb `emptydir`.

### Aplikacja pozostaje w stanie `Init:0/1`

Oznacza to, że `wait-for-postgres` nadal czeka na bazę:

```sh
${KUBE_CLI} get pods -n ocp-audit
${KUBE_CLI} logs statefulset/ocp-audit-postgres -n ocp-audit --tail=200
${KUBE_CLI} get endpoints ocp-audit-postgres -n ocp-audit
${KUBE_CLI} describe pod ocp-audit-postgres-0 -n ocp-audit
```

Najpierw usuń problem PostgreSQL lub PVC. Nie usuwaj initContainera.

### WebUI nie jest dostępne

```sh
${KUBE_CLI} get service ocp-audit-agent -n ocp-audit -o yaml
${KUBE_CLI} get endpoints ocp-audit-agent -n ocp-audit
${KUBE_CLI} logs deployment/ocp-audit-agent-server -n ocp-audit --tail=200
```

Do diagnostyki użyj port-forwardu opisanego w punkcie 9.

## 12. Odinstalowanie

Uruchom z katalogu rozpakowanej paczki:

```sh
bash scripts/deploy.sh --uninstall
```

Instalator zapyta o namespace i osobno o jego usunięcie. Usunięcie namespace
spowoduje również usunięcie PVC i danych audytu. Przed potwierdzeniem wykonaj
kopię wymaganych raportów.

## 13. Informacje bezpieczeństwa

- Proces audytora nie modyfikuje audytowanych zasobów. Instalator tworzy i
  usuwa wyłącznie zasoby potrzebne do działania aplikacji.
- Domyślny ClusterRole używa tylko `get`, `list` i `watch`.
- Dostęp do Secretów jest domyślnie wyłączony.
- Dostęp do logów Podów jest opcjonalny i read-only.
- Wartości Secretów nie są zapisywane ani prezentowane.
- Raporty przeznaczone do wysyłki poza środowisko klienta powinny być
  generowane z włączoną anonimizacją.
- Dane uwierzytelniające do registry mogą znaleźć się w lokalnym
  `overlays/generated/`; katalog należy chronić i usunąć po zakończeniu
  instalacji, jeżeli nie jest potrzebny do późniejszego odinstalowania.

## 14. Wdrożenie lokalne przez `build.sh` (bez zewnętrznego registry)

Skrypt `build.sh` w katalogu głównym paczki automatyzuje ścieżkę z rozdziałów
4-7 dla środowisk laboratoryjnych, w których obraz ma trafić do wewnętrznego
registry OpenShift zamiast do registry klienta.

```sh
./build.sh build     # zbudowanie obrazu lokalnie (podman albo docker)
./build.sh push      # wysłanie do registry klastra
./build.sh deploy    # interaktywny instalator z gotową referencją obrazu
./build.sh all       # build + push + deploy
```

`push` wybiera drogę do registry w tej kolejności:

1. `REGISTRY=host[:port]` — dowolne własne registry (Quay, Harbor,
   `localhost:5000`); wcześniej wymagany `podman login` albo `docker login`,
2. route `default-route` w namespace `openshift-image-registry`, jeżeli
   istnieje,
3. tunel `oc port-forward` do `svc/image-registry` — nie wymaga żadnej zmiany
   w klastrze poza prawem do port-forward.

Obraz trafia do namespace `ocp-audit` (zmienna `NAMESPACE`), czyli tego samego,
w którym działa aplikacja. Dzięki temu Pody pobierają obraz bez
`imagePullSecret` — w instalatorze na pytanie `Image pull secret` odpowiedz
`none`. Referencja używana przez klaster to:

```
image-registry.openshift-image-registry.svc:5000/ocp-audit/ocp-audit-agent:latest
```

Zmienne: `IMAGE_NAME`, `IMAGE_TAG`, `NAMESPACE`, `REGISTRY`, `ENGINE`
(`podman`/`docker`), `SUDO=sudo` gdy silnik kontenerów wymaga roota
(`oc` pozostaje wtedy uruchamiane jako użytkownik wywołujący).

### Środowisko bez dostępu do sieci

```sh
./build.sh package                  # obraz dzielony na części w image/
# przeniesienie katalogu image/ na maszynę docelową
./build.sh unpack                   # weryfikacja sum kontrolnych i import
./build.sh push
```

Alternatywnie `./build.sh save` tworzy pojedyncze `dist/*.tar.gz`, a
`./build.sh load <plik>` importuje je po drugiej stronie.
