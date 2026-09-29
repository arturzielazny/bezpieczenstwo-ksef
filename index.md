# Analiza bezpieczeństwa infrastruktury KSeF -- warstwa sieciowa i szyfrowanie

Data pierwotnej analizy: 2026-02-09
Rewizja: 2026-09-29 (ponowna weryfikacja wszystkich pomiarów, specyfikacji OpenAPI i oficjalnych SDK)

Analiza przygotowana z użyciem modeli AI Claude oraz Gemini.

## 0. Rewizja z 2026-09-29 -- co się zmieniło

Od pierwotnej analizy KSeF 2.0 przeszedł w tryb obowiązkowy (1 lutego 2026 dla największych podatników i odbioru faktur, 1 kwietnia 2026 dla pozostałych; 1 stycznia 2027 dla najmniejszych). Wszystkie pomiary powtórzono, a wnioski zweryfikowano.

| # | Wniosek z 2026-02-09 | Status | Komentarz |
|---|---|---|---|
| 1 | Cały ruch KSeF przechodzi przez chmurowy WAF Imperva/Incapsula, który terminuje TLS | **Aktualny, rozszerzony** | Doszły nowe hosty i drugi adres IP Impervy; nagłówki odpowiedzi (`x-cdn: Imperva`, ciasteczka `incap_ses_*`) potwierdzają proxy (sekcja 2) |
| 2 | Klucz prywatny certyfikatu TLS MF musi być na serwerach Impervy | **Aktualny, rozszerzony** | Imperva posiada dodatkowo **własne** certyfikaty GlobalSign DV dla `*.ksef.mf.gov.pl` i nowych hostów -- niezależnie od certyfikatu MF (sekcja 3) |
| 3 | Wysyłka faktur i eksport masowy są szyfrowane AES-256-CBC | **Aktualny** | Bez zmian w API |
| 4 | `GET /invoices/ksef/{ksefNumber}` i metadane zwracane jawnie | **Aktualny** | Bez zmian w API |
| 5 | Dostęp do faktur ograniczony do sprzedawcy i nabywcy | **Skorygowany** | Istnieją także role `Subject3` (podmiot trzeci) i `SubjectAuthorized` (podmiot upoważniony) (sekcja 5) |
| 6 | Certyfikat klucza publicznego MF „nie jest podpisany łańcuchem zaufania niezależnym od TLS" | **Błędny** | Certyfikaty są wystawione przez **Certum SMIME RSA CA** dla Ministerstwa Finansów i weryfikują się do Certum Trusted Root CA. Podmianę klucza da się wykryć -- ale oficjalne SDK nadal tego nie robią (sekcja 6.4) |
| 7 | Podmiana klucza RSA to główny sposób na obejście szyfrowania app-layer | **Skorygowany** | Prostszą drogą są tokeny dostępowe (bearer), widoczne jawnie dla podmiotu terminującego TLS -- pozwalają samodzielnie zlecić eksport z własnym kluczem AES (sekcja 6.2) |
| 8 | Thales jest właścicielem Imperva od 2019 roku | **Błędny** | Przejęcie zakończono **4 grudnia 2023** (w 2019 Thales przejął Gemalto) |
| 9 | Polecenie `curl https://ksef.mf.gov.pl/security/public-key-certificates` | **Błędne** | Zwraca HTTP 404. Poprawny adres: `https://api.ksef.mf.gov.pl/v2/security/public-key-certificates` |

**Nowe ustalenia w tej rewizji:**

- Endpoint `POST /tokens` zwraca długoterminowy token KSeF jawnym tekstem w JSON (sekcja 6.2).
- `refreshToken` jest ważny do 7 dni i nie jest powiązany kryptograficznie z klientem (sekcja 6.2).
- Pole `invoiceHash` (SHA-256 jawnej faktury) jest wysyłane jawnie przy uploadzie, a ten sam skrót jest częścią publicznego linku weryfikacyjnego KOD I (QR) (sekcja 6.3).
- Brak rekordów CAA dla `mf.gov.pl` i `gov.pl` (sekcja 3.4).

## 1. Streszczenie

Krajowy System e-Faktur (KSeF 2.0) korzysta z chmurowego WAF (Web Application Firewall) firmy Imperva/Incapsula w modelu SaaS. Imperva jest własnością Thales Group od grudnia 2023. Ruch do wszystkich środowisk KSeF (produkcja, demo, test, Aplikacja Podatnika, weryfikacja QR, portal informacyjny) przechodzi przez infrastrukturę Impervy, gdzie następuje terminacja TLS. Imperva ma więc techniczny dostęp do odszyfrowanego ruchu HTTP.

KSeF 2.0 stosuje dodatkowe szyfrowanie na poziomie aplikacji (RSA-OAEP + AES-256-CBC). Obejmuje ono tylko wysyłkę faktur i eksport masowy. Pobranie pojedynczej faktury, zapytania o metadane, tokeny uwierzytelniające i token KSeF przy jego generowaniu przechodzą przez warstwę Impervy jawnie.

W praktyce szyfrowanie app-layer **nie chroni treści faktur przed podmiotem terminującym TLS**. Taki podmiot widzi token dostępowy (`Authorization: Bearer ...`), którym może sam pobrać dowolną fakturę danego kontekstu albo zlecić eksport z własnym kluczem AES. Do tego nie potrzebuje podmiany klucza RSA MF.

Pierwotna analiza wskazywała podmianę klucza RSA MF jako atak niewykrywalny. Wymaga to korekty. Certyfikaty kluczy MF są podpisane przez publiczne CA (Certum), więc klient może je zweryfikować niezależnie od TLS. Oficjalne SDK (C#, Java) oraz dokumentacja MF nadal jednak takiej weryfikacji nie wykonują ani nie wymagają.

Wszystkie opisane możliwości są **zdolnościami technicznymi** wynikającymi z architektury. Analiza nie stwierdza, że ktokolwiek z nich korzysta.

## 2. Infrastruktura sieciowa

### 2.1. Rozwiązywanie nazw DNS

**Polecenia weryfikujące:**

```bash
for d in ksef.mf.gov.pl api.ksef.mf.gov.pl api-test.ksef.mf.gov.pl api-demo.ksef.mf.gov.pl \
         ap.ksef.mf.gov.pl ap-test.ksef.mf.gov.pl ap-demo.ksef.mf.gov.pl \
         qr.ksef.mf.gov.pl qr-test.ksef.mf.gov.pl ksef.podatki.gov.pl; do
  resolvectl query "$d"   # alternatywnie: getent hosts "$d" (bez informacji o CNAME)
done
```

**Wyniki z 2026-09-29:**

| Domena | Rola | CNAME | IP |
|---|---|---|---|
| ksef.mf.gov.pl | -- | nudnsjz.ng.impervadns.net | 45.60.74.103 |
| **api.ksef.mf.gov.pl** | **API produkcyjne** | hju8yoo.ng.impervadns.net | 45.60.74.103 |
| api-test.ksef.mf.gov.pl | API testowe (TE) | fdk3rx6.ng.impervadns.net | 45.60.74.103 |
| api-demo.ksef.mf.gov.pl | API przedprodukcyjne | 4sgun8h.ng.impervadns.net | 45.60.74.103 |
| ap-demo.ksef.mf.gov.pl | Aplikacja Podatnika (demo) | vmkkdg9.ng.impervadns.net | 45.60.74.103 |
| ksef-test.mf.gov.pl | -- | 7c99vzn.ng.impervadns.net | 45.60.74.103 |
| ksef-demo.mf.gov.pl | -- | vebbknt.ng.impervadns.net | 45.60.74.103 |
| qr-test.ksef.mf.gov.pl | Weryfikacja QR (TE) | sbjmvnp.ng.impervadns.net | 45.60.74.103 |
| ksef.podatki.gov.pl | Portal informacyjny | rjdumbx.ng.impervadns.net | 45.60.74.103 |
| **ap.ksef.mf.gov.pl** | **Aplikacja Podatnika (prod)** | brak (rekord A) | 45.60.186.93 |
| ap-test.ksef.mf.gov.pl | Aplikacja Podatnika (TE) | brak (rekord A) | 45.60.187.140 |
| **qr.ksef.mf.gov.pl** | **Weryfikacja QR (prod)** | brak (rekord A) | 45.60.187.129 |
| api-hub*.ksef.mf.gov.pl, api-up, api-pp, qr-up (nowe) | nieznana | *.ng.impervadns.net | 45.60.74.15 |
| api.ksef.podatki.gov.pl, ksefan.ksef.podatki.gov.pl (nowe) | nieznana | *.ng.impervadns.net | 45.60.74.15 |

Wszystkie adresy należą do puli Incapsula 45.60.0.0/16. Aplikacja Podatnika i produkcyjny serwis QR mają rekordy A wskazujące bezpośrednio na adresy Impervy, bez CNAME. Tak wygląda onboarding na dedykowanych adresach IP. Te hosty również przechodzą przez Imperva.

W lutym tabela zawierała cztery domeny o wspólnym IP 45.60.74.103. Obecnie ruch rozkłada się na co najmniej pięć adresów Impervy. Pojawiły się też nowe hosty (`api-hub`, `api-hub-test`, `api-hub-ti`, `api-hub-demo`, `api-up`, `api-pp`, `qr-up`, `qr-pp`, `ksefan*`), których przeznaczenie nie jest publicznie opisane. Ich nazwy wynikają z logów Certificate Transparency (sekcja 3.3).

### 2.2. Właściciel adresu IP

**Polecenie weryfikujące:**

```bash
whois 45.60.74.103 | grep -E 'NetRange|NetName|OrgName|Email|Updated'
```

**Wynik (2026-09-29):**

```
NetRange:       45.60.0.0 - 45.60.255.255
NetName:        THALES-IMPERVA-NA4-AGG-45-60      (w lutym: INCAPSULA-NET)
Updated:        2026-03-16
OrgName:        Incapsula Inc
OrgNOCEmail:    ww.dis.incapsula.noc@thalesgroup.com
OrgRoutingEmail: ww.dis.imperva.rir@thalesgroup.com
OrgAbuseEmail:  ww.dis.abuse@thalesgroup.com
```

Blok jest zarejestrowany w amerykańskim ARIN na Incapsula Inc (San Mateo, CA). W marcu 2026 zmieniono nazwę sieci na `THALES-IMPERVA-...`, co odzwierciedla integrację z Thales Group.

### 2.3. Traceroute

```bash
tracepath -m 30 45.60.74.103
```

**Wynik (2026-09-29, Polska):**

```
 1  unifi                              2.3ms    (router lokalny)
 2  100.64.0.1                        41.4ms    (ISP - CGNAT)
 3  172.16.251.106                    54.7ms    (ISP wewnętrzny)
 4  undefined.hostname.localhost      38.2ms    (ISP)
 5  undefined.hostname.localhost      43.0ms    (ISP)
 6  incapsula.plix.pl                 56.3ms    (Imperva @ PLIX)
 7+ no reply
```

Wynik jest zgodny z lutowym. Ruch trafia do węzła Impervy na PLIX (Warszawa). Wyższe opóźnienia wynikają z łącza satelitarnego punktu pomiarowego.

### 2.4. Nagłówki HTTP potwierdzające proxy

**Polecenie weryfikujące:**

```bash
curl -sD - -o /dev/null https://api.ksef.mf.gov.pl/v2/security/public-key-certificates
```

**Istotne nagłówki odpowiedzi:**

```
server: Kestrel                                  <- serwer źródłowy (ASP.NET Core)
x-cdn: Imperva
x-iinfo: 52-76363486-76356158 PNNN RT(...) ...  <- identyfikator żądania Impervy
set-cookie: visid_incap_3296082=...; Domain=.ksef.mf.gov.pl
set-cookie: incap_ses_683_3296082=...; Domain=.ksef.mf.gov.pl
strict-transport-security: max-age=31536000
```

Imperva wstrzykuje do odpowiedzi API własne ciasteczka śledzące (`visid_incap_*`, `incap_ses_*`) dla całej domeny `.ksef.mf.gov.pl`. Dotyczy to też odpowiedzi dla klientów maszynowych (ERP). API wystawia HSTS bez `includeSubDomains`. Aplikacja Podatnika (`ap.ksef.mf.gov.pl`) ma pełne HSTS z `includeSubDomains; preload`.

### 2.5. Wniosek dotyczący infrastruktury

Wniosek z lutego pozostaje aktualny: MF korzysta z **chmurowego Cloud WAF (Imperva/Incapsula)** w modelu SaaS i obejmuje nim wszystkie publiczne punkty styku KSeF. Należą do nich API, Aplikacja Podatnika, weryfikacja QR i portal. Wskazują na to adresy IP z puli Incapsula, CNAME do `impervadns.net`, ścieżka przez `incapsula.plix.pl` i nagłówki `x-cdn: Imperva`.

## 3. Certyfikaty SSL/TLS

### 3.1. Certyfikat MF serwowany na głównych hostach

```bash
for d in api.ksef.mf.gov.pl ap.ksef.mf.gov.pl qr.ksef.mf.gov.pl; do
  echo | openssl s_client -connect $d:443 -servername $d 2>/dev/null | \
    openssl x509 -noout -subject -issuer -dates -fingerprint -sha256
done
```

| Pole | Wartość |
|---|---|
| Podmiot | C=PL, L=Warszawa, O=MINISTERSTWO FINANSÓW, CN=*.ksef.mf.gov.pl |
| SAN | `*.ksef.mf.gov.pl`, `ksef.mf.gov.pl` |
| Wystawca | GeoTrust TLS RSA CA G1 (DigiCert) -> DigiCert Global Root G2 |
| Ważność | 2025-12-08 -- 2026-12-07 |
| SHA-256 | `D4:96:E5:50:09:EF:01:02:94:52:8E:96:12:7D:66:F8:61:F4:B1:06:5C:B5:FC:88:00:5A:32:3F:25:4B:6B:D8` |

Ten sam certyfikat (OV, RSA 2048) serwują `api`, `api-test`, `api-demo`, `ap`, `qr` i `ksef.mf.gov.pl`. Imperva terminuje TLS dla tych hostów tym certyfikatem, więc jego klucz prywatny jest zainstalowany w infrastrukturze Impervy. Wniosek z lutego pozostaje aktualny.

### 3.2. Certyfikaty wygenerowane przez Imperva (nowe ustalenie)

Imperva Cloud WAF może zamówić certyfikat w swoim imieniu u **GlobalSign** (tzw. *Imperva-generated certificate*). Klient zatwierdza wydanie rekordem TXT w DNS. Imperva generuje wtedy i przechowuje klucz prywatny sama. Obecnie takie certyfikaty są serwowane na części hostów:

| Host | Wystawca | Ważność |
|---|---|---|
| api-hub, api-hub-test, api-up, api-pp, qr-up (.ksef.mf.gov.pl) | GlobalSign Atlas R46 DV TLS CA 2026 Q3 | do XI-XII 2026 |
| ksef.podatki.gov.pl | GlobalSign Atlas R46 DV TLS CA 2026 Q3 | 2026-08-23 -- 2026-11-21 |

`ksef.podatki.gov.pl` ma w logach CT także certyfikat Certum OV wystawiony dla MF (`*.ksef.podatki.gov.pl`, ważny do 2026-11-25). Obecnie serwowany jest jednak certyfikat GlobalSign DV wygenerowany przez Imperva.

### 3.3. Certificate Transparency -- `*.ksef.mf.gov.pl`

**Polecenie weryfikujące:**

```bash
curl -s 'https://crt.sh/?q=%25.ksef.mf.gov.pl&output=json&exclude=expired' | python3 -c "
import json,sys
for c in sorted(json.load(sys.stdin), key=lambda x: x['not_before']):
    print(c['not_before'][:10], c['not_after'][:10], c['issuer_name'].split('CN=')[-1], '|', c['name_value'].replace(chr(10), ','))
" | sort -u
```

**Wynik (ważne certyfikaty na 2026-09-29):**

```
2025-12-08 2026-12-07 GeoTrust TLS RSA CA G1                  | *.ksef.mf.gov.pl,ksef.mf.gov.pl   <- certyfikat MF (OV)
2026-07-02 2026-09-30 GlobalSign Atlas R46 DV TLS CA 2026 Q2  | *.ksef.mf.gov.pl                  <- certyfikat Impervy (DV)
2026-07-16 2026-10-14 GlobalSign Atlas R46 DV TLS CA 2026 Q2  | qr-up / api-up / qr-pp / api-pp
2026-08-25 2026-11-23 GlobalSign Atlas R46 DV TLS CA 2026 Q3  | api-hub / api-hub-test / api-hub-ti / api-hub-demo
2026-09-14 2026-12-13 GlobalSign Atlas R46 DV TLS CA 2026 Q3  | api-up
```

Najważniejsza obserwacja: od 2026-07-02 istnieje **drugi, publicznie zaufany certyfikat wildcard `*.ksef.mf.gov.pl`**. Jego klucz prywatny wygenerowała Imperva. Wynika z tego, że:

- Imperva może terminować TLS dla dowolnego hosta `*.ksef.mf.gov.pl`, w tym `api.ksef.mf.gov.pl`, **własnym** kluczem, niezależnie od certyfikatu MF.
- Model „Keyless SSL" lub HSM po stronie MF niczego by tu nie zmienił, bo dla tej domeny istnieje ważny certyfikat z kluczem wyłącznie po stronie Impervy.
- Certyfikat wildcard Impervy wygasa 2026-09-30. Jego odnowienie (lub brak) będzie widoczne w CT.

### 3.4. Brak rekordów CAA

```bash
resolvectl query --type=CAA mf.gov.pl
resolvectl query --type=CAA gov.pl
```

Ani `mf.gov.pl`, ani `gov.pl` nie publikują rekordów CAA (RFC 8659). Każde publiczne CA może więc wydać certyfikat dla domen KSeF po przejściu walidacji domeny. Rekord CAA ograniczający wydawców do DigiCert i Certum nie zmieniłby pozycji Impervy jako proxy. Uniemożliwiłby jednak automatyczne wydawanie certyfikatów GlobalSign bez świadomej decyzji MF i utrudnił nieautoryzowaną emisję.

### 3.5. Implikacje

Pierwotny wniosek, że klucz prywatny TLS MF musi być u Impervy, jest aktualny. Wymaga jednak uzupełnienia: Imperva **nie potrzebuje** klucza MF, bo ma własne, publicznie zaufane certyfikaty dla tych samych nazw. Z punktu widzenia poufności TLS chroni wyłącznie odcinek klient–Imperva. Imperva jest dla klienta pełnoprawnym „serwerem KSeF".

## 4. Szyfrowanie na poziomie aplikacji (KSeF 2.0 API)

Źródło: [CIRFMF/ksef-docs/open-api.json](https://github.com/CIRFMF/ksef-docs/blob/main/open-api.json), stan z 2026-09-22 (commit `c50f855`).

### 4.1. Wysyłka faktur (sesja interaktywna i wsadowa)

Mechanizm pozostaje bez zmian. Klient generuje klucz AES-256 i IV, szyfruje fakturę algorytmem AES-256-CBC z PKCS#7, a klucz AES szyfruje RSA-OAEP (SHA-256) kluczem publicznym MF o przeznaczeniu `SymmetricKeyEncryption`. Pole `encryption` jest wymagane w `OpenOnlineSessionRequest` i `OpenBatchSessionRequest`. Od 2026 r. żądania zawierają też `publicKeyId`, który wskazuje, jakim kluczem MF zaszyfrowano klucz AES.

```bash
curl -sL 'https://raw.githubusercontent.com/CIRFMF/ksef-docs/main/open-api.json' | \
  python3 -c "import json,sys; s=json.load(sys.stdin); print(json.dumps(s['components']['schemas']['SendInvoiceRequest'], indent=2, ensure_ascii=False))"
```

Schemat `SendInvoiceRequest` wymaga pól `encryptedInvoiceContent`, `encryptedInvoiceHash`, `encryptedInvoiceSize`, **`invoiceHash`** i **`invoiceSize`**. Dwa ostatnie to skrót SHA-256 i rozmiar **jawnej** faktury, przesyłane jawnie (znaczenie w sekcji 6.3).

Szyfrowanie AES-CBC nie zapewnia integralności (brak MAC/AEAD). W kierunku klient -> KSeF integralność zabezpiecza pośrednio `invoiceHash` sprawdzany po odszyfrowaniu.

### 4.2. Eksport masowy

`POST /invoices/exports` wymaga pola `encryption` (klucz AES klienta zaszyfrowany RSA). Paczki (części do 50 MB, `*.zip.aes`) są szyfrowane AES-256-CBC kluczem klienta. Według dokumentacji środowisk adresy URL do pobrania paczek są w domenie danego środowiska, więc również przechodzą przez Imperva. Parametry w przykładowych URL-ach (`skoid`, `sktid`, `skv`, `sig`) mają format sygnatur SAS usługi Azure Blob Storage. Wskazuje to na magazyn danych w chmurze Microsoft Azure, choć nie zostało zweryfikowane na produkcji.

### 4.3. Pobranie pojedynczej faktury -- bez szyfrowania

```bash
curl -sL 'https://raw.githubusercontent.com/CIRFMF/ksef-docs/main/open-api.json' | \
  python3 -c "import json,sys; s=json.load(sys.stdin); print(json.dumps(s['paths']['/invoices/ksef/{ksefNumber}']['get']['responses']['200'], indent=2))"
```

Odpowiedź `200` ma typ `application/xml` (`type: string`). Treść faktury jest przesyłana jawnie, bez szyfrowania app-layer. Wymagane uprawnienie: `InvoiceRead`. Stan bez zmian od lutego.

### 4.4. Metadane faktur -- bez szyfrowania

`POST /invoices/query/metadata` zwraca jawny JSON (`QueryInvoicesMetadataResponse`) z numerami KSeF, NIP-ami stron, kwotami netto/brutto/VAT i datami. Stan bez zmian.

### 4.5. Pozostałe jawne dane wrażliwe (nowe w tej rewizji)

| Endpoint | Co jest przesyłane jawnie (poza TLS) |
|---|---|
| `POST /auth/token/redeem` | `accessToken` (JWT, ok. 15 min) i `refreshToken` (do 7 dni) |
| `POST /auth/token/refresh` | `refreshToken` w nagłówku, nowy `accessToken` w odpowiedzi |
| każde żądanie po uwierzytelnieniu | `Authorization: Bearer <accessToken>` |
| **`POST /tokens`** | **Token KSeF w odpowiedzi -- długoterminowy, ważny do odwołania** |
| `POST /collective-identifiers/*` | identyfikatory zbiorcze, kwoty i opisy płatności |
| `GET /sessions/.../upo` | UPO: numery KSeF, skróty faktur, daty |
| `POST /permissions/*` | struktura uprawnień: kto (PESEL/NIP/odcisk certyfikatu) ma dostęp do czego |

### 4.6. Podsumowanie według endpointów

| Endpoint | Operacja | Szyfrowanie app-layer | Co widzi podmiot terminujący TLS |
|---|---|---|---|
| `POST /sessions/online`, `/sessions/batch` | Otwarcie sesji | RSA-OAEP (wymiana klucza) | zaszyfrowany klucz AES |
| `POST /sessions/online/{ref}/invoices` | Wysyłka faktury | AES-256-CBC | zaszyfrowany blob **+ jawny SHA-256 i rozmiar faktury** |
| `POST /invoices/exports` + pobranie części | Eksport masowy | AES-256-CBC | zaszyfrowane paczki |
| `GET /invoices/ksef/{ksefNumber}` | **Pobranie faktury** | **brak** | **pełna treść XML** |
| `POST /invoices/query/metadata` | **Metadane** | **brak** | **NIP-y, kwoty, daty** |
| `POST /auth/token/redeem`, `/refresh` | **Tokeny sesji** | **brak** | **accessToken, refreshToken** |
| `POST /tokens` | **Generowanie tokena KSeF** | **brak** | **token KSeF** |
| `POST /auth/ksef-token` | Uwierzytelnienie tokenem KSeF | RSA-OAEP (`KsefTokenEncryption`) | zaszyfrowany token |

## 5. Model autoryzacji -- zakres dostępu (skorygowany)

Uwierzytelnienie odbywa się w kontekście (`ContextIdentifier`: NIP, identyfikator wewnętrzny, NIP-VAT UE lub Peppol ID). Uprawnienia (`InvoiceRead`, `InvoiceWrite` itd.) są nadawane w tym kontekście.

Pierwotna analiza podawała, że faktury widzą tylko sprzedawca (`Subject1`) i nabywca (`Subject2`). Enum `InvoiceQuerySubjectType` zawiera jednak cztery wartości:

| Wartość | Znaczenie |
|---|---|
| Subject1 | sprzedawca |
| Subject2 | nabywca |
| **Subject3** | **podmiot trzeci wskazany na fakturze (np. faktor, płatnik, odbiorca, JST)** |
| **SubjectAuthorized** | **podmiot upoważniony** |

Dochodzi do tego delegowanie uprawnień (`/permissions/*`): biura rachunkowe, uprawnienia pośrednie, podmioty podporządkowane i komornicze (`EnforcementOperations`). W praktyce jeden token biura rachunkowego lub integratora może dawać dostęp do faktur wielu firm. Ekspozycja pojedynczego tokena jest przez to szersza, niż zakładała pierwotna analiza.

Wniosek z lutego, że Imperva widzi jawnie tylko faktury aktualnie pobierane przez zalogowane podmioty, jest **zbyt optymistyczny** w świetle sekcji 6.2.

## 6. Ocena ryzyka

### 6.1. Co widzi podmiot terminujący TLS (Imperva)

**Zawsze:**
- adresy IP klientów, nagłówki, ścieżki URL (numery KSeF, numery referencyjne sesji)
- tokeny `accessToken` / `refreshToken` / `AuthenticationToken`
- rozmiary i częstotliwość żądań

**Przy pobieraniu faktur, metadanych, UPO i uprawnień:**
- pełna treść XML faktur, listy faktur z kwotami i NIP-ami, struktura uprawnień

**Przy wysyłce faktury:**
- zaszyfrowaną treść, ale jawny SHA-256 i rozmiar faktury

**Przy generowaniu tokena KSeF (API lub Aplikacja Podatnika):**
- sam token KSeF

### 6.2. Obejście szyfrowania app-layer bez podmiany klucza (nowe ustalenie)

Szyfrowanie app-layer chroni **dane w tranzycie**. Nie chroni **dostępu do danych**. Dostęp jest autoryzowany tokenem typu bearer, a token przechodzi przez tę samą warstwę TLS.

Podmiot terminujący TLS, który zdecydowałby się działać aktywnie, mógłby bez podmiany jakichkolwiek kluczy:

```
1. Odczytać nagłówek Authorization: Bearer <accessToken> z dowolnego żądania klienta
   (lub refreshToken z POST /auth/token/refresh -- ważny do 7 dni).
2. Wywołać POST /invoices/exports z WŁASNYM kluczem AES, zaszyfrowanym
   PRAWDZIWYM kluczem publicznym MF (pobranym jak każdy inny klient).
3. Pobrać paczkę i odszyfrować ją własnym kluczem AES.
   -> pełne archiwum faktur kontekstu (sprzedaż i zakup) w zakresie uprawnień tokena.
Alternatywnie: GET /invoices/ksef/{ksefNumber} -- faktury w postaci jawnej.
```

Czynniki, które ten scenariusz ułatwiają:

- **Brak powiązania tokena z klientem.** Specyfikacja nie przewiduje DPoP (RFC 9449) ani tokenów powiązanych z certyfikatem mTLS (RFC 8705). JWT z przykładu w OpenAPI (`alg: HS256`) nie zawiera claimu `cnf`.
- **Odświeżanie tokena.** `refreshToken` pozwala utrzymać dostęp do 7 dni bez ponownego podpisu XAdES.
- **Jawny token KSeF.** `POST /tokens` zwraca go jawnie w JSON. Token KSeF działa do odwołania i pozwala uwierzytelnić się od nowa.
- **Ograniczone wykrywanie po stronie serwera.** Serwer źródłowy widzi wszystkie połączenia jako przychodzące z adresów Impervy. Prawdziwy adres klienta zna tylko z nagłówków ustawianych przez proxy (np. `X-Forwarded-For`, `Incap-Client-IP`). Dodatkowe żądania wstrzyknięte przez proxy nie różnią się sieciowo od ruchu klienta. Podatnik widzi je co najwyżej jako dodatkowe operacje eksportu, jeśli przegląda historię.

Wniosek: dla poufności faktur **odbieranych** i **wystawionych w przeszłości** szyfrowanie app-layer nie stanowi bariery wobec podmiotu terminującego TLS. Realną barierą są wyłącznie umowa, audyt i reputacja operatora. Podmiana klucza RSA (sekcja 6.4) jest scenariuszem trudniejszym i łatwiejszym do wykrycia, a daje mniej.

### 6.3. Jawny skrót faktury i kod QR (nowe ustalenie)

`invoiceHash` (SHA-256 jawnego pliku faktury) jest wysyłany jawnie przy każdej wysyłce faktury. Ten sam skrót, zakodowany w Base64URL, tworzy razem z NIP-em sprzedawcy i datą wystawienia publiczny link weryfikacyjny KOD I:

```
https://qr.ksef.mf.gov.pl/invoice/{NIP sprzedawcy}/{DD-MM-RRRR}/{SHA-256 Base64URL}
```

Według [dokumentacji](https://github.com/CIRFMF/ksef-docs/blob/main/kody-qr.md) link prowadzi do „uproszczonej prezentacji podstawowych danych faktury" bez logowania. Pełny XML wymaga dodatkowych danych. Obserwator ruchu wysyłkowego ma skrót i NIP kontekstu, a datę może wywnioskować z czasu wysyłki. Może więc zbudować link KOD I dla faktur wysyłanych w zaszyfrowanej postaci, co częściowo niweluje szyfrowanie treści. Dodatkowo jawny skrót pozwala na ataki potwierdzające: sprawdzenie, czy wysłano fakturę o przewidywanej treści (np. faktury szablonowe o znanej kwocie).

### 6.4. Podmiana klucza publicznego RSA MF (skorygowane)

#### 6.4.1. Co było błędne w pierwotnej analizie

Pierwotna analiza zakładała, że klucz publiczny MF to „po prostu DER/Base64 serwowany z HTTP API", niepodpisany niezależnym łańcuchem zaufania. **To nieprawda.** Certyfikaty ważne od 2025-09-29, czyli obowiązujące także w dniu pierwotnej analizy, są certyfikatami X.509 wystawionymi przez publiczne CA:

```bash
curl -s https://api.ksef.mf.gov.pl/v2/security/public-key-certificates | python3 -c "
import json,sys,base64,subprocess
for i,c in enumerate(json.load(sys.stdin)):
    der=base64.b64decode(c['certificate']); open(f'mf_{i}.der','wb').write(der)
    print(c['usage'], c['publicKeyId'])
    print(subprocess.run(['openssl','x509','-inform','DER','-noout','-subject','-issuer','-dates'],
          input=der,capture_output=True,text=False).stdout.decode())
"
```

| Pole | `KsefTokenEncryption` | `SymmetricKeyEncryption` |
|---|---|---|
| Podmiot | O=Ministerstwo Finansów, organizationIdentifier=**VATPL-5260250274**, email konsultacje.ksef@mf.gov.pl | jak obok |
| Wystawca | **Certum SMIME RSA CA** (Asseco Data Systems) -> Certum Trusted Root CA | jak obok |
| Ważność | 2025-09-29 -- 2027-09-29 | 2025-09-29 -- 2027-09-29 |
| Klucz | RSA 2048 | RSA 2048 |
| `publicKeyId` (prod) | `U9nl7aASOL9UFAx2rTSIsSKZZ9tG8s0BuwtSxxCR6uQ=` | `cltYHGYo9EeryDOgOVvz7AsTpGbCsOxVh/uV4ugpcFY=` |
| Polityka | 2.23.140.1.5.2.2 (CA/B Forum S/MIME, organization-validated) | jak obok |

`publicKeyId` to Base64 skrótu SHA-256 z `SubjectPublicKeyInfo`. Środowiska TEST i DEMO używają wspólnej pary kluczy, innej niż produkcja.

**Weryfikacja łańcucha, niezależna od TLS i od Impervy:**

```bash
curl -s http://csmimersaca.repository.certum.pl/csmimersaca.cer | openssl x509 -inform DER -out certum-smime.pem
for i in 0 1; do
  openssl x509 -inform DER -in mf_$i.der -out mf_$i.pem
  openssl verify -purpose smimeencrypt -untrusted certum-smime.pem mf_$i.pem      # -> OK
  openssl x509 -in mf_$i.pem -noout -subject | grep -q 'VATPL-5260250274' && echo "podmiot: MF"
done
openssl ocsp -issuer certum-smime.pem -cert mf_1.pem -url http://csmimersaca.ocsp-certum.com -noverify   # -> good
```

Oba certyfikaty weryfikują się do Certum Trusted Root CA z systemowego magazynu zaufania. OCSP zwraca status `good` (2026-09-29).

Podmiot kontrolujący TLS nie jest w stanie podstawić własnego klucza tak, żeby przeszedł tę weryfikację. Wymagałoby to certyfikatu S/MIME wystawionego przez publiczne CA dla Ministerstwa Finansów z NIP-em 5260250274, czyli błędnej emisji lub kompromitacji CA. Pierwotna teza o niewykrywalności ataku była więc błędna **dla klienta, który weryfikuje certyfikat**.

Uwaga: dokumentacja MF ([klucze-publiczne-do-szyfrowania.md](https://github.com/CIRFMF/ksef-docs/blob/main/bezpieczenstwo/klucze-publiczne-do-szyfrowania.md), 05.05.2026) określa wystawcę jako „kwalifikowane centrum certyfikacji". Certyfikaty nie zawierają jednak rozszerzenia QCStatements, więc nie są certyfikatami kwalifikowanymi w rozumieniu eIDAS. Są publicznie zaufanymi certyfikatami S/MIME. Z punktu widzenia opisanej weryfikacji to wystarcza.

#### 6.4.2. Co pozostaje aktualne -- klienci nie weryfikują

| Element | Stan na 2026-09 | Weryfikacja łańcucha / pinning |
|---|---|---|
| Dokumentacja MF (`klucze-publiczne-do-szyfrowania.md`) | wskazuje wybór certyfikatu po `usage` i `validFrom` | **brak wymogu** weryfikacji łańcucha i podmiotu |
| SDK C# (`CryptographyService.cs`, commit `4b3f051`, 2026-09-24) | pobiera certyfikaty z API, odświeża cyklicznie, wyciąga klucz publiczny | **brak** (`X509Chain` nieużywany); ręczny pinning możliwy przez `SetExternalMaterials(...)` |
| SDK Java (`DefaultCryptographyService.java`, commit `dc6cb26`, 2026-09-25) | `parsePublicKeyFromCertificatePem` -> `CertificateFactory.generateCertificate` -> `getPublicKey` | **brak** (brak `CertPathValidator` / `PKIXParameters`) |

Procedura obsługi błędu `21470` (nieznany lub wycofany klucz) każe klientowi pobrać listę ponownie i użyć certyfikatu o najpóźniejszym `validFrom`. Klient bez weryfikacji łańcucha zaakceptuje więc każdy „nowy" certyfikat podany przez warstwę TLS. Aktywny pośrednik mógłby przy tym sam wymusić ponowne pobranie, zwracając błąd `21470`.

Scenariusz podmiany opisany w lutym (podstawienie klucza, odszyfrowanie, ponowne zaszyfrowanie prawdziwym kluczem MF) **pozostaje technicznie wykonalny wobec klientów zbudowanych na oficjalnych SDK** bez własnej walidacji. Nie jest jednak niewykrywalny: każdy, kto pobierze listę przez tę samą warstwę i zweryfikuje łańcuch, wykryje podmianę. Podmiana globalna byłaby wykryta niemal natychmiast.

#### 6.4.3. Ocena po korekcie

- Wobec klientów weryfikujących certyfikat: podmiana klucza praktycznie niemożliwa.
- Wobec klientów na oficjalnych SDK: możliwa, ale tylko selektywnie, bo globalna zostałaby szybko wykryta. Daje mniej niż przejęcie tokenów z sekcji 6.2. Jej jedyną unikalną wartością jest odczyt faktur w momencie wysyłki i przechwycenie tokena KSeF w `POST /auth/ksef-token`.
- W hierarchii ryzyk scenariusz ten jest **wtórny** wobec sekcji 6.2.

### 6.5. Czynniki łagodzące

1. Szyfrowanie app-layer chroni wysyłane faktury i paczki eksportu przed **pasywnym** podsłuchem, np. logowaniem ruchu na WAF.
2. Certyfikaty kluczy MF są weryfikowalne niezależnie od TLS (sekcja 6.4.1).
3. Tokeny `accessToken` mają krótki czas życia (ok. 15 min). Sesje można unieważniać (`DELETE /auth/sessions/*`), tokeny KSeF również (`DELETE /tokens/{ref}`).
4. Aktywne wykorzystanie tokenów lub podmiana kluczy to działania celowe. Byłyby naruszeniem umowy i prawa oraz niosłyby dla Thales/Imperva ryzyko wykrycia i poważne konsekwencje.
5. Ruch kierowany jest przez węzeł Impervy na PLIX (Warszawa). MF deklaruje, że serwery docelowe są w Polsce.

### 6.6. Czynniki ryzyka

1. Terminacja TLS i pełny wgląd w ruch po stronie podmiotu zewnętrznego wobec administracji (Imperva/Thales).
2. Imperva posiada własne, publicznie zaufane certyfikaty `*.ksef.mf.gov.pl` (sekcja 3.2).
3. Tokeny typu bearer bez powiązania z klientem (sekcja 6.2).
4. Brak szyfrowania app-layer dla pobierania faktur, metadanych, tokenów i UPO.
5. Jawny `invoiceHash` powiązany z publicznym linkiem KOD I (sekcja 6.3).
6. Oficjalne SDK i dokumentacja nie wymagają weryfikacji certyfikatu klucza MF (sekcja 6.4.2).
7. Brak rekordów CAA dla `mf.gov.pl` (sekcja 3.4).
8. Brak publicznej informacji o audycie tej konfiguracji ani o zakresie logowania treści żądań przez WAF.

### 6.7. Kontekst prawny

- **Imperva, Inc. / Incapsula Inc.** -- spółki amerykańskie (San Mateo, CA). Potencjalnie podlegają US CLOUD Act (dane w „posiadaniu, pieczy lub kontroli" dostawcy, także poza USA) i FISA 702 (dostawcy usług komunikacji elektronicznej). Czy terminujący TLS reverse proxy mieści się w tych definicjach, zależy od interpretacji. Nie jest to przesądzone, ale nie da się tego wykluczyć.
- **Thales S.A.** (Francja) -- właściciel od 4 grudnia 2023 (przejęcie od Thoma Bravo za ok. 3,6 mld USD). Podlega prawu francuskiemu i UE.
- Dla MF Imperva jest podmiotem przetwarzającym w rozumieniu RODO. Treść umowy powierzenia, lokalizacja logów oraz podstawa ewentualnego transferu danych poza EOG nie są publicznie znane.

## 7. Rekomendacje

### 7.1. Dla Ministerstwa Finansów

1. **Powiązanie tokenów z klientem.** Wprowadzić DPoP (RFC 9449) lub tokeny powiązane z certyfikatem KSeF przez mTLS (RFC 8705), żeby przechwycony token był bezużyteczny bez klucza prywatnego klienta. Wymaga to terminacji mTLS na serwerze MF albo przekazania informacji o certyfikacie klienta przez WAF, co należy świadomie zaprojektować.
2. **Szyfrowanie odpowiedzi.** Objąć szyfrowaniem app-layer `GET /invoices/ksef/{ksefNumber}` i metadane (np. klucz AES przekazywany w żądaniu, jak w eksporcie). Samo to nie wystarczy bez punktu 1.
3. **Nie zwracać tokena KSeF jawnie.** W `POST /tokens` szyfrować token kluczem podanym przez klienta w żądaniu.
4. **Wymóg weryfikacji certyfikatu klucza MF** w dokumentacji: łańcuch do Certum Trusted Root CA, `organizationIdentifier=VATPL-5260250274`, sprawdzenie OCSP. Wdrożyć to w SDK C# i Java jako zachowanie domyślne. Sprostować w dokumentacji określenie „kwalifikowane".
5. **Publikacja `publicKeyId` i odcisków certyfikatów** w kanale niezależnym od infrastruktury KSeF, np. BIP lub komunikat na gov.pl hostowany poza Impervą.
6. **Rekordy CAA** dla `ksef.mf.gov.pl` ograniczające wydawców do świadomie wybranych CA. Rozważyć rezygnację z certyfikatów generowanych przez Imperva na rzecz certyfikatów MF.
7. **Przejrzystość:** opublikować informację o modelu przetwarzania danych przez Imperva (logowanie treści, retencja, lokalizacja, audyty).

### 7.2. Dla integratorów i dostawców ERP

1. Weryfikować certyfikat klucza MF (łańcuch + podmiot) przy każdym pobraniu. Najlepiej pinować `publicKeyId` i traktować każdą zmianę jako zdarzenie wymagające potwierdzenia, nie jako automatyczną aktualizację. W SDK C#: `SetExternalMaterials(...)`.
2. Tokeny KSeF generować z minimalnymi uprawnieniami (np. osobno `InvoiceWrite` i `InvoiceRead`) i okresowo je rotować.
3. Unieważniać sesję (`DELETE /auth/sessions/current`) po zakończeniu pracy, zamiast polegać na 7-dniowym `refreshToken`.
4. Monitorować historię eksportów i sesji kontekstu (`GET /sessions`, `GET /auth/sessions`) pod kątem operacji niezainicjowanych przez własny system.

### 7.3. Dla podatników

Faktur przechowywanych w KSeF nie należy traktować jako poufnych wobec operatora infrastruktury pośredniczącej. Przy danych szczególnie wrażliwych (tajemnica przedsiębiorstwa w opisach pozycji, dane osobowe) warto ograniczać ich zakres na fakturze do wymaganego prawem minimum.

## 8. Metodologia

Pomiary z 2026-02-09 powtórzono 2026-09-29 z tej samej lokalizacji (Polska, Starlink CGNAT):

- `resolvectl query` -- rozwiązywanie nazw DNS z CNAME i rekordów CAA
- `whois` -- właściciel adresów IP (ARIN)
- `tracepath` -- ścieżka sieciowa
- `openssl s_client` / `x509` / `verify` / `ocsp` -- certyfikaty TLS i certyfikaty kluczy MF
- `curl -D -` -- nagłówki HTTP
- crt.sh -- logi Certificate Transparency
- specyfikacja OpenAPI KSeF 2.0 i dokumentacja: `CIRFMF/ksef-docs` @ `c50f855` (2026-09-22)
- SDK C#: `CIRFMF/ksef-client-csharp` @ `4b3f051` (2026-09-24); SDK Java: `CIRFMF/ksef-client-java` @ `dc6cb26` (2026-09-25)

Nie wykonywano żadnych prób ataku ani uwierzytelnienia. Wykorzystano wyłącznie publiczne endpointy (`/security/public-key-certificates`), publiczne rejestry i publiczne repozytoria. Wyniki odzwierciedlają stan na dzień pomiaru.

## 9. Źródła

- Dokumentacja KSeF: https://ksef.podatki.gov.pl/
- Dokumentacja techniczna MF: https://github.com/CIRFMF/ksef-docs
  - Klucze publiczne do szyfrowania: https://github.com/CIRFMF/ksef-docs/blob/main/bezpieczenstwo/klucze-publiczne-do-szyfrowania.md
  - Uwierzytelnianie: https://github.com/CIRFMF/ksef-docs/blob/main/uwierzytelnianie.md
  - Kody QR: https://github.com/CIRFMF/ksef-docs/blob/main/kody-qr.md
  - Środowiska: https://github.com/CIRFMF/ksef-docs/blob/main/srodowiska.md
- Specyfikacja OpenAPI: https://github.com/CIRFMF/ksef-docs/blob/main/open-api.json
- Klient C#: https://github.com/CIRFMF/ksef-client-csharp
- Klient Java: https://github.com/CIRFMF/ksef-client-java
- Komunikat MF o zmianie adresów środowisk: https://www.gov.pl/web/finanse/przypominamy-o-zmianie-adresow-srodowisk-ksef--komunikat-dla-integratorow
- Thales -- zakończenie przejęcia Imperva (4.12.2023): https://www.thalesgroup.com/en/news-centre/press-releases/thales-completes-acquisition-imperva-creating-global-leader
- Imperva -- certyfikaty generowane przez Imperva (GlobalSign): https://www.imperva.com/blog/add-ssl-support-to-incapsula-protected-site/ oraz https://docs-cybersec.thalesgroup.com/bundle/cloud-application-security/page/cname-account.htm
- Certificate Transparency: https://crt.sh/?q=%25.ksef.mf.gov.pl
- RFC 9449 (DPoP), RFC 8705 (mTLS-bound tokens), RFC 8659 (CAA)
