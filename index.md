# Analiza bezpieczenstwa infrastruktury KSeF -- warstwa sieciowa i szyfrowanie

Data analizy: 2026-02-09

## 1. Streszczenie

Krajowy System e-Faktur (KSeF 2.0) wykorzystuje chmurowy WAF (Web Application Firewall) firmy Imperva/Incapsula (nalezacej do Thales Group) w modelu SaaS. Ruch sieciowy do wszystkich srodowisk KSeF przechodzi przez infrastrukture nalezaca do Imperva, gdzie nastepuje terminacja TLS. Oznacza to, ze Imperva technicznie posiada dostep do odszyfrowanego ruchu HTTP.

KSeF 2.0 implementuje dodatkowe szyfrowanie na poziomie aplikacji (AES-256-CBC) dla operacji wysylania faktur oraz masowego eksportu. Jednakze endpoint pobierania pojedynczej faktury (`GET /invoices/ksef/{ksefNumber}`) zwraca dane jako plain XML chroniony wylacznie TLS -- ktory jest terminowany przez Imperva.

Ponadto klucz publiczny RSA Ministerstwa Finansow, na ktorym opiera sie szyfrowanie app-layer, jest pobierany dynamicznie z publicznego endpointu API (`GET /security/public-key-certificates`), ktory sam przechodzi przez Imperva. Brak pinningu klucza w SDK oznacza, ze podmiot kontrolujacy warstwe TLS moze teoretycznie podmienic klucz publiczny i zneutralizowac szyfrowanie na poziomie aplikacji (sekcja 6.4).

## 2. Infrastruktura sieciowa

### 2.1. Resolucja DNS

Wszystkie domeny KSeF rozwiazuja sie na ten sam adres IP poprzez rekordy CNAME w domenie Imperva.

**Polecenia weryfikujace:**

```bash
getent hosts ksef.mf.gov.pl
getent hosts api-test.ksef.mf.gov.pl
getent hosts ap-demo.ksef.mf.gov.pl
getent hosts ksef.podatki.gov.pl
```

**Wyniki z dnia analizy:**

| Domena | CNAME | IP |
|---|---|---|
| ksef.mf.gov.pl | nudnsjz.ng.impervadns.net | 45.60.74.103 |
| api-test.ksef.mf.gov.pl | fdk3rx6.ng.impervadns.net | 45.60.74.103 |
| ap-demo.ksef.mf.gov.pl | vmkkdg9.ng.impervadns.net | 45.60.74.103 |
| ksef.podatki.gov.pl | rjdumbx.ng.impervadns.net | 45.60.74.103 |

Wszystkie rekordy CNAME wskazuja na domene `ng.impervadns.net`, ktora jest infrastruktura DNS zarzadzana przez Imperva.

### 2.2. Wlasciciel adresu IP

**Polecenie weryfikujace:**

```bash
whois 45.60.74.103
```

**Kluczowe dane z ARIN:**

```
NetRange:       45.60.0.0 - 45.60.255.255
NetName:        INCAPSULA-NET
OrgName:        Incapsula Inc
Address:        One Curiosity Way, Suite 203, SAN MATEO, CA, US
OrgAbuseEmail:  ww.dis.abuse@thalesgroup.com
OrgRoutingEmail: ww.dis.imperva.rir@thalesgroup.com
OrgNOCEmail:    ww.dis.incapsula.noc@thalesgroup.com
```

Blok IP 45.60.0.0/16 jest zarejestrowany na Incapsula Inc w amerykanskim rejestrze ARIN. Kontakty techniczne (abuse, NOC, routing) prowadza do domen @thalesgroup.com -- Thales Group jest wlascicielem Imperva od 2019 roku.

### 2.3. Traceroute

**Polecenie weryfikujace:**

```bash
tracepath -m 30 45.60.74.103
```

**Wynik (z lokalizacji w Polsce):**

```
 1  unifi                              1.2ms    (router lokalny)
 2  100.64.0.1                        23.9ms    (ISP - CGNAT)
 3  172.16.251.24                     32.7ms    (ISP wewnetrzny)
 4  undefined.hostname.localhost      40.1ms    (ISP)
 5  undefined.hostname.localhost      30.8ms    (ISP)
 6  incapsula.plix.pl                 38.3ms    (Imperva @ PLIX)
 7-30  * * * (no reply)
```

Hop #6 (`incapsula.plix.pl`) wskazuje na wezel Impervy zlokalizowany na PLIX (Polish Internet Exchange Point) w Warszawie. Latencja ~38ms jest typowa dla polaczenia krajowego. Od hopu 7 serwer blokuje odpowiedzi ICMP -- standardowa praktyka dla WAF/CDN.

### 2.4. Wniosek dotyczacy infrastruktury

MF korzysta z **chmurowego Cloud WAF (Incapsula)** w modelu SaaS. Potwierdza to:

- IP z puli Incapsula (nie MF)
- CNAME do impervadns.net (DNS zarzadzany przez Imperva)
- Traceroute przez incapsula.plix.pl (sprzet Impervy na PLIX)
- Kontakty NOC/abuse prowadzace do Thales Group

Gdyby WAF dzialal on-premise na infrastrukturze MF, adres IP nalezalby do polskiej instytucji (np. NASK), DNS nie zawieralby CNAME do impervadns.net, a traceroute nie prowadzilby przez wezel incapsula.plix.pl.

## 3. Certyfikat SSL/TLS

### 3.1. Lancuch certyfikatow

**Polecenia weryfikujace:**

```bash
# Pelne dane certyfikatu
echo | openssl s_client -connect ksef.mf.gov.pl:443 \
  -servername ksef.mf.gov.pl 2>/dev/null | \
  openssl x509 -noout -text

# Lancuch certyfikatow (skrocony)
echo | openssl s_client -connect ksef.mf.gov.pl:443 \
  -servername ksef.mf.gov.pl -showcerts 2>/dev/null | \
  grep -E "subject=|issuer=|s:|i:"
```

**Wynik:**

| Poziom | Podmiot (Subject) | Wystawca (Issuer) |
|---|---|---|
| Certyfikat serwera | C=PL, L=Warszawa, O=MINISTERSTWO FINANSOW, CN=*.ksef.mf.gov.pl | GeoTrust TLS RSA CA G1 |
| Certyfikat posredni | GeoTrust TLS RSA CA G1 | DigiCert Global Root G2 |
| Root CA | DigiCert Global Root G2 | DigiCert Global Root G2 (self-signed) |

### 3.2. Szczegoly certyfikatu serwera

- **Wlasciciel:** MINISTERSTWO FINANSOW, Warszawa, PL
- **Domena:** `*.ksef.mf.gov.pl` (wildcard) + `ksef.mf.gov.pl`
- **Waznosc:** 2025-12-08 -- 2026-12-07
- **Klucz:** RSA 2048-bit
- **Algorytm podpisu:** SHA-256 z RSA

### 3.3. Implikacje dla bezpieczenstwa

Certyfikat SSL jest wystawiony na Ministerstwo Finansow. Poniewaz Imperva dziala jako reverse proxy terminujacy TLS, klucz prywatny tego certyfikatu **musi znajdowac sie na serwerach Impervy** -- bez niego nie moglyby odszyfrowac ruchu HTTPS w celu inspekcji WAF na warstwie 7 (HTTP).

Istnieje technologia "Keyless SSL" (stosowana np. przez Cloudflare), w ktorej klucz prywatny pozostaje u klienta, a CDN/WAF proxy'uje tylko handshake TLS. Jednakze nawet w tym modelu WAF uzyskuje klucze sesyjne i moze odszyfrowac ruch -- roznica polega jedynie na tym, ze nie posiada dlugoterminowego klucza prywatnego.

## 4. Szyfrowanie na poziomie aplikacji (KSeF 2.0 API)

### 4.1. Mechanizm szyfrowania -- wysylanie faktur

KSeF 2.0 implementuje obowiazkowe szyfrowanie hybrydowe (RSA + AES) na poziomie aplikacji.

**Zrodlo: oficjalne SDK KSeF**
- PHP: https://github.com/tommekk83/ksef-api-v2 (plik `src/Crypto.php`)
- C#: https://github.com/CIRFMF/ksef-client-csharp
- Java: https://github.com/CIRFMF/ksef-client-java

**Schemat szyfrowania przy wysylce faktury:**

```
1. Klient generuje losowy klucz AES-256 (32 bajty) + IV (16 bajtow)
2. Klient szyfruje XML faktury: AES-256-CBC z PKCS#7 padding
3. Klient szyfruje klucz AES: RSA OAEP (SHA-256/MGF1) kluczem publicznym MF
4. Klient wysyla: zaszyfrowany blob + zaszyfrowany klucz AES + IV
5. Serwer MF deszyfruje klucz AES swoim kluczem prywatnym RSA
6. Serwer MF deszyfruje fakture XML
```

**Polecenie weryfikujace (pobranie kodu zrodlowego):**

```bash
curl -sL 'https://raw.githubusercontent.com/tommekk83/ksef-api-v2/main/src/Crypto.php'
```

**Kluczowy fragment kodu (PHP SDK):**

```php
// Generowanie klucza AES-256
public function generateSymetricKey(): array {
    return [
        'key' => random_bytes(32),  // 256-bit
        'iv'  => random_bytes(16),  // 128-bit
    ];
}

// Szyfrowanie klucza AES kluczem publicznym MF
public function encryptSymmetricKey(string $symmetricKey): string {
    // RSA OAEP SHA-256/MGF1
    return $this->mfPublicKey->encrypt($symmetricKey);
}

// Szyfrowanie XML faktury
public function encryptXmlPayload(string $xml, string $symmetricKey, string $iv): string {
    return openssl_encrypt($xml, 'aes-256-cbc', $symmetricKey, OPENSSL_RAW_DATA, $iv);
}
```

Szyfrowanie przy otwieraniu sesji jest **obowiazkowe** -- pole `encryption` jest wymagane (nie nullable):

```php
// src/Models/Operations/OpenOnlineSessionRequest.php
public function __construct(
    OpenOnlineSessionFormCode $formCode,
    OpenOnlineSessionEncryption $encryption  // required
)
```

### 4.2. Mechanizm szyfrowania -- masowy eksport faktur

Eksport (pobieranie) faktur w paczkach rowniez wymaga podania klucza szyfrujacego.

**Polecenie weryfikujace:**

```bash
curl -sL 'https://raw.githubusercontent.com/tommekk83/ksef-api-v2/main/src/Models/Operations/ExportRequest.php'
curl -sL 'https://raw.githubusercontent.com/tommekk83/ksef-api-v2/main/src/Models/Operations/ExportEncryption.php'
```

**Schemat szyfrowania przy eksporcie:**

```
1. Klient generuje losowy klucz AES-256 + IV
2. Klient szyfruje klucz AES kluczem publicznym RSA MF
3. Klient wysyla zaszyfrowany klucz + IV w requeście eksportu
4. Serwer MF deszyfruje klucz AES swoim kluczem prywatnym RSA
5. Serwer MF szyfruje paczke faktur tym kluczem AES-256-CBC
6. Klient pobiera zaszyfrowana paczke i deszyfruje swoim kluczem AES
   (klient zna klucz, bo sam go wygenerował w kroku 1)
```

Pole `encryption` w `ExportRequest` jest **wymagane**:

```php
// src/Models/Operations/ExportRequest.php
public function __construct(
    ExportEncryption $encryption,  // required
    Filters $filters
)
```

Z dokumentacji API: "Paczka faktur jest dzielona na czesci o maksymalnym rozmiarze 50 MB. Kazda czesc jest zaszyfrowana algorytmem AES-256-CBC z dopelnieniem PKCS#7, przy uzyciu klucza symetrycznego przekazanego podczas inicjowania eksportu."

### 4.3. Brak szyfrowania -- pobieranie pojedynczej faktury

Endpoint `GET /invoices/ksef/{ksefNumber}` zwraca fakture jako **plain XML** bez szyfrowania na poziomie aplikacji.

**Polecenie weryfikujace:**

```bash
curl -sL 'https://raw.githubusercontent.com/tommekk83/ksef-api-v2/main/src/Invoices.php'
```

**Kluczowy fragment kodu:**

```php
// Invoices.php -- metoda getByKsefNumber
$httpOptions['headers']['Accept'] = 'application/xml';  // oczekuje plain XML
// ...
$obj = $httpResponse->getBody()->getContents();  // surowy XML, brak deszyfrowania
return new Operations\GetByKsefNumberResponse(
    // ...
    res: $obj  // typ: ?string -- zwykly string
);
```

Brak jakiegokolwiek parametru szyfrowania w requeście. Brak logiki deszyfrowania w odpowiedzi. Odpowiedz to `?string $res`.

### 4.4. Brak szyfrowania -- metadane faktur

Endpoint `POST /invoices/query/metadata` zwraca metadane (NIP-y, kwoty, daty, typy faktur) jako **plain JSON**.

**Polecenie weryfikujace:**

```bash
curl -sL 'https://raw.githubusercontent.com/tommekk83/ksef-api-v2/main/docs/sdks/invoices/README.md'
```

### 4.5. Podsumowanie szyfrowania wedlug endpointow

| Endpoint | Operacja | Szyfrowanie app-layer | Co widzi Imperva |
|---|---|---|---|
| `POST /sessions/online` | Otwarcie sesji | RSA OAEP (wymiana klucza) | zaszyfrowany klucz |
| `POST /sessions/online/{ref}/invoices/` | Wysylanie faktury | AES-256-CBC (obowiazkowe) | zaszyfrowany blob |
| `POST /invoices/exports` | Masowy eksport | AES-256-CBC (obowiazkowe) | zaszyfrowany blob |
| `GET /invoices/ksef/{ksefNumber}` | **Pobranie faktury** | **BRAK** | **pelna tresc XML** |
| `POST /invoices/query/metadata` | **Metadane faktur** | **BRAK** | **NIP-y, kwoty, daty** |

## 5. Model autoryzacji -- ograniczenie zasiegu

Dostep do faktur jest ograniczony kontekstem uwierzytelnienia (NIP).

**Polecenie weryfikujace:**

```bash
curl -sL 'https://raw.githubusercontent.com/CIRFMF/ksef-docs/main/uwierzytelnianie.md'
```

### 5.1. Kontekst sesji

Kazde uwierzytelnienie w KSeF wymaga podania `ContextIdentifier` -- NIP podmiotu, w imieniu ktorego wykonywane sa operacje. Token JWT (`accessToken`) jest przypisany do tego NIP-u. System weryfikuje, czy podmiot uwierzytelniajacy posiada uprawnienia do dzialania w kontekscie danego NIP-u.

### 5.2. Zakres widocznosci faktur

Filtry `SubjectType` ograniczaja widocznosc:

| SubjectType | Znaczenie |
|---|---|
| Subject1 | Faktury, w ktorych podmiot jest **sprzedawca** |
| Subject2 | Faktury, w ktorych podmiot jest **nabywca** |

Nie ma mozliwosci pobrania faktury, w ktorej NIP podmiotu nie wystepuje jako strona transakcji. Endpoint `GET /invoices/ksef/{ksefNumber}` wymaga tokena powiazanego z NIP-em jednej ze stron faktury.

### 5.3. Implikacje

Imperva widzi plain XML tylko tych faktur, ktore sa pobierane przez konkretny zalogowany podmiot -- nie ma dostępu do calej bazy faktur. Zakres ekspozycji jest ograniczony do faktur podmiotu wykonujacego zapytanie w danym momencie. Jednakowoz przy skali calego systemu (wszystkie polskie firmy korzystajace z KSeF) laczny wolumen ruchu nieszyfrowanego na poziomie aplikacji jest znaczny.

## 6. Ocena ryzyka

### 6.1. Co Imperva moze widziec

**Zawsze (niezaleznie od szyfrowania app-layer):**
- Adresy IP klientow
- Naglowki HTTP (endpointy API, tokeny sesji w naglowku Authorization)
- Parametry zapytan (zakresy dat, numery KSeF w URL-ach)
- Rozmiar i czestotliwosc zapytan (analiza ruchu)

**Przy pobieraniu pojedynczych faktur i metadanych:**
- Pelna tresc XML faktur (NIP-y, kwoty, pozycje, kontrahenci)
- Metadane: listy faktur z kwotami, datami, NIP-ami nabywcow/sprzedawcow

**Czego NIE widzi (szyfrowanie AES-256-CBC):**
- Tresc faktur wysylanych do KSeF
- Tresc paczek eksportowanych masowo

### 6.2. Czynniki lagodzace

1. Szyfrowanie app-layer dla uploadu i masowego eksportu skutecznie chroni te operacje
2. Autoryzacja ogranicza dostep do faktur wlasnego podmiotu
3. Wezel Impervy na PLIX (Warszawa) minimalizuje routing zagraniczny
4. MF deklaruje, ze serwery docelowe sa w Polsce
5. Imperva/Thales podlega regulacjom UE (RODO) w zakresie przetwarzania danych

### 6.3. Czynniki ryzyka

1. Imperva Inc. jest zarejestrowana w USA -- potencjalnie podlega US CLOUD Act
2. Thales Group (wlasciciel) ma siedzibe we Francji -- podlega prawu francuskiemu i EU
3. Brak szyfrowania app-layer dla `GET /invoices/ksef/{ksefNumber}` i metadanych
4. Klucz prywatny certyfikatu SSL musi byc na serwerach Impervy
5. Brak publicznej informacji o audycie bezpieczenstwa tej konfiguracji
6. Klucz publiczny RSA MF pobierany jest z endpointu API (`GET /api/v2/security/public-key-certificates`) -- gdyby Imperva podmienila ten klucz, moglaby odszyfrowac rowniez ruch szyfrowany na poziomie aplikacji (szczegoly w sekcji 6.4)

### 6.4. Ryzyko podmiany klucza publicznego RSA -- neutralizacja szyfrowania app-layer

#### 6.4.1. Opis wektora ataku

Szyfrowanie na poziomie aplikacji w KSeF 2.0 opiera sie na kryptogrfii asymetrycznej: klient szyfruje klucz symetryczny AES-256 **kluczem publicznym RSA Ministerstwa Finansow**, a serwer deszyfruje go odpowiadajacym kluczem prywatnym. Bezpieczenstwo tego schematu zalezy od tego, ze klient uzywa **autentycznego** klucza publicznego MF.

Klucz publiczny MF jest pobierany dynamicznie z endpointu API:

```
GET /security/public-key-certificates
```

**Polecenia weryfikujace:**

```bash
# Kod endpointu w SDK
curl -sL 'https://raw.githubusercontent.com/tommekk83/ksef-api-v2/main/src/Security.php'

# Model odpowiedzi
curl -sL 'https://raw.githubusercontent.com/tommekk83/ksef-api-v2/main/src/Models/Components/PublicKeyCertificate.php'

# Dokumentacja endpointu
curl -sL 'https://raw.githubusercontent.com/tommekk83/ksef-api-v2/main/docs/sdks/security/README.md'
```

**Kluczowe obserwacje:**

1. Endpoint `GET /security/public-key-certificates` **nie wymaga uwierzytelnienia** -- jest publiczny
2. Odpowiedz zawiera certyfikat w formacie DER/Base64 z polami `validFrom`, `validTo` i `usage`
3. SDK **nie zawiera wbudowanego (pinowanego) klucza publicznego MF** -- za kazdym razem pobiera go z API
4. Ruch do tego endpointu przechodzi przez Imperva (jak kazdy ruch do KSeF)
5. Zaden z analizowanych SDK (PHP, C#, Java) nie implementuje walidacji certyfikatu klucza publicznego MF wzgledem niezaleznego zrodla

**Model danych zwracanych z endpointu:**

```php
// src/Models/Components/PublicKeyCertificate.php
class PublicKeyCertificate {
    public string $certificate;       // DER Base64 -- sam klucz publiczny
    public \DateTime $validFrom;
    public \DateTime $validTo;
    public array $usage;              // KsefTokenEncryption | SymmetricKeyEncryption
}
```

Pole `usage` przyjmuje wartosci:
- `KsefTokenEncryption` -- szyfrowanie tokenow KSeF w procesie uwierzytelniania
- `SymmetricKeyEncryption` -- szyfrowanie klucza symetrycznego do szyfrowania faktur

#### 6.4.2. Scenariusz ataku

Podmiot kontrolujacy warstwe TLS (w tym przypadku Imperva) moze teoretycznie:

```
1. Klient wysyla: GET /security/public-key-certificates
2. Imperva przechwytuje odpowiedz serwera MF
3. Imperva podmienia klucz publiczny MF na SWOJ klucz publiczny
4. Klient otrzymuje sfalszyowny klucz i uzywa go do szyfrowania

5. Klient wysyla zaszyfrowana fakture (zaszyfrowana FAŁSZYWYM kluczem)
6. Imperva deszyfruje fakture SWOIM kluczem prywatnym
7. Imperva ponownie szyfruje fakture PRAWDZIWYM kluczem publicznym MF
8. Imperva przekazuje poprawnie zaszyfrowana fakture do serwera MF
9. Serwer MF deszyfruje i przetwarza fakture normalnie

Ani klient, ani serwer nie zauwazyliby podmiany.
```

Ten sam mechanizm umozliwilby odczyt szyfrowanych paczek eksportowych:

```
1. Klient wysyla klucz AES zaszyfrowany FAŁSZYWYM kluczem RSA
2. Imperva deszyfruje klucz AES, przekazuje go zaszyfrowanego PRAWDZIWYM kluczem MF
3. MF szyfruje eksport kluczem AES klienta
4. Imperva zna klucz AES -- moze odczytac eksportowane faktury
```

Taki atak rowniez pozwolilby na przechwycenie tokenow KSeF przesylanych w procesie uwierzytelniania (pole `usage: KsefTokenEncryption`), co umozliwiloby przejecie sesji uwierzytelnionych uzytkownikow.

#### 6.4.3. Dlaczego atak jest trudny do wykrycia

- Klient nie ma niezaleznego zrodla do weryfikacji klucza publicznego MF (brak pinningu)
- Serwer MF otrzymuje poprawnie zaszyfrowane dane (Imperva re-encryptuje prawdziwym kluczem)
- Zadna ze stron nie widzi anomalii w komunikacji
- Certyfikat klucza publicznego nie jest podpisany lancuchem zaufania niezaleznym od TLS (jest to po prostu DER/Base64 serwowany z HTTP API)
- Weryfikacja wymagalaby porownania klucza z zaufanym zrodlem offline (np. opublikowanym na stronie MF, w Dzienniku Ustaw, lub wbudowanym w certyfikowane oprogramowanie)

#### 6.4.4. Czynniki lagodzace

1. **Ryzyko reputacyjne** -- Imperva/Thales jest duza, publicznie znana firma. Aktywna podmiana kluczy byloby przestepstwem i koncem firmy w razie wykrycia
2. **Wymogi umowne** -- umowa miedzy MF a Imperva zapewne zawiera klauzule bezpieczenstwa i audytu
3. **Mozliwosc wykrycia** -- kazdy moze pobrac klucz z endpointu i porownac go z kluczem pobranym innym kanalem (np. bezposrednio z serwera MF z pominieciem Imperva, jesli taki kanal istnieje). Rozne systemy ERP pobierajace klucz z roznych lokalizacji sieciowych moglaby tez porownywac otrzymane klucze
4. **Selektywnosc ataku** -- podmiana klucza musialoby byc stosowane globalne (dla wszystkich klientow) lub selektywnie (dla wybranych IP), co zwieksza ryzyko wykrycia
5. **Atak wymaga aktywnej interwencji** -- samo terminowanie TLS to operacja pasywna; podmiana klucza wymagalaby modyfikacji logiki przetwarzania ruchu na WAF-ie

#### 6.4.5. Rekomendacje

1. **Key pinning** -- SDK i systemy ERP powinny wbudowac (pinowac) klucz publiczny MF lub jego hash, i porownywac go z kluczem pobranym z API. Jakakkoliwek rozbieznosc powinna skutkowac odmowa komunikacji i alertem
2. **Publikacja klucza offline** -- MF powinno opublikowac klucz publiczny (lub jego fingerprint SHA-256) w zrodle niezaleznym od infrastruktury KSeF, np. w Dzienniku Ustaw, na stronie gov.pl hosotwanej na innej infrastrukturze, lub w Biuletynie Informacji Publicznej
3. **Certificate Transparency** -- klucz publiczny MF moglby byc publikowany w logu CT lub podobnym mechanizmie transparentnosci
4. **Audyt niezalezny** -- niezalezna jednostka powinna okresowo porownywac klucz serwowany przez API z kluczem przechowywanym offline przez MF

**Polecenie weryfikujace -- porownanie klucza z roznych lokalizacji:**

```bash
# Pobranie klucza z API KSeF (przechodzi przez Imperva)
curl -s 'https://ksef.mf.gov.pl/security/public-key-certificates' | \
  python3 -m json.tool

# Porownanie z kluczem pobranym z innego zrodla (jesli dostepne)
# np. z dokumentacji offline, repozytorium CIRFMF, itp.

# Wyciagniecie fingerprinta klucza do porownania:
curl -s 'https://ksef.mf.gov.pl/security/public-key-certificates' | \
  python3 -c "
import json, sys, base64, hashlib
data = json.load(sys.stdin)
for cert in data:
    der = base64.b64decode(cert['certificate'])
    print(f'SHA-256: {hashlib.sha256(der).hexdigest()}')
    print(f'Usage: {cert[\"usage\"]}')
    print(f'Valid: {cert[\"validFrom\"]} - {cert[\"validTo\"]}')
    print()
"
```

## 7. Metodologia

Analiza przeprowadzona z uzyciem:
- `getent hosts` -- resolucja DNS
- `whois` -- identyfikacja wlasciciela IP (rejestr ARIN)
- `tracepath` -- sciezka sieciowa do serwera
- `openssl s_client` + `openssl x509` -- analiza certyfikatu SSL/TLS
- Analiza kodu zrodlowego SDK KSeF 2.0 (PHP: github.com/tommekk83/ksef-api-v2)
- Analiza oficjalnej dokumentacji CIRFMF (github.com/CIRFMF/ksef-docs)

Wszystkie polecenia mozna powtorzyc z dowolnej maszyny Linux z dostepem do internetu. Adresy IP i rekordy DNS moga ulec zmianie -- wyniki sa aktualne na dzien analizy.

## 8. Zrodla

- Oficjalna dokumentacja KSeF: https://ksef.podatki.gov.pl/
- Repozytorium CIRFMF (dokumentacja techniczna MF): https://github.com/CIRFMF/ksef-docs
- SDK PHP KSeF 2.0: https://github.com/tommekk83/ksef-api-v2
- SDK C# KSeF: https://github.com/CIRFMF/ksef-client-csharp
- SDK Java KSeF: https://github.com/CIRFMF/ksef-client-java
- Komunikat MF o zmianie adresow: https://www.gov.pl/web/finanse/przypominamy-o-zmianie-adresow-srodowisk-ksef--komunikat-dla-integratorow
- Imperva WAF deployment models: https://www.imperva.com/products/web-application-firewall-waf/
