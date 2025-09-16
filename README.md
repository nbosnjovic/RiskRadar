# RiskRadar

Aplikacija za sigurnosno skeniranje pomoću OWASP ZAP-a.  
Ovaj README je pisan za Windows + PowerShell.

---

## 1) Preduslovi

- **Docker Desktop** (Engine running) – https://www.docker.com/products/docker-desktop  
- **Python 3.11+** i **pip** – https://www.python.org/downloads/  

> Provjera:
> ```powershell
> docker version     # mora prikazati i Client i Server
> py --version       # ili python --version
> ```

---

## 2) Kloniraj repozitorij
git clone https://github.com/<TVOJ-USER>/RiskRadar.git
cd RiskRadar

## 3) Postavi Python okruženje
python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r requirements.txt

## 4)Pokreni OWASP ZAP (Docker)

1. Definiši API ključ (možeš izabrati svoj):
  $env:ZAP_API_KEY = "MOJ_TAJNI_KEY_123"

2. Pokreni ZAP kontejner:
  docker rm -f zap_rrmin 2>$null

  docker run -d --name zap_rrmin -u zap -p 8090:8090 `
  -e ZAP_API_KEY=$env:ZAP_API_KEY `
  ghcr.io/zaproxy/zaproxy:stable `
  zap.sh -daemon -host 0.0.0.0 -port 8090 `
  -config api.addrs.addr.name=".*" -config api.addrs.addr.regex=true `
  -config api.key=$env:ZAP_API_KEY

3. Provjeri da ZAP radi (sačekaj 20–30 sekundi):
  & "$Env:SystemRoot\System32\curl.exe" "http://localhost:8090/JSON/core/view/version/?apikey=$env:ZAP_API_KEY"

    Ako dobiješ nešto tipa:
    {"version":"2.16.0"}
      ZAP API radi

## 5)Pokreni aplikaciju
  U istom prozoru gdje je aktivan .venv:
    $env:ZAP_PROXY = "http://localhost:8090"
    $env:FLASK_APP = "app.py"

    flask run --host=0.0.0.0 --port=5000


    Aplikacija će biti dostupna na: http://127.0.0.1:5000

## 6)Dozvoljeno aktivno skeniranje(opciono): OWASP Juice Shop
      docker rm -f juice 2>$null
      docker run -d --name juice -p 3001:3000 bkimminich/juice-shop
      Otvoriti: http://localhost:3001
      Za sken target koristi: http://host.docker.internal:3001



U okviru ovog projekta, aktivno („full mode”) skeniranje dozvoljeno je isključivo nad web adresama eksplicitno navedenim u .env fajl-u, kao i u konfiguraciji ALLOWED_SCAN_HOSTS. 

Dozvoljene web adrese preuzete su sa: https://owasp.org/www-project-vulnerable-web-applications-directory/

http://testphp.vulnweb.com/
https://ginandjuice.shop/
https://google-gruyere.appspot.com/
http://testphp.yulweh.com/
https://ctflearn.com/
https://www.hackthissite.org/
https://hack-yourself-first.com/
http://aspnet.testsparker.com/
http://php.testsparker.com/process.php?file=Generics/index.nsp
https://secureby.design/
https://pentest-ground.com/
https://pentesteracademylab.appspot.com/
http://testhtml5.vulnweb.com/#/popular
https://solyd.com.br/
http://zero.webappsecurity.com/

Sve ostale adrese su zabranjene, a postavka ALLOW_ANY_ACTIVE_SCAN=false dodatno osigurava da se aktivno skeniranje ne može pokrenuti izvan ove liste. Sva testiranja provode se u edukativne i kontrolisane svrhe, uz poštivanje važećih zakona, uslova korištenja i etičkih smjernica.

Pasivno ("quick mode") skeniranje je dozvoljeno nad svim web adresama.
