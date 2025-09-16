# RiskRadar

Aplikacija za sigurnosno skeniranje pomoću OWASP ZAP-a.  
Ovaj README je pisan za Windows + PowerShell.

---

## 1) Preduslovi

- **Docker Desktop** (Engine running) – https://www.docker.com/products/docker-desktop  
- **Python 3.11+** i **pip** – https://www.python.org/downloads/  
- (Opcionalno) **Git** – https://git-scm.com/download/win

> Provjera:
> ```powershell
> docker version     # mora prikazati i Client i Server
> py --version       # ili python --version
> ```

---

## 2) Brzi start (lokalno, venv + Flask)

1) **Pokreni OWASP ZAP** u Dockeru na 8090  
   (odaberi API ključ – isti koristi i aplikacija)
   ```powershell
   $KEY = "<STAVI_SVOJ_API_KLJUC>"

   docker rm -f zap_rrmin 2>$null
   docker run -d --name zap_rrmin -u zap -p 8090:8090 `
     -e ZAP_API_KEY=$KEY `
     ghcr.io/zaproxy/zaproxy:stable `
     zap.sh -daemon -host 0.0.0.0 -port 8090 `
     -config api.addrs.addr.name=".*" -config api.addrs.addr.regex=true `
     -config api.key=$KEY
Brza provjera ZAP-a:

powershell
Copy code
& "$Env:SystemRoot\System32\curl.exe" http://localhost:8090/JSON/core/view/version/
Pokreni aplikaciju

powershell
Copy code
# u rootu projekta
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt

$env:ZAP_API_KEY = "<ISTI_KLJUC_KAO_GORE>"
$env:ZAP_PROXY   = "http://localhost:8090"
$env:FLASK_APP   = "app.py"

flask run --host=0.0.0.0 --port=5000
Otvori: http://localhost:5000

Skeniraj cilj

Ako skeniraš lokalni servis koji radi na Windows hostu (npr. Juice Shop):
koristi target http://host.docker.internal:<PORT> (jer ZAP radi u Dockeru).

QUICK = brzi pasivni pregled, FULL = uključuje active scan (više nalaza).

3) Demo cilj (opciono): OWASP Juice Shop
powershell
Copy code
docker rm -f juice 2>$null
docker run -d --name juice -p 3001:3000 bkimminich/juice-shop
Otvoriti: http://localhost:3001
Za sken target koristi: http://host.docker.internal:3001

4) Konfiguracija (env varijable)
Primjer .env.example (ne committati stvarne tajne):

ini
Copy code
ZAP_API_KEY=PUT_YOUR_KEY_HERE
ZAP_PROXY=http://localhost:8090
FLASK_APP=app.py
U Pythonu se u kodu već čita:

python
Copy code
from zapv2 import ZAPv2
import os
zap = ZAPv2(
  apikey=os.getenv("ZAP_API_KEY", "changeme"),
  proxies={
    "http":  os.getenv("ZAP_PROXY", "http://localhost:8090"),
    "https": os.getenv("ZAP_PROXY", "http://localhost:8090")
  }
)
Sigurnost: nemoj commitati .env. Dijelite ključ privatno.
Svako može imati svoj ključ; bitno je da ZAP i app koriste isti na toj mašini.

5) Troubleshooting (najčešće)
A) Docker pipe/_ping greška

arduino
Copy code
error during connect: ... dockerDesktopLinuxEngine/_ping ...
Docker engine nije pokrenut → otvori Docker Desktop i sačekaj Engine running.
Provjera: docker version mora pokazati i Client i Server.

B) Unable to connect to proxy (8090) / actively refused
ZAP ne radi ili port ne sluša. Pokreni ZAP komandama iz poglavlja 2.1 i provjeri:

powershell
Copy code
& "$Env:SystemRoot\System32\curl.exe" http://localhost:8090/JSON/core/view/version/
C) API key incorrect or not supplied (u ZAP logu)
App i ZAP nemaju isti ključ → postavi:

powershell
Copy code
$env:ZAP_API_KEY = "<ISTI_KLJUC_KAO_U_ZAPU>"
$env:ZAP_PROXY   = "http://localhost:8090"
D) 0 nalaza kada target = http://localhost:<port>
ZAP je u Dockeru → koristi http://host.docker.internal:<port> (npr. 3001).

E) ZAP unhealthy / health: starting
Pričekaj 20–60s (učitava add-onove). Ako /JSON/core/view/version/ vraća JSON, možeš nastaviti.

F) ExecutionPolicy pri aktivaciji venv-a

csharp
Copy code
running scripts is disabled on this system
Rješenje:

powershell
Copy code
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
6) (Opcionalno) Docker Compose varijanta
Ako želiš i aplikaciju u Dockeru (bez lokalnog Pythona), minimalni docker-compose.yml:

yaml
Copy code
version: "3.9"
services:
  zap:
    image: ghcr.io/zaproxy/zaproxy:stable
    command: >
      zap.sh -daemon -host 0.0.0.0 -port 8090
      -config api.addrs.addr.name=.*
      -config api.addrs.addr.regex=true
      -config api.key=${ZAP_API_KEY}
    ports:
      - "8090:8090"

  app:
    build: .
    depends_on: [zap]
    environment:
      ZAP_API_KEY: ${ZAP_API_KEY}
      ZAP_PROXY: http://zap:8090
      FLASK_APP: app.py
    ports:
      - "5000:5000"
Potreban je Dockerfile koji starta Flask (npr. CMD ["flask","run","--host=0.0.0.0","--port=5000"]).
U istom folderu kreiraj .env sa ZAP_API_KEY=<tvoj_kljuc> pa:

powershell
Copy code
docker compose up -d --build
