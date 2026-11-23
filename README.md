# Security Scanner

Scanner **passivo** di sicurezza per domini web, scritto in Python. Dato un dominio restituisce:

- un **punteggio di sicurezza da 0 a 100** (100 = sicuro) e un **livello di rischio**;
- per ogni problema la **gravita'**, i **punti persi** e il **perche'** e' pericoloso (quale attacco rende possibile);
- una **verifica di legittimita'** del dominio, che riconosce omografi e domini *lookalike* (es. `paypa1.com`, `gіthub.com` con la "i" cirillica).

Si usa da riga di comando oppure da un'interfaccia web locale.

> Lo scanner e' **passivo**: legge solo cio' che il sito mostra a un normale visitatore (homepage,
> header, certificato, DNS). Non prova attacchi e non cerca file nascosti.

## Requisiti

- Python 3.11 o successivo
- le librerie in `requirements.txt` (`requests`, `dnspython`)

```bash
pip install -r requirements.txt
```

Su Windows si usa `py` al posto di `python`.

## Uso

```bash
py scanner.py example.com            # report a terminale
py scanner.py example.com --json     # report in JSON
py scanner.py --update-tranco        # scarica/aggiorna la classifica dei siti piu' visitati

py app.py                            # interfaccia web su http://127.0.0.1:8000
py app.py --port 9000 --no-browser
```

Il repository include gia' la classifica [Tranco](https://tranco-list.eu/) dei 100.000 siti piu'
visitati (`data/tranco/`, la data di download e' in `info.json`), usata per riconoscere i domini che
imitano siti noti. La classifica cambia nel tempo: per aggiornarla basta `py scanner.py --update-tranco`.

## Cosa controlla

| Area | Esempi di controlli |
|---|---|
| HTTPS/TLS | HTTPS disponibile, redirect da HTTP, certificato valido e in scadenza, TLS 1.0/1.1 disabilitati |
| Legittimita' | caratteri ingannevoli (IDN), somiglianza con marchi noti, marchio dichiarato dalla pagina (verificato su Wikidata), eta' del dominio |
| Header | HSTS, Content-Security-Policy, protezione clickjacking, `nosniff`, Referrer-Policy, Permissions-Policy |
| Cookie | flag `Secure`, `HttpOnly`, `SameSite` |
| Info disclosure | banner del server, versioni dei framework |
| CORS | `Origin` arbitrari accettati |
| DNS/Email | SPF, DMARC, CAA |
| Varie | `security.txt` |

### Come si calcola il punteggio

`punteggio = punti ottenuti / punti massimi dei controlli applicabili * 100`

- I controlli che non si possono verificare o che non si applicano vengono **esclusi dal calcolo**:
  non contano ne' a favore ne' contro, e il report spiega sempre il motivo.
- Alcuni problemi critici mettono un **tetto** al punteggio: HTTPS assente (max 20), certificato non
  valido (max 35), dominio lookalike (max 15), dominio sospetto (max 50).
- **Livelli di rischio:** BASSO da 85, MODERATO da 65, ELEVATO da 45, ALTO da 25, sotto CRITICO.

### Verifica di legittimita'

Verdetti possibili: `UFFICIALE`, `LEGITTIMO` (prove che il proprietario e' lo stesso del marchio),
`NON SOSPETTO`, `SOSPETTO`, `LOOKALIKE`.

Lo scanner cerca somiglianze con i marchi noti: caratteri di altri alfabeti, lettere scambiate (`0`/`o`,
`rn`/`m`), errori di battitura, parole aggiunte (`marchio-login.com`), marchio nel sottodominio,
estensione diversa. Poi cerca prove che il proprietario sia lo stesso (certificato condiviso, nameserver,
redirect al sito ufficiale) e tiene conto di eta' e popolarita' del dominio.

## Casi particolari gestiti

- **Domini di solo redirect** (es. `zalando.com` -> `www.zalando.it`): il dominio viene giudicato sulla
  propria risposta di redirect (HTTPS, HSTS, TLS, certificato, primo salto da `http://`). I controlli sui
  contenuti, come CSP e clickjacking, non si applicano. La destinazione riceve un punteggio a parte,
  mostrato in evidenza.
- **Protezioni anti-bot** (AWS WAF, Cloudflare, Akamai, DataDome, Imperva...): se al posto della homepage
  arriva una pagina di blocco, o una risposta 401/403/429/5xx, il risultato e' segnato come
  "non affidabile". Header e cookie di quella pagina non vengono giudicati.
- **User-Agent:** ogni pagina viene chiesta sia "come un browser" sia "come lo scanner", perche' alcuni
  siti (es. google.com) mandano HSTS e redirect solo ai browser.
- **Certificato intermedio mancante:** viene recuperato via AIA, come fanno i browser, prima di
  dichiarare il certificato non valido.

## Test

I test non usano la rete: lavorano su risposte HTTP finte.

```bash
py -m unittest discover -s tests -v
```

## Struttura

```
scanner.py          riga di comando
app.py              server web locale (solo libreria standard)
web/                interfaccia web (HTML, CSS, JavaScript senza dipendenze)
secscan/
  scanner.py        orchestratore
  fetcher.py        richieste HTTP/HTTPS
  antibot.py        riconoscimento delle pagine di blocco
  scorer.py         punteggio, tetti, livelli
  report.py         report a terminale e JSON
  checks/           un modulo per area (tls, headers, web, dns_email, lookalike)
  lookalike/        verifica di legittimita' (omoglifi, marchi, Tranco, Wikidata, eta' del dominio)
tests/              test automatici
```

## Limiti

- E' un'analisi passiva della sola homepage: non sostituisce un penetration test.
- Un punteggio alto non certifica che il sito sia affidabile. Indica che la configurazione di sicurezza
  visibile dall'esterno e' buona.
- Se un sito blocca lo scanner, il punteggio si basa su meno controlli.
- I servizi esterni (Wikidata, RDAP, Tranco) possono essere lenti o non rispondere: in quel caso i
  controlli relativi vengono esclusi.
